//! Axum router configuration.

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

const API_RATE_LIMIT_BURST: u64 = 128;
const API_RATE_LIMIT_PER_SECOND: u64 = 64;

#[derive(Clone)]
struct ApiRateLimiter {
    bucket: Arc<crate::rate_limit::TokenBucket>,
}

async fn enforce_api_rate_limit(
    State(limiter): State<ApiRateLimiter>,
    request: Request<axum::body::Body>,
    next: Next,
) -> crate::Result<Response> {
    if !limiter.bucket.allow() {
        return Err(crate::ApiError::RateLimited(
            "local API request rate exceeded".into(),
        ));
    }

    Ok(next.run(request).await)
}

/// Build the Axum router with all API endpoints.
pub fn build_router(state: crate::state::SharedApiState) -> Router {
    let limiter = ApiRateLimiter {
        bucket: Arc::new(crate::rate_limit::TokenBucket::new(
            API_RATE_LIMIT_BURST,
            API_RATE_LIMIT_PER_SECOND,
        )),
    };

    Router::new()
        .route("/v1/status", get(crate::handlers::status::get_status))
        .route("/v1/peers", get(crate::handlers::peers::list_peers))
        .route("/v1/peers", post(crate::handlers::peers::add_peer))
        .route(
            "/v1/peers/:name",
            delete(crate::handlers::peers::remove_peer),
        )
        .route(
            "/v1/peers/:name/rotate",
            post(crate::handlers::peers::rotate_keys),
        )
        .route("/v1/tunnels", get(crate::handlers::tunnels::list_tunnels))
        .route("/v1/metrics", get(crate::handlers::metrics::get_metrics))
        .route(
            "/v1/algorithm",
            get(crate::handlers::algorithm::get_algorithm)
                .post(crate::handlers::algorithm::switch_algorithm),
        )
        .layer(middleware::from_fn_with_state(
            limiter,
            enforce_api_rate_limit,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{build_router, enforce_api_rate_limit, ApiRateLimiter};
    use crate::{
        models::{AddPeerRequest, PeerSummary},
        state::{ApiState, ControlCommand},
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::util::ServiceExt;

    fn test_state() -> crate::state::SharedApiState {
        ApiState::new(
            "chi-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "chacha20-poly1305".into(),
            vec![PeerSummary {
                name: "lon-01".into(),
                endpoint: Some("lon.example.com:51820".into()),
                allowed_ips: vec!["10.0.0.2/32".into()],
                connected: false,
                last_handshake: None,
            }],
        )
        .shared()
    }

    fn valid_add_peer_request(name: &str) -> AddPeerRequest {
        use base64::Engine as _;

        let mut rng = rand::thread_rng();
        let (identity, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("identity keypair");
        let _ = identity;
        let (_kem_secret, kem_public) =
            freeq_crypto::kem::HybridSecretKey::generate(&mut rng).expect("hybrid KEM keypair");

        AddPeerRequest {
            name: name.into(),
            public_key: base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes()),
            kem_key: base64::engine::general_purpose::STANDARD.encode(kem_public.to_bytes()),
            endpoint: Some("127.0.0.1:51820".into()),
            transport_cert_fingerprint: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            ),
            allowed_ips: vec!["10.0.0.3/32".into()],
        }
    }

    async fn read_body(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        String::from_utf8(bytes.to_vec()).expect("response body should be utf-8")
    }

    #[tokio::test]
    async fn status_route_returns_runtime_snapshot() {
        let state = test_state();
        state.mark_peer_connected("lon-01");

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = read_body(response).await;
        assert!(body.contains("\"name\":\"chi-01\""));
        assert!(body.contains("\"peer_count\":1"));
        assert!(body.contains("\"tunnel_count\":1"));
    }

    #[tokio::test]
    async fn peers_and_tunnels_routes_return_sorted_runtime_data() {
        let state = test_state();
        state.mark_peer_connected("lon-01");
        state.add_bytes_sent("lon-01", 128);
        state.add_bytes_received("lon-01", 256);

        let app = build_router(state.clone());

        let peers_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/peers")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(peers_response.status(), StatusCode::OK);
        let peers_body = read_body(peers_response).await;
        assert!(peers_body.contains("\"name\":\"lon-01\""));
        assert!(peers_body.contains("\"connected\":true"));

        let tunnels_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/tunnels")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(tunnels_response.status(), StatusCode::OK);
        let tunnels_body = read_body(tunnels_response).await;
        assert!(tunnels_body.contains("\"peer\":\"lon-01\""));
        assert!(tunnels_body.contains("\"bytes_sent\":128"));
        assert!(tunnels_body.contains("\"bytes_received\":256"));
    }

    #[tokio::test]
    async fn metrics_route_returns_prometheus_text() {
        let state = test_state();
        state.mark_peer_connected("lon-01");
        state.add_bytes_sent("lon-01", 128);

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("freeq_connected_peers 1"));
        assert!(body.contains("freeq_tunnel_bytes_sent_total{peer=\"lon-01\"} 128"));
    }

    #[tokio::test]
    async fn algorithm_route_returns_active_algorithm_set() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/algorithm")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("\"kem_algorithm\":\"ml-kem-768\""));
        assert!(body.contains("\"sign_algorithm\":\"ml-dsa-65\""));
        assert!(body.contains("\"bulk_algorithm\":\"chacha20-poly1305\""));
    }

    #[tokio::test]
    async fn add_and_remove_peer_routes_use_control_plane() {
        let state = test_state();
        let (control_tx, mut control_rx) = mpsc::channel(4);
        state.attach_control_plane(control_tx);

        let responder = tokio::spawn(async move {
            while let Some(command) = control_rx.recv().await {
                match command {
                    ControlCommand::AddPeer { request, response } => {
                        let _ = response.send(Ok(PeerSummary {
                            name: request.name,
                            endpoint: request.endpoint,
                            allowed_ips: request.allowed_ips,
                            connected: false,
                            last_handshake: None,
                        }));
                    }
                    ControlCommand::RemovePeer { response, .. } => {
                        let _ = response.send(Ok(()));
                        break;
                    }
                    ControlCommand::RotatePeerKeys { response, .. } => {
                        let _ = response.send(Ok(Vec::new()));
                    }
                }
            }
        });

        let app = build_router(state);
        let add_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peers")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&valid_add_peer_request("sfo-01"))
                            .expect("request should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(add_response.status(), StatusCode::OK);

        let remove_response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/peers/sfo-01")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(remove_response.status(), StatusCode::OK);

        responder.await.expect("responder should complete");
    }

    #[tokio::test]
    async fn rotate_peer_route_uses_control_plane() {
        let state = test_state();
        let (control_tx, mut control_rx) = mpsc::channel(4);
        state.attach_control_plane(control_tx);

        let responder = tokio::spawn(async move {
            while let Some(command) = control_rx.recv().await {
                if let ControlCommand::RotatePeerKeys {
                    peer_name,
                    response,
                } = command
                {
                    let _ = response.send(Ok(vec![peer_name.expect("peer name")]));
                    break;
                }
            }
        });

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/peers/lon-01/rotate")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        assert!(body.contains("lon-01"));

        responder.await.expect("responder should complete");
    }

    #[tokio::test]
    async fn rate_limiter_sheds_excess_requests() {
        let limiter = ApiRateLimiter {
            bucket: Arc::new(crate::rate_limit::TokenBucket::new(1, 0)),
        };
        let app = Router::new()
            .route("/v1/status", get(crate::handlers::status::get_status))
            .layer(middleware::from_fn_with_state(
                limiter,
                enforce_api_rate_limit,
            ))
            .with_state(test_state());

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

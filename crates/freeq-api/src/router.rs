//! Axum router configuration.

use axum::{
    routing::{delete, get, post},
    Router,
};

/// Build the Axum router with all API endpoints.
pub fn build_router(state: crate::state::SharedApiState) -> Router {
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
            post(crate::handlers::algorithm::switch_algorithm),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::build_router;
    use crate::{models::PeerSummary, state::ApiState};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
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

    async fn read_body(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        String::from_utf8(bytes.to_vec()).expect("response body should be utf-8")
    }

    #[tokio::test]
    async fn status_route_returns_runtime_snapshot() {
        let state = test_state();
        {
            let mut guard = state.write().await;
            guard.mark_peer_connected("lon-01");
        }

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
        {
            let mut guard = state.write().await;
            guard.mark_peer_connected("lon-01");
            guard.add_bytes_sent("lon-01", 128);
            guard.add_bytes_received("lon-01", 256);
        }

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
        {
            let mut guard = state.write().await;
            guard.mark_peer_connected("lon-01");
            guard.add_bytes_sent("lon-01", 128);
        }

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
}

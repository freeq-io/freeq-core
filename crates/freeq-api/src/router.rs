//! Axum router configuration.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Html,
    response::Response,
    routing::{delete, get, post},
    Router,
};

use crate::ApiState;

const DASHBOARD_HTML: &str = include_str!("../../../dashboard/index.html");
const SETUP_INTENT_HEADER: &str = "x-freeq-setup-intent";
const SETUP_INTENT_VALUE: &str = "local-dashboard";

/// Build the Axum router with all API endpoints.
pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/dashboard/", get(dashboard))
        .route("/v1/status", get(crate::handlers::status::get_status))
        .route("/v1/peers", get(crate::handlers::peers::list_peers))
        .route(
            "/v1/peers",
            post(crate::handlers::peers::add_peer)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .route(
            "/v1/invites",
            post(crate::handlers::peers::create_invite)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .route(
            "/v1/invites/join",
            post(crate::handlers::peers::join_invite)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .route(
            "/v1/peers/:name",
            delete(crate::handlers::peers::remove_peer)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .route(
            "/v1/peers/:name/rotate",
            post(crate::handlers::peers::rotate_keys)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .route("/v1/tunnels", get(crate::handlers::tunnels::list_tunnels))
        .route("/v1/metrics", get(crate::handlers::metrics::get_metrics))
        .route(
            "/v1/algorithm",
            post(crate::handlers::algorithm::switch_algorithm)
                .route_layer(middleware::from_fn(require_setup_intent)),
        )
        .with_state(state)
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn require_setup_intent(
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, &'static str)> {
    if !has_setup_intent(req.headers()) {
        return Err((
            StatusCode::FORBIDDEN,
            "missing FreeQ local setup intent header",
        ));
    }
    Ok(next.run(req).await)
}

fn has_setup_intent(headers: &HeaderMap) -> bool {
    headers
        .get(SETUP_INTENT_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(SETUP_INTENT_VALUE)
}

#[cfg(test)]
mod tests {
    use super::{dashboard, has_setup_intent, SETUP_INTENT_HEADER, SETUP_INTENT_VALUE};
    use axum::http::HeaderMap;

    #[tokio::test]
    async fn dashboard_html_contains_api_contract() {
        let body = dashboard().await.0;

        assert!(body.contains("FreeQ Setup"));
        assert!(body.contains("/v1/status"));
        assert!(body.contains("/v1/peers"));
    }

    #[test]
    fn setup_intent_header_policy_accepts_only_dashboard_value() {
        let mut headers = HeaderMap::new();
        assert!(!has_setup_intent(&headers));

        headers.insert(SETUP_INTENT_HEADER, "other".parse().expect("header"));
        assert!(!has_setup_intent(&headers));

        headers.insert(
            SETUP_INTENT_HEADER,
            SETUP_INTENT_VALUE.parse().expect("header"),
        );
        assert!(has_setup_intent(&headers));
    }
}

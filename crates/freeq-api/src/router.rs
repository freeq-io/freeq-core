//! Axum router configuration.

use axum::{
    response::Html,
    routing::{delete, get, post},
    Router,
};

use crate::ApiState;

const DASHBOARD_HTML: &str = include_str!("../../../dashboard/index.html");

/// Build the Axum router with all API endpoints.
pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/dashboard/", get(dashboard))
        .route("/v1/status", get(crate::handlers::status::get_status))
        .route("/v1/peers", get(crate::handlers::peers::list_peers))
        .route("/v1/peers", post(crate::handlers::peers::add_peer))
        .route("/v1/invites", post(crate::handlers::peers::create_invite))
        .route(
            "/v1/invites/join",
            post(crate::handlers::peers::join_invite),
        )
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

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

#[cfg(test)]
mod tests {
    use super::dashboard;

    #[tokio::test]
    async fn dashboard_html_contains_api_contract() {
        let body = dashboard().await.0;

        assert!(body.contains("FreeQ Setup"));
        assert!(body.contains("/v1/status"));
        assert!(body.contains("/v1/peers"));
    }
}

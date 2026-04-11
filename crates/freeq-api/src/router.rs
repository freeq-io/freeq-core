//! Axum router configuration.

use axum::{routing::{delete, get, post}, Router};

/// Build the Axum router with all API endpoints.
pub fn build_router() -> Router {
    Router::new()
        .route("/v1/status",              get(crate::handlers::status::get_status))
        .route("/v1/peers",               get(crate::handlers::peers::list_peers))
        .route("/v1/peers",               post(crate::handlers::peers::add_peer))
        .route("/v1/peers/:name",         delete(crate::handlers::peers::remove_peer))
        .route("/v1/peers/:name/rotate",  post(crate::handlers::peers::rotate_keys))
        .route("/v1/tunnels",             get(crate::handlers::tunnels::list_tunnels))
        .route("/v1/metrics",             get(crate::handlers::metrics::get_metrics))
        .route("/v1/algorithm",           post(crate::handlers::algorithm::switch_algorithm))
}

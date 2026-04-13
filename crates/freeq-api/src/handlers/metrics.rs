//! GET /v1/metrics — Prometheus-compatible text exposition.

use crate::state::SharedApiState;
use axum::extract::State;

/// Return node metrics in Prometheus text exposition format.
pub async fn get_metrics(State(state): State<SharedApiState>) -> String {
    state.metrics_exposition()
}

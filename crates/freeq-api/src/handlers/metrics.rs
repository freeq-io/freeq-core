//! GET /v1/metrics — Prometheus-compatible text exposition.

/// Return node metrics in Prometheus text exposition format.
pub async fn get_metrics() -> String {
    // TODO(v0.1): expose Prometheus metrics via metrics-exporter-prometheus
    "# FreeQ metrics\n".into()
}

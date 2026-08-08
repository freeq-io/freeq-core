//! GET /v1/metrics — Prometheus-compatible text exposition.

use crate::ApiState;
use axum::extract::State;

/// Return node metrics in Prometheus text exposition format.
pub async fn get_metrics(State(state): State<ApiState>) -> String {
    let snapshot = state.snapshot().await;

    format!(
        concat!(
            "# FreeQ metrics\n",
            "freeq_uptime_seconds {}\n",
            "freeq_tunnel_packets_ingested_total {}\n",
            "freeq_tunnel_encrypted_bytes_total {}\n",
            "freeq_tunnel_transport_frames_total {}\n",
            "freeq_tunnel_route_misses_total {}\n",
            "freeq_tunnel_malformed_packet_errors_total {}\n",
            "freeq_tunnel_crypto_errors_total {}\n",
            "freeq_tunnel_transport_errors_total {}\n",
            "freeq_tunnel_startup_blockers {}\n"
        ),
        snapshot.uptime_secs,
        snapshot.tunnel.packets_ingested,
        snapshot.tunnel.encrypted_bytes,
        snapshot.tunnel.transport_frames,
        snapshot.tunnel.route_misses,
        snapshot.errors.malformed_packet_errors,
        snapshot.errors.crypto_errors,
        snapshot.errors.transport_errors,
        snapshot.startup_blockers.len()
    )
}

#[cfg(test)]
mod tests {
    use super::get_metrics;
    use crate::{ApiState, ErrorKind, TunnelRuntimeSnapshot};
    use axum::extract::State;

    #[tokio::test]
    async fn metrics_export_contains_tunnel_and_error_counters() {
        let state = ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            1,
        );
        state
            .update_tunnel_snapshot(TunnelRuntimeSnapshot {
                interface_name: Some("freeq0".into()),
                interface_mtu: Some(1200),
                packets_ingested: 7,
                encrypted_bytes: 8192,
                transport_frames: 7,
                route_misses: 2,
            })
            .await;
        state
            .record_error(ErrorKind::Transport, "send queue overflow")
            .await;

        let metrics = get_metrics(State(state)).await;

        assert!(metrics.contains("freeq_tunnel_packets_ingested_total 7"));
        assert!(metrics.contains("freeq_tunnel_route_misses_total 2"));
        assert!(metrics.contains("freeq_tunnel_transport_errors_total 1"));
    }
}

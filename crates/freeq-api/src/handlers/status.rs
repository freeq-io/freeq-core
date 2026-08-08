//! GET /v1/status handler.

use crate::{models::StatusResponse, ApiState, Result};
use axum::{extract::State, Json};

/// Return the node's current status, uptime, and active algorithm configuration.
pub async fn get_status(State(state): State<ApiState>) -> Result<Json<StatusResponse>> {
    let snapshot = state.snapshot().await;

    Ok(Json(StatusResponse {
        name: snapshot.name,
        version: snapshot.version,
        uptime_secs: snapshot.uptime_secs,
        kem_algorithm: snapshot.kem_algorithm,
        sign_algorithm: snapshot.sign_algorithm,
        bulk_algorithm: snapshot.bulk_algorithm,
        peer_count: snapshot.peer_count,
        tunnel_count: snapshot.tunnel_count,
        interface_name: snapshot.tunnel.interface_name,
        interface_mtu: snapshot.tunnel.interface_mtu,
        packets_ingested: snapshot.tunnel.packets_ingested,
        encrypted_bytes: snapshot.tunnel.encrypted_bytes,
        transport_frames: snapshot.tunnel.transport_frames,
        route_misses: snapshot.tunnel.route_misses,
        malformed_packet_errors: snapshot.errors.malformed_packet_errors,
        crypto_errors: snapshot.errors.crypto_errors,
        transport_errors: snapshot.errors.transport_errors,
        last_error: snapshot.last_error.as_deref().map(redact_last_error),
        startup_blockers: snapshot.startup_blockers,
    }))
}

fn redact_last_error(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let class = if lower.contains("route") {
        "route"
    } else if lower.contains("crypto")
        || lower.contains("decrypt")
        || lower.contains("encrypt")
        || lower.contains("aead")
    {
        "crypto"
    } else if lower.contains("malformed") || lower.contains("packet") || lower.contains("mtu") {
        "packet"
    } else if lower.contains("tun") || lower.contains("interface") {
        "interface"
    } else {
        "transport"
    };
    format!("{class} error; see local daemon logs")
}

#[cfg(test)]
mod tests {
    use super::{get_status, redact_last_error};
    use crate::{ApiState, ErrorKind, TunnelRuntimeSnapshot};
    use axum::extract::State;

    #[tokio::test]
    async fn status_reports_runtime_and_error_counters() {
        let state = ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            2,
        );
        state
            .update_tunnel_snapshot(TunnelRuntimeSnapshot {
                interface_name: Some("freeq0".into()),
                interface_mtu: Some(1200),
                packets_ingested: 12,
                encrypted_bytes: 4096,
                transport_frames: 12,
                route_misses: 3,
            })
            .await;
        state
            .set_startup_blockers(vec!["kernel TUN event loop is not implemented".into()])
            .await;

        let response = get_status(State(state)).await.expect("status").0;

        assert_eq!(response.name, "nyc-01");
        assert_eq!(response.peer_count, 2);
        assert_eq!(response.packets_ingested, 12);
        assert_eq!(response.route_misses, 3);
        assert_eq!(response.interface_mtu, Some(1200));
        assert_eq!(response.startup_blockers.len(), 1);
    }

    #[test]
    fn status_redacts_last_error_detail() {
        let raw = "transport connect failed for 203.0.113.10:51820 using /etc/freeq/freeq.toml";
        let redacted = redact_last_error(raw);

        assert_eq!(redacted, "transport error; see local daemon logs");
        assert!(!redacted.contains("203.0.113.10"));
        assert!(!redacted.contains("/etc/freeq"));
    }

    #[tokio::test]
    async fn status_response_redacts_last_error() {
        let state = ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            2,
        );
        state
            .record_error(
                ErrorKind::Transport,
                "send failed to 203.0.113.10:51820 from /Users/test/.freeq/perf",
            )
            .await;

        let response = get_status(State(state)).await.expect("status").0;

        assert_eq!(
            response.last_error.as_deref(),
            Some("transport error; see local daemon logs")
        );
    }
}

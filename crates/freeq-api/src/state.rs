//! Shared daemon-backed API state.

use std::sync::Arc;
use std::time::Instant;

use crate::models::PeerSummary;
use tokio::sync::RwLock;

/// Shared API state handle used by Axum handlers and daemon setup code.
#[derive(Clone)]
pub struct ApiState {
    inner: Arc<RwLock<RuntimeState>>,
}

/// Tunnel runtime counters mirrored into the API layer.
#[derive(Debug, Clone, Default)]
pub struct TunnelRuntimeSnapshot {
    /// Name of the active tunnel interface, if initialized.
    pub interface_name: Option<String>,
    /// Configured MTU, if initialized.
    pub interface_mtu: Option<usize>,
    /// Successfully ingested packets.
    pub packets_ingested: u64,
    /// Encrypted bytes emitted by the tunnel pipeline.
    pub encrypted_bytes: u64,
    /// QUIC-sized frames emitted by transport framing.
    pub transport_frames: u64,
    /// Packets rejected before encryption because no route matched.
    pub route_misses: u64,
}

/// Runtime error counters exposed to `/v1/status` and `/v1/metrics`.
#[derive(Debug, Clone, Default)]
pub struct ErrorCounters {
    /// Packet parse or MTU validation failures.
    pub malformed_packet_errors: u64,
    /// Packet failures during AEAD or keying work.
    pub crypto_errors: u64,
    /// Packet failures during transport framing or datagram handling.
    pub transport_errors: u64,
}

/// Categorized error kind used when updating shared daemon state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid packet structure or MTU violation.
    MalformedPacket,
    /// Failure inside the crypto pipeline.
    Crypto,
    /// Failure inside transport framing or sending.
    Transport,
}

/// Read-only snapshot returned by [`ApiState::snapshot`].
#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    /// Node name from configuration.
    pub name: String,
    /// Daemon version.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Active KEM algorithm.
    pub kem_algorithm: String,
    /// Active signature algorithm.
    pub sign_algorithm: String,
    /// Active bulk algorithm.
    pub bulk_algorithm: String,
    /// Configured peer count.
    pub peer_count: usize,
    /// Current tunnel count.
    pub tunnel_count: usize,
    /// Current tunnel stats snapshot.
    pub tunnel: TunnelRuntimeSnapshot,
    /// Current error counters.
    pub errors: ErrorCounters,
    /// Most recent daemon error summary, if any.
    pub last_error: Option<String>,
    /// Current startup blockers.
    pub startup_blockers: Vec<String>,
    /// Known peer summaries visible to the setup UI.
    pub known_peers: Vec<PeerSummary>,
}

#[derive(Debug)]
struct RuntimeState {
    name: String,
    version: String,
    started_at: Instant,
    kem_algorithm: String,
    sign_algorithm: String,
    bulk_algorithm: String,
    peer_count: usize,
    tunnel_count: usize,
    tunnel: TunnelRuntimeSnapshot,
    errors: ErrorCounters,
    last_error: Option<String>,
    startup_blockers: Vec<String>,
    known_peers: Vec<PeerSummary>,
}

impl ApiState {
    /// Construct shared API state from daemon configuration basics.
    pub fn new(
        name: String,
        version: String,
        kem_algorithm: String,
        sign_algorithm: String,
        bulk_algorithm: String,
        peer_count: usize,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RuntimeState {
                name,
                version,
                started_at: Instant::now(),
                kem_algorithm,
                sign_algorithm,
                bulk_algorithm,
                peer_count,
                tunnel_count: 0,
                tunnel: TunnelRuntimeSnapshot::default(),
                errors: ErrorCounters::default(),
                last_error: None,
                startup_blockers: Vec::new(),
                known_peers: Vec::new(),
            })),
        }
    }

    /// Replace the current tunnel runtime snapshot.
    pub async fn update_tunnel_snapshot(&self, snapshot: TunnelRuntimeSnapshot) {
        let mut state = self.inner.write().await;
        state.tunnel = snapshot;
        state.tunnel_count = usize::from(state.tunnel.packets_ingested > 0);
    }

    /// Replace the current list of startup blockers.
    pub async fn set_startup_blockers(&self, startup_blockers: Vec<String>) {
        self.inner.write().await.startup_blockers = startup_blockers;
    }

    /// Record an operational error and increment the appropriate counter.
    pub async fn record_error(&self, kind: ErrorKind, message: impl Into<String>) {
        let mut state = self.inner.write().await;
        match kind {
            ErrorKind::MalformedPacket => state.errors.malformed_packet_errors += 1,
            ErrorKind::Crypto => state.errors.crypto_errors += 1,
            ErrorKind::Transport => state.errors.transport_errors += 1,
        }
        state.last_error = Some(message.into());
    }

    /// Replace the current tunnel snapshot and aggregated error counters together.
    pub async fn update_runtime_counters(
        &self,
        snapshot: TunnelRuntimeSnapshot,
        errors: ErrorCounters,
    ) {
        let mut state = self.inner.write().await;
        state.tunnel = snapshot;
        state.tunnel_count = usize::from(state.tunnel.packets_ingested > 0);
        state.errors = errors;
    }

    /// Replace the current peer count.
    pub async fn set_peer_count(&self, peer_count: usize) {
        self.inner.write().await.peer_count = peer_count;
    }

    /// Return the known peer summaries currently visible to the setup UI.
    pub async fn known_peers(&self) -> Vec<PeerSummary> {
        self.inner.read().await.known_peers.clone()
    }

    /// Add or replace a known peer summary and keep the peer count in sync.
    pub async fn upsert_known_peer(&self, peer: PeerSummary) {
        let mut state = self.inner.write().await;
        if let Some(existing) = state
            .known_peers
            .iter_mut()
            .find(|candidate| candidate.node_id == peer.node_id || candidate.name == peer.name)
        {
            *existing = peer;
        } else {
            state.known_peers.push(peer);
        }
        state.peer_count = state.known_peers.len();
    }

    /// Capture an immutable snapshot for handler responses.
    pub async fn snapshot(&self) -> RuntimeSnapshot {
        let state = self.inner.read().await;
        RuntimeSnapshot {
            name: state.name.clone(),
            version: state.version.clone(),
            uptime_secs: state.started_at.elapsed().as_secs(),
            kem_algorithm: state.kem_algorithm.clone(),
            sign_algorithm: state.sign_algorithm.clone(),
            bulk_algorithm: state.bulk_algorithm.clone(),
            peer_count: state.peer_count,
            tunnel_count: state.tunnel_count,
            tunnel: state.tunnel.clone(),
            errors: state.errors.clone(),
            last_error: state.last_error.clone(),
            startup_blockers: state.startup_blockers.clone(),
            known_peers: state.known_peers.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiState, ErrorKind, TunnelRuntimeSnapshot};
    use crate::models::PeerSummary;

    #[tokio::test]
    async fn snapshot_reflects_tunnel_and_error_updates() {
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
                packets_ingested: 5,
                encrypted_bytes: 7000,
                transport_frames: 5,
                route_misses: 1,
            })
            .await;
        state
            .set_startup_blockers(vec!["kernel TUN event loop is not implemented".into()])
            .await;
        state
            .record_error(ErrorKind::Transport, "send queue overflow")
            .await;

        let snapshot = state.snapshot().await;

        assert_eq!(snapshot.tunnel_count, 1);
        assert_eq!(snapshot.tunnel.packets_ingested, 5);
        assert_eq!(snapshot.errors.transport_errors, 1);
        assert_eq!(snapshot.last_error.as_deref(), Some("send queue overflow"));
        assert_eq!(snapshot.startup_blockers.len(), 1);
    }

    #[tokio::test]
    async fn known_peer_upsert_updates_peer_count() {
        let state = ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            0,
        );

        state
            .upsert_known_peer(PeerSummary {
                node_id: Some("node-1".into()),
                name: "peer-one".into(),
                endpoint: Some("198.51.100.10:51820".into()),
                allowed_ips: vec!["10.66.0.2/32".into()],
                connected: false,
                last_handshake: None,
                trust_state: Some("invited".into()),
                enrollment_source: Some("invite".into()),
            })
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.peer_count, 1);
        assert_eq!(snapshot.known_peers.len(), 1);
    }
}

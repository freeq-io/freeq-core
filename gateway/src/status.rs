//! Gateway operational status and diagnostics.
//!
//! Production rule: process liveness is not network health. This module keeps a
//! single, always-readable status snapshot so operators, local agents, and
//! support bundles never have to infer health from silence or "daemon running".
//!
//! Status is updated from the accept path, session table, and self-heal loops.
//! A periodic pulse logs a structured snapshot; the loopback HTTP endpoint
//! serves the same JSON.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Maximum recent failure reasons retained for support (no secrets).
const RECENT_ERROR_CAP: usize = 16;

/// High-level gateway process/network state.
///
/// These are gateway-side states (accept path). Leaf-side states like
/// `GATEWAY_UNREACHABLE` live on freeqd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GatewayState {
    /// Process starting; endpoint not bound yet.
    Starting,
    /// QUIC endpoint bound and accept loop healthy.
    Listening,
    /// Accept path recently failed; self-heal backoff / rebind in progress.
    AcceptDegraded,
    /// Bind failed; retrying with backoff. Not accepting leaves.
    BindFailed,
    /// Graceful shutdown requested.
    ShuttingDown,
}

impl GatewayState {
    /// Human-readable description for logs and operators.
    pub fn description(self) -> &'static str {
        match self {
            Self::Starting => "gateway starting; not yet accepting leaves",
            Self::Listening => "accepting inbound leaf sessions (never dials)",
            Self::AcceptDegraded => {
                "accept path degraded; self-heal retry/backoff active (not silent)"
            }
            Self::BindFailed => "failed to bind listen socket; retrying bind (not accepting)",
            Self::ShuttingDown => "shutdown in progress",
        }
    }

    /// Whether the gateway is currently able to accept new leaf sessions.
    pub fn accepting(self) -> bool {
        matches!(self, Self::Listening | Self::AcceptDegraded)
    }
}

impl std::fmt::Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "STARTING"),
            Self::Listening => write!(f, "LISTENING"),
            Self::AcceptDegraded => write!(f, "ACCEPT_DEGRADED"),
            Self::BindFailed => write!(f, "BIND_FAILED"),
            Self::ShuttingDown => write!(f, "SHUTTING_DOWN"),
        }
    }
}

/// Point-in-time snapshot for logs, HTTP `/status`, and support bundles.
#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    /// Gateway node name from config.
    pub node_name: String,
    /// Process state machine value.
    pub state: GatewayState,
    /// Operator-facing state description.
    pub state_description: String,
    /// True when the accept path is willing to take new handshakes.
    pub accepting: bool,
    /// Hard product invariant: gateway never dials leaves.
    pub dials_leaves: bool,
    /// UDP listen address.
    pub listen_addr: String,
    /// Loopback status HTTP address, if enabled.
    pub status_addr: Option<String>,
    /// Configured relay_leaf peers (expected identities).
    pub configured_leaves: usize,
    /// Currently online authenticated leaves.
    pub online_sessions: usize,
    /// Online leaf node IDs (authenticated names).
    pub online_nodes: Vec<String>,
    /// Seconds since process start.
    pub uptime_secs: u64,
    /// Unix epoch seconds of this snapshot.
    pub snapshot_unix_secs: u64,
    /// Counters (monotonically increasing where noted).
    pub counters: StatusCounters,
    /// Most recent non-secret error reasons (newest last).
    pub recent_errors: Vec<String>,
    /// Last state transition reason (non-secret).
    pub last_transition_reason: String,
}

/// Atomic operational counters exposed in every status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct StatusCounters {
    /// Successful QUIC accepts (pre-handshake).
    pub accepts_total: u64,
    /// Accept() errors (transient or fatal).
    pub accept_errors: u64,
    /// Successful authenticated leaf handshakes.
    pub handshakes_ok: u64,
    /// Failed / timed-out handshakes (excluding cloaked probes).
    pub handshakes_failed: u64,
    /// Unauthenticated probes silently dropped (cloaking).
    pub cloaked_probes: u64,
    /// Sessions inserted into the table.
    pub sessions_established: u64,
    /// Existing sessions replaced by a newer inbound session for same node.
    pub sessions_replaced: u64,
    /// Sessions removed due to close/timeout/reap.
    pub sessions_removed: u64,
    /// Sessions reaped as dead by the background reaper.
    pub sessions_reaped: u64,
    /// Datagrams received on leaf sessions (forward path may still be TODO).
    pub datagrams_received: u64,
    /// Datagrams dropped because destination leaf has no active session.
    pub remote_leaf_offline_drops: u64,
    /// Endpoint rebind attempts after accept-path failure.
    pub rebinds: u64,
    /// Consecutive accept errors since last success (resets on success).
    pub consecutive_accept_errors: u64,
}

/// Shared diagnostics handle used across gateway tasks.
pub struct GatewayDiagnostics {
    node_name: String,
    listen_addr: String,
    status_addr: Option<String>,
    configured_leaves: usize,
    started_at: Instant,
    state: RwLock<GatewayState>,
    last_transition_reason: RwLock<String>,
    recent_errors: RwLock<VecDeque<String>>,
    online_nodes: RwLock<Vec<String>>,

    accepts_total: AtomicU64,
    accept_errors: AtomicU64,
    handshakes_ok: AtomicU64,
    handshakes_failed: AtomicU64,
    cloaked_probes: AtomicU64,
    sessions_established: AtomicU64,
    sessions_replaced: AtomicU64,
    sessions_removed: AtomicU64,
    sessions_reaped: AtomicU64,
    datagrams_received: AtomicU64,
    remote_leaf_offline_drops: AtomicU64,
    rebinds: AtomicU64,
    consecutive_accept_errors: AtomicU64,
}

impl GatewayDiagnostics {
    /// Create diagnostics for a gateway process.
    pub fn new(
        node_name: impl Into<String>,
        listen_addr: impl Into<String>,
        status_addr: Option<String>,
        configured_leaves: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_name: node_name.into(),
            listen_addr: listen_addr.into(),
            status_addr,
            configured_leaves,
            started_at: Instant::now(),
            state: RwLock::new(GatewayState::Starting),
            last_transition_reason: RwLock::new("process start".into()),
            recent_errors: RwLock::new(VecDeque::with_capacity(RECENT_ERROR_CAP)),
            online_nodes: RwLock::new(Vec::new()),
            accepts_total: AtomicU64::new(0),
            accept_errors: AtomicU64::new(0),
            handshakes_ok: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            cloaked_probes: AtomicU64::new(0),
            sessions_established: AtomicU64::new(0),
            sessions_replaced: AtomicU64::new(0),
            sessions_removed: AtomicU64::new(0),
            sessions_reaped: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            remote_leaf_offline_drops: AtomicU64::new(0),
            rebinds: AtomicU64::new(0),
            consecutive_accept_errors: AtomicU64::new(0),
        })
    }

    /// Transition process state with an operator-visible reason.
    pub async fn set_state(&self, state: GatewayState, reason: impl Into<String>) {
        let reason = reason.into();
        let mut guard = self.state.write().await;
        if *guard != state {
            tracing::info!(
                previous = %*guard,
                next = %state,
                reason = %reason,
                description = state.description(),
                "gateway state transition"
            );
            *guard = state;
            *self.last_transition_reason.write().await = reason;
        }
    }

    /// Current process state.
    pub async fn state(&self) -> GatewayState {
        *self.state.read().await
    }

    /// Record a non-secret recent error for support diagnostics.
    pub async fn record_error(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let mut errors = self.recent_errors.write().await;
        if errors.len() >= RECENT_ERROR_CAP {
            errors.pop_front();
        }
        errors.push_back(reason);
    }

    /// Replace the online node ID list from the session table snapshot.
    pub async fn set_online_nodes(&self, nodes: Vec<String>) {
        *self.online_nodes.write().await = nodes;
    }

    pub fn inc_accepts_total(&self) {
        self.accepts_total.fetch_add(1, Ordering::Relaxed);
        self.consecutive_accept_errors.store(0, Ordering::Relaxed);
    }

    pub fn inc_accept_error(&self) -> u64 {
        self.accept_errors.fetch_add(1, Ordering::Relaxed);
        self.consecutive_accept_errors
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    #[allow(dead_code)] // used by future alerting / rebind policy hooks
    pub fn consecutive_accept_errors(&self) -> u64 {
        self.consecutive_accept_errors.load(Ordering::Relaxed)
    }

    pub fn inc_handshake_ok(&self) {
        self.handshakes_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_handshake_failed(&self) {
        self.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cloaked_probe(&self) {
        self.cloaked_probes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_established(&self) {
        self.sessions_established.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_replaced(&self) {
        self.sessions_replaced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_removed(&self) {
        self.sessions_removed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_reaped(&self) {
        self.sessions_reaped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_datagram_received(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)] // forward path will count offline destination drops
    pub fn inc_remote_leaf_offline_drop(&self) {
        self.remote_leaf_offline_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rebind(&self) {
        self.rebinds.fetch_add(1, Ordering::Relaxed);
    }

    fn counters_snapshot(&self) -> StatusCounters {
        StatusCounters {
            accepts_total: self.accepts_total.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            handshakes_ok: self.handshakes_ok.load(Ordering::Relaxed),
            handshakes_failed: self.handshakes_failed.load(Ordering::Relaxed),
            cloaked_probes: self.cloaked_probes.load(Ordering::Relaxed),
            sessions_established: self.sessions_established.load(Ordering::Relaxed),
            sessions_replaced: self.sessions_replaced.load(Ordering::Relaxed),
            sessions_removed: self.sessions_removed.load(Ordering::Relaxed),
            sessions_reaped: self.sessions_reaped.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            remote_leaf_offline_drops: self.remote_leaf_offline_drops.load(Ordering::Relaxed),
            rebinds: self.rebinds.load(Ordering::Relaxed),
            consecutive_accept_errors: self.consecutive_accept_errors.load(Ordering::Relaxed),
        }
    }

    /// Build a full status snapshot (always safe to expose on loopback).
    pub async fn snapshot(&self) -> StatusSnapshot {
        let state = *self.state.read().await;
        let online_nodes = self.online_nodes.read().await.clone();
        let recent_errors = self
            .recent_errors
            .read()
            .await
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let last_transition_reason = self.last_transition_reason.read().await.clone();
        StatusSnapshot {
            node_name: self.node_name.clone(),
            state,
            state_description: state.description().into(),
            accepting: state.accepting(),
            dials_leaves: false,
            listen_addr: self.listen_addr.clone(),
            status_addr: self.status_addr.clone(),
            configured_leaves: self.configured_leaves,
            online_sessions: online_nodes.len(),
            online_nodes,
            uptime_secs: self.started_at.elapsed().as_secs(),
            snapshot_unix_secs: system_unix_secs(),
            counters: self.counters_snapshot(),
            recent_errors,
            last_transition_reason,
        }
    }

    /// Emit a structured status pulse log line.
    pub async fn log_pulse(&self) {
        let snap = self.snapshot().await;
        tracing::info!(
            state = %snap.state,
            accepting = snap.accepting,
            dials_leaves = snap.dials_leaves,
            online = snap.online_sessions,
            configured_leaves = snap.configured_leaves,
            online_nodes = ?snap.online_nodes,
            uptime_secs = snap.uptime_secs,
            accepts_total = snap.counters.accepts_total,
            accept_errors = snap.counters.accept_errors,
            consecutive_accept_errors = snap.counters.consecutive_accept_errors,
            handshakes_ok = snap.counters.handshakes_ok,
            handshakes_failed = snap.counters.handshakes_failed,
            cloaked_probes = snap.counters.cloaked_probes,
            sessions_established = snap.counters.sessions_established,
            sessions_replaced = snap.counters.sessions_replaced,
            sessions_removed = snap.counters.sessions_removed,
            sessions_reaped = snap.counters.sessions_reaped,
            datagrams_received = snap.counters.datagrams_received,
            remote_leaf_offline_drops = snap.counters.remote_leaf_offline_drops,
            rebinds = snap.counters.rebinds,
            last_error = snap.recent_errors.last().map(String::as_str).unwrap_or(""),
            last_transition = %snap.last_transition_reason,
            "gateway status"
        );
    }
}

fn system_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Periodically log status so silence is never the only signal.
pub async fn run_status_pulse(diagnostics: Arc<GatewayDiagnostics>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick so startup logs stay readable; main logs initial state.
    tick.tick().await;
    loop {
        tick.tick().await;
        if diagnostics.state().await == GatewayState::ShuttingDown {
            diagnostics.log_pulse().await;
            return;
        }
        diagnostics.log_pulse().await;
    }
}

/// Minimal loopback HTTP status server (`GET /status`, `GET /healthz`).
///
/// Bound only to the configured address (default loopback). Does not expose
/// secrets or identity private keys.
pub async fn run_status_http(
    diagnostics: Arc<GatewayDiagnostics>,
    addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};

    async fn status_handler(
        State(diagnostics): State<Arc<GatewayDiagnostics>>,
    ) -> impl IntoResponse {
        Json(diagnostics.snapshot().await)
    }

    async fn healthz_handler(
        State(diagnostics): State<Arc<GatewayDiagnostics>>,
    ) -> impl IntoResponse {
        let snap = diagnostics.snapshot().await;
        // Ready only when we can accept leaves. Bind failures are not healthy.
        if snap.state.accepting() {
            (StatusCode::OK, Json(snap))
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, Json(snap))
        }
    }

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/healthz", get(healthz_handler))
        .with_state(diagnostics);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| anyhow::anyhow!("failed to bind gateway status HTTP on {addr}: {err}"))?;
    tracing::info!(%addr, "gateway status HTTP listening (/status, /healthz)");
    axum::serve(listener, app)
        .await
        .map_err(|err| anyhow::anyhow!("gateway status HTTP server error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{GatewayDiagnostics, GatewayState};

    #[tokio::test]
    async fn snapshot_always_reports_never_dials() {
        let diag = GatewayDiagnostics::new("gw-1", "0.0.0.0:51820", None, 2);
        diag.set_state(GatewayState::Listening, "test").await;
        diag.set_online_nodes(vec!["leaf-a".into()]).await;
        diag.inc_handshake_ok();
        let snap = diag.snapshot().await;
        assert!(!snap.dials_leaves);
        assert!(snap.accepting);
        assert_eq!(snap.online_sessions, 1);
        assert_eq!(snap.counters.handshakes_ok, 1);
    }

    #[tokio::test]
    async fn state_transition_is_logged_path_updates() {
        let diag = GatewayDiagnostics::new("gw-1", "0.0.0.0:51820", None, 0);
        assert_eq!(diag.state().await, GatewayState::Starting);
        diag.set_state(GatewayState::BindFailed, "bind eaddrinuse")
            .await;
        assert_eq!(diag.state().await, GatewayState::BindFailed);
        assert!(!diag.state().await.accepting());
    }
}

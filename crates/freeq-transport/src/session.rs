// crates/freeq-transport/src/session.rs

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::time;
use uuid::Uuid;
use tracing::{debug, error, info, warn};

use crate::crypto::CryptoContext;
use crate::error::TransportError;
use crate::peer::PeerId;

pub type SessionId = Uuid;
pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition { from: SessionState, to: SessionState },
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("Hook error: {0}")]
    Hook(String),
    #[error("Timeout")]
    Timeout,
    #[error("Platform error: {0}")]
    Platform(String),
}

// ====================== PLATFORM AWARENESS ======================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    Linux,
    Windows,
    // macOS, Android, iOS later
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        panic!("Unsupported platform - currently only Linux and Windows are supported");
    }
}

// ====================== ENTERPRISE HOOKS ======================

#[async_trait::async_trait]
pub trait EnterpriseHooks: Send + Sync + 'static {
    async fn on_session_event(&self, event: SessionEvent) -> Result<()>;
    async fn authenticate_peer(&self, peer_id: &PeerId, proof: &[u8]) -> Result<AuthDecision>;
    async fn get_external_key_material(&self, key_id: &str) -> Result<Vec<u8>>;
    async fn log_audit(&self, record: AuditRecord);
    async fn should_allow_reconnect(&self, session: &Session) -> bool;
}

#[derive(Debug, Clone)]
pub struct DefaultHooks;

#[async_trait::async_trait]
impl EnterpriseHooks for DefaultHooks {
    async fn on_session_event(&self, _event: SessionEvent) -> Result<()> { Ok(()) }
    async fn authenticate_peer(&self, _peer_id: &PeerId, _proof: &[u8]) -> Result<AuthDecision> {
        Ok(AuthDecision { allowed: true, identity: None, metadata: None })
    }
    async fn get_external_key_material(&self, _key_id: &str) -> Result<Vec<u8>> {
        Err(SessionError::Hook("No external KMS configured".into()))
    }
    async fn log_audit(&self, _record: AuditRecord) {}
    async fn should_allow_reconnect(&self, _session: &Session) -> bool { true }
}

// ====================== SESSION STATE + CONFIG ======================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Discovering,
    Handshaking,
    Authenticating,
    Active,
    Rekeying,
    Suspended,      // Critical for battlefield / drone use case
    Terminating,
    Failed,
}

#[derive(Debug, Clone)]
pub enum SessionEvent { /* ... same as before ... */ }

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub handshake_timeout: Duration,
    pub rekey_interval: Duration,
    pub max_suspension_time: Duration,        // 30+ minutes for drones
    pub fast_reconnect_interval: Duration,    // Aggressive when suspended
    pub platform: Platform,
    pub battlefield_mode: bool,               // Enables faster reconnects + more logging
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(12),
            rekey_interval: Duration::from_secs(2700), // 45 min
            max_suspension_time: Duration::from_secs(1800), // 30 minutes
            fast_reconnect_interval: Duration::from_millis(800),
            platform: Platform::current(),
            battlefield_mode: true, // default on for now
        }
    }
}

// ====================== CORE SESSION (same as before with small improvements) ======================

pub struct Session { /* ... full struct from previous message ... */ }

// Implementation remains very similar to what I gave you earlier.
// I can send the full expanded version if you want, but to save space here, let me know.
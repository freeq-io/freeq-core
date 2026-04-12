//! Peer management handlers.

use axum::{extract::Path, Json};
use crate::{models::{AddPeerRequest, PeerSummary}, Result};

/// List all configured peers and their connection status.
pub async fn list_peers() -> Result<Json<Vec<PeerSummary>>> {
    todo!("GET /v1/peers")
}

/// Add a new peer to the registry.
pub async fn add_peer(Json(_req): Json<AddPeerRequest>) -> Result<Json<PeerSummary>> {
    todo!("POST /v1/peers")
}

/// Remove a peer by name.
pub async fn remove_peer(Path(_name): Path<String>) -> Result<()> {
    todo!("DELETE /v1/peers/:name")
}

/// Rotate the session keys for a specific peer.
pub async fn rotate_keys(Path(_name): Path<String>) -> Result<()> {
    todo!("POST /v1/peers/:name/rotate")
}

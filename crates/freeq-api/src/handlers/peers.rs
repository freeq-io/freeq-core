//! Peer management handlers.

use crate::{
    models::{AddPeerRequest, PeerSummary},
    ApiError, Result,
};
use axum::{
    extract::{Path, State},
    Json,
};

/// List all configured peers and their connection status.
pub async fn list_peers(
    State(state): State<crate::state::SharedApiState>,
) -> Result<Json<Vec<PeerSummary>>> {
    Ok(Json(state.peer_summaries()))
}

/// Add a new peer to the registry.
pub async fn add_peer(Json(_req): Json<AddPeerRequest>) -> Result<Json<PeerSummary>> {
    Err(ApiError::NotImplemented(
        "peer creation is not implemented yet".into(),
    ))
}

/// Remove a peer by name.
pub async fn remove_peer(Path(_name): Path<String>) -> Result<()> {
    Err(ApiError::NotImplemented(
        "peer removal is not implemented yet".into(),
    ))
}

/// Rotate the session keys for a specific peer.
pub async fn rotate_keys(Path(_name): Path<String>) -> Result<()> {
    Err(ApiError::NotImplemented(
        "peer key rotation is not implemented yet".into(),
    ))
}

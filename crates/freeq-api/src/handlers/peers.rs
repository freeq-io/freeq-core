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
pub async fn add_peer(
    State(state): State<crate::state::SharedApiState>,
    Json(req): Json<AddPeerRequest>,
) -> Result<Json<PeerSummary>> {
    req.validate()?;
    let control = state.control_plane().ok_or_else(|| {
        ApiError::NotImplemented("daemon peer mutation control plane is not available".into())
    })?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control
        .send(crate::state::ControlCommand::AddPeer {
            request: req,
            response: response_tx,
        })
        .await
        .map_err(|_| ApiError::Internal("daemon peer control plane is unavailable".into()))?;

    let peer = response_rx
        .await
        .map_err(|_| ApiError::Internal("daemon did not respond to peer add request".into()))?
        .map_err(ApiError::BadRequest)?;
    Ok(Json(peer))
}

/// Remove a peer by name.
pub async fn remove_peer(
    State(state): State<crate::state::SharedApiState>,
    Path(name): Path<String>,
) -> Result<()> {
    let control = state.control_plane().ok_or_else(|| {
        ApiError::NotImplemented("daemon peer mutation control plane is not available".into())
    })?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control
        .send(crate::state::ControlCommand::RemovePeer {
            name,
            response: response_tx,
        })
        .await
        .map_err(|_| ApiError::Internal("daemon peer control plane is unavailable".into()))?;

    response_rx
        .await
        .map_err(|_| ApiError::Internal("daemon did not respond to peer removal request".into()))?
        .map_err(ApiError::NotFound)?;
    Ok(())
}

/// Rotate the session keys for a specific peer.
pub async fn rotate_keys(
    State(state): State<crate::state::SharedApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<String>>> {
    let control = state.control_plane().ok_or_else(|| {
        ApiError::NotImplemented("daemon peer mutation control plane is not available".into())
    })?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control
        .send(crate::state::ControlCommand::RotatePeerKeys {
            peer_name: Some(name),
            response: response_tx,
        })
        .await
        .map_err(|_| ApiError::Internal("daemon peer control plane is unavailable".into()))?;

    let peers = response_rx
        .await
        .map_err(|_| {
            ApiError::Internal("daemon did not respond to peer key rotation request".into())
        })?
        .map_err(ApiError::NotFound)?;
    Ok(Json(peers))
}

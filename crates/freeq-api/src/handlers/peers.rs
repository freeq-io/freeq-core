//! Peer management handlers.

use axum::{extract::Path, Json};
use crate::{models::{AddPeerRequest, PeerSummary}, Result};

pub async fn list_peers() -> Result<Json<Vec<PeerSummary>>> {
    todo!("GET /v1/peers")
}

pub async fn add_peer(Json(_req): Json<AddPeerRequest>) -> Result<Json<PeerSummary>> {
    todo!("POST /v1/peers")
}

pub async fn remove_peer(Path(_name): Path<String>) -> Result<()> {
    todo!("DELETE /v1/peers/:name")
}

pub async fn rotate_keys(Path(_name): Path<String>) -> Result<()> {
    todo!("POST /v1/peers/:name/rotate")
}

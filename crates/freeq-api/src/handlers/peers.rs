//! Peer management handlers.

use crate::{
    models::{
        AddPeerRequest, InviteBundle, InviteCreateRequest, InviteCreateResponse, InviteJoinRequest,
        InviteJoinResponse, PeerSummary,
    },
    ApiError, ApiState, Result,
};
use axum::{extract::Path, extract::State, Json};
use chrono::{Duration, Utc};
use sha2::Digest as _;

const INVITE_SCHEMA: &str = "freeq.invite.v1";
const INVITE_TTL_MINUTES: i64 = 15;

/// List all configured peers and their connection status.
pub async fn list_peers(State(state): State<ApiState>) -> Result<Json<Vec<PeerSummary>>> {
    Ok(Json(state.known_peers().await))
}

/// Add a new peer to the registry.
pub async fn add_peer(
    State(state): State<ApiState>,
    Json(req): Json<AddPeerRequest>,
) -> Result<Json<PeerSummary>> {
    let peer = PeerSummary {
        node_id: Some(node_id_for_material(req.public_key.as_bytes())),
        name: req.name,
        endpoint: req.endpoint,
        allowed_ips: req.allowed_ips,
        connected: false,
        last_handshake: None,
        trust_state: Some("manual".into()),
        enrollment_source: Some("api".into()),
    };
    state.upsert_known_peer(peer.clone()).await;
    Ok(Json(peer))
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

/// Create a 15-minute public invite bundle for the local setup UI.
pub async fn create_invite(
    State(state): State<ApiState>,
    Json(req): Json<InviteCreateRequest>,
) -> Result<Json<InviteCreateResponse>> {
    let snapshot = state.snapshot().await;
    let now = Utc::now();
    let expires_at = now + Duration::minutes(INVITE_TTL_MINUTES);
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let pairing_code = nonce
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase();
    let node_id = node_id_for_material(snapshot.name.as_bytes());
    let label = req
        .label
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| snapshot.name.clone());
    let allowed_ips = req.allowed_ips.unwrap_or_default();
    let bundle = InviteBundle {
        schema: INVITE_SCHEMA.into(),
        inviter_name: label.clone(),
        inviter_node_id: node_id,
        endpoint: req.endpoint,
        allowed_ips,
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        pairing_hash: pairing_hash(&nonce, &pairing_code),
        nonce,
    };
    let bundle_text = serde_json::to_string_pretty(&bundle)
        .map_err(|err| ApiError::Internal(format!("failed to render invite bundle: {err}")))?;

    Ok(Json(InviteCreateResponse {
        bundle_name: format!("freeq-invite-{}.json", sanitize_file_label(&label)),
        bundle_text,
        expires_at: expires_at.to_rfc3339(),
        pairing_code_display: pairing_code,
        message: "Send the invite bundle to the peer and send the pairing code separately.".into(),
    }))
}

/// Join a 15-minute public invite bundle from the local setup UI.
pub async fn join_invite(
    State(state): State<ApiState>,
    Json(req): Json<InviteJoinRequest>,
) -> Result<Json<InviteJoinResponse>> {
    let bundle: InviteBundle = serde_json::from_str(&req.bundle_text)
        .map_err(|err| ApiError::BadRequest(format!("invite bundle is not valid JSON: {err}")))?;
    if bundle.schema != INVITE_SCHEMA {
        return Ok(Json(InviteJoinResponse {
            accepted: false,
            peer_name: None,
            node_id: None,
            message: "FAIL: invite bundle schema is not supported.".into(),
        }));
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(&bundle.expires_at)
        .map_err(|err| ApiError::BadRequest(format!("invite expiry is invalid: {err}")))?
        .with_timezone(&Utc);
    if Utc::now() > expires_at {
        return Ok(Json(InviteJoinResponse {
            accepted: false,
            peer_name: None,
            node_id: None,
            message: "FAIL: invite expired. Ask the inviter to create a new invite.".into(),
        }));
    }
    if pairing_hash(&bundle.nonce, req.pairing_code.trim()) != bundle.pairing_hash {
        return Ok(Json(InviteJoinResponse {
            accepted: false,
            peer_name: None,
            node_id: None,
            message: "FAIL: pairing code did not match the invite bundle.".into(),
        }));
    }

    let peer = PeerSummary {
        node_id: Some(bundle.inviter_node_id.clone()),
        name: bundle.inviter_name.clone(),
        endpoint: bundle.endpoint.clone(),
        allowed_ips: bundle.allowed_ips.clone(),
        connected: false,
        last_handshake: None,
        trust_state: Some("paired".into()),
        enrollment_source: Some("invite".into()),
    };
    state.upsert_known_peer(peer).await;

    Ok(Json(InviteJoinResponse {
        accepted: true,
        peer_name: Some(bundle.inviter_name),
        node_id: Some(bundle.inviter_node_id),
        message: "PASS: invite accepted and peer recorded locally.".into(),
    }))
}

fn pairing_hash(nonce: &str, pairing_code: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(nonce.as_bytes());
    hasher.update(b":");
    hasher.update(pairing_code.as_bytes());
    hex_lower(&hasher.finalize())
}

fn node_id_for_material(material: &[u8]) -> String {
    let digest = sha2::Sha256::digest(material);
    format!("fq-{}", &hex_lower(&digest)[..16])
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sanitize_file_label(label: &str) -> String {
    let mut out = String::new();
    for ch in label.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch);
        } else if ch.is_ascii_whitespace() || ch == '_' {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "peer".into()
    } else {
        out.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{create_invite, join_invite};
    use crate::models::{InviteCreateRequest, InviteCreateResponse, InviteJoinRequest};
    use crate::ApiState;
    use axum::{extract::State, Json};

    fn state() -> ApiState {
        ApiState::new(
            "patrick-mac".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            0,
        )
    }

    #[tokio::test]
    async fn create_invite_omits_private_material() {
        let response = create_invite(
            State(state()),
            Json(InviteCreateRequest {
                label: Some("patrick".into()),
                endpoint: Some("203.0.113.10:51820".into()),
                allowed_ips: Some(vec!["10.66.0.2/32".into()]),
            }),
        )
        .await
        .expect("invite")
        .0;

        assert_eq!(response.pairing_code_display.len(), 8);
        assert!(response.bundle_text.contains("freeq.invite.v1"));
        assert!(!response.bundle_text.contains("private"));
        assert!(!response
            .bundle_text
            .contains(&response.pairing_code_display));
    }

    #[tokio::test]
    async fn join_invite_records_known_peer() {
        let api_state = state();
        let invite: InviteCreateResponse = create_invite(
            State(api_state.clone()),
            Json(InviteCreateRequest {
                label: Some("patrick".into()),
                endpoint: None,
                allowed_ips: None,
            }),
        )
        .await
        .expect("invite")
        .0;

        let joined = join_invite(
            State(api_state.clone()),
            Json(InviteJoinRequest {
                bundle_text: invite.bundle_text,
                pairing_code: invite.pairing_code_display,
            }),
        )
        .await
        .expect("join")
        .0;

        assert!(joined.accepted);
        assert_eq!(api_state.known_peers().await.len(), 1);
    }
}

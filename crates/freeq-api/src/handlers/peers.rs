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
use rand::RngCore as _;
use sha2::Digest as _;
use std::{collections::BTreeMap, fs, path::Path as FsPath};

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
    let peer_env_path = state.local_peer_env_path().await.ok_or_else(|| {
        ApiError::BadRequest(
            "local public peer file is not available yet; rerun FreeQ setup".into(),
        )
    })?;
    let local_peer = read_peer_env(&peer_env_path)?;
    let now = Utc::now();
    let expires_at = now + Duration::minutes(INVITE_TTL_MINUTES);
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let pairing_code = generate_pairing_code();
    let node_id = node_id_for_material(local_peer.public_key.as_bytes());
    let label = req
        .label
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| local_peer.node_name.clone());
    let endpoint = req
        .endpoint
        .filter(|value| !value.trim().is_empty())
        .or(local_peer.public_endpoint.clone());
    if endpoint.as_deref().unwrap_or_default().trim().is_empty() {
        return Err(ApiError::BadRequest(
            "local public endpoint is missing; rerun FreeQ setup and enter a reachable endpoint"
                .into(),
        ));
    }
    let allowed_ips = req
        .allowed_ips
        .unwrap_or_else(|| vec![allowed_ip_from_node_address(&local_peer.node_address)]);
    let bundle = InviteBundle {
        schema: INVITE_SCHEMA.into(),
        inviter_name: label.clone(),
        inviter_node_id: node_id,
        endpoint,
        node_address: local_peer.node_address,
        node_listen: local_peer.node_listen,
        public_key: local_peer.public_key,
        kem_key: local_peer.kem_key,
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
            peer_file_path: None,
            activation_command: None,
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
            peer_file_path: None,
            activation_command: None,
            message: "FAIL: invite expired. Ask the inviter to create a new invite.".into(),
        }));
    }
    if pairing_hash(&bundle.nonce, req.pairing_code.trim()) != bundle.pairing_hash {
        return Ok(Json(InviteJoinResponse {
            accepted: false,
            peer_name: None,
            node_id: None,
            peer_file_path: None,
            activation_command: None,
            message: "FAIL: pairing code did not match the invite bundle.".into(),
        }));
    }

    let peer_file_path = install_peer_env_from_invite(&state, &bundle).await?;

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
        peer_file_path: Some(peer_file_path.display().to_string()),
        activation_command: Some("scripts/setup/freeq-connect-macos.sh --restart".into()),
        message: "PASS: invite accepted, peer file installed, and tunnel activation is ready."
            .into(),
    }))
}

#[derive(Debug)]
struct LocalPeerEnv {
    node_name: String,
    node_address: String,
    node_listen: Option<String>,
    public_endpoint: Option<String>,
    public_key: String,
    kem_key: String,
}

fn read_peer_env(path: &FsPath) -> Result<LocalPeerEnv> {
    let raw = fs::read_to_string(path).map_err(|err| {
        ApiError::BadRequest(format!(
            "failed to read local public peer file {}: {err}",
            path.display()
        ))
    })?;
    let values = parse_env_file(&raw)?;
    let required = |key: &str| -> Result<String> {
        values
            .get(key)
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .ok_or_else(|| ApiError::BadRequest(format!("local public peer file missing {key}")))
    };
    Ok(LocalPeerEnv {
        node_name: required("FREEQ_NODE_NAME")?,
        node_address: required("FREEQ_NODE_ADDRESS")?,
        node_listen: values
            .get("FREEQ_NODE_LISTEN")
            .filter(|value| !value.trim().is_empty())
            .cloned(),
        public_endpoint: values
            .get("FREEQ_PUBLIC_ENDPOINT")
            .filter(|value| !value.trim().is_empty())
            .cloned(),
        public_key: required("FREEQ_PUBLIC_KEY_B64")?,
        kem_key: required("FREEQ_KEM_KEY_B64")?,
    })
}

fn parse_env_file(raw: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(ApiError::BadRequest(format!(
                "peer env line is not KEY=VALUE: {trimmed}"
            )));
        };
        values.insert(key.trim().into(), strip_shell_quotes(value.trim()));
    }
    Ok(values)
}

fn strip_shell_quotes(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("'\\''", "'")
    } else {
        value.into()
    }
}

async fn install_peer_env_from_invite(
    state: &ApiState,
    bundle: &InviteBundle,
) -> Result<std::path::PathBuf> {
    let receive_dir = state.peer_receive_dir().await.ok_or_else(|| {
        ApiError::BadRequest(
            "local setup folder is not available yet; rerun FreeQ setup before joining invites"
                .into(),
        )
    })?;
    fs::create_dir_all(&receive_dir).map_err(|err| {
        ApiError::Internal(format!(
            "failed to create peer receive folder {}: {err}",
            receive_dir.display()
        ))
    })?;
    let peer_path = receive_dir.join(format!(
        "{}-peer.env",
        sanitize_file_label(&bundle.inviter_name)
    ));
    let content = format!(
        "# Public peer exchange file installed from a FreeQ invite.\nFREEQ_NODE_NAME={}\nFREEQ_NODE_ADDRESS={}\nFREEQ_NODE_LISTEN={}\nFREEQ_PUBLIC_ENDPOINT={}\nFREEQ_PUBLIC_KEY_B64={}\nFREEQ_KEM_KEY_B64={}\n",
        quote_shell(&bundle.inviter_name),
        quote_shell(&bundle.node_address),
        quote_shell(bundle.node_listen.as_deref().unwrap_or_default()),
        quote_shell(bundle.endpoint.as_deref().unwrap_or_default()),
        quote_shell(&bundle.public_key),
        quote_shell(&bundle.kem_key)
    );
    fs::write(&peer_path, content).map_err(|err| {
        ApiError::Internal(format!(
            "failed to install peer file {}: {err}",
            peer_path.display()
        ))
    })?;
    Ok(peer_path)
}

fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn allowed_ip_from_node_address(node_address: &str) -> String {
    let host = node_address
        .split('/')
        .next()
        .unwrap_or(node_address)
        .trim();
    if host.is_empty() {
        node_address.into()
    } else {
        format!("{host}/32")
    }
}

fn pairing_hash(nonce: &str, pairing_code: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(nonce.as_bytes());
    hasher.update(b":");
    hasher.update(pairing_code.as_bytes());
    hex_lower(&hasher.finalize())
}

fn generate_pairing_code() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_upper(&bytes)
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

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
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
    use std::{fs, path::PathBuf};

    fn state() -> ApiState {
        ApiState::new(
            "local-mac".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            0,
        )
    }

    async fn state_with_peer_env(node_name: &str) -> (ApiState, PathBuf) {
        let api_state = state();
        let root = std::env::temp_dir().join(format!(
            "freeq-api-invite-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let perf_dir = root.join(".freeq").join("perf");
        fs::create_dir_all(&perf_dir).expect("create perf dir");
        let peer_env = perf_dir.join("peer.env");
        fs::write(
            &peer_env,
            format!(
                "# Public peer exchange file.\nFREEQ_NODE_NAME='{node_name}'\nFREEQ_NODE_ADDRESS='10.66.0.2/24'\nFREEQ_NODE_LISTEN='0.0.0.0:51820'\nFREEQ_PUBLIC_ENDPOINT='203.0.113.10:51820'\nFREEQ_PUBLIC_KEY_B64='public-key-b64'\nFREEQ_KEM_KEY_B64='kem-key-b64'\n"
            ),
        )
        .expect("write peer env");
        api_state.set_local_peer_env_path(peer_env).await;
        (api_state, root)
    }

    #[tokio::test]
    async fn create_invite_omits_private_material() {
        let (api_state, root) = state_with_peer_env("local-node").await;
        let response = create_invite(
            State(api_state),
            Json(InviteCreateRequest {
                label: Some("local-node".into()),
                endpoint: None,
                allowed_ips: None,
            }),
        )
        .await
        .expect("invite")
        .0;

        assert_eq!(response.pairing_code_display.len(), 8);
        assert!(response
            .pairing_code_display
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_lowercase()));
        assert!(response.bundle_text.contains("freeq.invite.v1"));
        assert!(response.bundle_text.contains("203.0.113.10:51820"));
        assert!(response.bundle_text.contains("public-key-b64"));
        assert!(response.bundle_text.contains("kem-key-b64"));
        assert!(!response.bundle_text.contains("private"));
        assert!(!response
            .bundle_text
            .contains(&response.pairing_code_display));
        let bundle: crate::models::InviteBundle =
            serde_json::from_str(&response.bundle_text).expect("bundle json");
        assert_ne!(
            response.pairing_code_display,
            bundle
                .nonce
                .chars()
                .take(8)
                .collect::<String>()
                .to_ascii_uppercase()
        );
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[tokio::test]
    async fn join_invite_records_known_peer_and_installs_peer_file() {
        let (api_state, root) = state_with_peer_env("local-node").await;
        let invite: InviteCreateResponse = create_invite(
            State(api_state.clone()),
            Json(InviteCreateRequest {
                label: Some("local-node".into()),
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
        assert!(joined.peer_file_path.is_some());
        assert_eq!(
            joined.activation_command.as_deref(),
            Some("scripts/setup/freeq-connect-macos.sh --restart")
        );
        assert_eq!(api_state.known_peers().await.len(), 1);
        let installed_path = root
            .join("FreeQ")
            .join("02-put-peer-file-here")
            .join("local-node-peer.env");
        let installed = fs::read_to_string(installed_path).expect("read installed peer file");
        assert!(installed.contains("FREEQ_PUBLIC_ENDPOINT='203.0.113.10:51820'"));
        assert!(installed.contains("FREEQ_PUBLIC_KEY_B64='public-key-b64'"));
        assert!(!installed.contains("PRIVATE"));
        fs::remove_dir_all(root).expect("remove temp root");
    }
}

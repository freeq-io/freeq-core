//! 8-step mutual authentication and hybrid KEM handshake (§4.2).

use crate::Result;
use rand::RngCore;
use sha2::Digest as _;

const HANDSHAKE_VERSION: u8 = 1;
const INIT_MESSAGE: u8 = 1;
const RESPONSE_MESSAGE: u8 = 2;
const NONCE_LEN: usize = 32;
const FINGERPRINT_LEN: usize = crate::registry::FINGERPRINT_LEN;

#[derive(Debug)]
/// State machine for the initiating side of the handshake (Node A).
pub struct InitiatorHandshake {
    initiator_nonce: [u8; NONCE_LEN],
    initiator_kem_pubkey: Vec<u8>,
    expected_remote_identity: freeq_crypto::sign::IdentityPublicKey,
}

#[derive(Debug)]
/// State machine for the responding side of the handshake (Node B).
pub struct ResponderHandshake {
    initiator_nonce: [u8; NONCE_LEN],
    responder_nonce: [u8; NONCE_LEN],
    responder_kem_pubkey: Vec<u8>,
}

/// The session keys derived at the end of a successful handshake.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SessionKeys {
    /// 32-byte outbound bulk encryption key.
    pub outbound: [u8; 32],
    /// 32-byte inbound bulk encryption key.
    pub inbound: [u8; 32],
}

impl InitiatorHandshake {
    /// Begin a new handshake as the initiating node.
    ///
    /// Step 1: emit ML-DSA-65 signature over (nonce || A_kem_pubkey).
    pub fn new(
        identity_sk: &freeq_crypto::sign::IdentityKeypair,
        kem_pubkey: &[u8],
        expected_remote_identity: freeq_crypto::sign::IdentityPublicKey,
    ) -> Result<(Self, Vec<u8>)> {
        let initiator_nonce = random_nonce();
        let signature = identity_sk.sign_message(&challenge_init(&initiator_nonce, kem_pubkey))?;
        let initiator_fingerprint =
            fingerprint_for_public_key(&identity_sk.public_key().to_bytes());
        let message = encode_init_message(
            initiator_fingerprint,
            &initiator_nonce,
            kem_pubkey,
            &signature.0,
        );

        Ok((
            Self {
                initiator_nonce,
                initiator_kem_pubkey: kem_pubkey.to_vec(),
                expected_remote_identity,
            },
            message,
        ))
    }

    /// Process Node B's response (steps 3-4) and emit KEM ciphertext (step 5).
    pub fn process_response(self, msg: &[u8]) -> Result<(Self, Vec<u8>)> {
        let response = parse_response_message(msg)
            .map_err(|reason| crate::AuthError::HandshakeFailed { step: 3, reason })?;

        if response.initiator_nonce != self.initiator_nonce {
            return Err(crate::AuthError::HandshakeFailed {
                step: 4,
                reason: "response nonce does not match the initiator nonce".into(),
            });
        }

        let expected_fingerprint =
            fingerprint_for_public_key(&self.expected_remote_identity.to_bytes());
        if response.responder_fingerprint != expected_fingerprint {
            return Err(crate::AuthError::HandshakeFailed {
                step: 4,
                reason: "response fingerprint does not match the expected peer".into(),
            });
        }

        self.expected_remote_identity
            .verify_message(
                &challenge_response(
                    &response.responder_nonce,
                    &response.initiator_nonce,
                    &response.responder_kem_pubkey,
                ),
                &freeq_crypto::sign::Signature(response.signature.to_vec()),
            )
            .map_err(|e| crate::AuthError::HandshakeFailed {
                step: 4,
                reason: e.to_string(),
            })?;

        let _ = self.initiator_kem_pubkey;
        Err(crate::AuthError::HandshakeFailed {
            step: 5,
            reason: "hybrid KEM encapsulation is not implemented yet".into(),
        })
    }

    /// Finalize: derive session keys after both sides complete the hybrid KEM.
    pub fn finalize(self) -> Result<SessionKeys> {
        let _ = self;
        Err(crate::AuthError::HandshakeFailed {
            step: 8,
            reason: "session key derivation is blocked on hybrid KEM".into(),
        })
    }
}

impl ResponderHandshake {
    /// Process Node A's initial message (steps 2-3) and emit response.
    pub fn process_init(
        identity_sk: &freeq_crypto::sign::IdentityKeypair,
        kem_pubkey: &[u8],
        registry: &crate::registry::PeerRegistry,
        msg: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let init = parse_init_message(msg)
            .map_err(|reason| crate::AuthError::HandshakeFailed { step: 1, reason })?;

        let (peer_name, _) = registry
            .lookup_name_and_peer(&init.initiator_fingerprint)
            .ok_or(crate::AuthError::Cloaked)?;

        registry
            .verify_signature(
                peer_name,
                &challenge_init(&init.initiator_nonce, &init.initiator_kem_pubkey),
                init.signature,
            )
            .map_err(|e| crate::AuthError::HandshakeFailed {
                step: 2,
                reason: e.to_string(),
            })?;

        let responder_nonce = random_nonce();
        let response_signature = identity_sk.sign_message(&challenge_response(
            &responder_nonce,
            &init.initiator_nonce,
            kem_pubkey,
        ))?;
        let responder_fingerprint =
            fingerprint_for_public_key(&identity_sk.public_key().to_bytes());
        let response = encode_response_message(
            responder_fingerprint,
            &init.initiator_nonce,
            &responder_nonce,
            kem_pubkey,
            &response_signature.0,
        );

        Ok((
            Self {
                initiator_nonce: init.initiator_nonce,
                responder_nonce,
                responder_kem_pubkey: kem_pubkey.to_vec(),
            },
            response,
        ))
    }

    /// Process Node A's KEM ciphertext (steps 5-8) and finalize.
    pub fn process_kem(self, _msg: &[u8]) -> Result<SessionKeys> {
        let _ = (
            self.initiator_nonce,
            self.responder_nonce,
            self.responder_kem_pubkey,
        );
        Err(crate::AuthError::HandshakeFailed {
            step: 5,
            reason: "hybrid KEM processing is not implemented yet".into(),
        })
    }
}

struct ParsedInitMessage<'a> {
    initiator_fingerprint: [u8; FINGERPRINT_LEN],
    initiator_nonce: [u8; NONCE_LEN],
    initiator_kem_pubkey: Vec<u8>,
    signature: &'a [u8],
}

struct ParsedResponseMessage<'a> {
    responder_fingerprint: [u8; FINGERPRINT_LEN],
    initiator_nonce: [u8; NONCE_LEN],
    responder_nonce: [u8; NONCE_LEN],
    responder_kem_pubkey: Vec<u8>,
    signature: &'a [u8],
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn challenge_init(nonce: &[u8; NONCE_LEN], kem_pubkey: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NONCE_LEN + kem_pubkey.len());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(kem_pubkey);
    msg
}

fn challenge_response(
    responder_nonce: &[u8; NONCE_LEN],
    initiator_nonce: &[u8; NONCE_LEN],
    kem_pubkey: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity((NONCE_LEN * 2) + kem_pubkey.len());
    msg.extend_from_slice(responder_nonce);
    msg.extend_from_slice(initiator_nonce);
    msg.extend_from_slice(kem_pubkey);
    msg
}

fn encode_init_message(
    fingerprint: [u8; FINGERPRINT_LEN],
    nonce: &[u8; NONCE_LEN],
    kem_pubkey: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        2 + FINGERPRINT_LEN + NONCE_LEN + 4 + kem_pubkey.len() + signature.len(),
    );
    msg.push(HANDSHAKE_VERSION);
    msg.push(INIT_MESSAGE);
    msg.extend_from_slice(&fingerprint);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&(kem_pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    msg.extend_from_slice(kem_pubkey);
    msg.extend_from_slice(signature);
    msg
}

fn encode_response_message(
    fingerprint: [u8; FINGERPRINT_LEN],
    initiator_nonce: &[u8; NONCE_LEN],
    responder_nonce: &[u8; NONCE_LEN],
    kem_pubkey: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        2 + FINGERPRINT_LEN + (NONCE_LEN * 2) + 4 + kem_pubkey.len() + signature.len(),
    );
    msg.push(HANDSHAKE_VERSION);
    msg.push(RESPONSE_MESSAGE);
    msg.extend_from_slice(&fingerprint);
    msg.extend_from_slice(initiator_nonce);
    msg.extend_from_slice(responder_nonce);
    msg.extend_from_slice(&(kem_pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    msg.extend_from_slice(kem_pubkey);
    msg.extend_from_slice(signature);
    msg
}

fn parse_init_message(msg: &[u8]) -> std::result::Result<ParsedInitMessage<'_>, String> {
    if msg.len() < 2 + FINGERPRINT_LEN + NONCE_LEN + 4 {
        return Err("init message too short".into());
    }
    if msg[0] != HANDSHAKE_VERSION {
        return Err("unsupported handshake version".into());
    }
    if msg[1] != INIT_MESSAGE {
        return Err("unexpected handshake message type".into());
    }

    let mut cursor = 2;
    let initiator_fingerprint = msg[cursor..cursor + FINGERPRINT_LEN]
        .try_into()
        .map_err(|_| "invalid initiator fingerprint".to_string())?;
    cursor += FINGERPRINT_LEN;

    let initiator_nonce = msg[cursor..cursor + NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid initiator nonce".to_string())?;
    cursor += NONCE_LEN;

    let kem_len = u16::from_be_bytes(
        msg[cursor..cursor + 2]
            .try_into()
            .map_err(|_| "invalid initiator kem length".to_string())?,
    ) as usize;
    cursor += 2;

    let sig_len = u16::from_be_bytes(
        msg[cursor..cursor + 2]
            .try_into()
            .map_err(|_| "invalid initiator signature length".to_string())?,
    ) as usize;
    cursor += 2;

    let kem_end = cursor + kem_len;
    let sig_end = kem_end + sig_len;
    if sig_end != msg.len() {
        return Err("init message has invalid trailing length".into());
    }

    Ok(ParsedInitMessage {
        initiator_fingerprint,
        initiator_nonce,
        initiator_kem_pubkey: msg[cursor..kem_end].to_vec(),
        signature: &msg[kem_end..sig_end],
    })
}

fn parse_response_message(msg: &[u8]) -> std::result::Result<ParsedResponseMessage<'_>, String> {
    if msg.len() < 2 + FINGERPRINT_LEN + (NONCE_LEN * 2) + 4 {
        return Err("response message too short".into());
    }
    if msg[0] != HANDSHAKE_VERSION {
        return Err("unsupported handshake version".into());
    }
    if msg[1] != RESPONSE_MESSAGE {
        return Err("unexpected handshake message type".into());
    }

    let mut cursor = 2;
    let responder_fingerprint = msg[cursor..cursor + FINGERPRINT_LEN]
        .try_into()
        .map_err(|_| "invalid responder fingerprint".to_string())?;
    cursor += FINGERPRINT_LEN;

    let initiator_nonce = msg[cursor..cursor + NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid initiator nonce".to_string())?;
    cursor += NONCE_LEN;

    let responder_nonce = msg[cursor..cursor + NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid responder nonce".to_string())?;
    cursor += NONCE_LEN;

    let kem_len = u16::from_be_bytes(
        msg[cursor..cursor + 2]
            .try_into()
            .map_err(|_| "invalid responder kem length".to_string())?,
    ) as usize;
    cursor += 2;

    let sig_len = u16::from_be_bytes(
        msg[cursor..cursor + 2]
            .try_into()
            .map_err(|_| "invalid responder signature length".to_string())?,
    ) as usize;
    cursor += 2;

    let kem_end = cursor + kem_len;
    let sig_end = kem_end + sig_len;
    if sig_end != msg.len() {
        return Err("response message has invalid trailing length".into());
    }

    Ok(ParsedResponseMessage {
        responder_fingerprint,
        initiator_nonce,
        responder_nonce,
        responder_kem_pubkey: msg[cursor..kem_end].to_vec(),
        signature: &msg[kem_end..sig_end],
    })
}

fn fingerprint_for_public_key(public_key: &[u8]) -> [u8; FINGERPRINT_LEN] {
    sha2::Sha256::digest(public_key).into()
}

#[cfg(test)]
mod tests {
    use super::{InitiatorHandshake, ResponderHandshake};

    fn sample_peer(
        name: &str,
    ) -> (
        freeq_crypto::sign::IdentityKeypair,
        freeq_crypto::sign::IdentityPublicKey,
        crate::registry::PeerEntry,
    ) {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("key generation");
        let peer = crate::registry::PeerEntry {
            name: name.into(),
            identity_pubkey: public_key.to_bytes(),
            kem_pubkey: b"peer-kem".to_vec(),
            endpoint: Some("peer.example.com:51820".into()),
            allowed_ips: vec!["10.0.0.2/32".parse().expect("cidr")],
        };

        (keypair, public_key, peer)
    }

    #[test]
    fn responder_accepts_valid_initiator_message() {
        let (initiator_key, _initiator_public, initiator_peer) = sample_peer("initiator");
        let (responder_key, responder_public, _) = sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add peer");

        let (_state, init_msg) =
            InitiatorHandshake::new(&initiator_key, b"initiator-kem", responder_public.clone())
                .expect("build init");

        let (_state, response) = ResponderHandshake::process_init(
            &responder_key,
            b"responder-kem",
            &registry,
            &init_msg,
        )
        .expect("process init");

        assert!(!response.is_empty());
    }

    #[test]
    fn responder_rejects_tampered_initiator_signature() {
        let (initiator_key, _initiator_public, initiator_peer) = sample_peer("initiator");
        let (responder_key, responder_public, _) = sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add peer");

        let (_state, mut init_msg) =
            InitiatorHandshake::new(&initiator_key, b"initiator-kem", responder_public.clone())
                .expect("build init");
        let last = init_msg.last_mut().expect("signature byte");
        *last ^= 0x01;

        let err = ResponderHandshake::process_init(
            &responder_key,
            b"responder-kem",
            &registry,
            &init_msg,
        )
        .expect_err("tampered init should fail");

        assert!(matches!(
            err,
            crate::AuthError::HandshakeFailed { step: 2, .. }
        ));
    }

    #[test]
    fn initiator_rejects_unexpected_responder_identity() {
        let (initiator_key, _initiator_public, initiator_peer) = sample_peer("initiator");
        let (responder_key, responder_public, responder_peer) = sample_peer("responder");
        let (_other_key, other_public, _) = sample_peer("other-responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add initiator");
        registry.add_peer(responder_peer).expect("add responder");

        let (state, init_msg) =
            InitiatorHandshake::new(&initiator_key, b"initiator-kem", other_public)
                .expect("build init");
        let (_responder_state, response) = ResponderHandshake::process_init(
            &responder_key,
            b"responder-kem",
            &registry,
            &init_msg,
        )
        .expect("process init");

        let err = state
            .process_response(&response)
            .expect_err("unexpected responder should fail");

        assert!(matches!(
            err,
            crate::AuthError::HandshakeFailed { step: 4, .. }
        ));
        let _ = responder_public;
    }

    #[test]
    fn initiator_reaches_kem_not_implemented_after_authentication() {
        let (initiator_key, _initiator_public, initiator_peer) = sample_peer("initiator");
        let (responder_key, responder_public, responder_peer) = sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add initiator");
        registry.add_peer(responder_peer).expect("add responder");

        let (state, init_msg) =
            InitiatorHandshake::new(&initiator_key, b"initiator-kem", responder_public)
                .expect("build init");
        let (_responder_state, response) = ResponderHandshake::process_init(
            &responder_key,
            b"responder-kem",
            &registry,
            &init_msg,
        )
        .expect("process init");

        let err = state
            .process_response(&response)
            .expect_err("KEM step should still be unavailable");

        assert!(matches!(
            err,
            crate::AuthError::HandshakeFailed { step: 5, .. }
        ));
    }
}

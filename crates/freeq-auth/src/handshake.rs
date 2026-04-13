//! 8-step mutual authentication and hybrid KEM handshake (§4.2).

use crate::Result;
use rand::RngCore;
use sha2::Digest as _;

const HANDSHAKE_VERSION: u8 = 1;
const INIT_MESSAGE: u8 = 1;
const RESPONSE_MESSAGE: u8 = 2;
const KEM_MESSAGE: u8 = 3;
const NONCE_LEN: usize = 32;
const FINGERPRINT_LEN: usize = crate::registry::FINGERPRINT_LEN;

/// State machine for the initiating side of the handshake (Node A).
pub struct InitiatorHandshake {
    initiator_nonce: [u8; NONCE_LEN],
    responder_nonce: Option<[u8; NONCE_LEN]>,
    session_key: Option<[u8; 32]>,
    expected_remote_identity: freeq_crypto::sign::IdentityPublicKey,
}

/// State machine for the responding side of the handshake (Node B).
pub struct ResponderHandshake {
    initiator_nonce: [u8; NONCE_LEN],
    responder_nonce: [u8; NONCE_LEN],
    responder_kem_secret: freeq_crypto::kem::HybridSecretKey,
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
                responder_nonce: None,
                session_key: None,
                expected_remote_identity,
            },
            message,
        ))
    }

    /// Process Node B's response (steps 3-4) and emit KEM ciphertext (step 5).
    pub fn process_response<R>(mut self, msg: &[u8], rng: &mut R) -> Result<(Self, Vec<u8>)>
    where
        R: rand::CryptoRng + rand::RngCore + ?Sized,
    {
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

        let responder_kem_pubkey =
            freeq_crypto::kem::HybridPublicKey::from_bytes(&response.responder_kem_pubkey)
                .map_err(|e| crate::AuthError::HandshakeFailed {
                    step: 4,
                    reason: e.to_string(),
                })?;
        let session_nonce = handshake_nonce(&self.initiator_nonce, &response.responder_nonce);
        let (shared, ciphertext) = freeq_crypto::kem::hybrid_encapsulate(
            &responder_kem_pubkey.x25519_public_key(),
            responder_kem_pubkey.mlkem_public_key(),
            &session_nonce,
            rng,
        )
        .map_err(|e| crate::AuthError::HandshakeFailed {
            step: 5,
            reason: e.to_string(),
        })?;

        self.responder_nonce = Some(response.responder_nonce);
        self.session_key = Some(shared.session_key);

        let kem_message = encode_kem_message(
            &self.initiator_nonce,
            &response.responder_nonce,
            &ciphertext,
        );

        Ok((self, kem_message))
    }

    /// Finalize: derive session keys after both sides complete the hybrid KEM.
    pub fn finalize(self) -> Result<SessionKeys> {
        let responder_nonce = self
            .responder_nonce
            .ok_or(crate::AuthError::HandshakeFailed {
                step: 8,
                reason: "handshake is missing the responder nonce".into(),
            })?;
        let session_key = self.session_key.ok_or(crate::AuthError::HandshakeFailed {
            step: 8,
            reason: "hybrid KEM has not completed".into(),
        })?;

        derive_session_keys(
            session_key,
            &handshake_nonce(&self.initiator_nonce, &responder_nonce),
            Role::Initiator,
        )
    }
}

impl ResponderHandshake {
    /// Process Node A's initial message (steps 2-3) and emit response.
    pub fn process_init(
        identity_sk: &freeq_crypto::sign::IdentityKeypair,
        responder_kem_secret: freeq_crypto::kem::HybridSecretKey,
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
        let responder_kem_pubkey = responder_kem_secret.public_key()?.to_bytes();
        let response_signature = identity_sk.sign_message(&challenge_response(
            &responder_nonce,
            &init.initiator_nonce,
            &responder_kem_pubkey,
        ))?;
        let responder_fingerprint =
            fingerprint_for_public_key(&identity_sk.public_key().to_bytes());
        let response = encode_response_message(
            responder_fingerprint,
            &init.initiator_nonce,
            &responder_nonce,
            &responder_kem_pubkey,
            &response_signature.0,
        );

        Ok((
            Self {
                initiator_nonce: init.initiator_nonce,
                responder_nonce,
                responder_kem_secret,
            },
            response,
        ))
    }

    /// Process Node A's KEM ciphertext (steps 5-8) and finalize.
    pub fn process_kem(self, msg: &[u8]) -> Result<SessionKeys> {
        let kem_msg = parse_kem_message(msg)
            .map_err(|reason| crate::AuthError::HandshakeFailed { step: 5, reason })?;

        if kem_msg.initiator_nonce != self.initiator_nonce {
            return Err(crate::AuthError::HandshakeFailed {
                step: 5,
                reason: "KEM message initiator nonce does not match".into(),
            });
        }
        if kem_msg.responder_nonce != self.responder_nonce {
            return Err(crate::AuthError::HandshakeFailed {
                step: 5,
                reason: "KEM message responder nonce does not match".into(),
            });
        }

        let x25519_secret = self.responder_kem_secret.x25519_secret_bytes();
        let mlkem_seed = self.responder_kem_secret.mlkem_seed_bytes();
        let session_nonce = handshake_nonce(&self.initiator_nonce, &self.responder_nonce);
        let shared = freeq_crypto::kem::hybrid_decapsulate(
            &kem_msg.ciphertext,
            &x25519_secret,
            &mlkem_seed,
            &session_nonce,
        )
        .map_err(|e| crate::AuthError::HandshakeFailed {
            step: 5,
            reason: e.to_string(),
        })?;

        derive_session_keys(shared.session_key, &session_nonce, Role::Responder)
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

struct ParsedKemMessage {
    initiator_nonce: [u8; NONCE_LEN],
    responder_nonce: [u8; NONCE_LEN],
    ciphertext: freeq_crypto::kem::HybridCiphertext,
}

enum Role {
    Initiator,
    Responder,
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

fn encode_kem_message(
    initiator_nonce: &[u8; NONCE_LEN],
    responder_nonce: &[u8; NONCE_LEN],
    ciphertext: &freeq_crypto::kem::HybridCiphertext,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(2 + (NONCE_LEN * 2) + 2 + ciphertext.to_bytes().len());
    msg.push(HANDSHAKE_VERSION);
    msg.push(KEM_MESSAGE);
    msg.extend_from_slice(initiator_nonce);
    msg.extend_from_slice(responder_nonce);
    msg.extend_from_slice(&(ciphertext.mlkem_ct.len() as u16).to_be_bytes());
    msg.extend_from_slice(&ciphertext.x25519_epk);
    msg.extend_from_slice(&ciphertext.mlkem_ct);
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

fn parse_kem_message(msg: &[u8]) -> std::result::Result<ParsedKemMessage, String> {
    if msg.len() < 2 + (NONCE_LEN * 2) + 2 + 32 {
        return Err("KEM message too short".into());
    }
    if msg[0] != HANDSHAKE_VERSION {
        return Err("unsupported handshake version".into());
    }
    if msg[1] != KEM_MESSAGE {
        return Err("unexpected handshake message type".into());
    }

    let mut cursor = 2;
    let initiator_nonce = msg[cursor..cursor + NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid initiator nonce".to_string())?;
    cursor += NONCE_LEN;

    let responder_nonce = msg[cursor..cursor + NONCE_LEN]
        .try_into()
        .map_err(|_| "invalid responder nonce".to_string())?;
    cursor += NONCE_LEN;

    let mlkem_len = u16::from_be_bytes(
        msg[cursor..cursor + 2]
            .try_into()
            .map_err(|_| "invalid KEM ciphertext length".to_string())?,
    ) as usize;
    cursor += 2;

    let epk_end = cursor + 32;
    let ct_end = epk_end + mlkem_len;
    if ct_end != msg.len() {
        return Err("KEM message has invalid trailing length".into());
    }

    let mut serialized_ct = Vec::with_capacity(32 + mlkem_len);
    serialized_ct.extend_from_slice(&msg[cursor..epk_end]);
    serialized_ct.extend_from_slice(&msg[epk_end..ct_end]);

    Ok(ParsedKemMessage {
        initiator_nonce,
        responder_nonce,
        ciphertext: freeq_crypto::kem::HybridCiphertext::from_bytes(&serialized_ct)
            .map_err(|e| e.to_string())?,
    })
}

fn fingerprint_for_public_key(public_key: &[u8]) -> [u8; FINGERPRINT_LEN] {
    sha2::Sha256::digest(public_key).into()
}

fn handshake_nonce(
    initiator_nonce: &[u8; NONCE_LEN],
    responder_nonce: &[u8; NONCE_LEN],
) -> [u8; NONCE_LEN * 2] {
    let mut nonce = [0u8; NONCE_LEN * 2];
    nonce[..NONCE_LEN].copy_from_slice(initiator_nonce);
    nonce[NONCE_LEN..].copy_from_slice(responder_nonce);
    nonce
}

fn derive_session_keys(
    session_key: [u8; 32],
    handshake_nonce: &[u8],
    role: Role,
) -> Result<SessionKeys> {
    let outbound_label = match role {
        Role::Initiator => freeq_crypto::kdf::labels::OUTBOUND,
        Role::Responder => freeq_crypto::kdf::labels::INBOUND,
    };
    let inbound_label = match role {
        Role::Initiator => freeq_crypto::kdf::labels::INBOUND,
        Role::Responder => freeq_crypto::kdf::labels::OUTBOUND,
    };

    Ok(SessionKeys {
        outbound: freeq_crypto::kdf::hkdf_sha256(
            Some(handshake_nonce),
            &session_key,
            outbound_label,
        )?,
        inbound: freeq_crypto::kdf::hkdf_sha256(
            Some(handshake_nonce),
            &session_key,
            inbound_label,
        )?,
    })
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
        freeq_crypto::kem::HybridSecretKey,
        freeq_crypto::kem::HybridPublicKey,
    ) {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("key generation");
        let (kem_secret, kem_public) =
            freeq_crypto::kem::HybridSecretKey::generate(&mut rng).expect("KEM generation");
        let peer = crate::registry::PeerEntry {
            name: name.into(),
            identity_pubkey: public_key.to_bytes(),
            kem_pubkey: kem_public.to_bytes(),
            endpoint: Some("peer.example.com:51820".into()),
            allowed_ips: vec!["10.0.0.2/32".parse().expect("cidr")],
        };

        (keypair, public_key, peer, kem_secret, kem_public)
    }

    #[test]
    fn responder_accepts_valid_initiator_message() {
        let (
            initiator_key,
            _initiator_public,
            initiator_peer,
            _initiator_kem_secret,
            initiator_kem_public,
        ) = sample_peer("initiator");
        let (responder_key, responder_public, _, responder_kem_secret, _) =
            sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add peer");

        let (_state, init_msg) = InitiatorHandshake::new(
            &initiator_key,
            &initiator_kem_public.to_bytes(),
            responder_public.clone(),
        )
        .expect("build init");

        let (_state, response) = ResponderHandshake::process_init(
            &responder_key,
            responder_kem_secret,
            &registry,
            &init_msg,
        )
        .expect("process init");

        assert!(!response.is_empty());
    }

    #[test]
    fn responder_rejects_tampered_initiator_signature() {
        let (
            initiator_key,
            _initiator_public,
            initiator_peer,
            _initiator_kem_secret,
            initiator_kem_public,
        ) = sample_peer("initiator");
        let (responder_key, responder_public, _, responder_kem_secret, _) =
            sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add peer");

        let (_state, mut init_msg) = InitiatorHandshake::new(
            &initiator_key,
            &initiator_kem_public.to_bytes(),
            responder_public.clone(),
        )
        .expect("build init");
        let last = init_msg.last_mut().expect("signature byte");
        *last ^= 0x01;

        let result = ResponderHandshake::process_init(
            &responder_key,
            responder_kem_secret,
            &registry,
            &init_msg,
        );

        assert!(matches!(
            result,
            Err(crate::AuthError::HandshakeFailed { step: 2, .. })
        ));
    }

    #[test]
    fn initiator_rejects_unexpected_responder_identity() {
        let (
            initiator_key,
            _initiator_public,
            initiator_peer,
            _initiator_kem_secret,
            initiator_kem_public,
        ) = sample_peer("initiator");
        let (responder_key, responder_public, responder_peer, responder_kem_secret, _) =
            sample_peer("responder");
        let (_other_key, other_public, _, _, _) = sample_peer("other-responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add initiator");
        registry.add_peer(responder_peer).expect("add responder");

        let (state, init_msg) = InitiatorHandshake::new(
            &initiator_key,
            &initiator_kem_public.to_bytes(),
            other_public,
        )
        .expect("build init");
        let (_responder_state, response) = ResponderHandshake::process_init(
            &responder_key,
            responder_kem_secret,
            &registry,
            &init_msg,
        )
        .expect("process init");

        let result = state.process_response(&response, &mut rand::thread_rng());

        assert!(matches!(
            result,
            Err(crate::AuthError::HandshakeFailed { step: 4, .. })
        ));
        let _ = responder_public;
    }

    #[test]
    fn handshake_derives_matching_session_keys() {
        let (
            initiator_key,
            _initiator_public,
            initiator_peer,
            _initiator_kem_secret,
            initiator_kem_public,
        ) = sample_peer("initiator");
        let (responder_key, responder_public, responder_peer, responder_kem_secret, _) =
            sample_peer("responder");
        let mut registry = crate::registry::PeerRegistry::new();
        registry.add_peer(initiator_peer).expect("add initiator");
        registry.add_peer(responder_peer).expect("add responder");

        let (initiator_state, init_msg) = InitiatorHandshake::new(
            &initiator_key,
            &initiator_kem_public.to_bytes(),
            responder_public,
        )
        .expect("build init");
        let (responder_state, response) = ResponderHandshake::process_init(
            &responder_key,
            responder_kem_secret,
            &registry,
            &init_msg,
        )
        .expect("process init");
        let (initiator_state, kem_msg) = initiator_state
            .process_response(&response, &mut rand::thread_rng())
            .expect("process response");
        let initiator_keys = initiator_state.finalize().expect("initiator finalize");
        let responder_keys = responder_state.process_kem(&kem_msg).expect("process kem");

        assert_eq!(initiator_keys.outbound, responder_keys.inbound);
        assert_eq!(initiator_keys.inbound, responder_keys.outbound);
    }
}

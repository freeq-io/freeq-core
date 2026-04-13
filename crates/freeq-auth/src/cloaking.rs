//! Endpoint cloaking — silent drop of unauthenticated packets.
//!
//! This module implements the core security invariant: *no response is
//! ever sent to an unauthenticated sender*. The node is invisible at the
//! network level until a peer presents a valid ML-DSA-65 signature.

use crate::{registry::PeerRegistry, Result};

const FINGERPRINT_LEN: usize = crate::registry::FINGERPRINT_LEN;
const SIGNATURE_LEN_FIELD_LEN: usize = 2;

/// Decides whether an inbound packet should be processed or dropped.
///
/// Returns `Ok(())` if the packet is from a registered, authenticated peer.
/// Returns `Err(AuthError::Cloaked)` if it should be silently dropped.
///
/// This function must be called *before* any response is issued — including
/// ICMP errors, QUIC handshake responses, or TLS client hellos.
pub fn check_inbound(
    registry: &PeerRegistry,
    _src_addr: std::net::SocketAddr,
    packet: &[u8],
) -> Result<()> {
    let (fingerprint, signature, payload) = parse_cloaked_packet(packet)?;
    let (peer_name, _) = registry
        .lookup_name_and_peer(fingerprint)
        .ok_or(crate::AuthError::Cloaked)?;

    registry
        .verify_signature(peer_name, payload, signature)
        .map_err(|_| crate::AuthError::Cloaked)
}

fn parse_cloaked_packet(packet: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    if packet.len() < FINGERPRINT_LEN + SIGNATURE_LEN_FIELD_LEN {
        return Err(crate::AuthError::Cloaked);
    }

    let fingerprint = &packet[..FINGERPRINT_LEN];
    let sig_len_start = FINGERPRINT_LEN;
    let sig_len_end = sig_len_start + SIGNATURE_LEN_FIELD_LEN;
    let sig_len = u16::from_be_bytes(
        packet[sig_len_start..sig_len_end]
            .try_into()
            .map_err(|_| crate::AuthError::Cloaked)?,
    ) as usize;

    let sig_start = sig_len_end;
    let sig_end = sig_start
        .checked_add(sig_len)
        .ok_or(crate::AuthError::Cloaked)?;
    if sig_end > packet.len() {
        return Err(crate::AuthError::Cloaked);
    }

    Ok((fingerprint, &packet[sig_start..sig_end], &packet[sig_end..]))
}

#[cfg(test)]
mod tests {
    use super::check_inbound;
    use crate::registry::{PeerEntry, PeerRegistry, FINGERPRINT_LEN};

    fn cloaked_packet(
        fingerprint: [u8; FINGERPRINT_LEN],
        signature: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(FINGERPRINT_LEN + 2 + signature.len() + payload.len());
        packet.extend_from_slice(&fingerprint);
        packet.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        packet.extend_from_slice(signature);
        packet.extend_from_slice(payload);
        packet
    }

    fn sample_registry() -> (PeerRegistry, [u8; FINGERPRINT_LEN], Vec<u8>, Vec<u8>) {
        use sha2::Digest as _;

        let mut rng = rand::thread_rng();
        let (keypair, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("key generation");
        let payload = b"hello cloaked world".to_vec();
        let signature = keypair.sign_message(&payload).expect("signature").0;
        let fingerprint: [u8; FINGERPRINT_LEN] = sha2::Sha256::digest(public_key.to_bytes()).into();

        let mut registry = PeerRegistry::new();
        registry
            .add_peer(PeerEntry {
                name: "lon-01".into(),
                identity_pubkey: public_key.to_bytes(),
                kem_pubkey: vec![1, 2, 3],
                endpoint: Some("peer.example.com:51820".into()),
                allowed_ips: vec!["10.0.0.2/32".parse().expect("cidr")],
            })
            .expect("add peer");

        (registry, fingerprint, signature, payload)
    }

    #[test]
    fn cloaking_accepts_valid_packet() {
        let (registry, fingerprint, signature, payload) = sample_registry();
        let packet = cloaked_packet(fingerprint, &signature, &payload);

        check_inbound(
            &registry,
            "127.0.0.1:51820".parse().expect("socket addr"),
            &packet,
        )
        .expect("packet should be accepted");
    }

    #[test]
    fn cloaking_rejects_unknown_fingerprint() {
        let (registry, _fingerprint, signature, payload) = sample_registry();
        let packet = cloaked_packet([0u8; FINGERPRINT_LEN], &signature, &payload);

        let err = check_inbound(
            &registry,
            "127.0.0.1:51820".parse().expect("socket addr"),
            &packet,
        )
        .expect_err("packet should be rejected");

        assert!(matches!(err, crate::AuthError::Cloaked));
    }

    #[test]
    fn cloaking_rejects_tampered_payload() {
        let (registry, fingerprint, signature, mut payload) = sample_registry();
        payload[0] ^= 0x01;
        let packet = cloaked_packet(fingerprint, &signature, &payload);

        let err = check_inbound(
            &registry,
            "127.0.0.1:51820".parse().expect("socket addr"),
            &packet,
        )
        .expect_err("packet should be rejected");

        assert!(matches!(err, crate::AuthError::Cloaked));
    }
}

use freeq_crypto::{combine_secrets, FreeQKeyPair};
use zeroize::Zeroize;

#[test]
fn test_hybrid_combiner_non_commutativity() {
    let x25519 = [1u8; 32];
    let mlkem = [2u8; 32];
    let client = [3u8; 32];
    let server = [4u8; 32];

    let base = combine_secrets(&x25519, &mlkem, &client, &server);
    let mutated = combine_secrets(&x25519, &mlkem, &server, &client);

    assert_ne!(
        base, mutated,
        "VULNERABILITY: commutative layout detected in hybrid secret generation."
    );
}

#[test]
fn test_memory_zeroization_behavior() {
    let mut keypair = FreeQKeyPair {
        x25519_private: [0xa5; 32],
        x25519_public: [0x5a; 32],
        mlkem_private: [0x7e; 2400],
    };

    keypair.zeroize();

    assert_eq!(
        keypair.x25519_private, [0u8; 32],
        "VULNERABILITY: X25519 private material failed memory zeroization."
    );
    assert_eq!(
        keypair.x25519_public, [0x5a; 32],
        "public X25519 material should not be erased by keypair zeroization."
    );
    assert_eq!(
        keypair.mlkem_private, [0u8; 2400],
        "VULNERABILITY: ML-KEM private material failed memory zeroization."
    );
}

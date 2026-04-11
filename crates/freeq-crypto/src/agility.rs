//! Crypto-agility traits.
//!
//! Defines the abstract interfaces for KEM and signature schemes so that
//! the runtime algorithm can be swapped (ML-KEM-512 / 768 / 1024,
//! ML-DSA-44 / 65 / 87) without restarting nodes or interrupting traffic.

use crate::Result;

/// Active KEM algorithm parameter set.
///
/// Controls the security level and handshake size trade-off.
/// ML-KEM-768 is the default (Category 3 ≈ AES-192).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KemAlgorithm {
    /// FIPS 203 ML-KEM-512  — Category 1 ≈ AES-128, 1.6 KB handshake
    MlKem512,
    /// FIPS 203 ML-KEM-768  — Category 3 ≈ AES-192, 2.2 KB handshake (default)
    MlKem768,
    /// FIPS 203 ML-KEM-1024 — Category 5 ≈ AES-256, 3.2 KB handshake
    MlKem1024,
}

impl Default for KemAlgorithm {
    fn default() -> Self {
        Self::MlKem768
    }
}

/// Active signature algorithm parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignAlgorithm {
    /// FIPS 204 ML-DSA-44 — Category 2, 2.5 KB signature
    MlDsa44,
    /// FIPS 204 ML-DSA-65 — Category 3, 3.3 KB signature (default)
    MlDsa65,
    /// FIPS 204 ML-DSA-87 — Category 5, 4.6 KB signature
    MlDsa87,
    /// FIPS 205 SLH-DSA-SHA2-128f — hash-based backup, 17 KB signature
    SlhDsaSha2128f,
}

impl Default for SignAlgorithm {
    fn default() -> Self {
        Self::MlDsa65
    }
}

/// Active bulk encryption algorithm.
///
/// Selection is typically automatic based on CPU capabilities:
/// AES-256-GCM on x86 with AES-NI, ChaCha20-Poly1305 elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BulkAlgorithm {
    /// AES-256-GCM — hardware-accelerated on x86 with AES-NI
    Aes256Gcm,
    /// ChaCha20-Poly1305 — constant-time software, preferred on ARM
    ChaCha20Poly1305,
}

/// The complete cryptographic algorithm configuration for a node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlgorithmSuite {
    /// KEM algorithm (post-quantum component of hybrid KEM).
    pub kem: KemAlgorithm,
    /// Signature algorithm for mutual authentication.
    pub sign: SignAlgorithm,
    /// Bulk encryption algorithm.
    pub bulk: BulkAlgorithm,
}

impl Default for AlgorithmSuite {
    fn default() -> Self {
        Self {
            kem: KemAlgorithm::default(),
            sign: SignAlgorithm::default(),
            bulk: detect_bulk_algorithm(),
        }
    }
}

/// Detects the preferred bulk encryption algorithm for the current CPU.
///
/// Returns `Aes256Gcm` if AES-NI is available, `ChaCha20Poly1305` otherwise.
pub fn detect_bulk_algorithm() -> BulkAlgorithm {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") {
            return BulkAlgorithm::Aes256Gcm;
        }
    }
    BulkAlgorithm::ChaCha20Poly1305
}

/// Trait for KEM schemes — implemented for each ML-KEM parameter set.
pub trait KemScheme: Send + Sync {
    /// The decapsulation (private) key type.
    type DecapsKey: zeroize::ZeroizeOnDrop;
    /// The encapsulation (public) key type.
    type EncapsKey;
    /// The shared secret type.
    type SharedSecret: zeroize::ZeroizeOnDrop;
    /// The ciphertext type.
    type Ciphertext;

    /// Generate a fresh KEM keypair.
    fn generate_keypair(rng: &mut impl rand_core::CryptoRngCore)
        -> Result<(Self::DecapsKey, Self::EncapsKey)>;

    /// Encapsulate: produce a shared secret and ciphertext for `pk`.
    fn encapsulate(
        pk: &Self::EncapsKey,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext)>;

    /// Decapsulate: recover the shared secret from `ct` using `sk`.
    fn decapsulate(sk: &Self::DecapsKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret>;
}

/// Trait for signature schemes — implemented for each ML-DSA parameter set.
pub trait SignScheme: Send + Sync {
    /// The signing (private) key type.
    type SigningKey: zeroize::ZeroizeOnDrop;
    /// The verification (public) key type.
    type VerifyKey;
    /// The signature type.
    type Signature;

    /// Generate a fresh signing keypair.
    fn generate_keypair(rng: &mut impl rand_core::CryptoRngCore)
        -> Result<(Self::SigningKey, Self::VerifyKey)>;

    /// Sign a message.
    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Result<Self::Signature>;

    /// Verify a signature.
    fn verify(vk: &Self::VerifyKey, msg: &[u8], sig: &Self::Signature) -> Result<()>;
}

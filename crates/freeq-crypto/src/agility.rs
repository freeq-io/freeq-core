//! Crypto-agility configuration types.
//!
//! Enumerates the supported KEM, signature, and bulk encryption algorithm
//! parameter sets. The active suite is read from `freeq.toml` at startup.

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

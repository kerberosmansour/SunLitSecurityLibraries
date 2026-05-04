// Crypto algorithm selection and policy.
//
// Provides the `CryptoAlgorithm` enum for tagging encrypted envelopes with their
// algorithm, and `AlgorithmPolicy` for controlling which algorithms are permitted.

use std::fmt;

use crate::error::DataError;

/// Supported AEAD encryption algorithms.
///
/// Each variant corresponds to an algorithm that can be used for envelope encryption.
/// The algorithm tag is stored inside [`super::envelope::EnvelopeEncrypted`] so that
/// decryption can select the correct primitive even after the system default changes.
///
/// # Examples
///
/// ```
/// use secure_data::algorithm::CryptoAlgorithm;
///
/// let algo = CryptoAlgorithm::default();
/// assert_eq!(algo.as_str(), "AES-256-GCM");
///
/// let xchacha = CryptoAlgorithm::XChaCha20Poly1305;
/// assert_eq!(xchacha.as_str(), "XChaCha20-Poly1305");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CryptoAlgorithm {
    /// AES-256-GCM (NIST standard, 96-bit nonce, 128-bit tag).
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305 (192-bit nonce, 128-bit tag).
    XChaCha20Poly1305,
}

impl CryptoAlgorithm {
    /// Returns the canonical string identifier stored in encrypted envelopes.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_data::algorithm::CryptoAlgorithm;
    ///
    /// assert_eq!(CryptoAlgorithm::Aes256Gcm.as_str(), "AES-256-GCM");
    /// assert_eq!(CryptoAlgorithm::XChaCha20Poly1305.as_str(), "XChaCha20-Poly1305");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    /// Parses an algorithm string from an encrypted envelope.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::UnsupportedAlgorithm`] if the string does not match
    /// any known algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_data::algorithm::CryptoAlgorithm;
    ///
    /// let algo = CryptoAlgorithm::from_envelope_str("AES-256-GCM").unwrap();
    /// assert_eq!(algo, CryptoAlgorithm::Aes256Gcm);
    ///
    /// let err = CryptoAlgorithm::from_envelope_str("UNKNOWN");
    /// assert!(err.is_err());
    /// ```
    pub fn from_envelope_str(s: &str) -> Result<Self, DataError> {
        match s {
            "AES-256-GCM" => Ok(Self::Aes256Gcm),
            "XChaCha20-Poly1305" => Ok(Self::XChaCha20Poly1305),
            other => Err(DataError::UnsupportedAlgorithm {
                algorithm: other.to_string(),
            }),
        }
    }

    /// Returns the nonce length in bytes required by this algorithm.
    #[must_use]
    pub fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Returns the ordering rank for policy comparison.
    /// Higher rank means stronger/newer algorithm for downgrade prevention.
    fn rank(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
            Self::XChaCha20Poly1305 => 2,
        }
    }
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Policy controlling which encryption algorithms are permitted.
///
/// Use this to enforce minimum algorithm strength and select the preferred
/// algorithm for new encryptions. If a `min_algorithm` is set, any attempt to
/// encrypt with an algorithm ranked below it will be rejected.
///
/// # Examples
///
/// ```
/// use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
///
/// // Prefer XChaCha20 with no minimum (allows fallback to AES)
/// let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);
/// assert_eq!(policy.preferred(), CryptoAlgorithm::XChaCha20Poly1305);
/// assert!(policy.validate().is_ok());
///
/// // Require minimum XChaCha20 — AES would be rejected
/// let strict = AlgorithmPolicy::new(
///     CryptoAlgorithm::XChaCha20Poly1305,
///     Some(CryptoAlgorithm::XChaCha20Poly1305),
/// );
/// assert!(strict.validate().is_ok());
/// ```
#[derive(Debug, Clone, Default)]
pub struct AlgorithmPolicy {
    preferred: CryptoAlgorithm,
    min_algorithm: Option<CryptoAlgorithm>,
}

impl AlgorithmPolicy {
    /// Creates a policy with the given preferred algorithm and optional minimum.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
    ///
    /// let policy = AlgorithmPolicy::new(
    ///     CryptoAlgorithm::XChaCha20Poly1305,
    ///     Some(CryptoAlgorithm::Aes256Gcm),
    /// );
    /// assert!(policy.validate().is_ok());
    /// ```
    #[must_use]
    pub fn new(preferred: CryptoAlgorithm, min_algorithm: Option<CryptoAlgorithm>) -> Self {
        Self {
            preferred,
            min_algorithm,
        }
    }

    /// Creates a policy that prefers the given algorithm with no minimum restriction.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
    ///
    /// let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::Aes256Gcm);
    /// assert_eq!(policy.preferred(), CryptoAlgorithm::Aes256Gcm);
    /// ```
    #[must_use]
    pub fn prefer(algorithm: CryptoAlgorithm) -> Self {
        Self {
            preferred: algorithm,
            min_algorithm: None,
        }
    }

    /// Returns the preferred algorithm.
    #[must_use]
    pub fn preferred(&self) -> CryptoAlgorithm {
        self.preferred
    }

    /// Validates that the preferred algorithm meets the minimum requirement.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::AlgorithmBelowPolicyMinimum`] if the preferred
    /// algorithm ranks below the configured minimum.
    pub fn validate(&self) -> Result<(), DataError> {
        if let Some(min) = self.min_algorithm {
            if self.preferred.rank() < min.rank() {
                return Err(DataError::AlgorithmBelowPolicyMinimum {
                    requested: self.preferred.as_str().to_string(),
                    minimum: min.as_str().to_string(),
                });
            }
        }
        Ok(())
    }
}

// Error types for secure_data.

use thiserror::Error;

/// Errors produced by `secure_data` operations.
///
/// # Examples
///
/// ```
/// use secure_data::error::DataError;
///
/// let err = DataError::KeyNotFound { alias: "missing".into() };
/// assert!(err.to_string().contains("missing"));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DataError {
    /// The key with the given alias was not found.
    #[error("key not found: {alias}")]
    KeyNotFound {
        /// The key alias that was not found.
        alias: String,
    },

    /// The key version is not available for the requested operation.
    #[error("key version unavailable: alias={alias}, version={version}")]
    KeyVersionUnavailable {
        /// The key alias.
        alias: String,
        /// The key version identifier.
        version: String,
    },

    /// The key version has been deactivated and cannot be used for decryption.
    #[error("key deactivated: alias={alias}, version={version}")]
    KeyDeactivated {
        /// The key alias.
        alias: String,
        /// The key version identifier.
        version: String,
    },

    /// AEAD authentication failed — ciphertext or AAD was tampered.
    #[error("authentication failure: ciphertext or AAD was tampered")]
    AuthenticationFailure,

    /// Encryption operation failed.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Decryption operation failed.
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonce {
        /// Expected nonce length.
        expected: usize,
        /// Actual nonce length received.
        actual: usize,
    },

    /// Cannot deactivate the last remaining active/decrypt-only key version.
    #[error("cannot deactivate last key version for alias={alias}")]
    CannotDeactivateLastVersion {
        /// The key alias.
        alias: String,
    },

    /// The key ring does not contain the given alias.
    #[error("unknown key alias: {alias}")]
    UnknownAlias {
        /// The key alias that was not found.
        alias: String,
    },

    /// Secret reference parsing error.
    #[error("invalid secret reference: {input}")]
    InvalidSecretReference {
        /// The input string that could not be parsed.
        input: String,
    },

    /// A wrapped key had an unexpected length.
    #[error("wrapped key length mismatch")]
    WrappedKeyLengthMismatch,

    /// A key provider was unreachable or returned an unexpected error.
    #[error("provider unavailable: provider={provider}, reason={reason}")]
    ProviderUnavailable {
        /// The provider that was unavailable (e.g. "vault", "aws-kms").
        provider: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// A key provider rejected the request due to an authentication error.
    #[error("provider auth error: provider={provider}, reason={reason}")]
    ProviderAuthError {
        /// The provider that returned the auth error.
        provider: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// A secret reference could not be resolved because the secret does not exist.
    #[error("secret not found: {reference}")]
    SecretNotFound {
        /// The secret reference that was not found.
        reference: String,
    },

    /// The algorithm specified in an encrypted envelope is not supported.
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The algorithm identifier that was not recognized.
        algorithm: String,
    },

    /// The requested algorithm is below the policy minimum.
    #[error("algorithm below policy minimum: requested={requested}, minimum={minimum}")]
    AlgorithmBelowPolicyMinimum {
        /// The algorithm that was requested.
        requested: String,
        /// The minimum algorithm required by policy.
        minimum: String,
    },

    /// A post-quantum operation was requested but the `pq` feature is not
    /// compiled into this build.
    ///
    /// Emitted when `CryptoAlgorithm::HybridX25519MlKem768` is selected on a
    /// build without `--features pq`. The `pq` feature gates the optional
    /// dependencies (`ml-kem`, `x25519-dalek`, `hkdf`, `sha2`); without them
    /// the encrypt/decrypt path cannot construct the hybrid KEM. There is no
    /// silent fallback to a classical algorithm — see
    /// `docs/slo/design/pq-migration-plan.md` for the rationale.
    #[error("post-quantum unavailable: rebuild with `--features pq`")]
    PqUnavailable,

    /// A post-quantum envelope (carrying a `combiner_id`) was decoded on a
    /// build without `--features pq`.
    ///
    /// Distinct from `PqUnavailable` (encrypt-side request) — this variant is
    /// the decrypt-side counterpart, returned when a v2 hybrid envelope is
    /// presented to a non-PQ build. Never silently downgrades to a classical
    /// algorithm.
    #[error("post-quantum feature required: this envelope was produced with the `pq` feature; rebuild with `--features pq` to decrypt")]
    PqFeatureRequired,

    /// An envelope was rejected by an `AlgorithmPolicy` constraint that the
    /// existing `AlgorithmBelowPolicyMinimum` variant does not capture (e.g.,
    /// a wire-format-version policy that requires v2-or-higher envelopes).
    ///
    /// Distinct from `AlgorithmBelowPolicyMinimum`: that variant is about the
    /// rank of the AEAD algorithm. This variant is about higher-level policy
    /// decisions like minimum envelope version or required combiner.
    #[error("algorithm rejected by policy: {reason}")]
    AlgorithmRejectedByPolicy {
        /// Human-readable reason — must not include sensitive material.
        reason: String,
    },

    /// An envelope failed structural validation before any cryptographic
    /// operation was attempted.
    ///
    /// Examples: a v1 envelope (classical AEAD) carrying a `combiner_id`
    /// field; an envelope with internally inconsistent metadata. Returned
    /// from the deserialize / validate boundary, not from the AEAD path.
    #[error("envelope malformed: {reason}")]
    EnvelopeMalformed {
        /// Human-readable reason — must not include the malformed bytes.
        reason: String,
    },
}

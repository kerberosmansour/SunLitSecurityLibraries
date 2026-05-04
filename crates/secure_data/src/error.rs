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
}

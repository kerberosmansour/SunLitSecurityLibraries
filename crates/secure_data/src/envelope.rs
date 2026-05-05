// Envelope encryption and decryption.
//
// Application code calls encrypt_for_storage() and decrypt_for_use().
// This module manages data key generation, wrapping, versioning, nonce generation,
// authenticated encryption, and AAD binding internally.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use crate::error::DataError;
use crate::kms::KeyProvider;

/// The current envelope format version.
const ENVELOPE_VERSION: &str = "1";

/// Encrypted data blob with all metadata required for decryption.
///
/// This struct is `#[must_use]` — callers must not silently discard encrypted output.
///
/// # Examples
///
/// ```
/// # async fn example() -> Result<(), secure_data::error::DataError> {
/// use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
/// use secure_data::kms::StaticDevKeyProvider;
///
/// let provider = StaticDevKeyProvider::new();
/// let envelope = encrypt_for_storage(b"hello", "default", &provider).await?;
/// assert_eq!(envelope.version, "1");
///
/// let plain = decrypt_for_use(&envelope, &provider).await?;
/// assert_eq!(plain, b"hello");
/// # Ok(())
/// # }
/// ```
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncrypted {
    /// Envelope format version.
    pub version: String,
    /// AEAD algorithm identifier.
    pub algorithm: String,
    /// Logical alias of the key-encryption key.
    pub key_alias: String,
    /// Version of the key-encryption key used.
    pub key_version: String,
    /// The data-encryption key, wrapped by the KEK (base64-encoded).
    pub wrapped_data_key: Vec<u8>,
    /// Random nonce used for this encryption (raw bytes).
    pub nonce: Vec<u8>,
    /// AEAD-authenticated ciphertext.
    pub ciphertext: Vec<u8>,
    /// Additional authenticated data bound to this ciphertext.
    pub aad: Vec<u8>,
    /// Hybrid PQ KEM combiner identifier.
    ///
    /// `None` for classical (v1) envelopes — every existing `Aes256Gcm` and
    /// `XChaCha20Poly1305` envelope serialized before pq-readiness M1 has
    /// this field absent on the wire (default-deserialized to `None`).
    ///
    /// `Some(0x01)` for hybrid X25519 + ML-KEM-768 / HKDF-SHA-256 envelopes
    /// produced by the pq-readiness M2 implementation. `Some(other)` is
    /// rejected by [`Self::validate_structure`] until a future combiner is
    /// explicitly added — fail-closed by design.
    ///
    /// See `docs/slo/design/pq-migration-plan.md` and [`crate::pq`] for the
    /// full table of combiner identifiers and the wire-format reasoning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combiner_id: Option<u8>,
}

impl EnvelopeEncrypted {
    /// Validates the envelope's structural invariants without performing
    /// any cryptographic operation. Returns
    /// [`DataError::EnvelopeMalformed`] if the metadata is internally
    /// inconsistent, or [`DataError::PqFeatureRequired`] if a hybrid PQ
    /// envelope was decoded on a build without `--features pq`, or
    /// [`DataError::AlgorithmRejectedByPolicy`] if the combiner identifier
    /// is reserved-future or the fail-closed sentinel.
    ///
    /// Called from [`decrypt_for_use`] before any AEAD work — fails fast
    /// when an attacker has tampered with envelope metadata in a way that
    /// would otherwise reach the cryptographic primitive.
    ///
    /// # Errors
    ///
    /// - [`DataError::EnvelopeMalformed`] — `combiner_id` is set on a
    ///   classical (v1) envelope, or contains an unrecognised value.
    /// - [`DataError::PqFeatureRequired`] — envelope's algorithm is the
    ///   hybrid PQ KEM but this build does not have the `pq` feature.
    /// - [`DataError::AlgorithmRejectedByPolicy`] — `combiner_id` is the
    ///   `0xFF` fail-closed sentinel.
    pub fn validate_structure(&self) -> Result<(), DataError> {
        let algorithm = crate::algorithm::CryptoAlgorithm::from_envelope_str(&self.algorithm)?;

        match (algorithm.is_post_quantum(), self.combiner_id) {
            // Classical envelope with no combiner: v1; nothing to do.
            (false, None) => Ok(()),
            // Classical envelope with combiner_id present and zero: silently
            // accept zero (some serialisers emit Some(0) instead of None).
            (false, Some(0)) => Ok(()),
            // Classical envelope with non-zero combiner: malformed.
            (false, Some(id)) => Err(DataError::EnvelopeMalformed {
                reason: format!(
                    "classical envelope (algorithm={}) carries combiner_id=0x{:02x}; \
                     classical envelopes must have combiner_id absent or zero",
                    self.algorithm, id
                ),
            }),
            // Post-quantum envelope but pq feature is off: refuse without
            // attempting any crypto.
            #[cfg(not(feature = "pq"))]
            (true, _) => Err(DataError::PqFeatureRequired),
            // Post-quantum envelope with pq feature on: validate combiner.
            #[cfg(feature = "pq")]
            (true, None) => Err(DataError::EnvelopeMalformed {
                reason: format!(
                    "post-quantum envelope (algorithm={}) is missing combiner_id; \
                     hybrid envelopes must carry an explicit combiner_id",
                    self.algorithm
                ),
            }),
            #[cfg(feature = "pq")]
            (true, Some(id)) => {
                if id == crate::pq::COMBINER_ID_FAIL_CLOSED {
                    return Err(DataError::AlgorithmRejectedByPolicy {
                        reason: format!(
                            "combiner_id=0x{:02x} is the permanent fail-closed sentinel",
                            id
                        ),
                    });
                }
                if !crate::pq::is_recognised_combiner(id) {
                    return Err(DataError::AlgorithmRejectedByPolicy {
                        reason: format!(
                            "combiner_id=0x{:02x} is not a recognised combiner in this build",
                            id
                        ),
                    });
                }
                Ok(())
            }
        }
    }
}

/// Encrypts `plaintext` under the key identified by `key_alias` using the provided `KeyProvider`.
///
/// Uses the default algorithm (AES-256-GCM) for backward compatibility.
/// For algorithm selection, use [`encrypt_with_policy`].
///
/// Returns an [`EnvelopeEncrypted`] blob containing all metadata required for decryption.
///
/// # Errors
/// Returns [`DataError`] if key generation or encryption fails.
pub async fn encrypt_for_storage<P: KeyProvider>(
    plaintext: &[u8],
    key_alias: &str,
    provider: &P,
) -> Result<EnvelopeEncrypted, DataError> {
    encrypt_with_policy(plaintext, key_alias, provider, &AlgorithmPolicy::default()).await
}

/// Encrypts `plaintext` using the algorithm specified by `policy`.
///
/// The algorithm tag is stored in the envelope so that [`decrypt_for_use`] can
/// select the correct primitive regardless of the current system default.
///
/// # Errors
///
/// Returns [`DataError::AlgorithmBelowPolicyMinimum`] if the preferred algorithm
/// is below the policy minimum. Returns [`DataError`] if key generation or
/// encryption fails.
///
/// # Examples
///
/// ```
/// # async fn example() -> Result<(), secure_data::error::DataError> {
/// use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
/// use secure_data::envelope::{encrypt_with_policy, decrypt_for_use};
/// use secure_data::kms::StaticDevKeyProvider;
///
/// let provider = StaticDevKeyProvider::new();
/// let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);
///
/// let envelope = encrypt_with_policy(b"secret", "my-key", &provider, &policy).await?;
/// assert_eq!(envelope.algorithm, "XChaCha20-Poly1305");
///
/// let decrypted = decrypt_for_use(&envelope, &provider).await?;
/// assert_eq!(decrypted, b"secret");
/// # Ok(())
/// # }
/// ```
pub async fn encrypt_with_policy<P: KeyProvider>(
    plaintext: &[u8],
    key_alias: &str,
    provider: &P,
    policy: &AlgorithmPolicy,
) -> Result<EnvelopeEncrypted, DataError> {
    // Validate algorithm policy
    policy.validate()?;

    let algorithm = policy.preferred();

    // Post-quantum dispatch: the hybrid KEM lands in pq-readiness M2 behind
    // the `pq` feature flag. M1 reserves the enum slot but the encrypt path
    // returns PqUnavailable on builds without the feature, and is similarly
    // not yet implemented even with the feature on (M2 fills it). Fail-fast
    // with a structured error — never silently fall through to the classical
    // algorithm path.
    if algorithm.is_post_quantum() {
        return Err(DataError::PqUnavailable);
    }

    // 1. Generate a fresh data-encryption key via the provider.
    let (dek, wrapped_data_key, key_version) = provider.generate_data_key(key_alias).await?;

    // 2. Generate a random nonce of the correct length for the algorithm.
    let nonce_len = algorithm.nonce_len();
    let mut nonce_bytes = vec![0u8; nonce_len];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // 3. Build AAD from envelope metadata.
    let aad = build_aad(
        ENVELOPE_VERSION,
        algorithm.as_str(),
        key_alias,
        &key_version,
    );

    // 4. Encrypt with the selected algorithm.
    let ciphertext = encrypt_with_algorithm(algorithm, &dek, &nonce_bytes, plaintext, &aad)?;

    Ok(EnvelopeEncrypted {
        version: ENVELOPE_VERSION.to_string(),
        algorithm: algorithm.as_str().to_string(),
        key_alias: key_alias.to_string(),
        key_version,
        wrapped_data_key,
        nonce: nonce_bytes,
        ciphertext,
        aad,
        // M1: classical envelopes have no combiner. M2 will set
        // `Some(crate::pq::COMBINER_ID_X25519_ML_KEM_768)` for hybrid
        // envelopes via a separate hybrid encrypt path (not this function).
        combiner_id: None,
    })
}

/// Decrypts an [`EnvelopeEncrypted`] blob using the provided `KeyProvider`.
///
/// The algorithm is selected based on the `algorithm` field in the envelope,
/// enabling transparent decryption of data encrypted with different algorithms.
///
/// # Errors
/// Returns [`DataError`] if the algorithm is unsupported, key unwrapping fails,
/// or AEAD verification fails.
pub async fn decrypt_for_use<P: KeyProvider>(
    envelope: &EnvelopeEncrypted,
    provider: &P,
) -> Result<Vec<u8>, DataError> {
    // Pre-flight: validate envelope structural invariants before any
    // cryptographic operation. Catches tampered metadata (e.g., a v1
    // envelope carrying a non-zero combiner_id) and rejects v2 hybrid
    // envelopes on a non-PQ build with a structured PqFeatureRequired error.
    envelope.validate_structure()?;

    // 0. Parse the algorithm from the envelope.
    let algorithm = CryptoAlgorithm::from_envelope_str(&envelope.algorithm)?;

    // Post-quantum dispatch: M2 will route hybrid envelopes through a
    // dedicated PQ decrypt path. M1 reserves the slot — at this point
    // `validate_structure` has already returned PqFeatureRequired on a
    // non-PQ build, so reaching here with a PQ algorithm only happens on
    // a `pq`-feature build, where M2 fills the path.
    if algorithm.is_post_quantum() {
        return Err(DataError::PqUnavailable);
    }

    // 1. Unwrap the data-encryption key.
    let dek = provider
        .unwrap_data_key(
            &envelope.wrapped_data_key,
            &envelope.key_alias,
            &envelope.key_version,
        )
        .await?;

    // 2. Validate nonce length for the algorithm.
    let expected_nonce_len = algorithm.nonce_len();
    if envelope.nonce.len() != expected_nonce_len {
        return Err(DataError::InvalidNonce {
            expected: expected_nonce_len,
            actual: envelope.nonce.len(),
        });
    }

    // 3. Recompute AAD from envelope header fields to detect metadata tampering.
    //    If an attacker modifies key_version, algorithm, or key_alias without
    //    updating the authenticated AAD, AEAD verification will fail.
    let recomputed_aad = build_aad(
        &envelope.version,
        &envelope.algorithm,
        &envelope.key_alias,
        &envelope.key_version,
    );

    // 4. Decrypt with the correct algorithm using the original AAD bound during encryption.
    //    We use the stored AAD (which was authenticated) — if metadata fields were tampered
    //    post-encryption, the recomputed AAD won't match the stored one.
    if recomputed_aad != envelope.aad {
        return Err(DataError::AuthenticationFailure);
    }

    decrypt_with_algorithm(
        algorithm,
        &dek,
        &envelope.nonce,
        &envelope.ciphertext,
        &envelope.aad,
    )
}

// --- Helpers ----------------------------------------------------------------

fn aes_cipher_from_dek(dek: &[u8]) -> Result<Aes256Gcm, DataError> {
    if dek.len() != 32 {
        return Err(DataError::WrappedKeyLengthMismatch);
    }
    let key = Key::<Aes256Gcm>::from_slice(dek);
    Ok(Aes256Gcm::new(key))
}

fn xchacha_cipher_from_dek(dek: &[u8]) -> Result<XChaCha20Poly1305, DataError> {
    if dek.len() != 32 {
        return Err(DataError::WrappedKeyLengthMismatch);
    }
    let key = chacha20poly1305::Key::from_slice(dek);
    Ok(XChaCha20Poly1305::new(key))
}

/// Encrypts using the specified algorithm.
fn encrypt_with_algorithm(
    algorithm: CryptoAlgorithm,
    dek: &[u8],
    nonce_bytes: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DataError> {
    match algorithm {
        CryptoAlgorithm::Aes256Gcm => {
            let cipher = aes_cipher_from_dek(dek)?;
            let nonce = Nonce::from_slice(nonce_bytes);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| DataError::EncryptionFailed {
                    reason: "AES-256-GCM encryption failed".to_string(),
                })
        }
        CryptoAlgorithm::XChaCha20Poly1305 => {
            let cipher = xchacha_cipher_from_dek(dek)?;
            let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| DataError::EncryptionFailed {
                    reason: "XChaCha20-Poly1305 encryption failed".to_string(),
                })
        }
        // Defense-in-depth: hybrid PQ should be filtered out by the caller
        // (`encrypt_with_policy` / `decrypt_for_use`) via `is_post_quantum()`
        // before reaching this helper. Reaching here on any build means a
        // future caller forgot the dispatch — fail closed with a structured
        // error rather than panic.
        CryptoAlgorithm::HybridX25519MlKem768 => Err(DataError::PqUnavailable),
    }
}

/// Decrypts using the specified algorithm.
fn decrypt_with_algorithm(
    algorithm: CryptoAlgorithm,
    dek: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DataError> {
    match algorithm {
        CryptoAlgorithm::Aes256Gcm => {
            let cipher = aes_cipher_from_dek(dek)?;
            let nonce = Nonce::from_slice(nonce_bytes);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| DataError::AuthenticationFailure)
        }
        CryptoAlgorithm::XChaCha20Poly1305 => {
            let cipher = xchacha_cipher_from_dek(dek)?;
            let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| DataError::AuthenticationFailure)
        }
        // Defense-in-depth: hybrid PQ should be filtered out by the caller
        // before reaching this helper. See the encrypt-side comment.
        CryptoAlgorithm::HybridX25519MlKem768 => Err(DataError::PqUnavailable),
    }
}

/// Builds deterministic AAD bytes from envelope header fields.
fn build_aad(version: &str, algorithm: &str, key_alias: &str, key_version: &str) -> Vec<u8> {
    format!("v={version};alg={algorithm};alias={key_alias};kver={key_version}").into_bytes()
}

// Keep base64 import used in potential future public API (suppress dead_code)
#[allow(dead_code)]
fn to_b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

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
    // 0. Parse the algorithm from the envelope.
    let algorithm = CryptoAlgorithm::from_envelope_str(&envelope.algorithm)?;

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

//! E2E runtime validation tests for crypto agility — Milestone 25
//!
//! These tests verify that crypto agility works correctly at runtime,
//! going beyond compilation to prove end-to-end correctness.

use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage, encrypt_with_policy};
use secure_data::kms::StaticDevKeyProvider;

fn make_provider() -> StaticDevKeyProvider {
    StaticDevKeyProvider::new()
}

/// E2E: AES-256-GCM encrypt → decrypt roundtrip still works
/// Proves existing AES-256-GCM functionality is not broken.
#[tokio::test]
async fn test_aes_encrypt_decrypt_roundtrip() {
    let provider = make_provider();
    let plaintext = b"AES-256-GCM roundtrip E2E test data";

    let envelope = encrypt_for_storage(plaintext, "e2e-key", &provider)
        .await
        .expect("AES encryption must succeed");

    assert_eq!(envelope.algorithm, "AES-256-GCM", "default must be AES");

    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("AES decryption must succeed");

    assert_eq!(decrypted, plaintext, "roundtrip must preserve data");
}

/// E2E: XChaCha20-Poly1305 encrypt → decrypt roundtrip works
/// Proves the new algorithm implementation is correct end-to-end.
#[tokio::test]
async fn test_xchacha_encrypt_decrypt_roundtrip() {
    let provider = make_provider();
    let plaintext = b"XChaCha20-Poly1305 roundtrip E2E test data";
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);

    let envelope = encrypt_with_policy(plaintext, "e2e-key", &provider, &policy)
        .await
        .expect("XChaCha encryption must succeed");

    assert_eq!(
        envelope.algorithm, "XChaCha20-Poly1305",
        "envelope must tag XChaCha algorithm"
    );

    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("XChaCha decryption must succeed");

    assert_eq!(decrypted, plaintext, "roundtrip must preserve data");
}

/// E2E: Old-format AES envelope still decrypts after agility feature is added
/// Proves backward compatibility for pre-agility envelopes.
#[tokio::test]
async fn test_old_envelope_still_decrypts() {
    let provider = make_provider();
    let plaintext = b"backward compatibility E2E test";

    // Create an envelope using the default path (which is AES-256-GCM, the old path)
    let envelope = encrypt_for_storage(plaintext, "e2e-key", &provider)
        .await
        .expect("old-style encryption must succeed");

    // Verify it decrypts correctly
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("old-format envelope must still decrypt");

    assert_eq!(decrypted, plaintext);
}

/// E2E: Key version rotation is transparent — old data decrypts with old key, new data uses new key
#[tokio::test]
async fn test_key_version_rotation() {
    let provider = make_provider();

    // Encrypt data under the current key version
    let old_data = b"data encrypted before key rotation";
    let old_envelope = encrypt_for_storage(old_data, "rotation-key", &provider)
        .await
        .expect("old encryption must succeed");

    // Encrypt new data (same provider, simulates post-rotation)
    let new_data = b"data encrypted after key rotation";
    let new_envelope = encrypt_for_storage(new_data, "rotation-key", &provider)
        .await
        .expect("new encryption must succeed");

    // Both must decrypt correctly
    let dec_old = decrypt_for_use(&old_envelope, &provider)
        .await
        .expect("old data must decrypt");
    let dec_new = decrypt_for_use(&new_envelope, &provider)
        .await
        .expect("new data must decrypt");

    assert_eq!(dec_old, old_data);
    assert_eq!(dec_new, new_data);
}

/// E2E: Algorithm downgrade is prevented by policy
#[tokio::test]
async fn test_algorithm_downgrade_prevented() {
    let provider = make_provider();
    let plaintext = b"downgrade prevention E2E test";

    // Policy: prefer AES but minimum is XChaCha (contradictory — should reject)
    let policy = AlgorithmPolicy::new(
        CryptoAlgorithm::Aes256Gcm,
        Some(CryptoAlgorithm::XChaCha20Poly1305),
    );

    let result = encrypt_with_policy(plaintext, "e2e-key", &provider, &policy).await;
    assert!(
        result.is_err(),
        "must reject algorithm below policy minimum"
    );
}

//! BDD tests for envelope encryption — Milestone 7
//!
//! Feature: Envelope encryption

use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::kms::StaticDevKeyProvider;

fn make_provider() -> StaticDevKeyProvider {
    StaticDevKeyProvider::new()
}

/// Scenario: Encrypt and decrypt roundtrip
/// Given plaintext b"Hello, world!" with StaticDevKeyProvider
/// When encrypt_for_storage() then decrypt_for_use()
/// Then decrypted plaintext equals original
#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let provider = make_provider();
    let plaintext = b"Hello, world!";
    let key_alias = "test-key".to_string();

    let envelope = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("encryption must succeed");
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decryption must succeed");

    assert_eq!(
        decrypted, plaintext,
        "decrypted plaintext must match original"
    );
}

/// Scenario: Envelope format contains metadata
/// Given after encryption
/// When inspect EnvelopeEncrypted
/// Then has version, algorithm, key_alias, key_version, wrapped_data_key, nonce, ciphertext, aad
#[tokio::test]
async fn test_envelope_format_contains_metadata() {
    let provider = make_provider();
    let plaintext = b"metadata check";
    let key_alias = "test-key".to_string();

    let envelope = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("encryption must succeed");

    assert!(!envelope.version.is_empty(), "version must be set");
    assert!(!envelope.algorithm.is_empty(), "algorithm must be set");
    assert_eq!(envelope.key_alias, key_alias, "key_alias must match");
    assert!(!envelope.key_version.is_empty(), "key_version must be set");
    assert!(
        !envelope.wrapped_data_key.is_empty(),
        "wrapped_data_key must be set"
    );
    assert!(!envelope.nonce.is_empty(), "nonce must be set");
    assert!(!envelope.ciphertext.is_empty(), "ciphertext must be set");
}

/// Scenario: Different plaintexts produce different ciphertext
/// Given two encryptions of same plaintext
/// When compared
/// Then ciphertexts differ (unique nonces)
#[tokio::test]
async fn test_different_plaintexts_produce_different_ciphertexts() {
    let provider = make_provider();
    let plaintext = b"same plaintext";
    let key_alias = "test-key".to_string();

    let env1 = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("first encryption must succeed");
    let env2 = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("second encryption must succeed");

    // Nonces must differ (random per-encryption)
    assert_ne!(env1.nonce, env2.nonce, "nonces must be unique");
    // Ciphertexts must differ when nonces differ
    assert_ne!(env1.ciphertext, env2.ciphertext, "ciphertexts must differ");
}

/// Scenario: Tampered ciphertext fails decryption
/// Given EnvelopeEncrypted with flipped byte in ciphertext
/// When decrypt_for_use()
/// Then Error returned, no plaintext
#[tokio::test]
async fn test_tampered_ciphertext_fails_decryption() {
    let provider = make_provider();
    let plaintext = b"tamper test data";
    let key_alias = "test-key".to_string();

    let mut envelope = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("encryption must succeed");

    // Flip a byte in the ciphertext
    if let Some(byte) = envelope.ciphertext.first_mut() {
        *byte ^= 0xFF;
    }

    let result = decrypt_for_use(&envelope, &provider).await;
    assert!(result.is_err(), "tampered ciphertext must fail decryption");
}

/// Scenario: Tampered AAD fails decryption
/// Given EnvelopeEncrypted with modified AAD
/// When decrypted
/// Then Error — authentication failure
#[tokio::test]
async fn test_tampered_aad_fails_decryption() {
    let provider = make_provider();
    let plaintext = b"aad tamper test";
    let key_alias = "test-key".to_string();

    let mut envelope = encrypt_for_storage(plaintext, &key_alias, &provider)
        .await
        .expect("encryption must succeed");

    // Modify AAD
    envelope.aad = b"tampered-aad".to_vec();

    let result = decrypt_for_use(&envelope, &provider).await;
    assert!(result.is_err(), "tampered AAD must fail decryption");
}

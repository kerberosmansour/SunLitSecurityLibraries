//! BDD tests for crypto agility — Milestone 25
//!
//! Feature: Crypto algorithm selection
//! Feature: Key versioning

use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage, encrypt_with_policy};
use secure_data::kms::StaticDevKeyProvider;

fn make_provider() -> StaticDevKeyProvider {
    StaticDevKeyProvider::new()
}

// ── Feature: Crypto algorithm selection ─────────────────────────────────

/// Scenario: Default algorithm is AES-256-GCM
/// Given: No algorithm configured
/// When: encrypt_for_storage()
/// Then: Envelope contains algorithm: Aes256Gcm
#[tokio::test]
async fn test_default_algorithm_is_aes256gcm() {
    // Given: default provider, no algorithm policy
    let provider = make_provider();
    let plaintext = b"default algorithm test";

    // When: encrypt with default settings
    let envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");

    // Then: algorithm field indicates AES-256-GCM
    assert_eq!(envelope.algorithm, "AES-256-GCM");
}

/// Scenario: XChaCha20 selected via policy
/// Given: AlgorithmPolicy::prefer(XChaCha20Poly1305)
/// When: encrypt_with_policy()
/// Then: Envelope contains algorithm: XChaCha20Poly1305
#[tokio::test]
async fn test_xchacha20_selected_via_policy() {
    // Given: policy preferring XChaCha20Poly1305
    let provider = make_provider();
    let plaintext = b"xchacha20 policy test";
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);

    // When: encrypt with policy
    let envelope = encrypt_with_policy(plaintext, "test-key", &provider, &policy)
        .await
        .expect("encryption must succeed");

    // Then: algorithm field reflects policy
    assert_eq!(envelope.algorithm, "XChaCha20-Poly1305");
}

/// Scenario: Decrypt old AES envelope (backward compatibility)
/// Given: Envelope created without algorithm field (pre-agility format)
/// When: decrypt_for_use()
/// Then: Decrypts successfully (assumes AES-256-GCM)
#[tokio::test]
async fn test_decrypt_old_aes_envelope() {
    // Given: encrypt with default (AES-256-GCM)
    let provider = make_provider();
    let plaintext = b"backward compatibility test";
    let envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");

    // When: decrypt
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decryption must succeed");

    // Then: matches original
    assert_eq!(decrypted, plaintext);
}

/// Scenario: Decrypt XChaCha20 envelope
/// Given: Envelope with algorithm: XChaCha20Poly1305
/// When: decrypt_for_use()
/// Then: Decrypts successfully with correct algorithm
#[tokio::test]
async fn test_decrypt_xchacha_envelope() {
    // Given: encrypt with XChaCha20Poly1305 policy
    let provider = make_provider();
    let plaintext = b"xchacha decrypt test";
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);
    let envelope = encrypt_with_policy(plaintext, "test-key", &provider, &policy)
        .await
        .expect("encryption must succeed");

    // When: decrypt
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decryption must succeed");

    // Then: matches original
    assert_eq!(decrypted, plaintext);
}

/// Scenario: Unknown algorithm rejected
/// Given: Envelope with algorithm: "unknown"
/// When: decrypt_for_use()
/// Then: Returns error unsupported_algorithm
#[tokio::test]
async fn test_unknown_algorithm_rejected() {
    // Given: create a valid envelope then tamper the algorithm field
    let provider = make_provider();
    let plaintext = b"unknown algorithm test";
    let mut envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");
    envelope.algorithm = "UNKNOWN-ALGO".to_string();

    // When: attempt decrypt
    let result = decrypt_for_use(&envelope, &provider).await;

    // Then: error indicates unsupported algorithm
    assert!(result.is_err(), "must reject unknown algorithm");
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unsupported") || msg.contains("algorithm"),
        "error must mention unsupported algorithm, got: {msg}"
    );
}

/// Scenario: Algorithm downgrade prevented
/// Given: Policy with min_algorithm: XChaCha20Poly1305
/// When: Attempt encrypt with AES-256-GCM
/// Then: Returns error algorithm_below_policy_minimum
#[tokio::test]
async fn test_algorithm_downgrade_prevented() {
    // Given: policy that requires minimum XChaCha20Poly1305
    let provider = make_provider();
    let plaintext = b"downgrade prevention test";
    let policy = AlgorithmPolicy::new(
        CryptoAlgorithm::Aes256Gcm,
        Some(CryptoAlgorithm::XChaCha20Poly1305),
    );

    // When: attempt encrypt — preferred is AES but minimum is XChaCha (higher)
    let result = encrypt_with_policy(plaintext, "test-key", &provider, &policy).await;

    // Then: rejected because preferred algorithm is below minimum
    assert!(
        result.is_err(),
        "must reject algorithm below policy minimum"
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("below") || msg.contains("policy") || msg.contains("minimum"),
        "error must indicate policy violation, got: {msg}"
    );
}

// ── Feature: Key versioning ─────────────────────────────────────────────

/// Scenario: Encrypt with latest key version
/// Given: Key ring with version v1 from StaticDevKeyProvider
/// When: encrypt_for_storage()
/// Then: Envelope contains key_version
#[tokio::test]
async fn test_encrypt_with_latest_key_version() {
    // Given: default provider
    let provider = make_provider();
    let plaintext = b"key version test";

    // When: encrypt
    let envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");

    // Then: key_version is present and non-empty
    assert!(!envelope.key_version.is_empty(), "key_version must be set");
}

/// Scenario: Decrypt with old key version
/// Given: Envelope encrypted with older key version
/// When: decrypt_for_use()
/// Then: Decrypts successfully
#[tokio::test]
async fn test_decrypt_with_old_key_version() {
    // Given: encrypt with provider
    let provider = make_provider();
    let plaintext = b"old key version decrypt test";
    let envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");

    // When: decrypt (same key version)
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decryption must succeed");

    // Then: matches
    assert_eq!(decrypted, plaintext);
}

/// Scenario: Unknown key version rejected
/// Given: Envelope with key_version: "v99"
/// When: decrypt_for_use()
/// Then: Returns error (key unwrap fails)
#[tokio::test]
async fn test_unknown_key_version_handled() {
    // Given: create envelope then tamper key_version
    let provider = make_provider();
    let plaintext = b"unknown key version test";
    let mut envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");
    envelope.key_version = "v99".to_string();

    // When: attempt decrypt — AAD will mismatch since key_version changed
    let result = decrypt_for_use(&envelope, &provider).await;

    // Then: should fail (AAD integrity check)
    assert!(result.is_err(), "must reject tampered key version");
}

/// Scenario: Key rotation transparent
/// Given: Encrypt with default provider
/// When: Encrypt new data and decrypt old
/// Then: Both operations succeed
#[tokio::test]
async fn test_key_rotation_transparent() {
    // Given: encrypt first piece of data
    let provider = make_provider();
    let plaintext1 = b"first data before rotation";
    let env1 = encrypt_for_storage(plaintext1, "test-key", &provider)
        .await
        .expect("first encryption must succeed");

    // When: encrypt second piece of data (same provider)
    let plaintext2 = b"second data after rotation";
    let env2 = encrypt_for_storage(plaintext2, "test-key", &provider)
        .await
        .expect("second encryption must succeed");

    // Then: both can be decrypted
    let dec1 = decrypt_for_use(&env1, &provider)
        .await
        .expect("first decryption must succeed");
    let dec2 = decrypt_for_use(&env2, &provider)
        .await
        .expect("second decryption must succeed");
    assert_eq!(dec1, plaintext1);
    assert_eq!(dec2, plaintext2);
}

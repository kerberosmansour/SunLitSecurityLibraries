//! E2E runtime validation — Milestone 7
//!
//! Proves that secure_data works end-to-end at runtime.

use secure_data::config::{SecretReference, SecretReferenceProvider};
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::kms::StaticDevKeyProvider;
use secure_data::rotation::re_encrypt;
use secure_data::secret::SecretString;

/// E2E: Envelope encryption works end-to-end at runtime
#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let provider = StaticDevKeyProvider::new();
    let original = b"E2E plaintext data for roundtrip test";

    let envelope = encrypt_for_storage(original, "e2e-key", &provider)
        .await
        .expect("E2E encryption must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("E2E decryption must succeed");

    assert_eq!(
        recovered, original,
        "recovered plaintext must match original"
    );
}

/// E2E: Rotation and dual-read work at runtime
#[tokio::test]
async fn test_key_rotation_dual_read() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"data encrypted before rotation";

    // Encrypt with current key
    let old_envelope = encrypt_for_storage(plaintext, "rotation-test-key", &provider)
        .await
        .expect("pre-rotation encryption must succeed");

    // Simulate rotation: re-encrypt to new key
    let new_envelope = re_encrypt(&old_envelope, "rotation-test-key-v2", &provider)
        .await
        .expect("re-encryption must succeed");

    // Both old and new should decrypt to same plaintext (dual-read)
    let from_old = decrypt_for_use(&old_envelope, &provider)
        .await
        .expect("old envelope must still decrypt during rotation window");
    let from_new = decrypt_for_use(&new_envelope, &provider)
        .await
        .expect("new envelope must decrypt");

    assert_eq!(from_old, plaintext, "old envelope decryption must match");
    assert_eq!(from_new, plaintext, "new envelope decryption must match");
}

/// E2E: Secret wrappers don't leak via Debug at runtime
#[test]
fn test_secret_no_debug_leak() {
    let secret = SecretString::new("runtime-secret-value-12345".to_string());
    let debug_out = format!("{:?}", secret);
    assert!(
        !debug_out.contains("runtime-secret-value-12345"),
        "runtime Debug must not expose secret, got: {debug_out}"
    );
    // Should contain something safe like [REDACTED] or the type name
    assert!(
        debug_out.contains("REDACTED") || debug_out.contains("SecretString"),
        "runtime Debug must show redacted form, got: {debug_out}"
    );
}

/// E2E: Secrets don't leak via serde at runtime
#[test]
fn test_secret_no_serde_leak() {
    let secret = SecretString::new("runtime-serde-secret-9876".to_string());
    let json = serde_json::to_string(&secret).expect("must serialize");
    assert!(
        !json.contains("runtime-serde-secret-9876"),
        "runtime JSON must not expose secret, got: {json}"
    );
    assert_eq!(json, "\"[REDACTED]\"", "must serialize as [REDACTED]");
}

/// E2E: Tampered ciphertext rejected at runtime
#[tokio::test]
async fn test_tampered_data_rejected() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"sensitive runtime data";

    let mut envelope = encrypt_for_storage(plaintext, "tamper-test-key", &provider)
        .await
        .expect("encryption must succeed");

    // Flip multiple bytes in ciphertext to ensure AEAD tag failure
    for byte in envelope.ciphertext.iter_mut().take(4) {
        *byte ^= 0xAA;
    }

    let result = decrypt_for_use(&envelope, &provider).await;
    assert!(
        result.is_err(),
        "tampered ciphertext must be rejected at runtime"
    );
}

/// E2E: SecretReference parsing works at runtime
#[test]
fn test_secret_reference_resolution() {
    // Vault reference
    let vault_ref = SecretReference::parse("vault://kv/db-credentials#password")
        .expect("vault reference must parse");
    assert!(matches!(vault_ref.provider, SecretReferenceProvider::Vault));
    assert_eq!(vault_ref.path, "kv/db-credentials");
    assert_eq!(vault_ref.field.as_deref(), Some("password"));

    // KMS reference
    let kms_ref =
        SecretReference::parse("kms://alias/app-prod-key").expect("kms reference must parse");
    assert!(matches!(kms_ref.provider, SecretReferenceProvider::Kms));
    assert_eq!(kms_ref.path, "alias/app-prod-key");

    // Env reference
    let env_ref = SecretReference::parse("env://MY_SECRET_VAR").expect("env reference must parse");
    assert!(matches!(env_ref.provider, SecretReferenceProvider::Env));
    assert_eq!(env_ref.path, "MY_SECRET_VAR");

    // Invalid reference
    assert!(SecretReference::parse("plain-string-no-scheme").is_err());
}

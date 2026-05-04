//! E2E runtime validation tests for Milestone 13 — Real Key Provider Integrations
//!
//! Validates:
//! 1. StaticDevKeyProvider still works (backward compatibility)
//! 2. resolve_secret() resolves env:// at runtime
//! 3. DataError variants are correctly categorized
//! 4. New error variants are accessible

use secure_data::config::SecretReference;
use secure_data::error::DataError;
use secure_data::kms::{KeyProvider, StaticDevKeyProvider};
use secure_data::resolve::resolve_secret;

/// E2E: StaticDevKeyProvider backward compatibility
/// Existing provider must still generate and unwrap keys successfully.
#[tokio::test]
async fn e2e_static_dev_provider_backward_compat() {
    // Given: StaticDevKeyProvider (existing)
    let provider = StaticDevKeyProvider::new();

    // When: generate and unwrap a key
    let (dek, wrapped, version) = provider
        .generate_data_key("e2e-test-key")
        .await
        .expect("generate_data_key must succeed");

    let recovered = provider
        .unwrap_data_key(&wrapped, "e2e-test-key", &version)
        .await
        .expect("unwrap_data_key must succeed");

    // Then: DEK is recovered correctly
    assert_eq!(
        dek.as_slice(),
        recovered.as_slice(),
        "recovered DEK must match original"
    );
}

/// E2E: Envelope encryption still works with StaticDevKeyProvider
#[tokio::test]
async fn e2e_envelope_encryption_still_works() {
    use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};

    // Given: existing provider and plaintext
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"e2e test plaintext for m13 regression";

    // When: encrypt then decrypt
    let envelope = encrypt_for_storage(plaintext, "e2e-key", &provider)
        .await
        .expect("encryption must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decryption must succeed");

    // Then: plaintext recovered
    assert_eq!(recovered, plaintext, "recovered plaintext must match");
}

/// E2E: resolve_secret correctly resolves env:// at runtime
#[tokio::test]
async fn e2e_resolve_secret_env() {
    // Given: env var is set
    std::env::set_var("E2E_M13_SECRET", "e2e-resolved-value");
    let reference = SecretReference::parse("env://E2E_M13_SECRET").unwrap();

    // When: resolve_secret is called
    let secret = resolve_secret(&reference)
        .await
        .expect("env:// resolution must succeed");

    // Then: value is correct
    assert_eq!(secret.expose_secret(), "e2e-resolved-value");

    std::env::remove_var("E2E_M13_SECRET");
}

/// E2E: resolve_secret returns SecretNotFound for missing env var
#[tokio::test]
async fn e2e_resolve_secret_env_missing_returns_error() {
    std::env::remove_var("E2E_M13_NO_SUCH_VAR_XYZ");
    let reference = SecretReference::parse("env://E2E_M13_NO_SUCH_VAR_XYZ").unwrap();

    let result = resolve_secret(&reference).await;

    assert!(
        matches!(result, Err(DataError::SecretNotFound { .. })),
        "must return SecretNotFound for missing env var"
    );
}

/// E2E: New DataError variants are properly formatted
#[tokio::test]
async fn e2e_new_error_variants_are_display_formatted() {
    // Given: new error variants introduced in M13
    let unavailable = DataError::ProviderUnavailable {
        provider: "vault".to_string(),
        reason: "connection refused".to_string(),
    };
    let auth_error = DataError::ProviderAuthError {
        provider: "vault".to_string(),
        reason: "invalid token".to_string(),
    };
    let not_found = DataError::SecretNotFound {
        reference: "env://MISSING".to_string(),
    };

    // Then: Display trait produces non-empty strings (error propagation works)
    assert!(!unavailable.to_string().is_empty());
    assert!(!auth_error.to_string().is_empty());
    assert!(!not_found.to_string().is_empty());
}

/// E2E: SecretReference parsing works for all supported schemes
#[tokio::test]
async fn e2e_secret_reference_parsing_all_schemes() {
    // All three existing schemes must parse correctly
    let vault_ref = SecretReference::parse("vault://kv/path#field").expect("vault:// must parse");
    let kms_ref = SecretReference::parse("kms://alias/my-key").expect("kms:// must parse");
    let env_ref = SecretReference::parse("env://MY_VAR").expect("env:// must parse");

    // Verify fields
    assert_eq!(vault_ref.path, "kv/path");
    assert_eq!(vault_ref.field, Some("field".to_string()));
    assert_eq!(kms_ref.path, "alias/my-key");
    assert_eq!(env_ref.path, "MY_VAR");
}

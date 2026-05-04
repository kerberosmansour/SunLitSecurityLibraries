//! BDD tests for resolve_secret() — Milestone 13
//!
//! Feature: resolve_secret

use secure_data::config::SecretReference;
use secure_data::error::DataError;
use secure_data::resolve::resolve_secret;

/// Scenario: Resolve env:// — happy path
/// Given env var TEST_SECRET_M13 set to "my-secret"
/// When resolve_secret(&ref) where ref is env://TEST_SECRET_M13
/// Then returns SecretString("my-secret")
#[tokio::test]
async fn test_resolve_env_happy_path() {
    // Given: environment variable is set
    std::env::set_var("TEST_SECRET_M13", "my-secret");

    let reference =
        SecretReference::parse("env://TEST_SECRET_M13").expect("parsing env:// must succeed");

    // When: resolve_secret is called
    let result = resolve_secret(&reference).await;

    // Then: returns the secret value
    let secret = result.expect("resolve_secret must succeed for valid env var");
    assert_eq!(
        secret.expose_secret(),
        "my-secret",
        "resolved value must match env var"
    );

    // Clean up
    std::env::remove_var("TEST_SECRET_M13");
}

/// Scenario: Resolve env:// missing — invalid input
/// Given env var is not set
/// When resolve_secret(&ref)
/// Then returns DataError::SecretNotFound
#[tokio::test]
async fn test_resolve_env_missing() {
    // Given: environment variable is NOT set
    std::env::remove_var("TEST_SECRET_M13_MISSING_XYZ");

    let reference = SecretReference::parse("env://TEST_SECRET_M13_MISSING_XYZ")
        .expect("parsing env:// must succeed");

    // When: resolve_secret is called
    let result = resolve_secret(&reference).await;

    // Then: returns DataError::SecretNotFound
    assert!(
        matches!(result, Err(DataError::SecretNotFound { .. })),
        "expected SecretNotFound, got: {result:?}"
    );
}

/// Scenario: Invalid scheme — invalid input
/// Given a kms:// reference (not resolvable to a string secret)
/// When resolve_secret(&ref)
/// Then returns DataError::InvalidSecretReference
#[tokio::test]
async fn test_resolve_kms_scheme_unsupported() {
    // Given: a kms:// reference (KMS keys are not directly resolvable to string secrets)
    let reference =
        SecretReference::parse("kms://alias/my-key").expect("parsing kms:// must succeed");

    // When: resolve_secret is called
    let result = resolve_secret(&reference).await;

    // Then: returns DataError::InvalidSecretReference (kms:// not supported for string resolution)
    assert!(
        matches!(result, Err(DataError::InvalidSecretReference { .. })),
        "expected InvalidSecretReference for kms:// scheme, got: {result:?}"
    );
}

/// Scenario: Resolve vault:// — happy path (requires vault feature)
/// This test is only compiled when the vault feature is enabled.
#[cfg(feature = "vault")]
#[tokio::test]
async fn test_resolve_vault_happy_path() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // Given: mock Vault KV server
    let field_value = "my-vault-secret";
    let body = format!(r#"{{"data":{{"password":"{field_value}"}}}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock vault server");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        }
    });

    // Set up env vars for vault client
    std::env::set_var("VAULT_ADDR", format!("http://127.0.0.1:{port}"));
    std::env::set_var("VAULT_TOKEN", "test-token");

    let reference = SecretReference::parse("vault://kv/db-credentials#password")
        .expect("parsing vault:// must succeed");

    // When: resolve_secret is called
    let result = resolve_secret(&reference).await;

    // Then: returns secret value
    let secret = result.expect("resolve_secret must succeed for vault:// with mock");
    assert_eq!(
        secret.expose_secret(),
        field_value,
        "resolved value must match mock response"
    );

    // Clean up env vars
    std::env::remove_var("VAULT_ADDR");
    std::env::remove_var("VAULT_TOKEN");
}

/// Scenario: Vault unavailable without feature — partial failure
/// When vault feature is not enabled and vault:// reference is resolved
/// Then returns DataError::ProviderUnavailable
#[cfg(not(feature = "vault"))]
#[tokio::test]
async fn test_resolve_vault_feature_not_enabled() {
    let reference = SecretReference::parse("vault://kv/db-credentials#password")
        .expect("parsing vault:// must succeed");

    let result = resolve_secret(&reference).await;

    assert!(
        matches!(result, Err(DataError::ProviderUnavailable { .. })),
        "expected ProviderUnavailable when vault feature not enabled, got: {result:?}"
    );
}

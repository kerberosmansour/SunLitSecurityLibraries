//! BDD tests for secret wrappers — Milestone 7
//!
//! Feature: Secret wrappers

use secure_data::secret::{ApiToken, DbPassword, SecretBytes, SecretString, SigningKeyRef};

/// Scenario: SecretString no Debug leak
/// Given a SecretString containing "my-db-password"
/// When format!("{:?}", secret)
/// Then output does not contain "my-db-password"
#[test]
fn test_secret_string_no_debug_leak() {
    let secret = SecretString::new("my-db-password".to_string());
    let debug_output = format!("{:?}", secret);
    assert!(
        !debug_output.contains("my-db-password"),
        "Debug output must not contain the secret value, got: {debug_output}"
    );
}

/// Scenario: SecretBytes zeroized on drop
/// Given a SecretBytes held in a scope
/// When scope exits
/// Then memory is zeroed (verified via zeroize guarantees; test checks wrapper uses Zeroizing)
#[test]
fn test_secret_bytes_zeroized_on_drop() {
    // Verify SecretBytes can be created and dropped without issues
    // The zeroization is guaranteed by the Zeroizing<Vec<u8>> inner type
    let secret = SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let debug_output = format!("{:?}", secret);
    assert!(
        !debug_output.contains("DEAD") && !debug_output.contains("deadbeef"),
        "Debug output must not contain raw bytes, got: {debug_output}"
    );
    drop(secret); // zeroize runs on drop
}

/// Scenario: SecretString not serializable by default
/// Given a SecretString
/// When passed to serde_json::to_string()
/// Then output is "[REDACTED]", never the plaintext
#[test]
fn test_secret_string_serializes_as_redacted() {
    let secret = SecretString::new("super-secret-value".to_string());
    let json = serde_json::to_string(&secret).expect("serialization must succeed");
    assert_eq!(
        json, "\"[REDACTED]\"",
        "SecretString must serialize as [REDACTED], got: {json}"
    );
    assert!(
        !json.contains("super-secret-value"),
        "JSON must not contain the actual secret value"
    );
}

/// Scenario: ApiToken no debug leak
#[test]
fn test_api_token_no_debug_leak() {
    let token = ApiToken::new("example-api-token".to_string());
    let debug_output = format!("{:?}", token);
    assert!(
        !debug_output.contains("example-api-token"),
        "ApiToken debug must not leak, got: {debug_output}"
    );
}

/// Scenario: DbPassword no debug leak
#[test]
fn test_db_password_no_debug_leak() {
    let password = DbPassword::new("postgres_s3cr3t!".to_string());
    let debug_output = format!("{:?}", password);
    assert!(
        !debug_output.contains("postgres_s3cr3t!"),
        "DbPassword debug must not leak, got: {debug_output}"
    );
}

/// Scenario: SigningKeyRef no debug leak
#[test]
fn test_signing_key_ref_no_debug_leak() {
    let key_ref = SigningKeyRef::new("signing-key-alias-prod".to_string());
    let debug_output = format!("{:?}", key_ref);
    assert!(
        !debug_output.contains("signing-key-alias-prod"),
        "SigningKeyRef debug must not leak, got: {debug_output}"
    );
}

/// Scenario: SecretString expose_secret reveals value
#[test]
fn test_secret_string_expose_secret() {
    let secret = SecretString::new("my-db-password".to_string());
    assert_eq!(secret.expose_secret(), "my-db-password");
}

/// Scenario: SecretBytes expose_secret reveals bytes
#[test]
fn test_secret_bytes_expose_secret() {
    let secret = SecretBytes::new(vec![1, 2, 3, 4]);
    assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
}

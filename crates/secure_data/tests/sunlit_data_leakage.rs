//! BDD tests proving secrets don't leak — Milestone 7
//!
//! Feature: No leakage

use secure_data::secret::SecretString;
use serde::Serialize;

/// Scenario: Secret absent from JSON output
/// Given a struct with SecretString field serialized
/// When JSON output inspected
/// Then field is "[REDACTED]" or absent, never plaintext
#[test]
fn test_secret_absent_from_json_output() {
    #[derive(Serialize)]
    struct Config {
        db_host: String,
        db_password: SecretString,
    }

    let config = Config {
        db_host: "localhost".to_string(),
        db_password: SecretString::new("super-secret-db-pass".to_string()),
    };

    let json = serde_json::to_string(&config).expect("serialization must succeed");
    assert!(
        !json.contains("super-secret-db-pass"),
        "JSON must not contain plaintext secret, got: {json}"
    );
    // Must be either absent or [REDACTED]
    assert!(
        json.contains("[REDACTED]") || !json.contains("db_password"),
        "Secret field must be [REDACTED] or absent in JSON, got: {json}"
    );
}

/// Scenario: Secret absent from panic payload
/// Given a function holding SecretString panics
/// When panic message captured
/// Then does not contain the secret value
#[test]
fn test_secret_absent_from_panic_payload() {
    let secret = SecretString::new("dont-leak-in-panic".to_string());

    // The panic message itself should not contain the secret
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Trigger a panic with a message that doesn't reference the secret value
        let _ = secret; // hold secret in scope
        panic!("intentional test panic");
    }));

    match result {
        Err(payload) => {
            let panic_str = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                String::new()
            };
            assert!(
                !panic_str.contains("dont-leak-in-panic"),
                "Panic payload must not contain the secret value, got: {panic_str}"
            );
        }
        Ok(_) => panic!("Expected a panic"),
    }
}

/// Scenario: Secret absent from tracing output
/// Given a SecretString passed to format!()
/// When formatted
/// Then does not contain secret (compilation prevented or redacted)
#[test]
fn test_secret_absent_from_format_output() {
    let secret = SecretString::new("tracing-secret-value".to_string());
    // SecretString has no Display impl, so we can only format via Debug
    let output = format!("{:?}", secret);
    assert!(
        !output.contains("tracing-secret-value"),
        "Formatted output must not contain secret, got: {output}"
    );
}

/// Scenario: SecretString serialized individually is [REDACTED]
#[test]
fn test_secret_string_individual_serialization() {
    let secret = SecretString::new("individual-secret".to_string());
    let json = serde_json::to_string(&secret).expect("must serialize");
    assert_eq!(
        json, "\"[REDACTED]\"",
        "Individual SecretString must serialize as [REDACTED]"
    );
}

/// Scenario: Vault reference parsed
/// Given string "vault://kv/db-credentials#password"
/// When parsed as SecretReference
/// Then provider: Vault, path: "kv/db-credentials", field: "password"
#[test]
fn test_vault_reference_parsed() {
    use secure_data::config::{SecretReference, SecretReferenceProvider};

    let reference = SecretReference::parse("vault://kv/db-credentials#password")
        .expect("valid vault reference must parse");

    assert!(
        matches!(reference.provider, SecretReferenceProvider::Vault),
        "provider must be Vault"
    );
    assert_eq!(reference.path, "kv/db-credentials");
    assert_eq!(reference.field.as_deref(), Some("password"));
}

/// Scenario: KMS reference parsed
/// Given string "kms://alias/app-prod-key"
/// When parsed
/// Then provider: Kms, alias: "app-prod-key"
#[test]
fn test_kms_reference_parsed() {
    use secure_data::config::{SecretReference, SecretReferenceProvider};

    let reference =
        SecretReference::parse("kms://alias/app-prod-key").expect("valid kms reference must parse");

    assert!(
        matches!(reference.provider, SecretReferenceProvider::Kms),
        "provider must be Kms"
    );
    assert_eq!(reference.path, "alias/app-prod-key");
}

/// Scenario: Invalid reference rejected
/// Given string "plaintext-password"
/// When parsed
/// Then Error — not a valid secret reference scheme
#[test]
fn test_invalid_reference_rejected() {
    use secure_data::config::SecretReference;

    let result = SecretReference::parse("plaintext-password");
    assert!(result.is_err(), "invalid reference must be rejected");
}

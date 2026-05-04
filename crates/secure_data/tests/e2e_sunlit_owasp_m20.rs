#![cfg(feature = "password")]

//! E2E runtime validation tests for password hashing (Milestone 20).
//!
//! These tests verify end-to-end behaviour at runtime, going beyond
//! compilation checks to confirm that the password hashing subsystem
//! operates correctly in realistic scenarios.

use secure_data::password::{hash_password, verify_password};
use secure_data::secret::SecretString;

#[test]
fn test_argon2_hash_verify_roundtrip() {
    // Full hash → verify cycle works at runtime
    let password = SecretString::new("e2e-roundtrip-password-123!".to_string());

    let hash = hash_password(&password).expect("hash should succeed at runtime");

    // PHC format validation
    let phc = hash.expose_hash();
    assert!(phc.starts_with("$argon2id$"), "PHC format expected");
    assert!(phc.contains("$v="), "version field expected in PHC string");

    // Verify returns true for correct password
    let verified = verify_password(&password, &hash).expect("verify should succeed");
    assert!(verified, "correct password must verify");
}

#[test]
fn test_argon2_rejects_wrong_password() {
    // Wrong password correctly rejected at runtime
    let password = SecretString::new("the-real-password".to_string());
    let hash = hash_password(&password).expect("hash should succeed");

    let wrong = SecretString::new("not-the-real-password".to_string());
    let result = verify_password(&wrong, &hash).expect("verify should not error");
    assert!(!result, "wrong password must be rejected");
}

#[test]
fn test_password_hash_not_leaked() {
    // Hash value never appears in Debug/Display/JSON
    let password = SecretString::new("leak-test-password".to_string());
    let hash = hash_password(&password).expect("hash should succeed");
    let raw_hash = hash.expose_hash().to_string();

    // Debug
    let debug = format!("{:?}", hash);
    assert!(
        !debug.contains(&raw_hash),
        "Debug must not contain raw hash"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug must contain [REDACTED]"
    );

    // Serialize
    let json = serde_json::to_string(&hash).expect("serde should succeed");
    assert!(!json.contains(&raw_hash), "JSON must not contain raw hash");
    assert_eq!(json, "\"[REDACTED]\"");
}

#[test]
fn test_hash_uniqueness() {
    // Salt randomization works — two hashes of the same password differ
    let password = SecretString::new("uniqueness-test".to_string());

    let hash1 = hash_password(&password).expect("first hash");
    let hash2 = hash_password(&password).expect("second hash");

    assert_ne!(
        hash1.expose_hash(),
        hash2.expose_hash(),
        "hashes must differ due to random salt"
    );

    // Both must still verify
    assert!(verify_password(&password, &hash1).expect("verify 1"));
    assert!(verify_password(&password, &hash2).expect("verify 2"));
}

#![cfg(feature = "password")]

//! BDD acceptance tests for password hashing (Milestone 20).

use secure_data::password::{
    hash_password, verify_password, Argon2Hasher, PasswordError, PasswordHasher,
};
use secure_data::secret::SecretString;

// ── Feature: Password hashing with Argon2id ──────────────────────────────────

#[test]
fn hash_a_password_returns_phc_format() {
    // Given: a plaintext password
    let password = SecretString::new("correct-horse-battery".to_string());

    // When: hashed via hash_password()
    let hash = hash_password(&password).expect("hashing should succeed");

    // Then: returns PasswordHash in PHC format starting with $argon2id$
    assert!(
        hash.expose_hash().starts_with("$argon2id$"),
        "hash should start with $argon2id$, got: {}",
        hash.expose_hash()
    );
}

#[test]
fn verify_correct_password_returns_true() {
    // Given: a hashed password
    let password = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&password).expect("hashing should succeed");

    // When: verified with the same plaintext
    let result = verify_password(&password, &hash).expect("verify should succeed");

    // Then: returns true
    assert!(result, "correct password should verify as true");
}

#[test]
fn verify_wrong_password_returns_false() {
    // Given: a hashed password
    let password = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&password).expect("hashing should succeed");

    // When: verified with a different plaintext
    let wrong = SecretString::new("wrong-password".to_string());
    let result = verify_password(&wrong, &hash).expect("verify should not error");

    // Then: returns false; no error
    assert!(!result, "wrong password should verify as false");
}

#[test]
fn hash_is_unique_per_call() {
    // Given: the same password
    let password = SecretString::new("correct-horse-battery".to_string());

    // When: hashed twice
    let hash1 = hash_password(&password).expect("first hash");
    let hash2 = hash_password(&password).expect("second hash");

    // Then: hashes differ (random salt)
    assert_ne!(
        hash1.expose_hash(),
        hash2.expose_hash(),
        "two hashes of the same password should differ due to random salt"
    );
}

#[test]
fn empty_password_rejected() {
    // Given: an empty password
    let password = SecretString::new(String::new());

    // When: hash_password() is called
    let result = hash_password(&password);

    // Then: returns error with EmptyPassword
    assert!(result.is_err(), "empty password should be rejected");
    let err = result.unwrap_err();
    assert!(
        matches!(err, PasswordError::EmptyPassword),
        "error should be EmptyPassword, got: {err:?}"
    );
}

#[test]
fn password_hash_redacted_in_debug() {
    // Given: a PasswordHash value
    let password = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&password).expect("hashing should succeed");

    // When: formatted with Debug
    let debug_output = format!("{:?}", hash);

    // Then: contains [REDACTED], not the actual hash
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug should contain [REDACTED], got: {debug_output}"
    );
    assert!(
        !debug_output.contains("$argon2id$"),
        "Debug should not contain the raw hash"
    );
}

#[test]
fn password_hash_redacted_in_json() {
    // Given: a PasswordHash value
    let password = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&password).expect("hashing should succeed");

    // When: serialized to JSON
    let json = serde_json::to_string(&hash).expect("serialization should succeed");

    // Then: contains "[REDACTED]"
    assert_eq!(
        json, "\"[REDACTED]\"",
        "JSON should be [REDACTED], got: {json}"
    );
}

#[test]
fn timing_consistency_verify_password() {
    // Given: correct and incorrect passwords
    let password = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&password).expect("hashing should succeed");
    let wrong = SecretString::new("wrong-password-guess".to_string());

    // Warm up to avoid JIT-like effects
    let _ = verify_password(&password, &hash);
    let _ = verify_password(&wrong, &hash);

    // When: measure verification time for correct and incorrect passwords
    let iterations = 5;
    let mut correct_total = std::time::Duration::ZERO;
    let mut wrong_total = std::time::Duration::ZERO;

    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let _ = verify_password(&password, &hash);
        correct_total += start.elapsed();

        let start = std::time::Instant::now();
        let _ = verify_password(&wrong, &hash);
        wrong_total += start.elapsed();
    }

    let correct_avg_ms = correct_total.as_millis() as f64 / iterations as f64;
    let wrong_avg_ms = wrong_total.as_millis() as f64 / iterations as f64;

    // Then: time difference < 20ms (generous bound for CI variability)
    let diff_ms = (correct_avg_ms - wrong_avg_ms).abs();
    assert!(
        diff_ms < 20.0,
        "timing difference should be < 20ms, got {diff_ms:.2}ms \
         (correct avg: {correct_avg_ms:.2}ms, wrong avg: {wrong_avg_ms:.2}ms)"
    );
}

// ── Feature: Trait-based API equivalence ─────────────────────────────────────

#[test]
fn trait_hash_verify_matches_free_functions() {
    // Given: the Argon2Hasher trait implementor
    let hasher = Argon2Hasher::default();
    let password = SecretString::new("trait-test-password".to_string());

    // When: hash via trait
    let hash = hasher
        .hash_password(&password)
        .expect("trait hash should succeed");

    // Then: verify via free function works
    assert!(
        verify_password(&password, &hash).expect("free fn verify should succeed"),
        "free function should verify trait-produced hash"
    );
}

#[test]
fn free_function_hash_verified_by_trait() {
    // Given: a hash produced by the free function
    let password = SecretString::new("cross-verify-test".to_string());
    let hash = hash_password(&password).expect("free fn hash should succeed");

    // When: verified via trait
    let hasher = Argon2Hasher::default();

    // Then: trait verifier accepts it
    assert!(
        hasher
            .verify_password(&password, &hash)
            .expect("trait verify should succeed"),
        "trait should verify free-function-produced hash"
    );
}

#[test]
fn argon2_hasher_rejects_empty_password() {
    // Given: an empty password and the trait impl
    let hasher = Argon2Hasher::default();
    let password = SecretString::new(String::new());

    // When: hash via trait
    let result = hasher.hash_password(&password);

    // Then: returns EmptyPassword error
    assert!(matches!(result.unwrap_err(), PasswordError::EmptyPassword));
}

#[test]
fn password_hash_clone_works() {
    // Given: a PasswordHash
    let password = SecretString::new("clone-test".to_string());
    let hash = hash_password(&password).expect("should hash");

    // When: cloned
    let cloned = hash.clone();

    // Then: clone exposes the same value
    assert_eq!(hash.expose_hash(), cloned.expose_hash());
}

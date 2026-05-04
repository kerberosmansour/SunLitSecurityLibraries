//! BDD tests for data pseudonymization (Milestone 6).

use secure_privacy::pseudonymizer::Pseudonymizer;

// --- Feature: Data Pseudonymization ---

#[test]
fn given_email_with_salt_when_pseudonymized_twice_then_same_value() {
    let ps = Pseudonymizer::new(b"test-salt").unwrap();
    let v1 = ps.pseudonymize("user@example.com");
    let v2 = ps.pseudonymize("user@example.com");
    assert_eq!(v1, v2, "Pseudonymization must be deterministic");
}

#[test]
fn given_same_email_with_different_salts_when_pseudonymized_then_different_values() {
    let ps1 = Pseudonymizer::new(b"salt-one").unwrap();
    let ps2 = Pseudonymizer::new(b"salt-two").unwrap();
    let v1 = ps1.pseudonymize("user@example.com");
    let v2 = ps2.pseudonymize("user@example.com");
    assert_ne!(v1, v2, "Different salts must produce different pseudonyms");
}

#[test]
fn given_pseudonymized_value_when_inspected_then_not_reversible() {
    let ps = Pseudonymizer::new(b"secret-salt").unwrap();
    let pv = ps.pseudonymize("user@example.com");
    // The pseudonym is a hex-encoded HMAC-SHA256 — it should not contain the original
    assert!(
        !pv.value.contains("user@example.com"),
        "Pseudonym must not contain original value"
    );
    assert!(
        !pv.value.contains("user"),
        "Pseudonym must not contain any part of original value"
    );
    // HMAC-SHA256 produces a 64-char hex string
    assert_eq!(
        pv.value.len(),
        64,
        "HMAC-SHA256 hex should be 64 characters"
    );
}

#[test]
fn given_batch_of_identifiers_when_pseudonymized_then_all_processed() {
    let ps = Pseudonymizer::new(b"batch-salt").unwrap();
    let inputs: Vec<&str> = (0..100).map(|_| "test@example.com").collect();
    let results = ps.pseudonymize_batch(&inputs);
    assert_eq!(results.len(), 100);
    // All same input → all same output
    for r in &results {
        assert_eq!(r, &results[0]);
    }
}

#[test]
fn given_empty_salt_when_creating_pseudonymizer_then_error() {
    let result = Pseudonymizer::new(b"");
    assert!(result.is_err());
}

//! BDD acceptance tests for certificate pinning (Milestone 1).

use secure_network::cert_pin::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

fn test_cert_der() -> Vec<u8> {
    include_bytes!("testdata/test_cert.der").to_vec()
}

fn spki_hash_of(cert_der: &[u8]) -> [u8; 32] {
    CertPinValidator::spki_hash(cert_der).expect("valid test cert")
}

// --- Feature: Certificate Pinning ---

/// Scenario: Pinned cert matches SPKI hash
#[test]
fn pinned_cert_matches_spki_hash() {
    let cert_der = test_cert_der();
    let hash = spki_hash_of(&cert_der);

    let mut pin_set = PinSet::new();
    pin_set.add_pin(hash);

    let validator = CertPinValidator::new(pin_set);
    assert_eq!(validator.validate_der(&cert_der), CertPinResult::Valid);
}

/// Scenario: Pinned cert does not match
#[test]
fn pinned_cert_does_not_match() {
    let cert_der = test_cert_der();
    let wrong_hash = [0xFFu8; 32];

    let mut pin_set = PinSet::new();
    pin_set.add_pin(wrong_hash);

    let validator = CertPinValidator::new(pin_set);
    let sink = InMemorySink::new();
    let result = validator.validate_der_and_emit(&cert_der, &sink);

    assert_eq!(result, CertPinResult::PinMismatch);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::CertPinFailure);
    assert_eq!(events[0].reason_code, Some("cert_pin_mismatch"));
}

/// Scenario: Multiple pins — one matches
#[test]
fn multiple_pins_one_matches() {
    let cert_der = test_cert_der();
    let correct_hash = spki_hash_of(&cert_der);

    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAAu8; 32]);
    pin_set.add_pin([0xBBu8; 32]);
    pin_set.add_pin(correct_hash);

    let validator = CertPinValidator::new(pin_set);
    assert_eq!(validator.validate_der(&cert_der), CertPinResult::Valid);
}

/// Scenario: Empty pin set always allows
#[test]
fn empty_pin_set_returns_no_pins_configured() {
    let cert_der = test_cert_der();
    let pin_set = PinSet::new();

    let validator = CertPinValidator::new(pin_set);
    assert_eq!(
        validator.validate_der(&cert_der),
        CertPinResult::NoPinsConfigured
    );
}

/// Scenario: Expired cert detected
/// Uses `validate_der_at` with a time far in the future to simulate expiry.
#[test]
fn expired_cert_detected() {
    let cert_der = test_cert_der();
    let hash = spki_hash_of(&cert_der);

    let mut pin_set = PinSet::new();
    pin_set.add_pin(hash);

    let validator = CertPinValidator::new(pin_set).with_expiry_check(true);

    // Set "now" to year 2099, well past the cert's not_after
    let far_future = time::OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let sink = InMemorySink::new();
    let result = validator.validate_der_at_and_emit(&cert_der, far_future, &sink);

    assert_eq!(result, CertPinResult::Expired);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::CertPinFailure);
    assert_eq!(events[0].reason_code, Some("cert_expired"));
}

/// Scenario: Certificate chain validation
#[test]
fn certificate_chain_validation_with_pinned_leaf() {
    let cert_der = test_cert_der();
    let correct_hash = spki_hash_of(&cert_der);

    let mut pin_set = PinSet::new();
    pin_set.add_pin(correct_hash);

    let validator = CertPinValidator::new(pin_set);
    let chain: Vec<&[u8]> = vec![&cert_der];
    assert_eq!(validator.validate_chain(&chain), CertPinResult::Valid);
}

/// Scenario: Empty chain fails
#[test]
fn empty_chain_fails() {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAAu8; 32]);

    let validator = CertPinValidator::new(pin_set);
    let chain: Vec<&[u8]> = vec![];
    assert_eq!(validator.validate_chain(&chain), CertPinResult::PinMismatch);
}

/// Scenario: PinSet from hex hashes
#[test]
fn pin_set_from_hex_hashes() {
    let hex = "0102030405060708091011121314151617181920212223242526272829303132";
    let pin_set = PinSet::from_hex_hashes(&[hex]).unwrap();
    assert_eq!(pin_set.len(), 1);
}

#[test]
fn pin_set_from_invalid_hex_errors() {
    let result = PinSet::from_hex_hashes(&["not-valid-hex"]);
    assert!(result.is_err());
}

/// Scenario: No event emitted on valid pin match
#[test]
fn no_event_on_valid_pin() {
    let cert_der = test_cert_der();
    let hash = spki_hash_of(&cert_der);

    let mut pin_set = PinSet::new();
    pin_set.add_pin(hash);

    let validator = CertPinValidator::new(pin_set);
    let sink = InMemorySink::new();
    let result = validator.validate_der_and_emit(&cert_der, &sink);

    assert_eq!(result, CertPinResult::Valid);
    assert!(sink.events().is_empty());
}

/// Scenario: Invalid DER data results in PinMismatch
#[test]
fn invalid_der_returns_pin_mismatch() {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAAu8; 32]);

    let validator = CertPinValidator::new(pin_set);
    assert_eq!(
        validator.validate_der(b"not a valid cert"),
        CertPinResult::PinMismatch
    );
}

/// Scenario: spki_hash utility works
#[test]
fn spki_hash_utility() {
    let cert_der = test_cert_der();
    let hash = CertPinValidator::spki_hash(&cert_der).unwrap();
    assert_eq!(hash.len(), 32);
    // Hash should be deterministic
    let hash2 = CertPinValidator::spki_hash(&cert_der).unwrap();
    assert_eq!(hash, hash2);
}

#[test]
fn spki_hash_invalid_der_errors() {
    let result = CertPinValidator::spki_hash(b"invalid");
    assert!(result.is_err());
}

//! CVE regression tests — MASWE-0052: Insecure certificate validation patterns.
//!
//! Milestone 9 — BDD: Certificate pinning validation catches insecure patterns.
use secure_network::{CertPinResult, CertPinValidator, PinSet};

/// MASWE-0052: Empty pin set must reject all certificates.
#[test]
fn maswe_0052_empty_pin_set_rejects() {
    let pin_set = PinSet::new();
    let validator = CertPinValidator::new(pin_set);
    let result = validator.validate_der(b"fake-der-data");
    assert_eq!(
        result,
        CertPinResult::NoPinsConfigured,
        "Empty pin set must return NoPinsConfigured"
    );
}

/// MASWE-0052: Random DER bytes should never match a configured pin.
#[test]
fn maswe_0052_random_der_never_matches() {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAA; 32]);
    let validator = CertPinValidator::new(pin_set);

    // Provide garbage DER data — should result in PinMismatch
    let result = validator.validate_der(b"this-is-not-a-real-certificate");
    assert_eq!(
        result,
        CertPinResult::PinMismatch,
        "Random bytes must not match any configured pin"
    );
}

/// MASWE-0052: Pin matching via PinSet::matches proves the core validation logic.
#[test]
fn maswe_0052_pin_matching_logic() {
    let mut pin_set = PinSet::new();
    let known_hash: [u8; 32] = [0xDE; 32];
    pin_set.add_pin(known_hash);

    assert!(
        pin_set.matches(&known_hash),
        "Pin set must match a previously added hash"
    );

    let unknown_hash: [u8; 32] = [0xBE; 32];
    assert!(
        !pin_set.matches(&unknown_hash),
        "Pin set must not match an unknown hash"
    );
}

/// MASWE-0052: Multiple pins — any match is valid.
#[test]
fn maswe_0052_multiple_pins_any_match() {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0x01; 32]);
    pin_set.add_pin([0x02; 32]);
    pin_set.add_pin([0x03; 32]);

    assert!(pin_set.matches(&[0x02; 32]));
    assert!(!pin_set.matches(&[0x04; 32]));
}

/// MASWE-0052: Validate chain with empty data.
#[test]
fn maswe_0052_empty_chain() {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAA; 32]);
    let validator = CertPinValidator::new(pin_set);

    let result = validator.validate_chain(&[]);
    assert_eq!(
        result,
        CertPinResult::PinMismatch,
        "Empty certificate chain must be rejected"
    );
}

/// MASWE-0052: from_hex_hashes rejects invalid hex.
#[test]
fn maswe_0052_invalid_hex_hash() {
    let result = PinSet::from_hex_hashes(&["not-valid-hex-at-all"]);
    assert!(result.is_err(), "Invalid hex should fail");
}

/// MASWE-0052: from_hex_hashes accepts valid SHA-256 hex strings.
#[test]
fn maswe_0052_valid_hex_hash() {
    let hex_hash = "aa".repeat(32); // 64 hex chars = 32 bytes
    let result = PinSet::from_hex_hashes(&[&hex_hash]);
    assert!(result.is_ok(), "Valid 64-char hex should succeed");
    let pin_set = result.unwrap();
    assert_eq!(pin_set.len(), 1);
}

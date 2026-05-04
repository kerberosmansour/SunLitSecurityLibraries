//! BDD acceptance tests for app integrity verification (Milestone 5).

use secure_resilience::integrity::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

// --- Feature: App Integrity Verification ---

/// Scenario: Valid app signature verified
/// Given `IntegrityCheck` with known-good signing cert hash
/// When App signature matches
/// Then `IntegrityResult::Valid`
#[test]
fn given_known_good_hash_when_signature_matches_then_valid() {
    let expected_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let check = IntegrityCheck::new_signature(expected_hash);

    let result = check.verify(expected_hash);
    assert_eq!(result, IntegrityResult::Valid);
}

/// Scenario: Tampered app signature detected
/// Given `IntegrityCheck` with expected hash
/// When Hash mismatch
/// Then `IntegrityResult::Tampered` + critical security event
#[test]
fn given_expected_hash_when_mismatch_then_tampered_with_event() {
    let sink = InMemorySink::new();
    let expected_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let actual_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let check = IntegrityCheck::new_signature(expected_hash);

    let result = check.verify_with_events(actual_hash, &sink);
    assert_eq!(result, IntegrityResult::Tampered);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::IntegrityViolation);
}

/// Scenario: Sideloaded app detected
/// Given `IntegrityCheck` with store verification
/// When App not from official store
/// Then `IntegrityResult::SideLoaded` + security event
#[test]
fn given_store_verification_when_not_from_store_then_sideloaded() {
    let sink = InMemorySink::new();
    let allowed_stores = vec![
        "com.android.vending".to_string(),
        "com.apple.appstore".to_string(),
    ];
    let check = IntegrityCheck::new_store_verification(allowed_stores);

    let result = check.verify_store_with_events("com.unknown.store", &sink);
    assert_eq!(result, IntegrityResult::SideLoaded);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::IntegrityViolation);
}

/// Scenario: Valid store installation
/// Given `IntegrityCheck` with store verification
/// When App from official store
/// Then `IntegrityResult::Valid`
#[test]
fn given_store_verification_when_from_official_store_then_valid() {
    let sink = InMemorySink::new();
    let allowed_stores = vec![
        "com.android.vending".to_string(),
        "com.apple.appstore".to_string(),
    ];
    let check = IntegrityCheck::new_store_verification(allowed_stores);

    let result = check.verify_store_with_events("com.android.vending", &sink);
    assert_eq!(result, IntegrityResult::Valid);

    let events = sink.events();
    assert!(events.is_empty());
}

/// Scenario: Resource integrity verified
/// Given `IntegrityCheck` with resource hashes
/// When All resources match expected hashes
/// Then `IntegrityResult::Valid`
#[test]
fn given_resource_hashes_when_all_match_then_valid() {
    let mut check = IntegrityCheck::new_resource_integrity();
    check.add_resource_hash("config.xml", "aabbccdd");
    check.add_resource_hash("assets/main.js", "eeff0011");

    let mut actual = std::collections::HashMap::new();
    actual.insert("config.xml".to_string(), "aabbccdd".to_string());
    actual.insert("assets/main.js".to_string(), "eeff0011".to_string());

    let result = check.verify_resources(&actual);
    assert_eq!(result, IntegrityResult::Valid);
}

/// Scenario: Resource integrity tampered
/// Given `IntegrityCheck` with resource hashes
/// When A resource hash mismatches
/// Then `IntegrityResult::Tampered`
#[test]
fn given_resource_hashes_when_mismatch_then_tampered() {
    let sink = InMemorySink::new();
    let mut check = IntegrityCheck::new_resource_integrity();
    check.add_resource_hash("config.xml", "aabbccdd");
    check.add_resource_hash("assets/main.js", "eeff0011");

    let mut actual = std::collections::HashMap::new();
    actual.insert("config.xml".to_string(), "aabbccdd".to_string());
    actual.insert("assets/main.js".to_string(), "tampered!".to_string());

    let result = check.verify_resources_with_events(&actual, &sink);
    assert_eq!(result, IntegrityResult::Tampered);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::IntegrityViolation);
}

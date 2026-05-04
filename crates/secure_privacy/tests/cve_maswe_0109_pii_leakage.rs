//! CVE regression tests — MASWE-0109: PII leakage in log/event data.
//!
//! Milestone 9 — BDD: PII in log and event data detected by classifier.
use secure_privacy::{PiiClassification, PiiClassifier};

/// MASWE-0109: Email addresses in event labels are detected.
#[test]
fn maswe_0109_email_in_event_data() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("user@example.com"),
        PiiClassification::Email,
        "Email must be classified as PII"
    );
}

/// MASWE-0109: Email embedded in larger text is detected.
#[test]
fn maswe_0109_email_in_text() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("Contact john.doe@company.org for details"),
        PiiClassification::Email,
        "Email embedded in text must be detected"
    );
}

/// MASWE-0109: Phone numbers are detected.
#[test]
fn maswe_0109_phone_number() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("+1 555-123-4567"),
        PiiClassification::PhoneNumber,
    );
}

/// MASWE-0109: IP addresses are detected.
#[test]
fn maswe_0109_ip_address() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("Connection from 192.168.1.100"),
        PiiClassification::IpAddress,
    );
}

/// MASWE-0109: Device identifiers (IMEI) are detected.
#[test]
fn maswe_0109_imei_detected() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("Device IMEI: 353456789012345"),
        PiiClassification::DeviceIdentifier,
    );
}

/// MASWE-0109: Safe text has no PII classification.
#[test]
fn maswe_0109_safe_text_no_pii() {
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("Login successful"),
        PiiClassification::None,
    );
}

/// MASWE-0109: Custom PII patterns can be added.
#[test]
fn maswe_0109_custom_pattern() {
    let mut classifier = PiiClassifier::new();
    classifier
        .add_custom_pattern("ssn", r"\d{3}-\d{2}-\d{4}")
        .unwrap();
    assert_eq!(
        classifier.classify("SSN: 123-45-6789"),
        PiiClassification::Custom("ssn".to_string()),
    );
}

/// MASWE-0109: Multiple PII types — email takes priority over IP when present.
#[test]
fn maswe_0109_priority_order() {
    let classifier = PiiClassifier::new();
    // Contains both email and IP — email regex matches first
    let result = classifier.classify("admin@example.com logged in from 192.168.1.1");
    assert_eq!(
        result,
        PiiClassification::Email,
        "Email should be detected first when present alongside IP"
    );
}

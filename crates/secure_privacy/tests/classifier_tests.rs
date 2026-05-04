//! BDD tests for PII classification (Milestone 6).

use secure_privacy::classifier::{PiiClassification, PiiClassifier};

// --- Feature: PII Classification ---

#[test]
fn given_email_address_when_classified_then_returns_email() {
    let classifier = PiiClassifier::new();
    let result = classifier.classify("user@example.com");
    assert_eq!(result, PiiClassification::Email);
}

#[test]
fn given_phone_number_when_classified_then_returns_phone_number() {
    let classifier = PiiClassifier::new();
    let result = classifier.classify("+1-555-0123");
    assert_eq!(result, PiiClassification::PhoneNumber);
}

#[test]
fn given_uuid_when_classified_then_returns_none() {
    let classifier = PiiClassifier::new();
    let result = classifier.classify("550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(result, PiiClassification::None);
}

#[test]
fn given_ip_address_when_classified_then_returns_ip_address() {
    let classifier = PiiClassifier::new();
    let result = classifier.classify("192.168.1.100");
    assert_eq!(result, PiiClassification::IpAddress);
}

#[test]
fn given_imei_when_classified_then_returns_device_identifier() {
    let classifier = PiiClassifier::new();
    // 15-digit IMEI number
    let result = classifier.classify("353456789012345");
    assert_eq!(result, PiiClassification::DeviceIdentifier);
}

#[test]
fn given_custom_pattern_when_classified_then_returns_custom() {
    let mut classifier = PiiClassifier::new();
    // Credit card pattern (simplified)
    classifier
        .add_custom_pattern("credit_card", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")
        .unwrap();
    let result = classifier.classify("4111-1111-1111-1111");
    assert_eq!(result, PiiClassification::Custom("credit_card".to_string()));
}

#[test]
fn given_plain_text_when_classified_then_returns_none() {
    let classifier = PiiClassifier::new();
    let result = classifier.classify("hello world");
    assert_eq!(result, PiiClassification::None);
}

//! E2E runtime validation tests for Milestone 6 — secure_privacy.
//!
//! These tests prove end-to-end integration of PII classification,
//! pseudonymization, consent enforcement, retention checking, and security
//! event emission across the full privacy pipeline.

use secure_privacy::classifier::{PiiClassification, PiiClassifier};
use secure_privacy::consent::{ConsentDecision, ConsentPolicy, ConsentPurpose};
use secure_privacy::pseudonymizer::Pseudonymizer;
use secure_privacy::retention::{RetentionPolicy, RetentionStatus};
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;
use time::{Duration, OffsetDateTime};

/// E2E: Full privacy pipeline — classify PII, pseudonymize it, check consent,
/// verify retention, and confirm correct security events.
#[test]
fn test_privacy_pipeline_classify_pseudonymize_check_consent_and_retention() {
    let sink = InMemorySink::new();

    // 1. Classify input data as PII
    let classifier = PiiClassifier::new();
    let classification = classifier.classify("user@example.com");
    assert_eq!(classification, PiiClassification::Email);

    // 2. Pseudonymize the PII
    let pseudonymizer = Pseudonymizer::new(b"e2e-test-salt").unwrap();
    let pseudonym = pseudonymizer.pseudonymize("user@example.com");
    assert!(!pseudonym.value.contains("user@example.com"));
    assert_eq!(pseudonym.value.len(), 64);

    // 3. Check consent before processing
    let purpose = ConsentPurpose::new("analytics");
    let mut consent = ConsentPolicy::new(purpose.clone());
    consent.grant();
    let decision = consent.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::Allowed);

    // 4. Check retention status
    let retention = RetentionPolicy::new(90, "user_data");
    let now = OffsetDateTime::now_utc();
    let created_at = now - Duration::days(30);
    let status = retention.check_status(created_at, now, &sink);
    assert_eq!(status, RetentionStatus::Active);

    // No events — everything was within policy
    assert!(sink.events().is_empty());
}

/// E2E: Consent denied pipeline — PII classified, consent denied, events emitted.
#[test]
fn test_privacy_pipeline_denied_consent_emits_event() {
    let sink = InMemorySink::new();

    // Classify
    let classifier = PiiClassifier::new();
    assert_eq!(
        classifier.classify("10.0.0.1"),
        PiiClassification::IpAddress
    );

    // Deny consent
    let purpose = ConsentPurpose::new("tracking");
    let mut consent = ConsentPolicy::new(purpose.clone());
    consent.deny();
    let decision = consent.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::Denied);

    // Verify event
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::ConsentViolation);
}

/// E2E: Expired retention pipeline — data past retention emits event.
#[test]
fn test_privacy_pipeline_expired_retention_emits_event() {
    let sink = InMemorySink::new();

    let retention = RetentionPolicy::new(30, "session_data");
    let now = OffsetDateTime::now_utc();
    let created_at = now - Duration::days(60);
    let status = retention.check_status(created_at, now, &sink);
    assert_eq!(status, RetentionStatus::Expired);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::RetentionExpiry);
}

/// E2E: Purpose mismatch — consent for one purpose, used for another.
#[test]
fn test_privacy_pipeline_purpose_mismatch_emits_event() {
    let sink = InMemorySink::new();

    let analytics = ConsentPurpose::new("analytics");
    let marketing = ConsentPurpose::new("marketing");
    let mut consent = ConsentPolicy::new(analytics);
    consent.grant();

    let decision = consent.check_consent(&marketing, &sink);
    assert_eq!(decision, ConsentDecision::PurposeMismatch);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::ConsentViolation);
}

/// E2E: Batch pseudonymization produces deterministic, non-reversible results.
#[test]
fn test_privacy_pipeline_batch_pseudonymization() {
    let pseudonymizer = Pseudonymizer::new(b"batch-e2e-salt").unwrap();
    let inputs = vec!["alice@test.com", "bob@test.com", "alice@test.com"];
    let results = pseudonymizer.pseudonymize_batch(&inputs);

    assert_eq!(results.len(), 3);
    // Same input produces same output
    assert_eq!(results[0], results[2]);
    // Different inputs produce different outputs
    assert_ne!(results[0], results[1]);
}

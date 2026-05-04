//! BDD tests for consent policy (Milestone 6).

use secure_privacy::consent::{ConsentDecision, ConsentPolicy, ConsentPurpose};
use security_events::sink::InMemorySink;

// --- Feature: Consent Policy ---

#[test]
fn given_consent_granted_when_processing_checked_then_allowed() {
    let sink = InMemorySink::new();
    let purpose = ConsentPurpose::new("analytics");
    let mut policy = ConsentPolicy::new(purpose.clone());
    policy.grant();

    let decision = policy.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::Allowed);
    assert!(sink.events().is_empty(), "No event for allowed consent");
}

#[test]
fn given_consent_denied_when_processing_checked_then_denied_with_event() {
    let sink = InMemorySink::new();
    let purpose = ConsentPurpose::new("analytics");
    let mut policy = ConsentPolicy::new(purpose.clone());
    policy.deny();

    let decision = policy.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::Denied);
    assert_eq!(sink.events().len(), 1, "Denial should emit an event");
}

#[test]
fn given_no_consent_record_when_processing_checked_then_not_collected() {
    let sink = InMemorySink::new();
    let purpose = ConsentPurpose::new("analytics");
    let policy = ConsentPolicy::new(purpose.clone());

    let decision = policy.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::NotCollected);
    assert_eq!(sink.events().len(), 1, "NotCollected should emit an event");
}

#[test]
fn given_consent_granted_then_withdrawn_when_processing_checked_then_withdrawn() {
    let sink = InMemorySink::new();
    let purpose = ConsentPurpose::new("analytics");
    let mut policy = ConsentPolicy::new(purpose.clone());
    policy.grant();
    policy.withdraw();

    let decision = policy.check_consent(&purpose, &sink);
    assert_eq!(decision, ConsentDecision::Withdrawn);
    assert_eq!(sink.events().len(), 1, "Withdrawal should emit an event");
}

#[test]
fn given_consent_for_analytics_when_used_for_marketing_then_purpose_mismatch() {
    let sink = InMemorySink::new();
    let analytics = ConsentPurpose::new("analytics");
    let marketing = ConsentPurpose::new("marketing");
    let mut policy = ConsentPolicy::new(analytics);
    policy.grant();

    let decision = policy.check_consent(&marketing, &sink);
    assert_eq!(decision, ConsentDecision::PurposeMismatch);
    assert_eq!(
        sink.events().len(),
        1,
        "Purpose mismatch should emit an event"
    );
}

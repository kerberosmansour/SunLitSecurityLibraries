//! BDD tests for data retention policy (Milestone 6).

use secure_privacy::retention::{check_no_policy, RetentionPolicy, RetentionStatus};
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;
use time::{Duration, OffsetDateTime};

// --- Feature: Data Retention Policy ---

#[test]
fn given_data_within_retention_period_when_checked_then_active() {
    let sink = InMemorySink::new();
    let policy = RetentionPolicy::new(90, "user_data");
    let now = OffsetDateTime::now_utc();
    let created_at = now - Duration::days(30);

    let status = policy.check_status(created_at, now, &sink);
    assert_eq!(status, RetentionStatus::Active);
    assert!(sink.events().is_empty(), "No event for active data");
}

#[test]
fn given_data_past_retention_period_when_checked_then_expired_with_event() {
    let sink = InMemorySink::new();
    let policy = RetentionPolicy::new(90, "user_data");
    let now = OffsetDateTime::now_utc();
    let created_at = now - Duration::days(100);

    let status = policy.check_status(created_at, now, &sink);
    assert_eq!(status, RetentionStatus::Expired);
    let events = sink.events();
    assert_eq!(events.len(), 1, "Expiry should emit an event");
    assert_eq!(events[0].kind, EventKind::RetentionExpiry);
}

#[test]
fn given_no_retention_policy_when_checked_then_no_policy() {
    let status = check_no_policy();
    assert_eq!(status, RetentionStatus::NoPolicy);
}

#[test]
fn given_data_exactly_at_retention_limit_when_checked_then_active() {
    let sink = InMemorySink::new();
    let policy = RetentionPolicy::new(90, "user_data");
    let now = OffsetDateTime::now_utc();
    // Exactly 90 days — not past, should be active
    let created_at = now - Duration::days(90);

    let status = policy.check_status(created_at, now, &sink);
    assert_eq!(status, RetentionStatus::Active);
}

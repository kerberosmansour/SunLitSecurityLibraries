//! BDD tests for event serialization schema.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;

#[test]
fn test_event_serializes_to_json() {
    let event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::High,
        EventOutcome::Failure,
    );
    let json = serde_json::to_value(&event).expect("should serialize");
    assert!(
        json.get("timestamp").is_some(),
        "Should have timestamp field"
    );
    assert!(json.get("event_id").is_some(), "Should have event_id field");
    assert!(json.get("kind").is_some(), "Should have kind field");
    assert!(json.get("severity").is_some(), "Should have severity field");
    assert!(json.get("outcome").is_some(), "Should have outcome field");
}

#[test]
fn test_event_with_optional_fields_null() {
    let event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Info,
        EventOutcome::Unknown,
    );
    let json = serde_json::to_value(&event).expect("should serialize");
    // Optional fields should be absent (skip_serializing_if = None)
    assert!(
        json.get("actor").is_none(),
        "actor should be absent when None"
    );
    assert!(
        json.get("source_ip").is_none(),
        "source_ip should be absent when None"
    );
    assert!(
        json.get("session_id").is_none(),
        "session_id should be absent when None"
    );
}

//! BDD tests for the redaction engine.

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::redact::{RedactionEngine, RedactionPolicy, RedactionStrategy};

fn make_event_with_label(
    key: &str,
    value: &str,
    classification: DataClassification,
) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        key.to_string(),
        EventValue::Classified {
            value: value.to_string(),
            classification,
        },
    );
    event
}

#[test]
fn test_public_field_passes_through() {
    let engine = RedactionEngine::with_default_policy();
    let event = make_event_with_label("user_name", "alice", DataClassification::Public);
    let processed = engine.process_event(event);
    let val = processed
        .labels
        .get("user_name")
        .expect("label should exist");
    let EventValue::Classified { value, .. } = val;
    assert_eq!(value, "alice");
}

#[test]
fn test_secret_field_is_redacted() {
    let engine = RedactionEngine::with_default_policy();
    let event = make_event_with_label("api_key", "supersecret123", DataClassification::Secret);
    let processed = engine.process_event(event);
    let val = processed.labels.get("api_key").expect("label should exist");
    let EventValue::Classified { value, .. } = val;
    assert_eq!(value, "[REDACTED]");
}

#[test]
fn test_pii_field_is_hashed() {
    let engine = RedactionEngine::with_default_policy();
    let event = make_event_with_label("email", "user@example.com", DataClassification::PII);
    let processed = engine.process_event(event);
    let val = processed.labels.get("email").expect("label should exist");
    let EventValue::Classified { value, .. } = val;
    assert!(
        value.starts_with("SHA256:"),
        "Expected SHA256: prefix, got {value}"
    );
}

#[test]
fn test_credentials_field_is_dropped() {
    let engine = RedactionEngine::with_default_policy();
    let event = make_event_with_label("password", "hunter2", DataClassification::Credentials);
    let processed = engine.process_event(event);
    assert!(
        !processed.labels.contains_key("password"),
        "Credentials label should be dropped"
    );
}

#[test]
fn test_internal_field_allowed() {
    let engine = RedactionEngine::with_default_policy();
    let event = make_event_with_label("service_name", "auth-service", DataClassification::Internal);
    let processed = engine.process_event(event);
    let val = processed
        .labels
        .get("service_name")
        .expect("label should exist");
    let EventValue::Classified { value, .. } = val;
    assert_eq!(value, "auth-service");
}

#[test]
fn test_custom_policy_allow_all() {
    let policy = RedactionPolicy {
        public: RedactionStrategy::Allow,
        internal: RedactionStrategy::Allow,
        confidential: RedactionStrategy::Allow,
        pii: RedactionStrategy::Allow,
        regulated: RedactionStrategy::Allow,
        secret: RedactionStrategy::Allow,
        credentials: RedactionStrategy::Allow,
    };
    let engine = RedactionEngine::new(policy);
    let event = make_event_with_label("secret_key", "do-not-leak", DataClassification::Credentials);
    let processed = engine.process_event(event);
    assert!(processed.labels.contains_key("secret_key"));
}

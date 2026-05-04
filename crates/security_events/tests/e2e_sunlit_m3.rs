//! End-to-end integration tests for Milestone 3.

use secure_errors::incident::emit_event_for_incident;
use secure_errors::kind::AppError;
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::detect::DetectionEngine;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::rate_limit::RateLimiter;
use security_events::redact::RedactionEngine;
use security_events::sanitize::sanitize_for_text_sink;
use security_events::sink::{SecuritySink, StdoutJsonSink};

#[test]
fn test_security_event_roundtrip() {
    let event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::High,
        EventOutcome::Success,
    );
    let json = serde_json::to_string(&event).expect("should serialize");
    assert!(json.contains("AdminAction"));
    assert!(json.contains("event_id"));
}

#[test]
fn test_redaction_engine_runtime() {
    let mut event = SecurityEvent::new(
        EventKind::SecretAccess,
        SecuritySeverity::High,
        EventOutcome::Success,
    );
    event.labels.insert(
        "token".to_string(),
        EventValue::Classified {
            value: "abc123".to_string(),
            classification: DataClassification::Credentials,
        },
    );
    let engine = RedactionEngine::with_default_policy();
    let processed = engine.process_event(event);
    assert!(
        !processed.labels.contains_key("token"),
        "Credentials must be dropped"
    );
}

#[test]
fn test_stdout_json_sink() {
    let sink = StdoutJsonSink;
    let event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Medium,
        EventOutcome::Failure,
    );
    // Should not panic
    sink.write_event(&event);
}

#[test]
fn test_detection_threshold_integration() {
    let engine = DetectionEngine::new(2, 60);
    let actor = "bot@example.com";
    assert!(engine.record_authz_denied(actor).is_none());
    assert!(engine.record_authz_denied(actor).is_none());
    let escalation = engine.record_authz_denied(actor);
    assert!(escalation.is_some(), "Should escalate after threshold");
}

#[test]
fn test_log_injection_prevention() {
    let malicious = "normal\nContent-Type: text/html\n<script>alert(1)</script>";
    let sanitized = sanitize_for_text_sink(malicious);
    assert!(!sanitized.contains('\n'), "newlines must be escaped");
}

#[test]
fn test_rate_limiter_under_load() {
    let limiter = RateLimiter::new(3, 60);
    assert!(limiter.should_allow(&EventKind::AuthnFailure));
    assert!(limiter.should_allow(&EventKind::AuthnFailure));
    assert!(limiter.should_allow(&EventKind::AuthnFailure));
    assert!(
        !limiter.should_allow(&EventKind::AuthnFailure),
        "Should be rate-limited after 3"
    );
    // Different kind should be independent
    assert!(limiter.should_allow(&EventKind::AdminAction));
}

#[test]
fn test_error_event_integration() {
    let err = AppError::Forbidden {
        policy: "test-policy",
    };
    // Should not panic
    emit_event_for_incident(&err);

    let err2 = AppError::Dependency { dep: "db" };
    emit_event_for_incident(&err2);
}

#[test]
fn test_emit_security_event_no_panic() {
    let event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::High,
        EventOutcome::Blocked,
    );
    // Should not panic even without a subscriber
    emit_security_event(event);
}

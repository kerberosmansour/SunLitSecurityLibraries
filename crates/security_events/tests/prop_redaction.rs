//! Property tests — redaction invariants.
//!
//! Milestone 9 — BDD: Secret fields never appear in redacted output.
use proptest::prelude::*;
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::redact::RedactionEngine;
use security_events::sanitize::sanitize_for_text_sink;

fn make_event_with_secret(value: String) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "token".to_string(),
        EventValue::Classified {
            value,
            classification: DataClassification::Secret,
        },
    );
    event
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Secret values never appear verbatim in redacted output
    #[test]
    fn prop_secret_never_in_redacted_output(secret in "[a-zA-Z0-9]{8,32}") {
        let engine = RedactionEngine::with_default_policy();
        let event = make_event_with_secret(secret.clone());
        let redacted = engine.process_event(event);
        for v in redacted.labels.values() {
            let EventValue::Classified { value, .. } = v;
            prop_assert_ne!(value, &secret, "secret leaked into redacted output");
        }
    }

    /// sanitize_for_text_sink never panics on arbitrary input
    #[test]
    fn prop_sanitize_no_panic(s in ".*") {
        let _ = sanitize_for_text_sink(&s);
    }

    /// sanitize_for_text_sink output never contains raw newline or carriage return
    #[test]
    fn prop_sanitize_no_raw_newlines(s in ".*") {
        let sanitized = sanitize_for_text_sink(&s);
        prop_assert!(!sanitized.contains('\n'), "raw newline in sanitized output");
        prop_assert!(!sanitized.contains('\r'), "raw CR in sanitized output");
    }
}

#![no_main]
//! Fuzz target: MobileRedactionEngine::scrub_event never panics on arbitrary label values.
use libfuzzer_sys::fuzz_target;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::mobile_redaction::MobileRedactionEngine;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let engine = MobileRedactionEngine::new();
        let mut event = SecurityEvent::new(
            EventKind::AuthzDeny,
            security_core::severity::SecuritySeverity::Low,
            EventOutcome::Success,
        );
        event.labels.insert(
            "device_id".to_string(),
            EventValue::Classified {
                value: s.to_string(),
                classification: security_core::classification::DataClassification::Internal,
            },
        );
        let _ = engine.scrub_event(event);
    }
});

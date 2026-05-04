//! BDD acceptance tests for Milestone 7 — Mobile Log Sanitization.
//!
//! Tests mobile device ID scrubbing, location coordinate scrubbing,
//! and log level enforcement per MASVS-STORAGE-2 and MASVS-CODE-2.

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::mobile_redaction::{LogLevel, LogLevelEnforcer, MobileRedactionEngine};

/// Helper to extract a classified value from a label, panicking if absent.
fn get_classified_value<'a>(event: &'a SecurityEvent, key: &str) -> &'a str {
    match event.labels.get(key) {
        Some(EventValue::Classified { value, .. }) => value.as_str(),
        _ => panic!("expected Classified label for key"),
    }
}

// =============================================================================
// Feature: Mobile Device ID Scrubbing
// =============================================================================

#[test]
fn given_event_with_imei_label_when_mobile_redaction_applied_then_imei_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "device_id".to_string(),
        EventValue::Classified {
            value: "353456789012345".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "device_id"),
        "[DEVICE_ID_REDACTED]"
    );
}

#[test]
fn given_event_with_idfv_label_when_redaction_applied_then_idfv_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "idfv".to_string(),
        EventValue::Classified {
            value: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "idfv"),
        "[DEVICE_ID_REDACTED]"
    );
}

#[test]
fn given_event_with_advertising_id_when_redaction_applied_then_ad_id_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    // GAID (Google Advertising ID) format
    event.labels.insert(
        "ad_id".to_string(),
        EventValue::Classified {
            value: "38400000-8cf0-11bd-b23e-10b96e40000d".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(get_classified_value(&redacted, "ad_id"), "[AD_ID_REDACTED]");
}

#[test]
fn given_event_with_mac_address_when_redaction_applied_then_mac_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "mac".to_string(),
        EventValue::Classified {
            value: "AA:BB:CC:DD:EE:FF".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "mac"),
        "[DEVICE_ID_REDACTED]"
    );
}

#[test]
fn given_event_with_mac_dash_format_when_redaction_applied_then_mac_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "mac".to_string(),
        EventValue::Classified {
            value: "AA-BB-CC-DD-EE-FF".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "mac"),
        "[DEVICE_ID_REDACTED]"
    );
}

#[test]
fn given_event_with_normal_data_when_redaction_applied_then_data_preserved() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "action".to_string(),
        EventValue::Classified {
            value: "user_login".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(get_classified_value(&redacted, "action"), "user_login");
}

#[test]
fn given_event_with_gps_coordinates_when_redaction_applied_then_location_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "location".to_string(),
        EventValue::Classified {
            value: "37.7749, -122.4194".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "location"),
        "[LOCATION_REDACTED]"
    );
}

#[test]
fn given_event_with_negative_coords_when_redaction_applied_then_location_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "gps".to_string(),
        EventValue::Classified {
            value: "-33.8688, 151.2093".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "gps"),
        "[LOCATION_REDACTED]"
    );
}

// =============================================================================
// Feature: Log Level Enforcement
// =============================================================================

#[test]
fn given_release_enforcer_when_debug_event_submitted_then_event_suppressed() {
    let enforcer = LogLevelEnforcer::release();
    assert!(!enforcer.should_emit(LogLevel::Debug));
}

#[test]
fn given_release_enforcer_when_info_event_submitted_then_event_emitted() {
    let enforcer = LogLevelEnforcer::release();
    assert!(enforcer.should_emit(LogLevel::Info));
}

#[test]
fn given_release_enforcer_when_warn_event_submitted_then_event_emitted() {
    let enforcer = LogLevelEnforcer::release();
    assert!(enforcer.should_emit(LogLevel::Warn));
}

#[test]
fn given_release_enforcer_when_error_event_submitted_then_event_emitted() {
    let enforcer = LogLevelEnforcer::release();
    assert!(enforcer.should_emit(LogLevel::Error));
}

#[test]
fn given_release_enforcer_when_trace_event_submitted_then_event_suppressed() {
    let enforcer = LogLevelEnforcer::release();
    assert!(!enforcer.should_emit(LogLevel::Trace));
}

#[test]
fn given_debug_enforcer_when_debug_event_submitted_then_event_emitted() {
    let enforcer = LogLevelEnforcer::debug();
    assert!(enforcer.should_emit(LogLevel::Debug));
}

#[test]
fn given_debug_enforcer_when_trace_event_submitted_then_event_emitted() {
    let enforcer = LogLevelEnforcer::debug();
    assert!(enforcer.should_emit(LogLevel::Trace));
}

// =============================================================================
// Feature: Integration with RedactionEngine
// =============================================================================

#[test]
fn given_mobile_redaction_and_classification_redaction_when_both_applied_then_both_effective() {
    let mobile = MobileRedactionEngine::new();
    let classification = security_events::RedactionEngine::with_default_policy();

    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "device_imei".to_string(),
        EventValue::Classified {
            value: "353456789012345".to_string(),
            classification: DataClassification::PII,
        },
    );
    event.labels.insert(
        "username".to_string(),
        EventValue::Classified {
            value: "alice".to_string(),
            classification: DataClassification::PII,
        },
    );

    // Mobile redaction first (scrubs device IDs), then classification redaction (hashes PII)
    let scrubbed = mobile.scrub_event(event);
    let redacted = classification.process_event(scrubbed);

    // IMEI should be device-ID-redacted then hashed (since it's PII)
    assert!(get_classified_value(&redacted, "device_imei").starts_with("SHA256:"));
    // username should just be hashed (PII policy)
    assert!(get_classified_value(&redacted, "username").starts_with("SHA256:"));
}

// =============================================================================
// Feature: IMEI edge cases
// =============================================================================

#[test]
fn given_14_digit_number_when_redaction_applied_then_not_treated_as_imei() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "code".to_string(),
        EventValue::Classified {
            value: "12345678901234".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(get_classified_value(&redacted, "code"), "12345678901234");
}

#[test]
fn given_16_digit_number_when_redaction_applied_then_not_treated_as_imei() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "code".to_string(),
        EventValue::Classified {
            value: "1234567890123456".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(get_classified_value(&redacted, "code"), "1234567890123456");
}

// =============================================================================
// Feature: Lowercase UUID / advertising ID
// =============================================================================

#[test]
fn given_lowercase_uuid_when_redaction_applied_then_ad_id_redacted() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.labels.insert(
        "gaid".to_string(),
        EventValue::Classified {
            value: "cdda802e-fb9c-47ad-9866-0794d394c912".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(get_classified_value(&redacted, "gaid"), "[AD_ID_REDACTED]");
}

// =============================================================================
// Feature: Key-based heuristics for UUID disambiguation
// =============================================================================

#[test]
fn given_uuid_in_event_id_key_when_redaction_applied_then_preserved() {
    let engine = MobileRedactionEngine::new();
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    // A UUID in a non-device key should be preserved
    event.labels.insert(
        "correlation_id".to_string(),
        EventValue::Classified {
            value: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            classification: DataClassification::Internal,
        },
    );
    let redacted = engine.scrub_event(event);
    assert_eq!(
        get_classified_value(&redacted, "correlation_id"),
        "550e8400-e29b-41d4-a716-446655440000"
    );
}

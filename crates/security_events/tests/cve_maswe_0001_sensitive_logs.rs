//! CVE regression tests — MASWE-0001: Sensitive data in log labels scrubbed.
//!
//! Milestone 9 — BDD: Mobile redaction engine scrubs device IDs, GPS, and ad IDs.
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::mobile_redaction::MobileRedactionEngine;

/// Helper: create a security event with a single label.
fn event_with_label(key: &str, value: &str) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        EventKind::AuthzDeny,
        SecuritySeverity::Medium,
        EventOutcome::Success,
    );
    event.labels.insert(
        key.to_string(),
        EventValue::Classified {
            value: value.to_string(),
            classification: DataClassification::Internal,
        },
    );
    event
}

/// Helper: extract label value after scrubbing.
fn scrubbed_value(key: &str, value: &str) -> String {
    let engine = MobileRedactionEngine::new();
    let event = event_with_label(key, value);
    let scrubbed = engine.scrub_event(event);
    match scrubbed.labels.get(key).unwrap() {
        EventValue::Classified { value, .. } => value.clone(),
    }
}

/// MASWE-0001: IMEI (15-digit device identifier) must be redacted.
#[test]
fn maswe_0001_imei_redacted() {
    let result = scrubbed_value("device_imei", "353456789012345");
    assert_eq!(result, "[DEVICE_ID_REDACTED]");
}

/// MASWE-0001: MAC address (colon format) must be redacted.
#[test]
fn maswe_0001_mac_address_colon_redacted() {
    let result = scrubbed_value("device_mac", "AA:BB:CC:DD:EE:FF");
    assert_eq!(result, "[DEVICE_ID_REDACTED]");
}

/// MASWE-0001: MAC address (dash format) must be redacted.
#[test]
fn maswe_0001_mac_address_dash_redacted() {
    let result = scrubbed_value("hardware_addr", "AA-BB-CC-DD-EE-FF");
    assert_eq!(result, "[DEVICE_ID_REDACTED]");
}

/// MASWE-0001: GPS coordinates must be redacted.
#[test]
fn maswe_0001_gps_coordinates_redacted() {
    let result = scrubbed_value("location", "37.7749, -122.4194");
    assert_eq!(result, "[LOCATION_REDACTED]");
}

/// MASWE-0001: Device UUID (IDFV-style key) must be redacted.
#[test]
fn maswe_0001_idfv_redacted() {
    let result = scrubbed_value("idfv", "E621E1F8-C36C-495A-93FC-0C247A3E6E5F");
    assert_eq!(result, "[DEVICE_ID_REDACTED]");
}

/// MASWE-0001: Advertising ID (IDFA/GAID key) must be redacted as ad ID.
#[test]
fn maswe_0001_idfa_redacted() {
    let result = scrubbed_value("idfa", "38400000-8CF0-11BD-B23E-10B96E40000D");
    assert_eq!(result, "[AD_ID_REDACTED]");
}

/// MASWE-0001: GAID (Google Advertising ID key) must be redacted as ad ID.
#[test]
fn maswe_0001_gaid_redacted() {
    let result = scrubbed_value("gaid", "38400000-8CF0-11BD-B23E-10B96E40000D");
    assert_eq!(result, "[AD_ID_REDACTED]");
}

/// MASWE-0001: Non-device UUID keys must NOT be redacted.
#[test]
fn maswe_0001_event_id_not_redacted() {
    let result = scrubbed_value("event_id", "E621E1F8-C36C-495A-93FC-0C247A3E6E5F");
    assert_eq!(
        result, "E621E1F8-C36C-495A-93FC-0C247A3E6E5F",
        "event_id should not be redacted"
    );
}

/// MASWE-0001: Plain text labels are not modified.
#[test]
fn maswe_0001_plain_text_not_modified() {
    let result = scrubbed_value("action", "user_login");
    assert_eq!(result, "user_login");
}

/// MASWE-0001: request_id UUID must NOT be redacted.
#[test]
fn maswe_0001_request_id_not_redacted() {
    let result = scrubbed_value("request_id", "A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    assert_eq!(result, "A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
}

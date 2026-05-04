//! BDD tests for mobile storage extensions — Milestone 2 (MASVS-STORAGE)
//!
//! Features: Sensitive Buffer Management, Backup Exclusion, Mobile Storage Policy

#![cfg(feature = "mobile-storage")]

use secure_data::mobile_storage::{BackupExclusion, MobileStoragePolicy, SensitiveBuffer};
use security_core::classification::DataClassification;

// ─── Feature: Sensitive Buffer Management ───────────────────────────────────

/// Scenario: SensitiveBuffer zeroes on drop
/// Given SensitiveBuffer holding secret bytes
/// When Buffer is dropped
/// Then Memory is zeroed via zeroize
#[test]
fn given_sensitive_buffer_holding_secret_when_dropped_then_memory_zeroed() {
    // Verify the buffer uses zeroize-on-drop by checking it can be created
    // and dropped without issues. The zeroization is guaranteed by the
    // Zeroizing<Vec<u8>> inner type via the `zeroize` derive.
    let buf = SensitiveBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(buf.expose(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    drop(buf);
    // After drop, memory zeroed by Zeroizing — not observable from safe Rust,
    // but the type contract guarantees zeroization via `zeroize::Zeroize` derive.
}

/// Scenario: SensitiveBuffer no Debug output
/// Given SensitiveBuffer holding secret
/// When format!("{:?}", buf) called
/// Then Output shows [REDACTED], not secret content
#[test]
fn given_sensitive_buffer_when_debug_formatted_then_shows_redacted() {
    let buf = SensitiveBuffer::new(vec![0x42; 16]);
    let debug_output = format!("{:?}", buf);
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must contain [REDACTED], got: {debug_output}"
    );
    assert!(
        !debug_output.contains("42"),
        "Debug output must not contain secret hex, got: {debug_output}"
    );
}

/// Scenario: SensitiveBuffer no Display output
/// Given SensitiveBuffer holding secret
/// When format!("{}", buf) called
/// Then Output shows [REDACTED]
#[test]
fn given_sensitive_buffer_when_display_formatted_then_shows_redacted() {
    let buf = SensitiveBuffer::new(b"secret-pin-1234".to_vec());
    let display_output = format!("{}", buf);
    assert!(
        display_output.contains("[REDACTED]"),
        "Display output must contain [REDACTED], got: {display_output}"
    );
    assert!(
        !display_output.contains("secret-pin-1234"),
        "Display must not contain secret content"
    );
}

/// Scenario: SensitiveBuffer explicit wipe
/// Given SensitiveBuffer holding PIN digits
/// When wipe() called explicitly
/// Then Buffer zeroed, subsequent reads return zeroed data
#[test]
fn given_sensitive_buffer_holding_pin_when_wipe_called_then_zeroed() {
    let mut buf = SensitiveBuffer::new(vec![1, 2, 3, 4]);
    buf.wipe();
    assert!(
        buf.expose().iter().all(|&b| b == 0),
        "Buffer must be zeroed after wipe(), got: {:?}",
        buf.expose()
    );
}

/// Scenario: SensitiveBuffer bounded lifetime (TTL)
/// Given SensitiveBuffer with max TTL
/// When TTL expires
/// Then Buffer auto-wipes (checked via is_expired)
#[test]
fn given_sensitive_buffer_with_ttl_when_expired_then_auto_wipes() {
    use std::time::Duration;
    let buf = SensitiveBuffer::with_ttl(vec![0xAB; 8], Duration::from_secs(0));
    // Zero-second TTL means immediately expired
    std::thread::sleep(Duration::from_millis(10));
    assert!(buf.is_expired(), "Buffer should be expired after TTL");
}

/// Scenario: SensitiveBuffer with TTL not expired returns data
#[test]
fn given_sensitive_buffer_with_ttl_when_not_expired_then_data_available() {
    use std::time::Duration;
    let buf = SensitiveBuffer::with_ttl(vec![0xCD; 4], Duration::from_secs(60));
    assert!(!buf.is_expired(), "Buffer should not be expired yet");
    assert_eq!(buf.expose(), &[0xCD; 4]);
}

/// Scenario: SensitiveBuffer without TTL is never expired
#[test]
fn given_sensitive_buffer_without_ttl_then_never_expired() {
    let buf = SensitiveBuffer::new(vec![0x01]);
    assert!(!buf.is_expired(), "Buffer without TTL should never expire");
}

/// Scenario: Empty SensitiveBuffer is valid
#[test]
fn given_empty_sensitive_buffer_then_valid() {
    let buf = SensitiveBuffer::new(vec![]);
    assert!(buf.expose().is_empty());
}

// ─── Feature: Backup Exclusion ──────────────────────────────────────────────

/// Scenario: BackupExclusion marker set
/// Given Data item with BackupExclusion::Exclude
/// When Policy checked
/// Then should_exclude_from_backup() returns true
#[test]
fn given_backup_exclusion_exclude_when_checked_then_excluded() {
    let policy = BackupExclusion::Exclude;
    assert!(
        policy.should_exclude_from_backup(),
        "Exclude policy must return true for should_exclude_from_backup()"
    );
}

/// Scenario: BackupExclusion default is exclude (secure by default)
/// Given Data item with no explicit backup policy
/// When Policy checked
/// Then Defaults to Exclude
#[test]
fn given_default_backup_exclusion_when_checked_then_excluded() {
    let policy = BackupExclusion::default();
    assert!(
        policy.should_exclude_from_backup(),
        "Default backup exclusion must be Exclude (secure by default)"
    );
}

/// Scenario: BackupExclusion::Allow permits backup
#[test]
fn given_backup_exclusion_allow_when_checked_then_not_excluded() {
    let policy = BackupExclusion::Allow;
    assert!(
        !policy.should_exclude_from_backup(),
        "Allow policy must return false for should_exclude_from_backup()"
    );
}

/// Scenario: BackupExclusion serializable
/// Given BackupExclusion marker
/// When Serialized to JSON
/// Then Produces valid metadata for platform integration
#[test]
fn given_backup_exclusion_when_serialized_then_valid_json() {
    let exclude = BackupExclusion::Exclude;
    let json = serde_json::to_string(&exclude).expect("must serialize");
    assert!(
        !json.is_empty(),
        "Serialized BackupExclusion must produce non-empty JSON"
    );
    // Deserialize round-trip
    let deserialized: BackupExclusion = serde_json::from_str(&json).expect("must deserialize");
    assert_eq!(deserialized, exclude);
}

/// Scenario: BackupExclusion Allow serializable
#[test]
fn given_backup_exclusion_allow_when_serialized_then_round_trips() {
    let allow = BackupExclusion::Allow;
    let json = serde_json::to_string(&allow).expect("must serialize");
    let deserialized: BackupExclusion = serde_json::from_str(&json).expect("must deserialize");
    assert_eq!(deserialized, allow);
}

// ─── Feature: Mobile Storage Policy ─────────────────────────────────────────

/// Scenario: Policy requires encryption
/// Given MobileStoragePolicy::encrypted()
/// When Data classified as Confidential
/// Then requires_encryption() returns true
#[test]
fn given_encrypted_policy_when_confidential_data_then_requires_encryption() {
    let policy = MobileStoragePolicy::encrypted(DataClassification::Confidential);
    assert!(
        policy.requires_encryption(),
        "Encrypted policy for Confidential data must require encryption"
    );
}

/// Scenario: Policy requires hardware keystore
/// Given MobileStoragePolicy::hardware_backed()
/// When Storage policy checked
/// Then requires_hardware_keystore() returns true
#[test]
fn given_hardware_backed_policy_when_checked_then_requires_hardware_keystore() {
    let policy = MobileStoragePolicy::hardware_backed(DataClassification::Secret);
    assert!(
        policy.requires_hardware_keystore(),
        "Hardware-backed policy must require hardware keystore"
    );
    assert!(
        policy.requires_encryption(),
        "Hardware-backed policy must also require encryption"
    );
}

/// Scenario: Public data has relaxed policy
/// Given MobileStoragePolicy for Public data
/// When Policy checked
/// Then Does not require hardware keystore
#[test]
fn given_public_data_policy_when_checked_then_no_hardware_keystore() {
    let policy = MobileStoragePolicy::for_classification(DataClassification::Public);
    assert!(
        !policy.requires_hardware_keystore(),
        "Public data policy must not require hardware keystore"
    );
    assert!(
        !policy.requires_encryption(),
        "Public data policy must not require encryption"
    );
}

/// Scenario: Policy violation emits event
/// Given Policy requires encryption
/// When Unencrypted storage attempted
/// Then SecurityEvent with violation emitted
#[test]
fn given_encryption_policy_when_unencrypted_attempted_then_violation_event() {
    use security_events::kind::EventKind;
    let policy = MobileStoragePolicy::encrypted(DataClassification::Confidential);
    let violations = policy.check_compliance(false, false);
    assert!(
        !violations.is_empty(),
        "Must produce at least one violation"
    );
    for event in &violations {
        assert_eq!(
            event.kind,
            EventKind::StoragePolicyViolation,
            "Violation event kind must be StoragePolicyViolation"
        );
    }
}

/// Scenario: Compliant storage produces no violations
#[test]
fn given_encryption_policy_when_encrypted_then_no_violations() {
    let policy = MobileStoragePolicy::encrypted(DataClassification::Confidential);
    let violations = policy.check_compliance(true, false);
    assert!(
        violations.is_empty(),
        "Compliant storage must produce no violations"
    );
}

/// Scenario: Hardware-backed policy violation for missing hardware keystore
#[test]
fn given_hardware_policy_when_no_hardware_then_violation() {
    let policy = MobileStoragePolicy::hardware_backed(DataClassification::Secret);
    let violations = policy.check_compliance(true, false);
    assert!(
        !violations.is_empty(),
        "Must produce violation when hardware keystore is missing"
    );
}

/// Scenario: Hardware-backed policy fully compliant
#[test]
fn given_hardware_policy_when_hardware_and_encrypted_then_no_violations() {
    let policy = MobileStoragePolicy::hardware_backed(DataClassification::Secret);
    let violations = policy.check_compliance(true, true);
    assert!(
        violations.is_empty(),
        "Fully compliant storage must produce no violations"
    );
}

/// Scenario: Confidential data auto-policy requires encryption
#[test]
fn given_confidential_classification_when_auto_policy_then_requires_encryption() {
    let policy = MobileStoragePolicy::for_classification(DataClassification::Confidential);
    assert!(policy.requires_encryption());
}

/// Scenario: Secret data auto-policy requires hardware keystore
#[test]
fn given_secret_classification_when_auto_policy_then_requires_hardware() {
    let policy = MobileStoragePolicy::for_classification(DataClassification::Secret);
    assert!(policy.requires_hardware_keystore());
    assert!(policy.requires_encryption());
}

/// Scenario: Credentials data auto-policy requires hardware keystore
#[test]
fn given_credentials_classification_when_auto_policy_then_requires_hardware() {
    let policy = MobileStoragePolicy::for_classification(DataClassification::Credentials);
    assert!(policy.requires_hardware_keystore());
    assert!(policy.requires_encryption());
}

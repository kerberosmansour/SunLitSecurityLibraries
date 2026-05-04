//! E2E runtime validation tests for Milestone 2 — `secure_data` mobile storage
//!
//! These tests validate the end-to-end integration of mobile storage types
//! with the existing `secure_data` and `security_events` crates.

#![cfg(feature = "mobile-storage")]

use secure_data::mobile_storage::{BackupExclusion, MobileStoragePolicy, SensitiveBuffer};
use security_core::classification::DataClassification;
use security_events::kind::EventKind;

/// E2E: Full lifecycle of SensitiveBuffer — create, read, wipe, verify zeroed
#[test]
fn e2e_sensitive_buffer_lifecycle() {
    // Create buffer with simulated biometric template data
    let mut buf = SensitiveBuffer::new(vec![0xFE, 0xED, 0xFA, 0xCE]);
    assert_eq!(buf.expose(), &[0xFE, 0xED, 0xFA, 0xCE]);

    // Wipe explicitly
    buf.wipe();
    assert!(buf.expose().iter().all(|&b| b == 0));

    // Drop triggers zeroize again (idempotent)
    drop(buf);
}

/// E2E: SensitiveBuffer with TTL auto-expiry integration
#[test]
fn e2e_sensitive_buffer_ttl_expiry() {
    use std::time::Duration;

    // Create with zero TTL → immediately expired
    let buf = SensitiveBuffer::with_ttl(vec![0x01, 0x02], Duration::from_secs(0));
    std::thread::sleep(Duration::from_millis(10));
    assert!(buf.is_expired());
}

/// E2E: BackupExclusion metadata round-trip through JSON
#[test]
fn e2e_backup_exclusion_json_round_trip() {
    for &variant in &[BackupExclusion::Exclude, BackupExclusion::Allow] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let restored: BackupExclusion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, variant);
    }
}

/// E2E: MobileStoragePolicy compliance check produces security events
#[test]
fn e2e_storage_policy_violation_events() {
    let policy = MobileStoragePolicy::hardware_backed(DataClassification::Credentials);

    // Not encrypted, no hardware → should produce violations
    let violations = policy.check_compliance(false, false);
    assert!(violations.len() >= 2, "Expected at least 2 violations");

    for event in &violations {
        assert_eq!(event.kind, EventKind::StoragePolicyViolation);
    }
}

/// E2E: MobileStoragePolicy::for_classification auto-selects appropriate policy
#[test]
fn e2e_auto_classification_policy() {
    // Public → no requirements
    let public = MobileStoragePolicy::for_classification(DataClassification::Public);
    assert!(!public.requires_encryption());
    assert!(!public.requires_hardware_keystore());
    assert!(public.check_compliance(false, false).is_empty());

    // Confidential → encryption required
    let conf = MobileStoragePolicy::for_classification(DataClassification::Confidential);
    assert!(conf.requires_encryption());
    assert!(!conf.requires_hardware_keystore());

    // Secret → hardware + encryption
    let secret = MobileStoragePolicy::for_classification(DataClassification::Secret);
    assert!(secret.requires_encryption());
    assert!(secret.requires_hardware_keystore());

    // Credentials → hardware + encryption
    let creds = MobileStoragePolicy::for_classification(DataClassification::Credentials);
    assert!(creds.requires_encryption());
    assert!(creds.requires_hardware_keystore());
}

/// E2E: SensitiveBuffer Debug and Display never leak data
#[test]
fn e2e_sensitive_buffer_no_data_leak() {
    let secret_data = b"super-secret-pin-9999".to_vec();
    let buf = SensitiveBuffer::new(secret_data);

    let debug = format!("{:?}", buf);
    let display = format!("{}", buf);

    assert!(!debug.contains("super-secret-pin-9999"));
    assert!(!display.contains("super-secret-pin-9999"));
    assert!(debug.contains("[REDACTED]"));
    assert!(display.contains("[REDACTED]"));
}

/// E2E: Existing secure_data APIs still work (backward compatibility)
#[test]
fn e2e_existing_secret_types_unchanged() {
    use secure_data::secret::{SecretBytes, SecretString};

    let s = SecretString::new("test-key".to_string());
    assert_eq!(s.expose_secret(), "test-key");
    assert!(format!("{:?}", s).contains("REDACTED"));

    let b = SecretBytes::new(vec![1, 2, 3]);
    assert_eq!(b.expose_secret(), &[1, 2, 3]);
    assert!(format!("{:?}", b).contains("REDACTED"));
}

//! BDD tests for biometric authentication validation — Milestone 3 (MASVS-AUTH)
//!
//! Features: Biometric Authentication Validation, Device Credential Binding

#![cfg(feature = "biometric")]

use secure_identity::biometric::{
    BiometricAuthResult, BiometricClass, BiometricPolicy, BiometricRejection, BiometricValidation,
    CryptoBinding,
};
use security_events::event::EventOutcome;
use security_events::kind::EventKind;

// ─── Feature: Biometric Authentication Validation ───────────────────────────

/// Scenario: Strong biometric result accepted
/// Given BiometricAuthResult with Class3 (strong) biometric and cryptographic binding
/// When Validation called
/// Then BiometricValidation::Accepted
#[test]
fn given_class3_biometric_with_crypto_binding_when_validated_then_accepted() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-abc".to_string(),
        }),
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy::default();

    let validation = policy.validate(&result, None);
    assert_eq!(validation, BiometricValidation::Accepted);
}

/// Scenario: Weak biometric result rejected
/// Given BiometricAuthResult with Class1 (convenience)
/// When Policy requires Class3 minimum
/// Then BiometricValidation::Rejected(WeakBiometric) + security event
#[test]
fn given_class1_biometric_when_policy_requires_class3_then_rejected_weak() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class1,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-abc".to_string(),
        }),
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy::default(); // default requires Class3

    let validation = policy.validate(&result, None);
    assert_eq!(
        validation,
        BiometricValidation::Rejected(BiometricRejection::WeakBiometric)
    );

    // Verify security event emission
    let events = policy.validate_with_events(&result, None);
    assert!(!events.is_empty());
    assert_eq!(events[0].kind, EventKind::BiometricAuthFailure);
    assert_eq!(events[0].outcome, EventOutcome::Blocked);
}

/// Scenario: No cryptographic binding rejected
/// Given BiometricAuthResult without crypto proof
/// When Policy requires binding
/// Then BiometricValidation::Rejected(NoCryptoBinding)
#[test]
fn given_biometric_without_crypto_binding_when_policy_requires_it_then_rejected() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: None,
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy::default(); // default requires binding

    let validation = policy.validate(&result, None);
    assert_eq!(
        validation,
        BiometricValidation::Rejected(BiometricRejection::NoCryptoBinding)
    );
}

/// Scenario: Enrollment change invalidates keys
/// Given BiometricAuthResult with stale enrollment ID
/// When Enrollment ID changed since key creation
/// Then BiometricValidation::Rejected(EnrollmentChanged)
#[test]
fn given_stale_enrollment_id_when_enrollment_changed_then_rejected() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-old".to_string(),
        }),
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy::default();

    // Current enrollment is different from what the result claims
    let validation = policy.validate(&result, Some("enroll-current"));
    assert_eq!(
        validation,
        BiometricValidation::Rejected(BiometricRejection::EnrollmentChanged)
    );
}

/// Scenario: Device credential (PIN/pattern) accepted when allowed
/// Given BiometricAuthResult with device credential fallback
/// When Policy allows device credential
/// Then BiometricValidation::Accepted
#[test]
fn given_device_credential_fallback_when_policy_allows_it_then_accepted() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-abc".to_string(),
        }),
        device_credential_fallback: true,
    };
    let policy = BiometricPolicy {
        allow_device_credential: true,
        ..BiometricPolicy::default()
    };

    let validation = policy.validate(&result, None);
    assert_eq!(validation, BiometricValidation::Accepted);
}

/// Scenario: Device credential rejected when not allowed
/// Given BiometricAuthResult with device credential fallback
/// When Policy disallows device credential
/// Then BiometricValidation::Rejected
#[test]
fn given_device_credential_fallback_when_policy_disallows_it_then_rejected() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-abc".to_string(),
        }),
        device_credential_fallback: true,
    };
    let policy = BiometricPolicy {
        allow_device_credential: false,
        ..BiometricPolicy::default()
    };

    let validation = policy.validate(&result, None);
    assert_eq!(
        validation,
        BiometricValidation::Rejected(BiometricRejection::DeviceCredentialNotAllowed)
    );
}

/// Scenario: Class2 biometric accepted when policy allows Class2 minimum
#[test]
fn given_class2_biometric_when_policy_allows_class2_then_accepted() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class2,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-abc".to_string(),
        }),
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy {
        minimum_class: BiometricClass::Class2,
        ..BiometricPolicy::default()
    };

    let validation = policy.validate(&result, None);
    assert_eq!(validation, BiometricValidation::Accepted);
}

/// Scenario: Enrollment match passes validation
#[test]
fn given_matching_enrollment_id_when_validated_then_accepted() {
    let result = BiometricAuthResult {
        biometric_class: BiometricClass::Class3,
        crypto_binding: Some(CryptoBinding {
            key_id: "key-001".to_string(),
            enrollment_id: "enroll-current".to_string(),
        }),
        device_credential_fallback: false,
    };
    let policy = BiometricPolicy::default();

    // Same enrollment ID
    let validation = policy.validate(&result, Some("enroll-current"));
    assert_eq!(validation, BiometricValidation::Accepted);
}

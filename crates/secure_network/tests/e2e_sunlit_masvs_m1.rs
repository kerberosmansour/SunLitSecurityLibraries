//! E2E runtime validation tests for Milestone 1 — secure_network.
//!
//! These tests prove end-to-end integration of TLS policy enforcement,
//! certificate pinning, cleartext detection, and security event emission.

use secure_network::cert_pin::*;
use secure_network::cleartext::*;
use secure_network::tls_policy::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

/// E2E: TLS policy rejects weak version at runtime.
/// Proves TLS version enforcement works end-to-end —
/// TLS 1.0/1.1 connections are rejected with correct `Deny` result.
#[test]
fn test_tls_policy_rejects_weak_version_at_runtime() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let sink = InMemorySink::new();

    // TLS 1.0 rejected
    let result = policy.validate_and_emit(TlsVersion::Tls10, &CipherSuite::Aes256Gcm, &sink);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::TlsVersion { .. }
        }
    ));

    // TLS 1.1 rejected
    let result = policy.validate_and_emit(TlsVersion::Tls11, &CipherSuite::Aes256Gcm, &sink);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::TlsVersion { .. }
        }
    ));

    // TLS 1.2 accepted
    let result = policy.validate_and_emit(TlsVersion::Tls12, &CipherSuite::Aes256Gcm, &sink);
    assert_eq!(result, TlsValidationResult::Allow);

    // TLS 1.3 accepted
    let result = policy.validate_and_emit(TlsVersion::Tls13, &CipherSuite::Aes256Gcm, &sink);
    assert_eq!(result, TlsValidationResult::Allow);

    // Two violations emitted (1.0 and 1.1)
    let events = sink.events();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.kind == EventKind::TlsViolation));
}

/// E2E: Certificate pinning validates DER certificate chains.
/// Known-good cert matches pin; known-bad cert fails.
#[test]
fn test_cert_pin_validates_real_cert_chain() {
    let cert_der = include_bytes!("../tests/testdata/test_cert.der");
    let correct_hash = CertPinValidator::spki_hash(cert_der).unwrap();

    // Valid pin — should pass
    let mut pin_set = PinSet::new();
    pin_set.add_pin(correct_hash);
    let validator = CertPinValidator::new(pin_set);
    assert_eq!(validator.validate_der(cert_der), CertPinResult::Valid);

    // Wrong pin — should fail
    let mut wrong_pin_set = PinSet::new();
    wrong_pin_set.add_pin([0xFFu8; 32]);
    let validator = CertPinValidator::new(wrong_pin_set);
    assert_eq!(validator.validate_der(cert_der), CertPinResult::PinMismatch);

    // Chain validation — leaf matches
    let mut chain_pin_set = PinSet::new();
    chain_pin_set.add_pin(correct_hash);
    let validator = CertPinValidator::new(chain_pin_set);
    let chain: Vec<&[u8]> = vec![cert_der.as_slice()];
    assert_eq!(validator.validate_chain(&chain), CertPinResult::Valid);
}

/// E2E: Cleartext detection blocks HTTP URLs, allows HTTPS, exempts localhost.
#[test]
fn test_cleartext_detector_blocks_http_urls() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);

    // HTTP blocked
    assert_eq!(
        detector.check("http://api.example.com/data"),
        CleartextResult::CleartextBlocked
    );

    // HTTPS allowed
    assert_eq!(
        detector.check("https://api.example.com/data"),
        CleartextResult::Secure
    );

    // Localhost exempted
    assert_eq!(
        detector.check("http://127.0.0.1:8080/dev"),
        CleartextResult::ExemptedLocalhost
    );

    // FTP blocked as insecure scheme
    assert!(matches!(
        detector.check("ftp://files.example.com"),
        CleartextResult::InsecureScheme { .. }
    ));
}

/// E2E: Each violation type emits the correct EventKind via InMemorySink.
#[test]
fn test_violations_emit_security_events() {
    let sink = InMemorySink::new();

    // TLS violation
    let tls_policy = TlsPolicy::new(TlsVersion::Tls12);
    tls_policy.validate_and_emit(TlsVersion::Tls10, &CipherSuite::Aes256Gcm, &sink);
    assert_eq!(sink.events().last().unwrap().kind, EventKind::TlsViolation);

    // Cert pin failure
    let cert_der = include_bytes!("../tests/testdata/test_cert.der");
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xFFu8; 32]);
    let pin_validator = CertPinValidator::new(pin_set);
    pin_validator.validate_der_and_emit(cert_der, &sink);
    assert_eq!(
        sink.events().last().unwrap().kind,
        EventKind::CertPinFailure
    );

    // Cleartext blocked
    let detector = CleartextDetector::new();
    detector.check_and_emit("http://insecure.example.com", &sink);
    assert_eq!(
        sink.events().last().unwrap().kind,
        EventKind::CleartextBlocked
    );

    // Total: 3 events
    assert_eq!(sink.events().len(), 3);

    // Verify each type is present
    let kinds: Vec<EventKind> = sink.events().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::TlsViolation));
    assert!(kinds.contains(&EventKind::CertPinFailure));
    assert!(kinds.contains(&EventKind::CleartextBlocked));
}

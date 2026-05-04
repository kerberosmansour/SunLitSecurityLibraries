//! BDD acceptance tests for TLS policy enforcement (Milestone 1).

use secure_network::tls_policy::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

// --- Feature: TLS Policy Enforcement ---

/// Scenario: TLS 1.3 connection allowed
/// Given `TlsPolicy` configured with min version TLS 1.2
/// When Connection reports TLS 1.3
/// Then `TlsValidationResult::Allow` returned
#[test]
fn tls_13_connection_allowed() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls13, &CipherSuite::Aes256Gcm);
    assert_eq!(result, TlsValidationResult::Allow);
}

/// Scenario: TLS 1.0 connection rejected
/// Given `TlsPolicy` configured with min version TLS 1.2
/// When Connection reports TLS 1.0
/// Then `TlsValidationResult::Deny` with `TlsVersion` reason
#[test]
fn tls_10_connection_rejected() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls10, &CipherSuite::Aes256Gcm);
    assert_eq!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::TlsVersion {
                minimum: TlsVersion::Tls12,
                actual: TlsVersion::Tls10,
            },
        }
    );
}

/// Scenario: TLS 1.1 connection rejected
/// Given `TlsPolicy` configured with min version TLS 1.2
/// When Connection reports TLS 1.1
/// Then `TlsValidationResult::Deny` with `TlsVersion` reason
#[test]
fn tls_11_connection_rejected() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls11, &CipherSuite::Aes256Gcm);
    assert_eq!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::TlsVersion {
                minimum: TlsVersion::Tls12,
                actual: TlsVersion::Tls11,
            },
        }
    );
}

/// Scenario: Weak cipher suite rejected
/// Given `TlsPolicy` with cipher allowlist
/// When Connection uses RC4/DES cipher
/// Then Deny with `WeakCipher` reason
#[test]
fn weak_cipher_rc4_rejected() {
    let policy = TlsPolicy::new(TlsVersion::Tls12)
        .with_allowed_ciphers(vec![CipherSuite::Aes256Gcm, CipherSuite::Chacha20Poly1305]);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Rc4);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::WeakCipher { .. }
        }
    ));
}

#[test]
fn weak_cipher_des_rejected() {
    let policy =
        TlsPolicy::new(TlsVersion::Tls12).with_allowed_ciphers(vec![CipherSuite::Aes256Gcm]);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Des);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::WeakCipher { .. }
        }
    ));
}

#[test]
fn null_cipher_rejected() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Null);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::WeakCipher { .. }
        }
    ));
}

/// Scenario: Strong cipher suite allowed
/// Given `TlsPolicy` with cipher allowlist
/// When Connection uses AES-256-GCM
/// Then Allow
#[test]
fn strong_cipher_aes256_gcm_allowed() {
    let policy = TlsPolicy::new(TlsVersion::Tls12)
        .with_allowed_ciphers(vec![CipherSuite::Aes256Gcm, CipherSuite::Chacha20Poly1305]);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Aes256Gcm);
    assert_eq!(result, TlsValidationResult::Allow);
}

#[test]
fn chacha20_poly1305_allowed() {
    let policy = TlsPolicy::new(TlsVersion::Tls12)
        .with_allowed_ciphers(vec![CipherSuite::Aes256Gcm, CipherSuite::Chacha20Poly1305]);
    let result = policy.validate(TlsVersion::Tls13, &CipherSuite::Chacha20Poly1305);
    assert_eq!(result, TlsValidationResult::Allow);
}

/// Scenario: Cipher not in allowlist rejected
#[test]
fn cipher_not_in_allowlist_rejected() {
    let policy =
        TlsPolicy::new(TlsVersion::Tls12).with_allowed_ciphers(vec![CipherSuite::Aes256Gcm]);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Aes128Cbc);
    assert!(matches!(
        result,
        TlsValidationResult::Deny {
            reason: TlsDenyReason::WeakCipher { .. }
        }
    ));
}

/// Scenario: TLS violation emits security event
/// Given Any TLS policy violation
/// When Violation detected
/// Then `SecurityEvent` with `EventKind::TlsViolation` emitted
#[test]
fn tls_violation_emits_security_event() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let sink = InMemorySink::new();
    let result = policy.validate_and_emit(TlsVersion::Tls10, &CipherSuite::Aes256Gcm, &sink);

    assert!(matches!(result, TlsValidationResult::Deny { .. }));
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::TlsViolation);
    assert_eq!(events[0].reason_code, Some("tls_version_too_low"));
}

#[test]
fn weak_cipher_violation_emits_security_event() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let sink = InMemorySink::new();
    let result = policy.validate_and_emit(TlsVersion::Tls12, &CipherSuite::Rc4, &sink);

    assert!(matches!(result, TlsValidationResult::Deny { .. }));
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::TlsViolation);
    assert_eq!(events[0].reason_code, Some("weak_cipher_suite"));
}

#[test]
fn no_event_on_valid_connection() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let sink = InMemorySink::new();
    let result = policy.validate_and_emit(TlsVersion::Tls13, &CipherSuite::Aes256Gcm, &sink);

    assert_eq!(result, TlsValidationResult::Allow);
    assert!(sink.events().is_empty());
}

/// Scenario: No allowlist means any non-weak cipher accepted
#[test]
fn no_cipher_allowlist_accepts_non_weak() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Aes128Cbc);
    assert_eq!(result, TlsValidationResult::Allow);
}

/// Scenario: TLS 1.2 at minimum boundary is accepted
#[test]
fn tls_12_at_boundary_accepted() {
    let policy = TlsPolicy::new(TlsVersion::Tls12);
    let result = policy.validate(TlsVersion::Tls12, &CipherSuite::Aes256Gcm);
    assert_eq!(result, TlsValidationResult::Allow);
}

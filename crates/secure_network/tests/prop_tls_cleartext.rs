//! Property tests — TLS policy and cleartext detection invariants for secure_network.
//!
//! Milestone 9 — BDD: TLS and cleartext safety properties.
use proptest::prelude::*;
use secure_network::{
    CipherSuite, CleartextDetector, CleartextResult, TlsPolicy, TlsValidationResult, TlsVersion,
};

/// Helper: map u8 to a TlsVersion variant deterministically.
fn tls_version_from_u8(v: u8) -> TlsVersion {
    match v % 5 {
        0 => TlsVersion::Ssl3,
        1 => TlsVersion::Tls10,
        2 => TlsVersion::Tls11,
        3 => TlsVersion::Tls12,
        _ => TlsVersion::Tls13,
    }
}

/// Helper: map u8 to a CipherSuite variant.
fn cipher_from_u8(v: u8) -> CipherSuite {
    match v % 8 {
        0 => CipherSuite::Aes128Gcm,
        1 => CipherSuite::Aes256Gcm,
        2 => CipherSuite::Chacha20Poly1305,
        3 => CipherSuite::Aes128Cbc,
        4 => CipherSuite::Aes256Cbc,
        5 => CipherSuite::Rc4,
        6 => CipherSuite::Des,
        _ => CipherSuite::Null,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// No TlsVersion below the minimum ever returns Allow.
    #[test]
    fn prop_tls_rejects_below_min_version(
        min_idx in 0u8..5,
        actual_idx in 0u8..5,
        cipher_idx in 0u8..8,
    ) {
        let min_version = tls_version_from_u8(min_idx);
        let actual_version = tls_version_from_u8(actual_idx);
        let cipher = cipher_from_u8(cipher_idx);
        let policy = TlsPolicy::new(min_version);
        let result = policy.validate(actual_version, &cipher);

        if actual_version < min_version {
            prop_assert_ne!(
                result,
                TlsValidationResult::Allow,
                "TLS version {:?} is below minimum {:?} but was allowed",
                actual_version,
                min_version,
            );
        }
    }

    /// No http:// URL ever returns Secure (except localhost exemption).
    #[test]
    fn prop_cleartext_never_allows_http(host in "[a-z]{1,20}\\.[a-z]{2,5}", path in "[a-z/]{0,30}") {
        let url = format!("http://{host}/{path}");
        let detector = CleartextDetector::new();
        let result = detector.check(&url);
        prop_assert_ne!(
            result,
            CleartextResult::Secure,
            "http:// URL should never be Secure",
        );
    }

    /// https:// URLs always return Secure.
    #[test]
    fn prop_https_always_secure(host in "[a-z]{1,20}\\.[a-z]{2,5}", path in "[a-z/]{0,30}") {
        let url = format!("https://{host}/{path}");
        let detector = CleartextDetector::new();
        let result = detector.check(&url);
        prop_assert_eq!(
            result,
            CleartextResult::Secure,
            "https:// URL should always be Secure",
        );
    }

    /// TlsPolicy::validate never panics on any combination of inputs.
    #[test]
    fn prop_tls_validate_no_panic(
        min_idx in 0u8..5,
        actual_idx in 0u8..5,
        cipher_idx in 0u8..8,
    ) {
        let policy = TlsPolicy::new(tls_version_from_u8(min_idx));
        let _ = policy.validate(tls_version_from_u8(actual_idx), &cipher_from_u8(cipher_idx));
    }

    /// CleartextDetector::check never panics on arbitrary strings.
    #[test]
    fn prop_cleartext_check_no_panic(url in ".*") {
        let detector = CleartextDetector::new().with_localhost_exemption(true);
        let _ = detector.check(&url);
    }
}

# `secure_network` — Developer Guide

> **OWASP MASVS-NETWORK**: TLS policy validation, cleartext blocking, certificate pinning, and mTLS client identity checks.

`secure_network` is a pure policy crate. It does not open sockets or perform TLS handshakes; your HTTP/TLS stack supplies connection metadata and certificates, and this crate decides whether the result satisfies your security policy.

---

## Quick Start

```toml
[dependencies]
secure_network = "0.1.2"
```

```rust
use secure_network::{CipherSuite, TlsPolicy, TlsValidationResult, TlsVersion};

let policy = TlsPolicy::new(TlsVersion::Tls12);
let result = policy.validate(TlsVersion::Tls13, &CipherSuite::Aes256Gcm);

assert_eq!(result, TlsValidationResult::Allow);
```

---

## TLS Policy

Set the oldest protocol version your service accepts, then optionally add a cipher allowlist:

```rust
use secure_network::{CipherSuite, TlsPolicy, TlsValidationResult, TlsVersion};

let policy = TlsPolicy::new(TlsVersion::Tls12).with_allowed_ciphers(vec![
    CipherSuite::Aes128Gcm,
    CipherSuite::Aes256Gcm,
    CipherSuite::Chacha20Poly1305,
]);

assert_eq!(
    policy.validate(TlsVersion::Tls11, &CipherSuite::Aes256Gcm),
    TlsValidationResult::Deny {
        reason: secure_network::tls_policy::TlsDenyReason::TlsVersion {
            minimum: TlsVersion::Tls12,
            actual: TlsVersion::Tls11,
        },
    }
);

assert_eq!(
    policy.validate(TlsVersion::Tls13, &CipherSuite::Rc4),
    TlsValidationResult::Deny {
        reason: secure_network::tls_policy::TlsDenyReason::WeakCipher {
            cipher: CipherSuite::Rc4,
        },
    }
);
```

`validate_and_emit()` records a `TlsViolation` security event through any `security_events::sink::SecuritySink`.

---

## Cleartext Detection

Use `CleartextDetector` for URL allow/deny decisions before outbound requests, redirect targets, or mobile network policies are accepted:

```rust
use secure_network::{CleartextDetector, CleartextResult};

let detector = CleartextDetector::new();

assert_eq!(detector.check("https://api.example.com"), CleartextResult::Secure);
assert_eq!(detector.check("http://api.example.com"), CleartextResult::CleartextBlocked);
assert_eq!(
    detector.check("ftp://files.example.com"),
    CleartextResult::InsecureScheme {
        scheme: "ftp".to_string(),
    }
);
```

Local development tools can opt into a narrow localhost exception:

```rust
use secure_network::{CleartextDetector, CleartextResult};

let detector = CleartextDetector::new().with_localhost_exemption(true);
assert_eq!(detector.check("http://127.0.0.1:3000"), CleartextResult::ExemptedLocalhost);
```

---

## Certificate Pinning

Pin SHA-256 hashes of certificate Subject Public Key Info (SPKI). The validator accepts DER-encoded certificates and compares the leaf certificate by default:

```rust
use secure_network::{CertPinResult, CertPinValidator, PinSet};

let pins = PinSet::from_hex_hashes(&[
    "0000000000000000000000000000000000000000000000000000000000000000",
])?;
let validator = CertPinValidator::new(pins).with_expiry_check(true);

let result = validator.validate_der(&[]);
assert_eq!(result, CertPinResult::PinMismatch);
# Ok::<(), secure_network::NetworkSecurityError>(())
```

For a real certificate, compute the pin once from the DER leaf certificate, store it out-of-band, then validate future connections against that hash:

```rust,ignore
use secure_network::{CertPinResult, CertPinValidator, PinSet};

let spki_hash = CertPinValidator::spki_hash(leaf_cert_der)?;
let mut pins = PinSet::new();
pins.add_pin(spki_hash);

let validator = CertPinValidator::new(pins);
assert_eq!(validator.validate_chain(&[leaf_cert_der]), CertPinResult::Valid);
```

Keep at least one backup pin during certificate rotation so a planned reissue does not become an outage.

---

## mTLS Edge Identity

When TLS terminates at a trusted edge, pass the extracted client-certificate metadata into `MtlsClientIdentity`. The library validates trust source, validity bounds, and your revocation lookup:

```rust
use secure_network::{MtlsClientIdentity, MtlsClientIdentityStatus, NoMtlsRevocations};
use time::{Duration, OffsetDateTime};

let now = OffsetDateTime::now_utc();
let identity = MtlsClientIdentity::new(
    "serial-123",
    "fingerprint-abc",
    now - Duration::days(1),
    now + Duration::days(30),
    true,
);

assert_eq!(
    identity.validate_at(now, &NoMtlsRevocations),
    MtlsClientIdentityStatus::Valid
);
```

Do not trust mTLS identity headers unless the edge component is authenticated and strips spoofed inbound copies before forwarding.

---

## When To Use Which Check

| Need | API |
|---|---|
| Enforce TLS version and cipher policy | `TlsPolicy::validate()` |
| Emit audit events for TLS violations | `TlsPolicy::validate_and_emit()` |
| Block cleartext URLs and insecure schemes | `CleartextDetector::check()` |
| Emit audit events for cleartext attempts | `CleartextDetector::check_and_emit()` |
| Validate SPKI pinning | `CertPinValidator::validate_der()` or `validate_chain()` |
| Validate edge-provided mTLS identity | `MtlsClientIdentity::validate_at()` |

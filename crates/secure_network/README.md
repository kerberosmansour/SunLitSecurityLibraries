# secure_network

[![crates.io](https://img.shields.io/crates/v/secure_network.svg)](https://crates.io/crates/secure_network)
[![docs.rs](https://docs.rs/secure_network/badge.svg)](https://docs.rs/secure_network)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

TLS configuration validation, SPKI certificate pinning, mTLS identity, and cleartext detection for OWASP **MASVS-NETWORK-1** and **MASVS-NETWORK-2**. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You're shipping a mobile or desktop app and need to **pin server certificates** by SPKI hash, with current+backup pin rotation.
- You operate an mTLS gateway and need to **extract and revocation-check** client identities from a verified chain.
- You need to **validate TLS configuration** (allowed versions, cipher suites) against a policy without performing the handshake yourself.
- You need a **cleartext detector** to guarantee mobile traffic isn't slipping out over plain HTTP.

All types are pure-Rust **policy objects and validators** — they do not perform TLS handshakes. The application provides raw certificate chains and TLS parameters; this crate provides the validation logic.

## Install

```toml
[dependencies]
secure_network = "0.1"
```

## Quick examples

### Certificate pinning by SPKI SHA-256

```rust
use secure_network::cert_pin::{CertPinValidator, PinSet};

// Current pin and backup pin (best practice: always have a backup).
let pins = PinSet::from_hex_hashes(&[
    "abc123...64hex",  // SPKI SHA-256 of current cert
    "def456...64hex",  // SPKI SHA-256 of backup
])?;

let validator = CertPinValidator::new(pins);
// Pass each presented leaf certificate (DER bytes) into validator.validate()
// during connection setup; reject the connection on mismatch.
# Ok::<(), Box<dyn std::error::Error>>(())
```

### TLS configuration policy

```rust
use secure_network::tls_policy::{CipherSuite, TlsPolicy, TlsVersion};

let policy = TlsPolicy::builder()
    .min_version(TlsVersion::Tls12)
    .allow_cipher(CipherSuite::Tls13Aes256GcmSha384)
    .allow_cipher(CipherSuite::Tls13ChaCha20Poly1305Sha256)
    .build();

let result = policy.validate(TlsVersion::Tls13, CipherSuite::Tls13Aes256GcmSha384);
assert!(result.is_allow());
```

### Cleartext-traffic detection

```rust
use secure_network::cleartext::{CleartextDetector, CleartextResult};

let detector = CleartextDetector::default();
match detector.evaluate("http://api.example.com/data") {
    CleartextResult::Cleartext { .. } => panic!("plain HTTP forbidden"),
    CleartextResult::Encrypted => { /* fine */ }
}
```

## What's inside

| Module | Use it for |
|---|---|
| `cert_pin::PinSet` / `CertPinValidator` | SPKI SHA-256 pin validation with multi-pin rotation. |
| `tls_policy::TlsPolicy` | Allowed-version and allowed-cipher policy for connection setup. |
| `tls_policy::TlsValidationResult` / `TlsDenyReason` | Structured validation results for logging/telemetry. |
| `cleartext::CleartextDetector` | Detect cleartext URLs/hosts for mobile/desktop egress checks. |
| `mtls::MtlsClientIdentity` / `MtlsClientIdentityStatus` | Typed mTLS client identity extraction from a verified chain. |
| `mtls::MtlsRevocationLookup` / `NoMtlsRevocations` | Pluggable revocation hooks (CRL, OCSP, custom store). |
| `error::NetworkSecurityError` | Structured errors with no PII or hostnames. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Pure Rust; depends on `x509-parser` and `sha2`

## Status

Alpha.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

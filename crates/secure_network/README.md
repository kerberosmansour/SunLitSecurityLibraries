# secure_network

[![crates.io](https://img.shields.io/crates/v/secure_network.svg)](https://crates.io/crates/secure_network)
[![docs.rs](https://docs.rs/secure_network/badge.svg)](https://docs.rs/secure_network)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

TLS configuration validation, certificate pinning, and cleartext detection (OWASP MASVS-NETWORK-1, MASVS-NETWORK-2). Part of the **SunLit Security Libraries** workspace.

All types are pure-Rust **policy objects and validators** — they do not perform TLS handshakes. The application provides raw certificate chains and TLS parameters; this crate provides the validation logic.

## What this crate gives you

- `TlsPolicy` / `TlsValidationResult` / `TlsVersion` / `CipherSuite` — Validate TLS configuration against allowed-version and allowed-cipher policies.
- `CertPinValidator` / `PinSet` — SPKI SHA-256 certificate pinning with multi-pin (current + backup) support.
- `CleartextDetector` — Detects cleartext traffic patterns for mobile/desktop egress checks.
- `MtlsClientIdentity` / `MtlsClientIdentityStatus` / `MtlsRevocationLookup` — mTLS client-identity extraction and revocation policy.
- `NetworkSecurityError` — Structured errors with no PII or hostnames.

## Install

```toml
[dependencies]
secure_network = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

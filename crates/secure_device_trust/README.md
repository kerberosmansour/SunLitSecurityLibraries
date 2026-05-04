# secure_device_trust

[![crates.io](https://img.shields.io/crates/v/secure_device_trust.svg)](https://crates.io/crates/secure_device_trust)
[![docs.rs](https://docs.rs/secure_device_trust/badge.svg)](https://docs.rs/secure_device_trust)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Typed **native-client device-trust** policy decisions: bootstrap identity, client type and platform, attestation rollout mode, trust tiers, and short-lived session-certificate lifecycle. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

You're building a service that talks to **native desktop or mobile clients** (Tauri desktop app, iOS, Android), and you want auth that goes deeper than "the user has a JWT":

- Bind sessions to **short-lived per-device certificates** rather than long-lived bearer tokens.
- Express **trust tiers** that combine bootstrap evidence, platform attestation freshness, and revocation status.
- Get **typed CSR validation** with named rejection reasons so issuance-policy violations are observable.
- Plug into `secure_authz` for deny-by-default predicates (e.g. "this route requires HardwareTrust on iOS or macOS").

## Install

```toml
[dependencies]
secure_device_trust = "0.1"
```

## Quick example — issue a session certificate

```rust
use secure_device_trust::session::{
    SessionCertificateIssuer, SessionCertificateRequest,
    SessionCsrProfile, NoRevocations,
};
use secure_device_trust::{ClientType, Platform};

let issuer = SessionCertificateIssuer::new(
    /* signer impl */ todo!(),
    SessionCsrProfile::default_for(ClientType::Mobile, Platform::Ios),
    NoRevocations,
);

let req = SessionCertificateRequest::builder()
    .client_type(ClientType::Mobile)
    .platform(Platform::Ios)
    // .csr(...)  // user-provided CSR bytes
    .build();

match issuer.issue(&req) {
    Ok(bundle) => { /* return bundle.signed_session_certificate to the client */ }
    Err(e) => { /* reason is typed: SessionCertificateError::CsrRejected { reason: .. } */ }
}
```

## What's inside

| Type | Use it for |
|---|---|
| `ClientType` | `Desktop`, `Mobile`, `Ci`. |
| `Platform` | `MacOs`, `Ios`, `Android`, `Windows`, `Linux`, `Ci`, `Unsupported`. |
| `AttestationMode` | `Off` / `Monitor` / `Enforce` — backend-owned attestation rollout. |
| `BootstrapStatus` / `BootstrapBinding` | Authorised vs. revoked, per-install vs. shared-app credential. |
| `SessionCertificateIssuer` / `SessionCertificateSigner` | Short-lived session cert issuance pipeline. |
| `SessionCertificateRequest` / `SessionCertificateBundle` / `SignedSessionCertificate` | Issuance I/O types. |
| `SessionCsrProfile` / `CsrExtensionRequest` / `CsrRejectionReason` | Strict CSR policy with named rejection reasons. |
| `SessionExtendedKeyUsage` / `SessionSubjectAltName` | Profile-aware EKU/SAN validation. |
| `SessionCertificatePolicy` | Refresh windows and revocation-policy hooks. |
| `RevocationChecker` / `RevocationHandle` / `NoRevocations` | Pluggable revocation lookup. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Built on `security_core` for shared identity types

## Status

Alpha. Native-client device-trust is the active milestone driving this crate; expect iteration on the trust-tier policy model before 1.0.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

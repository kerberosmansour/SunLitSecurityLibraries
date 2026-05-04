# secure_device_trust

[![crates.io](https://img.shields.io/crates/v/secure_device_trust.svg)](https://crates.io/crates/secure_device_trust)
[![docs.rs](https://docs.rs/secure_device_trust/badge.svg)](https://docs.rs/secure_device_trust)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Typed native-client device-trust policy decisions. Part of the **SunLit Security Libraries** workspace.

Models bootstrap identity, client type and platform, attestation rollout mode, trust-tier decisions, and short-lived session-certificate lifecycle policy — used by `secure_identity` (passwordless step-up) and `secure_authz` (deny-by-default predicates over device trust tier and attestation freshness).

## What this crate gives you

- `ClientType` / platform / attestation-mode taxonomy for native (desktop and mobile) clients.
- `SessionCertificateIssuer` / `SessionCertificateSigner` / `SessionCertificateBundle` — Short-lived session-certificate issuance and CSR validation.
- `SessionCsrProfile` / `CsrExtensionRequest` / `CsrRejectionReason` — Strict CSR policy with named rejection reasons.
- `SessionExtendedKeyUsage` / `SessionSubjectAltName` — Profile-aware SAN/EKU validation.
- `SessionCertificatePolicy` / `RevocationChecker` — Refresh and revocation policy hooks.

## Install

```toml
[dependencies]
secure_device_trust = "0.1"
```

## Status

Alpha. Native-client device-trust is the milestone driving this crate; expect iteration on the trust-tier policy model before 1.0.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

# security_core

[![crates.io](https://img.shields.io/crates/v/security_core.svg)](https://crates.io/crates/security_core)
[![docs.rs](https://docs.rs/security_core/badge.svg)](https://docs.rs/security_core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The shared type vocabulary for the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace. Every other `secure_*` / `security_events` crate depends on this one for identity, classification, severity, correlation, time, and redaction primitives.

## When to reach for this crate

You're building a Rust service or library that needs to talk to other security crates in this workspace, or you want a consistent, redaction-aware vocabulary for identity and data classification across your own modules.

**This crate contains only types and traits — no business logic, no I/O, no async.**

## Install

```toml
[dependencies]
security_core = "0.1"
```

## What's inside

| Module | Use it for |
|---|---|
| `identity` | `AuthenticatedIdentity` — the canonical "who is making this request" type, consumed by `secure_authz`, `secure_identity`, audit logs. |
| `classification` | `DataClassification` (Public, Internal, Confidential, PII, Secret) — tag every data flow so logs and serializers can redact. |
| `severity` | `SecuritySeverity` — standardized event severity for `security_events`, RASP, and SIEM forwarding. |
| `context` | Correlation context propagated across crates and threads. |
| `redact` | Redaction primitives so secrets never escape into logs. |
| `time` | Test-friendly clock abstraction. Inject your own clock in unit tests; production gets `OffsetDateTime::now_utc()`. |
| `types` | Shared `RequestId`, `TenantId`, `TraceId`, `ActorId` newtypes. |

## Quick example

```rust
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use security_core::classification::DataClassification;
use time::OffsetDateTime;
use uuid::Uuid;

// Construct the identity an HTTP middleware would normally extract from a JWT.
let id = AuthenticatedIdentity {
    actor_id: ActorId::from(Uuid::new_v4()),
    tenant_id: Some(TenantId::from(Uuid::new_v4())),
    roles: vec!["reader".to_owned()],
    attributes: Default::default(),
    authenticated_at: OffsetDateTime::now_utc(),
};

// Tag a payload so downstream serializers know to redact it.
let class = DataClassification::PII;
assert_ne!(class, DataClassification::Public);
```

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- Pure Rust, no system dependencies

## Status

Alpha. APIs may change before 1.0; pinning to `version = "0.1"` is recommended.

## Links

- Workspace: <https://github.com/kerberosmansour/SunLitSecurityLibraries>
- Architecture overview: [ARCHITECTURE.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/ARCHITECTURE.md)
- Threat model: [THREAT_MODEL.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/THREAT_MODEL.md)

## Related crates

Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace:

| Crate | Purpose |
|---|---|
| [`security_events`](https://crates.io/crates/security_events) | Security logging and tamper-evident audit chain. |
| [`secure_errors`](https://crates.io/crates/secure_errors) | Three-layer error model with redaction-safe public errors. |
| [`secure_output`](https://crates.io/crates/secure_output) | Context-aware output encoders (HTML, JSON, URL, JS, CSS, XML, LDAP, shell). |
| [`secure_data`](https://crates.io/crates/secure_data) | Secrets, envelope encryption, Argon2id, FIPS, mobile storage. |
| [`secure_network`](https://crates.io/crates/secure_network) | TLS policy, SPKI pinning, mTLS, cleartext detection. |
| [`secure_device_trust`](https://crates.io/crates/secure_device_trust) | Native-client device trust and session certificates. |
| [`secure_resilience`](https://crates.io/crates/secure_resilience) | RASP and environment-detection policy. |
| [`secure_privacy`](https://crates.io/crates/secure_privacy) | PII classification, consent, retention, pseudonymization. |
| [`secure_boundary`](https://crates.io/crates/secure_boundary) | Input validation, security headers, boundary protections. |
| [`secure_identity`](https://crates.io/crates/secure_identity) | JWT/OIDC, MFA, sessions, biometric step-up. |
| [`secure_authz`](https://crates.io/crates/secure_authz) | Typed deny-by-default authorization with device-trust predicates. |

## Getting help

- **Questions, ideas, design discussions** — open a [GitHub Discussion](https://github.com/kerberosmansour/SunLitSecurityLibraries/discussions).
- **Bug reports** — use the bug-report template in [GitHub Issues](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues).
- **Security issues** — please do **not** open a public issue. See [SECURITY.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/SECURITY.md) for the responsible-disclosure process.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CODE_OF_CONDUCT.md) before opening a PR.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

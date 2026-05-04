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

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

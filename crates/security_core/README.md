# security_core

[![crates.io](https://img.shields.io/crates/v/security_core.svg)](https://crates.io/crates/security_core)
[![docs.rs](https://docs.rs/security_core/badge.svg)](https://docs.rs/security_core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Shared types, traits, and abstractions for the **SunLit Security Libraries** — the foundation that every other `secure_*` / `security_*` crate in this workspace builds on. Pure types and traits, no business logic, no I/O.

## What this crate gives you

- `identity` — `AuthenticatedIdentity` and identity-resolution traits used by `secure_authz`, `secure_identity`, and friends.
- `classification` — `DataClassification` levels for tagging data flows.
- `severity` — Standardized severity levels for security signals.
- `context` — Correlation context for cross-crate tracing.
- `redact` — Redaction primitives so secrets never escape into logs.
- `time` — Time abstraction (clock injection for tests + replay-safe timestamps).
- `types` — Shared identifier and policy types.

## Install

```toml
[dependencies]
security_core = "0.1"
```

## Status

Alpha. API may change before 1.0. Pinned to `version = "0.1.x"` recommended until then.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries
- Architecture: [ARCHITECTURE.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/ARCHITECTURE.md)
- Threat model: [THREAT_MODEL.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/THREAT_MODEL.md)

## License

Dual-licensed under MIT or Apache-2.0 at your option.

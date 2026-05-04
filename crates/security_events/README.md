# security_events

[![crates.io](https://img.shields.io/crates/v/security_events.svg)](https://crates.io/crates/security_events)
[![docs.rs](https://docs.rs/security_events/badge.svg)](https://docs.rs/security_events)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Security logging, monitoring, and tamper-evident audit trail (OWASP C9). Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You need **strongly-typed security events** instead of free-form log lines, so SIEMs, redactors, and policy engines can reason about them.
- You need a **tamper-evident audit chain** (HMAC-sealed events) for compliance contexts.
- You're shipping events to multiple sinks (stdout JSON, OpenTelemetry, HTTP collector) and want one schema to feed them.
- You want **PII redaction** and rate-limiting at the event layer rather than scattered across call sites.

## Install

```toml
[dependencies]
security_events = "0.1"

# OpenTelemetry integration:
# security_events = { version = "0.1", features = ["otel"] }
```

## What's inside

| Module | Use it for |
|---|---|
| `event::SecurityEvent` | The strongly-typed event record (kind, outcome, severity, classification). |
| `kind::EventKind` | Standardized event categories (auth, authz, data access, network, etc.). |
| `event::EventOutcome` | `Success`, `Failure`, `Blocked`, `Unknown`. |
| `event::EventValue::Classified` | Field values carrying their `DataClassification` so sinks can redact. |
| `audit_chain::AuditChain` | Hash-chained, tamper-evident audit log. Each event commits to its predecessor. |
| `hmac::HmacEventSigner` | HMAC-seal events for integrity-verified shipping to a remote collector. |
| `correlation` | Parent/child correlation IDs (`with_parent`, `attach_parent`, `filter_by_parent`). |
| `redact::RedactionEngine` | Programmatic redaction policy for PII fields. |
| `mobile_redaction::MobileRedactionEngine` | Stricter mobile-OS log-level enforcement. |
| `rate_limit` | Drop or aggregate noisy event sources without losing high-severity signals. |
| `sink` | Pluggable event sinks (stdout, JSON, OTel, HTTP). |
| `layer` | `tracing` `Layer` so events flow alongside spans. |

## Quick example

```rust
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;

// Build a typed authentication-failure event for the audit log.
let event = SecurityEvent::builder()
    .kind(EventKind::Authentication)
    .outcome(EventOutcome::Failure)
    .severity(SecuritySeverity::Medium)
    .field("user_email", EventValue::Classified {
        value: "user@example.com".to_owned(),
        classification: DataClassification::PII,  // sink will redact
    })
    .build();

// Emit to whichever sink(s) you've configured.
// (See `security_events::sink` for stdout / JSON / OTel / HTTP sinks.)
```

## Feature flags

| Flag | Default | Purpose |
|---|---|---|
| `otel` | off | OpenTelemetry-tracing integration via `tracing-opentelemetry` and `opentelemetry`. |
| `http-sink` | off | Ship events to an HTTP collector via `reqwest`. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- Async-friendly but does not require an async runtime in core paths

## Status

Alpha.

## Related crates

Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace:

| Crate | Purpose |
|---|---|
| [`security_core`](https://crates.io/crates/security_core) | Shared types, identity, classification, severity, redaction. |
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

# security_events

[![crates.io](https://img.shields.io/crates/v/security_events.svg)](https://crates.io/crates/security_events)
[![docs.rs](https://docs.rs/security_events/badge.svg)](https://docs.rs/security_events)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Security logging, monitoring, and tamper-evident audit (OWASP C9). Part of the **SunLit Security Libraries** workspace.

## What this crate gives you

- `SecurityEvent` — Strongly-typed event records with `EventKind`, `EventOutcome`, `EventValue`.
- `AuditChain` — Hash-chained, tamper-evident event log.
- `HmacEventSigner` — HMAC-sealed events for integrity-verified shipping.
- `redact` / `sanitize` / `mobile_redaction` — Make sure PII and secrets never reach a sink.
- `correlation` — Parent/child correlation IDs across services and sinks.
- `rate_limit` — Drop or aggregate noisy event sources without losing high-severity ones.
- `sink` — Pluggable event sinks (stdout, JSON, OTel, HTTP).
- `layer` — `tracing` `Layer` integration so events flow alongside spans.

## Feature flags

| Flag | Default | Purpose |
|---|---|---|
| `otel` | off | OpenTelemetry-tracing integration via `tracing-opentelemetry`/`opentelemetry`. |
| `http-sink` | off | Ship events to an HTTP collector via `reqwest`. |

## Install

```toml
[dependencies]
security_events = "0.1"
```

## Status

Alpha. API may change before 1.0.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries
- Architecture: [ARCHITECTURE.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/ARCHITECTURE.md)

## License

Dual-licensed under MIT or Apache-2.0 at your option.

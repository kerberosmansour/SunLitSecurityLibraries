# secure_resilience

[![crates.io](https://img.shields.io/crates/v/secure_resilience.svg)](https://crates.io/crates/secure_resilience)
[![docs.rs](https://docs.rs/secure_resilience/badge.svg)](https://docs.rs/secure_resilience)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Anti-tampering and environment-detection policy engine for **MASVS-RESILIENCE**. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

You're building a mobile or desktop client that needs **runtime self-protection** (RASP) — root/jailbreak detection, emulator detection, debugger detection, and integrity checks — and you want a policy engine that can:

- Aggregate signals from many platform-specific probes into a single threat level.
- Decide an action (`Allow`, `Warn`, `Block`, `Degrade`) based on configurable policy.
- Emit `security_events` for every block/degrade decision so you have an audit trail.

This crate is a **pure policy engine** — *you* write the platform-specific probes (or use a vendor SDK), and you feed signals in. This crate decides what to do with them.

## Install

```toml
[dependencies]
secure_resilience = "0.1"
```

## Quick example — RASP decision pipeline

```rust
use secure_resilience::{
    EnvironmentSignal, ThreatLevel, Confidence,
    RaspEngine, RaspPolicy, RaspDecision, ResponseAction,
};

// Configure policy: jailbreak high-confidence -> block; medium -> warn.
let policy = RaspPolicy::builder()
    .on_signal_category("jailbreak", ResponseAction::Block)
    .on_signal_category("debugger", ResponseAction::Degrade)
    .build();

let engine = RaspEngine::new(policy);

// A platform probe detected jailbreak with high confidence.
let signal = EnvironmentSignal::builder()
    .category("jailbreak")
    .confidence(Confidence::High)
    .threat_level(ThreatLevel::Critical)
    .build();

match engine.evaluate(&signal) {
    RaspDecision::Block { signal_category } => {
        // Refuse the operation, surface the user-safe error.
    }
    RaspDecision::Degrade { capabilities_removed } => {
        // Continue but disable sensitive capabilities listed.
    }
    RaspDecision::Warn { .. } | RaspDecision::Allow => { /* proceed */ }
}
```

## What's inside

| Module | Use it for |
|---|---|
| `environment::EnvironmentSignal` / `Confidence` / `ThreatLevel` | The signal-input vocabulary your probes feed in. |
| `rasp::RaspEngine` / `RaspPolicy` / `RaspDecision` / `ResponseAction` | Policy aggregation and decision output. |
| `integrity::IntegrityCheck` / `IntegrityCheckResult` / `IntegrityResult` | App-bundle integrity verification primitives. |
| `error::ResilienceError` | Structured, redaction-safe errors. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Emits `security_events::SecurityEvent` for block/degrade decisions

## Status

Alpha.

## Related crates

Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace:

| Crate | Purpose |
|---|---|
| [`security_core`](https://crates.io/crates/security_core) | Shared types, identity, classification, severity, redaction. |
| [`security_events`](https://crates.io/crates/security_events) | Security logging and tamper-evident audit chain. |
| [`secure_errors`](https://crates.io/crates/secure_errors) | Three-layer error model with redaction-safe public errors. |
| [`secure_output`](https://crates.io/crates/secure_output) | Context-aware output encoders (HTML, JSON, URL, JS, CSS, XML, LDAP, shell). |
| [`secure_data`](https://crates.io/crates/secure_data) | Secrets, envelope encryption, Argon2id, FIPS, mobile storage. |
| [`secure_network`](https://crates.io/crates/secure_network) | TLS policy, SPKI pinning, mTLS, cleartext detection. |
| [`secure_device_trust`](https://crates.io/crates/secure_device_trust) | Native-client device trust and session certificates. |
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

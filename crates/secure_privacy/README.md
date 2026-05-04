# secure_privacy

[![crates.io](https://img.shields.io/crates/v/secure_privacy.svg)](https://crates.io/crates/secure_privacy)
[![docs.rs](https://docs.rs/secure_privacy/badge.svg)](https://docs.rs/secure_privacy)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Data-minimization and privacy-control policy engine for OWASP **MASVS-PRIVACY**. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You need a **PII classifier** that scans free-form fields for emails, phone numbers, IPs, IMEIs, or your own custom regex patterns.
- You're implementing **purpose-bound consent** and want a typed state machine instead of a homegrown bool grid.
- You need **time-window data retention** with structured `expired` / `due_soon` / `active` decisions.
- You need **reversible pseudonymization** for analytics joins without leaking the underlying identifier.

Pure policy engine: storage and UI are yours; this crate provides the state machines, validators, and classifiers.

## Install

```toml
[dependencies]
secure_privacy = "0.1"
```

## Quick examples

### PII classification

```rust
use secure_privacy::{PiiClassification, PiiClassifier};

let classifier = PiiClassifier::new();
assert_eq!(classifier.classify("user@example.com"), PiiClassification::Email);
assert_eq!(classifier.classify("(415) 555-0123"),  PiiClassification::PhoneNumber);
assert_eq!(classifier.classify("192.168.1.42"),    PiiClassification::IpAddress);
assert_eq!(classifier.classify("hello world"),     PiiClassification::None);

// Add a custom pattern (e.g. internal account ID).
let mut custom = PiiClassifier::new();
custom.add_pattern("acct_id", r"^acct_[A-Z0-9]{12}$").unwrap();
assert_eq!(custom.classify("acct_AB12CD34EF56"),
           PiiClassification::Custom("acct_id".to_owned()));
```

### Purpose-bound consent

```rust
use secure_privacy::{ConsentDecision, ConsentPolicy, ConsentPurpose, ConsentState};

let policy = ConsentPolicy::default();

let decision = policy.evaluate(
    ConsentState::Granted,
    ConsentPurpose::Analytics,
);
match decision {
    ConsentDecision::Allow => { /* track */ }
    ConsentDecision::Deny { .. } => { /* don't track */ }
}
```

### Retention enforcement

```rust
use secure_privacy::{RetentionPolicy, RetentionStatus};
use time::{Duration, OffsetDateTime};

let policy = RetentionPolicy::days(30);

let created_at = OffsetDateTime::now_utc() - Duration::days(45);
match policy.evaluate(created_at) {
    RetentionStatus::Expired => { /* delete */ }
    RetentionStatus::Active { .. } => { /* keep */ }
    RetentionStatus::DueSoon { .. } => { /* schedule deletion */ }
}
```

## What's inside

| Module | Use it for |
|---|---|
| `classifier::PiiClassifier` / `PiiClassification` | Detect emails, phone numbers, IPs, IMEIs, and custom-regex PII. |
| `consent::ConsentPolicy` / `ConsentDecision` / `ConsentPurpose` / `ConsentState` | Typed purpose-bound consent state machine. |
| `pseudonymizer::Pseudonymizer` / `PseudonymizedValue` | Reversible pseudonymization for analytics joins. |
| `retention::RetentionPolicy` / `RetentionStatus` | Time-window retention with structured outcomes. |
| `error::PrivacyError` | Structured, redaction-safe errors. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

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
| [`secure_resilience`](https://crates.io/crates/secure_resilience) | RASP and environment-detection policy. |
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

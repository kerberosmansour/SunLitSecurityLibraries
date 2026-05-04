# secure_privacy

[![crates.io](https://img.shields.io/crates/v/secure_privacy.svg)](https://crates.io/crates/secure_privacy)
[![docs.rs](https://docs.rs/secure_privacy/badge.svg)](https://docs.rs/secure_privacy)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Data minimization and privacy controls (OWASP MASVS-PRIVACY). Part of the **SunLit Security Libraries** workspace.

Pure-Rust **policy engine** for PII discovery/classification, pseudonymization, consent tracking, and retention. The consuming app implements storage and UI; this crate provides the state machine, validation, and classification logic.

## What this crate gives you

- `PiiClassifier` / `PiiClassification` — Detect and classify PII fields in structured data.
- `Pseudonymizer` / `PseudonymizedValue` — Reversible pseudonymization for joined analytics workflows.
- `ConsentPolicy` / `ConsentDecision` / `ConsentPurpose` / `ConsentState` — Purpose-bound consent state machine.
- `RetentionPolicy` / `RetentionStatus` — Time-window retention policy with structured outcomes.
- `PrivacyError` — Structured, redaction-safe errors.

## Install

```toml
[dependencies]
secure_privacy = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

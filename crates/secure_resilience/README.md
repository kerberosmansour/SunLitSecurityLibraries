# secure_resilience

[![crates.io](https://img.shields.io/crates/v/secure_resilience.svg)](https://crates.io/crates/secure_resilience)
[![docs.rs](https://docs.rs/secure_resilience/badge.svg)](https://docs.rs/secure_resilience)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Anti-tampering and environment detection (OWASP MASVS-RESILIENCE). Part of the **SunLit Security Libraries** workspace.

Pure-Rust **policy engine** for environment-detection signals and integrity verification. The consuming app implements platform-specific detection (e.g. root/jailbreak probes) and feeds signals into this crate for policy evaluation.

## What this crate gives you

- `EnvironmentSignal` / `Confidence` / `ThreatLevel` — Typed environment-detection signals (root/jailbreak, emulator, debugger).
- `IntegrityCheck` / `IntegrityCheckResult` / `IntegrityResult` — App-integrity verification.
- `RaspEngine` / `RaspPolicy` / `RaspDecision` / `ResponseAction` — Runtime Application Self-Protection signal aggregation and response policy.
- `ResilienceError` — Structured, redaction-safe errors.

## Install

```toml
[dependencies]
secure_resilience = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

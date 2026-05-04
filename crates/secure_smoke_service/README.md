# secure_smoke_service

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Not published to crates.io** (`publish = false`). This crate is a verification microservice — not a demo, not a starter template.

## What it is

A purpose-built axum (and optional actix-web) microservice with **50+ routes**, each exercising one specific security control from the SunLit Security Libraries. Used by the **Dastardly DAST scan** in CI to catch regressions across the boundary, output, identity, authz, data, network, resilience, and privacy controls.

## What it covers

| Route family | Crate exercised |
|---|---|
| `/smoke/xss`, `/smoke/sqli`, `/smoke/path-traversal`, … | `secure_boundary` (validation, deep-link safety, webview-file blocks) |
| `/smoke/encode/*` | `secure_output` (HTML, JSON, URL, JS, CSS, XML, LDAP, shell encoders) |
| `/smoke/auth/*`, `/smoke/biometric/*` | `secure_identity` (incl. biometric and device-binding) |
| `/smoke/authz/*`, `/smoke/device-trust/*` | `secure_authz` |
| `/smoke/data/*`, `/smoke/mobile-storage/*` | `secure_data` (incl. mobile-storage features) |
| `/smoke/network/*`, `/smoke/cleartext` | `secure_network` |
| `/smoke/resilience/*` | `secure_resilience` |
| `/smoke/privacy/*` | `secure_privacy` |
| `/smoke/error/*` | `secure_errors` |

## Run locally

```bash
cargo run -p secure_smoke_service
```

Then point any DAST scanner (or `curl`) at `http://127.0.0.1:8080`.

## Why a separate service from `secure_reference_service`?

- **`secure_reference_service`** demonstrates one **good** end-to-end wiring of the workspace.
- **`secure_smoke_service`** intentionally exposes one route per control so a black-box scanner can prove each control fires. It is *not* a recommended composition.

## Links

- Workspace: <https://github.com/kerberosmansour/SunLitSecurityLibraries>
- Dastardly scan workflow: [`.github/workflows/dastardly.yml`](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/.github/workflows/dastardly.yml)

## Related crates (published on crates.io)

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

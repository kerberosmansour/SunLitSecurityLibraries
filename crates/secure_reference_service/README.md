# secure_reference_service

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Not published to crates.io** (`publish = false`). This crate is an in-tree reference axum service used for integration testing and as a worked example of how the workspace crates compose end-to-end.

## What it demonstrates

A small axum service wired with the full SunLit Security Libraries stack:

- **`secure_boundary`** — secure JSON extractors with four-stage validation, security headers, Fetch Metadata, and secure CORS.
- **`secure_errors`** — single-source-of-truth error mapping; every error response goes through `into_response_parts` so the wire shape is stable.
- **`secure_identity`** — JWT/OIDC authentication producing `AuthenticatedIdentity`.
- **`secure_authz`** — `AuthzLayer` enforcing deny-by-default policy on guarded routes.
- **`secure_data`** — secret/envelope-encryption primitives in handler logic.
- **`secure_output`** — context-aware encoders for response payloads.
- **`secure_network`** — TLS policy and pin validation utilities.
- **`security_events`** — structured audit events emitted alongside spans.
- **`resilience::ResilienceConfig`** — timeout budgeting and retry policy.

The library facade exposes `build_router(state, &resilience_config)` so integration tests can spin up the same stack the binary runs.

## Run locally

```bash
cargo run -p secure_reference_service
```

## Used by

- Workspace integration tests under `crates/secure_reference_service/tests/`.
- `Crate Packaging Preflight` and feature-matrix CI jobs as a smoke target.

## Links

- Workspace: <https://github.com/kerberosmansour/SunLitSecurityLibraries>
- Architecture overview: [ARCHITECTURE.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/ARCHITECTURE.md)

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

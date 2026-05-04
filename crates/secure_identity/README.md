# secure_identity

[![crates.io](https://img.shields.io/crates/v/secure_identity.svg)](https://crates.io/crates/secure_identity)
[![docs.rs](https://docs.rs/secure_identity/badge.svg)](https://docs.rs/secure_identity)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Authentication helpers for JWT, OIDC, MFA, API keys, sessions, and step-up policy. Part of the **SunLit Security Libraries** workspace.

## What this crate gives you

- `Authenticator` / `AuthenticationRequest` / `TokenKind` — Pluggable authentication entry-point with TOTP and password backends.
- `jwks` — JWKS discovery, caching, and signature verification.
- `mfa` / `totp` — Step-up MFA with TOTP.
- `api_key` — API key issuance and validation.
- `session` — Session creation, expiration, and revocation policy.
- `passwordless` — Passwordless authentication helpers.
- `auth_events` — `security_events`-typed authentication audit emission.
- `boot` / `dev` — Bootstrapping for production wiring and a dev-only stub.
- `error` — Structured, redaction-safe authentication errors.

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `oidc` | off | `oidc` module — OIDC discovery and PKCE-first authentication via `openidconnect` + `reqwest`. |
| `session-redis` | off | `session_redis` — Redis-backed session storage. |
| `biometric` | off | `biometric`, `device_binding`, `step_up` — biometric auth, device binding, step-up policy (MASVS-AUTH-2, MASVS-AUTH-3). |

## Install

```toml
[dependencies]
secure_identity = { version = "0.1", features = ["oidc"] }
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

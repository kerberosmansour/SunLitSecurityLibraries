# secure_identity

[![crates.io](https://img.shields.io/crates/v/secure_identity.svg)](https://crates.io/crates/secure_identity)
[![docs.rs](https://docs.rs/secure_identity/badge.svg)](https://docs.rs/secure_identity)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Authentication building blocks: JWT validation, JWKS, OIDC (PKCE), API keys, sessions, MFA/TOTP, biometric step-up, and passwordless flows. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You're integrating an OIDC provider and want **PKCE-first authorization-code flow** with cached JWKS.
- You need **MFA/TOTP** with replay defense and clock-skew tolerance.
- You need **API key issuance/validation** that survives a key-leak audit.
- You want **biometric step-up** + device-binding (MASVS-AUTH-2/3).
- You want a **production-safe boot check** that refuses to start a service which has a `DevAuthenticator` registered in `APP_ENV=production`.

Output is a `security_core::identity::AuthenticatedIdentity`, which `secure_authz` consumes to make policy decisions.

## Install

```toml
[dependencies]
secure_identity = "0.1.2"

# OIDC (PKCE) flows:
# secure_identity = { version = "0.1.2", features = ["oidc"] }

# Redis-backed sessions:
# secure_identity = { version = "0.1.2", features = ["session-redis"] }

# Biometric / device-binding / step-up:
# secure_identity = { version = "0.1.2", features = ["biometric"] }
```

## Quick example — production boot check

```rust
use secure_identity::boot::assert_no_dev_identity_in_production;

fn main() {
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    let has_dev_source = /* true iff your authenticator chain has DevAuthenticator */ false;

    if let Err(violation) = assert_no_dev_identity_in_production(&app_env, has_dev_source) {
        // Crash before any request handler runs.
        panic!("{violation}");
    }
    // ... start the service
}
```

## What's inside

| Module | Use it for |
|---|---|
| `authenticator::Authenticator` / `AuthenticationRequest` / `TokenKind` | Pluggable authentication entry-point. |
| `jwks` | JWKS discovery, caching, and RSA/EC signature verification. |
| `token` | JWT issuance/validation with strict alg enforcement. |
| `mfa` / `totp` | TOTP step-up with replay defense and skew tolerance. |
| `api_key` | API key issuance and constant-time validation. |
| `session` | Session creation, expiration, and revocation policy. |
| `session_redis` (feature) | Redis-backed session storage. |
| `passwordless` | Passwordless authentication helpers. |
| `oidc` (feature) | OIDC discovery + PKCE auth-code flow via `openidconnect`. |
| `biometric` / `device_binding` / `step_up` (feature) | Biometric, device-binding, and step-up policy (MASVS-AUTH-2/3). |
| `boot` | `assert_no_dev_identity_in_production` startup guard. |
| `dev` | A `DevAuthenticator` for tests; production boot guards against this. |
| `auth_events` | `security_events`-typed authentication audit events. |

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `oidc` | off | `oidc` module — OIDC discovery and PKCE-first authentication via `openidconnect` + `reqwest`. |
| `session-redis` | off | `session_redis` — Redis-backed session storage. |
| `biometric` | off | `biometric`, `device_binding`, `step_up` (MASVS-AUTH-2, MASVS-AUTH-3). |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Boot-time guard against `DevAuthenticator` reaching production

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
| [`secure_privacy`](https://crates.io/crates/secure_privacy) | PII classification, consent, retention, pseudonymization. |
| [`secure_boundary`](https://crates.io/crates/secure_boundary) | Input validation, security headers, boundary protections. |
| [`secure_authz`](https://crates.io/crates/secure_authz) | Typed deny-by-default authorization with device-trust predicates. |

## Getting help

- **Questions, ideas, design discussions** — open a [GitHub Discussion](https://github.com/kerberosmansour/SunLitSecurityLibraries/discussions).
- **Bug reports** — use the bug-report template in [GitHub Issues](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues).
- **Security issues** — please do **not** open a public issue. See [SECURITY.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/SECURITY.md) for the responsible-disclosure process.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CODE_OF_CONDUCT.md) before opening a PR.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

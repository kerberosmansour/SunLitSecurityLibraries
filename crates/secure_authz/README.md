# secure_authz

[![crates.io](https://img.shields.io/crates/v/secure_authz.svg)](https://crates.io/crates/secure_authz)
[![docs.rs](https://docs.rs/secure_authz/badge.svg)](https://docs.rs/secure_authz)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Deny-by-default authorization (OWASP **C7**) with typed subjects/actions/resources, RBAC + ABAC, tenant isolation, native device-trust predicates, and HTTP-framework middleware. Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## What this gives you

- **Identity-agnostic.** Feed it `security_core::identity::AuthenticatedIdentity` from `secure_identity`, Keycloak, Auth0, or your own.
- **Typed subjects, actions, resources** — no role strings in business code.
- **Pluggable policy engine.** Default is casbin RBAC; swap in your own `Authorizer`.
- **Tenant isolation** primitives that prevent cross-tenant resource access by construction.
- **Bounded LRU decision cache** with TTL — fast, but never unbounded.
- **Native device-trust predicates** that combine `secure_device_trust`, `secure_identity`, and `secure_network` context — express "this route requires a session pinned to verified mTLS, on a hardware-attested iOS device".
- **HTTP middleware** — `AuthzLayer` (axum) and `AuthzTransform` (actix-web).

## Install

```toml
[dependencies]
secure_authz = "0.1.2"  # default features: ["axum"]

# For actix-web:
# secure_authz = { version = "0.1.2", default-features = false, features = ["actix-web"] }
```

## Quick example (axum) — guard a route with `AuthzLayer`

```rust
use std::sync::Arc;
use axum::{routing::get, Router};
use secure_authz::action::Action;
use secure_authz::resource::ResourceRef;
use secure_authz::middleware::AuthzLayer;
use secure_authz::testkit::MockAuthorizer;  // for tests; use a real Authorizer in prod

async fn list_items() -> &'static str { "you may read items" }

let authz = Arc::new(MockAuthorizer::allow());
let app = Router::new()
    .route("/items", get(list_items))
    .layer(AuthzLayer::new(authz, Action::Read, ResourceRef::new("item")));
// Upstream auth middleware (e.g. secure_identity) must put an
// AuthenticatedIdentity into request extensions before AuthzLayer runs.
```

## Quick example (actix-web)

See [`examples/actix_authz_minimal.rs`](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/crates/secure_authz/examples/actix_authz_minimal.rs) — a complete runnable service wiring `AuthzTransform` plus a stand-in upstream auth middleware. Run it with:

```bash
cargo run --example actix_authz_minimal -p secure_authz --features actix-web
```

## What's inside

| Module / type | Use it for |
|---|---|
| `subject` / `action::Action` / `resource::ResourceRef` | Typed subject/action/resource vocabulary. |
| `policy` / `Authorizer` trait | Plug your own policy engine. |
| `casbin_engine` | Default casbin RBAC implementation. |
| `tenant` | Tenant-isolation primitives. |
| `cache` | Bounded LRU decision cache with TTL. |
| `device_trust` | Predicates combining `secure_device_trust`, `secure_identity`, and `secure_network` context. |
| `middleware::AuthzLayer` | axum tower `Layer` (feature `axum`). |
| `actix::AuthzTransform` | actix-web middleware (feature `actix-web`). |
| `testkit::MockAuthorizer` | `MockAuthorizer::allow()` / `::deny()` for unit tests. |

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | `middleware::AuthzLayer` as a tower `Layer`. |
| `actix-web` | off | `actix::AuthzTransform` as an actix middleware. |

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
| [`secure_privacy`](https://crates.io/crates/secure_privacy) | PII classification, consent, retention, pseudonymization. |
| [`secure_boundary`](https://crates.io/crates/secure_boundary) | Input validation, security headers, boundary protections. |
| [`secure_identity`](https://crates.io/crates/secure_identity) | JWT/OIDC, MFA, sessions, biometric step-up. |

## Getting help

- **Questions, ideas, design discussions** — open a [GitHub Discussion](https://github.com/kerberosmansour/SunLitSecurityLibraries/discussions).
- **Bug reports** — use the bug-report template in [GitHub Issues](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues).
- **Security issues** — please do **not** open a public issue. See [SECURITY.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/SECURITY.md) for the responsible-disclosure process.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CODE_OF_CONDUCT.md) before opening a PR.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

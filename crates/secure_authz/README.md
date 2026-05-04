# secure_authz

[![crates.io](https://img.shields.io/crates/v/secure_authz.svg)](https://crates.io/crates/secure_authz)
[![docs.rs](https://docs.rs/secure_authz/badge.svg)](https://docs.rs/secure_authz)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Authorization enforcement (OWASP C7). Part of the **SunLit Security Libraries** workspace.

Framework-neutral core plus optional HTTP framework adapters. Identity-agnostic — feed it `security_core::identity::AuthenticatedIdentity` from `secure_identity`, Keycloak, Auth0, or any custom provider.

## What this crate gives you

- Typed subjects, actions, and resources — no role strings in business code.
- Pluggable policy engine (default: casbin RBAC).
- Tenant isolation primitives.
- Bounded LRU decision cache with TTL.
- `device_trust` predicates that accept `secure_device_trust`, `secure_identity`, and `secure_network` context — route policies can prove a session is pinned to verified mTLS.
- `middleware::AuthzLayer` (axum) and `actix::AuthzTransform` (actix-web) middleware.

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | `middleware::AuthzLayer` as a tower `Layer`. |
| `actix-web` | off | `actix::AuthzTransform` as an actix middleware. |

## Install

```toml
[dependencies]
secure_authz = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

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
secure_authz = "0.1"  # default features: ["axum"]

# For actix-web:
# secure_authz = { version = "0.1", default-features = false, features = ["actix-web"] }
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

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

# `secure_authz` on Actix-web 4 — integration guide

> Part of the [SunLitSecurityLibraries dev-guide](./README.md). Target audience: engineers adding authorization enforcement to an Actix-web 4 service with `secure_authz`.

## What `AuthzTransform` gives you

A drop-in Actix-web 4 middleware that enforces an [`Authorizer`] decision on every request:

- Reads an `AuthenticatedIdentity` from request extensions (set by an upstream auth middleware).
- Resolves the identity into a `Subject` via the identity-agnostic `DefaultSubjectResolver`.
- Calls `Authorizer::authorize(subject, action, resource)`.
- Short-circuits with **403 Forbidden** if:
  - no identity is present, or
  - the authorizer returns `Decision::Deny`, or
  - the decision is `Decision::Allow { obligations: [...] }` and any listed obligation is not present in the request's `ObligationFulfillment` marker.

Behaviorally identical to the axum [`AuthzLayer`] — same rejection semantics, same `Decision::Deny` handling, same obligation short-circuit. Cross-framework parity is a test-enforced invariant (see [`sg_gate_a_parity_authz.rs`](../../crates/secure_authz/tests/sg_gate_a_parity_authz.rs)).

## Adding the dependency

```toml
[dependencies]
secure_authz = { version = "0.1.2", default-features = false, features = ["actix-web"] }
security_core = "0.1.2"   # only if you need AuthenticatedIdentity types directly
actix-web = "4"
```

`default-features = false` disables the (default) `axum` feature. Omit it if you want both the tower `AuthzLayer` and the Actix `AuthzTransform` available in the same crate (mixed-framework workspace).

## Wiring identity upstream

`AuthzTransform` reads from request extensions — it does not authenticate tokens itself. Put your auth middleware (JWT validator, session resolver, `secure_identity` adapter, etc.) BEFORE `AuthzTransform` in the wrap chain. `secure_authz` never imports an identity crate; you bring your own.

The minimal contract an upstream auth middleware must satisfy:

```rust,ignore
use actix_web::HttpMessage;
use security_core::identity::AuthenticatedIdentity;

// Inside your auth middleware's `call`:
req.extensions_mut().insert(AuthenticatedIdentity {
    actor_id,                    // from your ID provider
    tenant_id,                   // optional
    roles,                       // from claims
    attributes,                  // from claims
    authenticated_at,            // when the token was verified
});
```

That's all `AuthzTransform` needs to see.

## Declaring the action/resource for a route

```rust,ignore
use actix_web::{web, App, HttpResponse};
use std::sync::Arc;
use secure_authz::action::Action;
use secure_authz::actix::AuthzTransform;
use secure_authz::resource::ResourceRef;

let authz = Arc::new(your_authorizer());

let _app = App::new()
    // Install upstream auth FIRST so the identity is in extensions
    // before AuthzTransform reads it.
    .wrap(your_upstream_auth_middleware())
    // Then AuthzTransform.
    .wrap(AuthzTransform::new(
        authz,
        Action::Read,
        ResourceRef::new("article").with_tenant("acme"),
    ))
    .route("/articles", web::get().to(|| async { HttpResponse::Ok().body("ok") }));
```

The middleware order in Actix is OUTER-first on request, INNER-first on response — so `.wrap(auth).wrap(authz)` means the auth middleware runs first on the request path, exactly what we want.

## Obligations (MFA, step-up)

If a policy returns `Decision::Allow { obligations: ["mfa"] }`, the enforcer checks the request for a matching `ObligationFulfillment`:

```rust,ignore
use actix_web::HttpMessage;
use secure_authz::enforce::ObligationFulfillment;

// Inside an MFA-verifying middleware:
if mfa_was_verified(&req) {
    req.extensions_mut().insert(ObligationFulfillment {
        fulfilled: vec!["mfa".to_owned()],
    });
}
```

If any listed obligation is missing from `fulfilled`, `AuthzTransform` short-circuits with 403. A policy that returns `Allow` with an empty `obligations` vector never requires fulfillment.

## Cross-reference with axum adapter

| | axum | actix-web 4 |
|---|---|---|
| Layer/middleware | `AuthzLayer` (tower) | `AuthzTransform` (actix) |
| Subject resolution | `DefaultSubjectResolver` — same | `DefaultSubjectResolver` — same |
| Decision enforcement | `enforce::run_check` | `enforce::run_check` (shared) |
| Deny response | 403 empty body | 403 empty body |
| Obligation fulfilled | `ObligationFulfillment` ext | `ObligationFulfillment` ext |
| Missing identity | 403 | 403 |

The shared `enforce::run_check` is the single source of truth. If you write a middleware that needs the same enforcement outside a standard framework, call `run_check` directly.

## Common pitfalls

### 1. Forgetting the upstream auth middleware

If no `AuthenticatedIdentity` is in extensions, `AuthzTransform` returns 403 for every request. If you see 100% 403s, that's almost always the cause. Test the order: the middleware that inserts `AuthenticatedIdentity` must be `.wrap()`ed AFTER `AuthzTransform` (so it runs FIRST on the request path — Actix wrap is outer-first-on-request).

### 2. Mixing `AuthzTransform` with `secure_identity`

`secure_authz` does not depend on `secure_identity`. If you use `secure_identity`'s token validation, wire it via its own middleware to populate `AuthenticatedIdentity`, then `AuthzTransform` reads from there. This keeps the identity-agnostic invariant intact.

### 3. Per-route action/resource

`AuthzTransform` takes `Action` and `ResourceRef` at construction time — one transform per route group is the right granularity. For fine-grained resource IDs (e.g. per-article), either:
- parse the path and build `ResourceRef::new("article").with_id(...)` inside the handler and re-check manually, or
- attach a `ResourceRef` to request extensions in a per-route middleware before `AuthzTransform`.

## Minimal runnable example

See [`crates/secure_authz/examples/actix_authz_minimal.rs`](../../crates/secure_authz/examples/actix_authz_minimal.rs) and run:

```sh
cargo run --example actix_authz_minimal -p secure_authz --features actix-web
```

The example includes a mock upstream auth middleware (token extracted from the `x-mock-identity` header) so you can see the transform enforce correctly both when identity is present and when it's missing.

## See also

- [`AuthzTransform` rustdoc](../../crates/secure_authz/src/actix/middleware.rs) — API reference
- [`enforce::run_check` rustdoc](../../crates/secure_authz/src/enforce.rs) — the shared enforcement helper
- [`docs/dev-guide/secure_errors-actix.md`](./secure_errors-actix.md) — wire error mapping alongside authz
- [`docs/dev-guide/README.md`](./README.md) — dev-guide index

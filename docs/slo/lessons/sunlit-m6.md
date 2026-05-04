# Lessons Learned — Milestone 6: `secure_authz` — Access Control Enforcement (OWASP C7)

**Date**: 2026-04-06
**Milestone**: 6 — `secure_authz`
**Status**: done

---

## What We Built

A deny-by-default authorization enforcer implementing OWASP C7, providing:

| Module | Contents |
|---|---|
| `decision` | `Decision` (`#[must_use]`, `#[non_exhaustive]`): `Allow { obligations }`, `Deny { reason }`. `DenyReason` (`#[non_exhaustive]`): 7 variants covering all failure modes. |
| `subject` | `Subject` struct: actor_id (String), tenant_id (Option<String>), roles (SmallVec<[String; 4]>), attributes (BTreeMap). |
| `resolver` | `SubjectResolver` trait + `DefaultSubjectResolver` — maps `AuthenticatedIdentity` fields directly. Identity-agnostic: accepts from any `IdentitySource`. |
| `resource` | `ResourceRef` struct with builder methods (`with_tenant`, `with_owner`, `with_id`). |
| `action` | `Action` enum (`#[non_exhaustive]`): Read, Write, Delete, Create, Admin, Custom(String). No role strings in business code. |
| `policy` | `PolicyEngine` sealed trait + `DefaultPolicyEngine` backed by casbin v2. Simple ABAC-style model: `r.sub == p.sub && r.obj == p.obj && r.act == p.act`. Policies added programmatically. |
| `enforcer` | `Authorizer` trait + `DefaultAuthorizer<P: PolicyEngine>`. Full deny-by-default pipeline: subject validation → resource validation → tenant check → cache → policy eval → decision log. |
| `ownership` | `is_owner()` and `is_same_tenant()` helper functions. |
| `decision_log` | Structured `SecurityEvent` emission via `security_events::emit::emit_security_event`. Deny events emit `AuthzDeny`, cross-tenant → `CrossTenantAttempt`, engine errors → `ErrorEscalation`. |
| `cache` | `DecisionCache`: bounded LRU (`lru` v0.12) with TTL. Policy-version-keyed `CacheKey`. |
| `middleware` | `AuthzLayer<A>` + `AuthzService<A, S>` — Tower Layer/Service for axum 0.8. Reads `AuthenticatedIdentity` from request extensions, returns 403 on Deny. |
| `testkit` | `MockAuthorizer` (allow/deny variants with call count), `test_subject`, `test_subject_with_tenant` helpers. |

**29 tests** passing across 6 test files.

---

## Key Design Decisions

### 1. Simple ABAC-style casbin model (no grouping)

The casbin model uses direct subject matching (`r.sub == p.sub`) rather than role grouping (`g(r.sub, p.sub)`). The `DefaultAuthorizer` evaluates each of the subject's roles separately against the engine, trying actor_id first, then each role. This avoids the need to mutate the casbin enforcer's grouping policy at evaluation time.

**Trade-off**: Multiple casbin `enforce()` calls per authorization check. Acceptable for the inline evaluation use case; callers with large role sets may want a custom `PolicyEngine`.

### 2. `PolicyEngine::evaluate` returns `impl Future + Send`

Using native `async fn in trait` with the return type spelled out explicitly (`fn evaluate(...) -> impl Future<Output = ...> + Send`) ensures the future is `Send`-compatible for use in the axum middleware. Without `+ Send`, the Tower `Service::call` future cannot satisfy the `Send` bound required by `BoxFuture`.

### 3. `tokio::sync::Mutex` over `RwLock`

`tokio::sync::RwLockReadGuard<casbin::Enforcer>` is `!Send` (casbin's Enforcer may not be `Sync`). `tokio::sync::MutexGuard<casbin::Enforcer>` is `Send` as long as `casbin::Enforcer: Send`. Using `Mutex` solves the `Send` bound issue for the async evaluator.

### 4. Heuristic for deny reason

When the policy engine returns `false` (no match), the deny reason is:
- `NoPolicyMatch` — if subject has no roles (no applicable policy exists)
- `InsufficientRole` — if subject has roles but none grant access

This is a heuristic, not guaranteed to be correct in all ABAC scenarios. For production use, a more sophisticated policy engine should return structured denial reasons.

### 5. Fixture files for casbin

Use `concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/rbac_model.conf")` and `../fixtures/empty_policy.csv` for deterministic file paths at compile time. This avoids runtime path resolution issues across different invocation contexts.

### 6. `#[must_use]` on `Decision`

Annotating `Decision` with `#[must_use]` ensures callers cannot silently discard authorization results. Combined with `#[non_exhaustive]`, this prevents both silent permission grants and forward-compatibility breaks.

### 7. No `secure_identity` dependency

Verified via `cargo tree -p secure_authz | grep secure_identity` → empty. The crate depends only on `security_core::identity::AuthenticatedIdentity` and `security_core::identity::IdentitySource` (trait bound interface). This enables any identity provider to integrate without pulling in `secure_identity`.

---

## Gotchas

1. **`casbin::Enforcer: Send` but `!Sync`**: Use `tokio::sync::Mutex` (not `RwLock`) to hold the enforcer. `MutexGuard<T>` is `Send` when `T: Send`; `RwLockReadGuard<T>` requires `T: Sync`.

2. **`async fn` in trait + `Send`**: Rust 1.75 native async fn in trait does NOT automatically bound the returned future to `Send`. You must spell it out: `fn method(&self, ...) -> impl Future<Output = T> + Send`. Adding `#[allow(async_fn_in_trait)]` alone is not enough for tower middleware.

3. **casbin `FileAdapter` with empty policy**: Pass an empty CSV file (`fixtures/empty_policy.csv`) as the adapter source. Do NOT use a non-existent path — `FileAdapter::new` will fail on load. Create the file as part of the crate.

4. **Deferred features** (document in future milestones):
   - `#[protect()]` proc macro — hand-written middleware is used instead
   - Hierarchical resource inheritance
   - Field-level authorization
   - SQL/data-layer row filtering
   - Bulk authorization for list filtering

5. **Tower `Service::call` requires `Clone` on `inner`**: The `AuthzService::call` method clones `self.inner` to get a mutable reference. Axum routers implement `Clone`, so this works transparently.

---

## Test Coverage

- **5 BDD deny-default tests** (`sunlit_authz_deny_default.rs`): no roles, empty subject, missing resource, role+no-policy, cross-tenant
- **5 BDD policy tests** (`sunlit_authz_policies.rs`): RBAC allow/deny, ABAC, no role strings, multiple roles
- **4 BDD tenant tests** (`sunlit_authz_tenant.rs`): same tenant, cross-tenant, no tenant, resource without tenant
- **3 BDD ownership tests** (`sunlit_authz_ownership.rs`): owner allow, non-owner deny, is_owner helper
- **5 BDD cache tests** (`sunlit_authz_cache.rs`): call count, bounded size, TTL expiry, version invalidation, hit
- **7 E2E tests** (`e2e_sunlit_m6.rs`): deny-by-default, RBAC evaluation, cross-tenant, cache lifecycle, middleware integration, engine failure, authz independence

---

## What the Next Milestone Needs From This One

- `secure_data` (M7) may use `Authorizer` to gate secret access decisions
- The `AuthzLayer` middleware can protect axum routes in the reference service (M8)
- `MockAuthorizer` in `testkit` is available for tests in downstream crates
- Export `PolicyEngine` trait via `pub use policy::PolicyEngine` if downstream crates need to implement it (currently sealed)

---

## Rules for the Next Milestone

1. Use `secure_authz::testkit::MockAuthorizer` for authorization mocking in M7/M8 tests.
2. `Authorizer` is object-safe via `impl Authorizer for Arc<dyn Authorizer>` pattern if dynamic dispatch is needed.
3. The `AuthzLayer` middleware requires `AuthenticatedIdentity` in request extensions — set by a prior auth layer.
4. `DecisionCache` uses `std::sync::Mutex` internally (not async), so it can be used in synchronous contexts without an async executor.

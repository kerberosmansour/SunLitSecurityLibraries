# Lessons Learned — Milestone 8: `secure_reference_service` — Reference Axum Integration + Resilience

**Date**: 2026-04-06
**Milestone**: 8 — `secure_reference_service`
**Status**: done

---

## What We Built

A reference axum binary (`secure_reference_service`) that composes all eight SunLit Security Library crates into a working application:

| Module | Contents |
|---|---|
| `main.rs` | Entry point: tracing init, startup config validation (`SecurityConfig::validate()`), graceful shutdown via `ctrl_c()` |
| `lib.rs` | Library façade re-exporting all modules and `build_router()` for integration testing |
| `dto.rs` | `CreateItemRequest`, `UpdateItemRequest`, `ItemResponse` with `#[serde(deny_unknown_fields)]` and `SecureValidate` impls |
| `auth_dev.rs` | `DevAuthLayer` — Tower middleware that resolves `AuthenticatedIdentity` from `X-Dev-Subject`/`X-Dev-Tenant`/`X-Dev-Roles` headers (dev only) |
| `config.rs` | `SecurityConfig` with `validate()` — fails fast on missing policy, empty key alias, or invalid secret reference |
| `state.rs` | `AppState` — in-memory item store, `DefaultAuthorizer<DefaultPolicyEngine>`, `StaticDevKeyProvider`, `KeyRing` |
| `error.rs` | `AppHttpError` wrapping `AppError` via `secure_errors::http::into_response_parts` |
| `resilience.rs` | `ResilienceConfig` — request timeout and concurrency limit configuration |
| `middleware.rs` | `apply_security_stack()` applying all layers in mandatory order |
| `routes/health.rs` | `GET /health` — liveness check, no security middleware |
| `routes/items.rs` | CRUD routes: `POST /items`, `GET /items/{id}`, `PUT /items/{id}`, `DELETE /items/{id}` |
| `routes/panic_test.rs` | `GET /panic-test` — intentional panic for boundary test |
| `tests/e2e_sunlit_m8.rs` | **17 integration tests** covering all BDD scenarios |

---

## Key Design Decisions

### 1. `SecurityHeadersLayer` Requires `Response<Body>` — `TraceLayer` Must Be Outermost

`SecurityHeadersService` is implemented as `impl Service<Request<Body>, Response = Response<Body>>`. `TraceLayer` from `tower-http` wraps the response body in `ResponseBody<UnsyncBoxBody<...>>`, which breaks the type contract if placed inside the same `ServiceBuilder` chain as `SecurityHeadersLayer`.

**Solution**: Apply `TraceLayer` via a separate, outermost `.layer()` call on the axum `Router`, after all other layers in the security stack. This keeps the type chain valid throughout the stack.

### 2. Library Target Required for Integration Tests

Since `build_router` and the sub-modules live in `main.rs`, integration tests in `tests/` cannot import them. Adding a `[lib]` target (`src/lib.rs`) that re-exports all modules resolves this cleanly, with `main.rs` delegating to the library's `build_router`.

### 3. `PropagateRequestIdLayer` Required for Response Correlation Header

`SetRequestIdLayer` injects `X-Request-Id` into the request but does not echo it to the response. `PropagateRequestIdLayer::x_request_id()` must be added adjacent to `SetRequestIdLayer` to propagate the ID to the response headers.

### 4. `axum::Router::layer()` Order vs. `ServiceBuilder` Order

In axum, `.layer()` calls stack from innermost to outermost: the **last** `.layer()` call is outermost and handles requests first. This is the reverse of `ServiceBuilder` ordering. When using individual `.layer()` calls:
- First `.layer()` = innermost (closest to handler)
- Last `.layer()` = outermost (sees request first)

This means `DevAuthLayer` is listed first (innermost) and `TraceLayer` last (outermost) in `middleware.rs`.

### 5. `SecureJson<T>` Pattern Matching

`SecureJson<T>` has a private inner field — direct destructuring `SecureJson(req): SecureJson<T>` fails. Use `payload: SecureJson<T>` + `payload.into_inner()` instead.

### 6. `Uuid::new_v5` Requires `v5` Feature

The workspace `uuid` dependency only enables `["v4", "serde"]`. `Uuid::new_v5` requires the `v5` feature. In `DevAuthLayer`, fall back to `Uuid::new_v4()` when the actor_id header is not a valid UUID string.

### 7. `TimeoutLayer::with_status_code` Argument Order

`TimeoutLayer::with_status_code(status_code, timeout)` — status code first, duration second (opposite of the deprecated `TimeoutLayer::new(timeout)`).

---

## Gotchas

1. **`CatchPanicLayer` response body type**: `CatchPanicLayer` returns `Response<UnsyncBoxBody<...>>`, same body-type issue as `TraceLayer`. Keeping it inside the `SecurityHeadersLayer` chain requires that no body-transforming layers appear between them — use separate `.layer()` calls.

2. **Cross-tenant isolation requires explicit handler logic**: The `AuthzLayer` from `secure_authz` checks RBAC policies (role + resource kind) but does not check tenant ownership. Tenant isolation must be enforced explicitly in route handlers by comparing `subject.tenant_id` with `item.tenant_id`.

3. **`DevAuthLayer` emits `AuthnFailure` security event on missing header**: This is the correct behavior — any unauthenticated request should generate an audit event. The event flows through `security_events::emit::emit_security_event` into the tracing infrastructure.

4. **`DefaultBodyLimit` must be applied before `SecureJson`**: Apply `DefaultBodyLimit::max(N)` as a `.layer()` on the sub-router (not globally) so that the limit applies before `SecureJson` attempts to read the body.

---

## Test Coverage — 17 Tests

| Test | Category | Result |
|---|---|---|
| `test_startup_config_validation_no_policy` | resilience | ✅ |
| `test_startup_config_validation_invalid_key` | resilience | ✅ |
| `test_startup_config_validation_dev_ok` | resilience | ✅ |
| `test_all_responses_have_security_headers` | security headers | ✅ |
| `test_security_headers_on_item_response` | security headers | ✅ |
| `test_security_headers_on_error_response` | security headers | ✅ |
| `test_full_crud_lifecycle` | E2E happy path | ✅ |
| `test_unauthorized_request_rejected` | authz | ✅ |
| `test_get_item_unauthorized_role` | authz | ✅ |
| `test_cross_tenant_blocked` | tenant isolation | ✅ |
| `test_unknown_field_blocked` | boundary | ✅ |
| `test_create_item_with_invalid_data` | validation | ✅ |
| `test_wrong_content_type_rejected` | boundary | ✅ |
| `test_panic_caught_by_middleware` | resilience | ✅ |
| `test_middleware_ordering_correlation_id` | middleware ordering | ✅ |
| `test_security_events_emitted` | events | ✅ |
| `test_error_no_internal_leak` | error safety | ✅ |

---

## What the Next Milestone Needs From This One

- `build_router()` is public and testable — adversarial tests (M9) can drive requests through the full stack
- All CRUD routes use `SecureJson` + `SecureValidate` — fuzzing targets are the DTOs
- `DevAuthLayer` is the identity boundary — property tests can generate arbitrary actor/tenant combinations
- `DefaultBodyLimit::max(2MiB)` is wired — body-size fuzzing can target the limit boundary

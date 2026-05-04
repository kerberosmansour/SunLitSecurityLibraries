# Lessons Learned — M16: Security Smoke-Test Microservice

## What went well

1. **Route pattern reuse**: The reference service's middleware ordering and state construction patterns transferred directly. Building 39 routes was fast once `AppState` was wired.
2. **BDD tests as contract**: Writing 40 smoke tests + 10 e2e tests using `tower::ServiceExt::oneshot()` gave instant feedback. The entire test suite runs in ~30ms.
3. **Type system catches integration errors early**: `SecureJson<T>` requiring `SecureValidate`, `Decision` being `#[non_exhaustive]`, and `DefaultPolicyEngine::new_empty()` returning `Result` were all caught at compile time — no runtime surprises.

## What was tricky

1. **`Decision` is `#[non_exhaustive]`**: Direct `match` on `Allow`/`Deny` doesn't compile. Required a `_ =>` wildcard arm or a helper function like `decision_to_response()`.
2. **`sanitize_header_value()` returns `Result`**: Not `String`. The error variant `BoundaryRejection::InvalidHeaderValue` needed to be mapped to a 422 response.
3. **Never-type fallback in Rust 2024**: A `CatchPanicLayer` handler returning `impl IntoResponse` caused `never type fallback` errors. Fix: use explicit `Response` return type.
4. **`DefaultPolicyEngine::new_empty()` is async and fallible**: Both `new_empty().await` and `add_policy()` return `Result` — easy to miss when composing `AppState`.
5. **JWT `alg:none` crafting**: Need `base64` crate to manually construct the unsigned token for testing the CVE-2015-9235 scenario.

## Design decisions

1. **`TokenValidator` instead of `DevAuthLayer`**: Auth routes exercise real JWT validation (signature, expiry, issuer, audience) rather than trusting headers. This is closer to production flow.
2. **One route per attack class**: Each route isolates a single security control. Test failures pinpoint exactly which control broke.
3. **Shared `AppState` with `Arc` wrapping**: Session manager, key ring, and authorizer share across routes via `Arc` — same pattern as reference service.
4. **OpenAPI 3.1 for DAST**: The spec is designed for OWASP ZAP consumption in M17 with typed request/response schemas.

## Patterns to reuse

- `decision_to_response()` helper for `#[non_exhaustive]` `Decision` types
- `make_valid_token()` / `make_expired_token()` test helpers for JWT creation
- `response_body()` helper for `BodyExt::collect()` in tests
- Body bomb testing with `tower-http` body limits (1 MiB) — just send >1 MiB, assert non-200

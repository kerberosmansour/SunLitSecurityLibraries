# Lessons Learned — Milestone 15: Authorization Fixes + Error Handling Middleware

**Date:** 2026-04-06
**Milestone:** M15 — Authorization Fixes + Error Handling Middleware

---

## What changed
- `CacheKey` in `secure_authz` now includes `tenant_id: Option<String>` to prevent cross-tenant cache poisoning
- `AuthzLayer` middleware now enforces `Decision::Allow` obligations — non-empty obligations that aren't satisfied via `ObligationFulfillment` in request extensions result in 403
- `AppError::RateLimit` is now a struct variant with `retry_after_seconds: Option<u64>`
- `ErrorMappingLayer` provides opt-in automatic `AppError` → HTTP response mapping via `IntoResponse` impl
- `context_propagation` module provides task-local `ErrorContext` storage for request/actor/tenant IDs

## Design decisions and why
- `ErrorMappingLayer` implemented as a passthrough `Layer` with `IntoResponse` impl on `AppError` — simplest design that integrates naturally with axum's type system. The layer exists as the opt-in mechanism and future extension point.
- `ObligationFulfillment` is a marker type in request extensions — middleware or prior layers insert it to signal satisfied obligations. This avoids coupling the authz layer to specific obligation implementations.
- `context_propagation` uses `thread_local!` with `RefCell<Option<ErrorContext>>` — works with tokio's single-threaded-per-task model. No async runtime dependency needed.
- `tower-layer` used instead of full `tower` crate for the `Layer` trait — it's already a transitive dependency via `axum-core`, avoids adding a new direct dependency.

## Mistakes made
- Initial E2E test used wrong `policy_version` (1 instead of 2) — `DefaultPolicyEngine` starts at version 1 and increments on each `add_policy` call.
- First attempt at `AuthenticatedIdentity` construction used a non-existent `::new()` constructor — it's a plain public struct requiring struct literal syntax.
- `IdentitySource` is a trait, not an enum — can't use `IdentitySource::Jwt` as a value.

## Root causes
- Not checking actual struct/trait definitions before writing test code
- Not verifying policy engine version semantics before writing assertions

## What was harder than expected
- The `AppError::RateLimit` change from unit variant to struct variant required updating all existing pattern matches across production code (`incident.rs`, `classify.rs`, `http.rs`) and test files (`e2e_sunlit_m2.rs`, `sunlit_errors_mapping.rs`). Struct variant changes have wider blast radius than expected.

## Naming conventions established
- `ObligationFulfillment` — marker type for satisfied obligations in request extensions
- `ErrorMappingLayer` — the opt-in error mapping middleware
- `ErrorContext` — task-local context for error enrichment
- `retry_after_seconds` — the field name for retry-after data in `RateLimit`

## Test patterns that worked well
- Stub authorizer pattern for testing middleware obligation enforcement — simple `StubAuthorizer` struct with configurable `Decision` return
- Building test identities with struct literal syntax matching the existing `make_identity`/`test_subject_with_tenant` patterns

## Missing tests that should exist now
- Integration test verifying `ObligationFulfillment` actually satisfies obligations and allows the request through
- Test for `clear_error_context()` function
- Test verifying that `ErrorMappingLayer` works with other axum middleware in a full stack

## Rules for the next milestone
- When changing an enum variant from unit to struct, search the entire workspace for all pattern matches using `grep_search` before implementing
- Always check `policy_version` semantics when constructing cache keys in tests — `DefaultPolicyEngine` increments version on each `add_policy` call
- Construct `AuthenticatedIdentity` using struct literal syntax, not constructor methods
- When adding `tower` trait implementations, prefer `tower-layer` / `tower-service` sub-crates over full `tower` to minimize dependency surface

## Template improvements suggested
- The "Files to Read Before Changing Anything" list should include test files that construct the types being changed

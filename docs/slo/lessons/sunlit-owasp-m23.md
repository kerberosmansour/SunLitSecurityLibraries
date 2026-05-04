# Lessons Learned — sunlit-owasp Milestone 23

## What changed
- Added ABAC guard primitives in `secure_authz::abac` and temporal permission windows in `secure_authz::temporal`
- Extended `DefaultAuthorizer` with `with_abac_guard()`, `with_time_source()`, and `authorize_bulk()`
- Added `CacheKey::for_request()` and default `PolicyEngine::evaluate_bulk()`
- Added deny reasons for ABAC mismatch and temporal window failures

## Design decisions and why
- Used closure-based ABAC guards (`AttributeGuard`) instead of a policy language to keep the API Rust-idiomatic and lightweight
- Performed temporal checks before policy engine evaluation so expired/not-yet-active permissions fail fast
- Kept trait evolution additive via default methods (`evaluate_bulk`) to preserve compatibility

## Mistakes made
- Initial implementation triggered clippy `double_must_use` warnings on ABAC combinators
- A temporal doctest compared full timestamps with subsecond precision after serialization truncation

## Root causes
- Redundant `#[must_use]` was applied to methods returning a type already marked `#[must_use]`
- Temporal attributes store Unix seconds, so nanos are not round-tripped

## What was harder than expected
- Balancing ABAC/temporal additions while preserving existing deny-by-default RBAC behavior and middleware compatibility

## Naming conventions established
- Modules: `abac`, `temporal`
- APIs: `AttributeGuard`, `AttributePredicate`, `PermissionWindow`, `authorize_bulk`, `for_request`
- Test files: `sunlit_owasp_abac.rs`, `sunlit_owasp_temporal.rs`, `e2e_sunlit_owasp_m23.rs`

## Test patterns that worked well
- Fixed-clock injection via `with_time_source()` for deterministic temporal tests
- E2E cache-key isolation checks using same actor/resource with different tenants

## Missing tests that should exist now
- Temporal constraints sourced from resource attributes in end-to-end middleware flows
- Performance-focused benchmark for large `authorize_bulk()` request sets

## Rules for the next milestone
- Keep all trait/API expansion additive with defaults where existing implementations might break
- Inject deterministic clocks in all time-sensitive tests
- Validate clippy/doc tests early when adding new public API docs

## Template improvements suggested
- Clarify that if BDD/E2E stubs already exist in red phase, they may be reused instead of recreated

# Completion Summary — sunlit-imp Milestone 15

## Goal completed
- `CacheKey` in `secure_authz` now includes `tenant_id` for tenant-scoped cache isolation, preventing cross-tenant cache poisoning
- `AuthzLayer` middleware enforces `Decision::Allow` obligations — unmet obligations result in 403 Forbidden
- `AppError::RateLimit` carries optional `retry_after_seconds` for 429 `Retry-After` header
- `ErrorMappingLayer` provides opt-in automatic `AppError` → HTTP response mapping
- Task-local `ErrorContext` propagation for request/actor/tenant IDs

## Files changed
- `crates/secure_authz/src/cache.rs` — added `tenant_id: Option<String>` to `CacheKey`
- `crates/secure_authz/src/enforcer.rs` — populate `tenant_id` in cache key from subject
- `crates/secure_authz/src/middleware.rs` — added obligation enforcement, `ObligationFulfillment` type, `check_obligations` helper
- `crates/secure_errors/src/kind.rs` — changed `RateLimit` from unit to struct variant with `retry_after_seconds`
- `crates/secure_errors/src/http.rs` — updated RateLimit match, added `retry_after_seconds()` function
- `crates/secure_errors/src/middleware.rs` — NEW: `ErrorMappingLayer` + `IntoResponse` impl for `AppError`
- `crates/secure_errors/src/context_propagation.rs` — NEW: task-local `ErrorContext` storage
- `crates/secure_errors/src/lib.rs` — added module declarations for `middleware` and `context_propagation`
- `crates/secure_errors/src/incident.rs` — updated `RateLimit` pattern match
- `crates/secure_errors/src/classify.rs` — updated `RateLimit` pattern match
- `crates/secure_errors/Cargo.toml` — added `tower-layer` dependency, expanded dev-dependencies
- `crates/secure_authz/Cargo.toml` — added `uuid`, `time` dev-dependencies
- `crates/secure_authz/tests/sunlit_authz_cache.rs` — updated CacheKey constructions with `tenant_id: None`
- `crates/secure_authz/tests/e2e_sunlit_m6.rs` — updated CacheKey construction with `tenant_id: None`
- `crates/secure_errors/tests/e2e_sunlit_m2.rs` — updated `AppError::RateLimit` to struct variant
- `crates/secure_errors/tests/sunlit_errors_mapping.rs` — updated `AppError::RateLimit` to struct variant
- `ARCHITECTURE.md` — documented cache fix, obligation enforcement, ErrorMappingLayer, context propagation

## Tests added
- `crates/secure_authz/tests/sunlit_imp_authz_cache_tenant.rs` — tenant-scoped cache BDD tests
- `crates/secure_authz/tests/sunlit_imp_authz_obligations.rs` — obligation enforcement BDD tests
- `crates/secure_errors/tests/sunlit_imp_error_mapping.rs` — ErrorMappingLayer + retry-after BDD tests

## Runtime validations added
- `crates/secure_authz/tests/e2e_sunlit_imp_m15.rs` — tenant cache poisoning prevention, obligation enforcement at runtime
- `crates/secure_errors/tests/e2e_sunlit_imp_m15.rs` — ErrorMappingLayer all-variants mapping, context propagation

## Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all pre-existing tests green | all pass | Pass | |
| Baseline clippy | `cargo clippy --workspace --all-targets -- -D warnings` | no warnings | clean | Pass | |
| BDD tests created | tenant cache, obligations, error mapping | compile or fail for expected reason | compile | Pass | |
| E2E stubs created | e2e_sunlit_imp_m15 (authz + errors) | compile or fail for expected reason | compile | Pass | |
| Implementation | CacheKey tenant_id, obligations, RateLimit, ErrorMappingLayer, context_propagation | contract satisfied | all tests pass | Pass | |
| Full tests | `cargo test --workspace` | green | all pass, 0 failures | Pass | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | all pass | Pass | |
| Build/boot | `cargo build --workspace && cargo run -p secure_reference_service` | builds, health OK | builds clean, health {"status":"ok"} | Pass | |
| Test artifact cleanup | `git status` | no untracked test artifacts | clean | Pass | |
| .gitignore review | review `.gitignore` | patterns current | no changes needed | Pass | |
| Clippy clean | `cargo clippy --workspace --all-targets -- -D warnings` | no warnings | clean | Pass | |

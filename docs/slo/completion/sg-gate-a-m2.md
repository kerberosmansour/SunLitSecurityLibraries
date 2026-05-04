# Completion Summary — sg-gate-a Milestone 2

## Goal completed
Actix-web 4 consumers can now depend on `secure_authz` and `secure_errors` with `features = ["actix-web"]` and get drop-in adapters for `AuthzTransform` (authz enforcement) and `AppError → HttpResponse` error mapping. Both adapters route through framework-neutral logic (`enforce::run_check` / `http::into_response_parts`), so decisions and error responses are byte-identical to the axum path — verified by 12 cross-framework parity tests.

## Files changed
- `crates/secure_authz/Cargo.toml` — feature flags, optional deps, `required-features` for new example.
- `crates/secure_authz/src/lib.rs` — Feature Overview; `actix` module; `enforce` module.
- `crates/secure_authz/src/enforce.rs` — NEW framework-neutral enforcement helpers (`run_check`, `EnforceOutcome`, `ObligationFulfillment`).
- `crates/secure_authz/src/middleware.rs` — axum `AuthzLayer` delegates to `enforce::run_check`; file gated on `#[cfg(feature = "axum")]`.
- `crates/secure_authz/src/actix/mod.rs` — NEW: module doc + re-exports.
- `crates/secure_authz/src/actix/middleware.rs` — NEW: `AuthzTransform` + `AuthzMiddleware`.
- `crates/secure_authz/examples/actix_authz_minimal.rs` — NEW runnable example.
- `crates/secure_errors/Cargo.toml` — feature flags, optional deps, `required-features` for new example.
- `crates/secure_errors/src/lib.rs` — Feature Overview; `actix` module.
- `crates/secure_errors/src/middleware.rs` — gated on `#[cfg(feature = "axum")]`.
- `crates/secure_errors/src/actix.rs` — NEW: `impl ResponseError for AppError`.
- `crates/secure_errors/examples/actix_error_minimal.rs` — NEW runnable example.
- `crates/secure_smoke_service/Cargo.toml` — dev-deps on `secure_authz` + `secure_errors` with `actix-web` feature.
- `docs/dev-guide/secure_authz-actix.md` — NEW integration guide.
- `docs/dev-guide/secure_errors-actix.md` — NEW integration guide.
- `docs/slo/completed/RUNBOOK-sunlit-guardian-gate-a.md` — Milestone Tracker: M2 `done`.

## Tests added
- `crates/secure_authz/tests/sg_gate_a_actix_authz.rs` — 5 scenarios (allow, deny, missing identity, obligations unfulfilled, obligations fulfilled).
- `crates/secure_errors/tests/sg_gate_a_actix_errors.rs` — 10 scenarios (every `AppError` variant + body-leak regression).
- `crates/secure_authz/tests/sg_gate_a_parity_authz.rs` — 3 cross-framework parity scenarios (allow, deny, missing identity).
- `crates/secure_errors/tests/sg_gate_a_parity_errors.rs` — 9 cross-framework parity scenarios (every `AppError` variant, including both `RateLimit` retry configs).

Total new tests: **27**.

## Runtime validations added
- `crates/secure_smoke_service/tests/e2e_sg_gate_a_m2.rs` — 5 runtime-validation scenarios (service boots, authz allow reaches handler, authz deny returns 403, handler `RateLimit` error maps to 429 + Retry-After, `PublicError` body shape).

## Compatibility checks performed
- `cargo test --workspace` — 1090 passing, 0 failing.
- `cargo test -p secure_authz --features "axum actix-web"` — green.
- `cargo test -p secure_errors --features "axum actix-web"` — green.
- `cargo check -p secure_authz --no-default-features` and `cargo check -p secure_errors --no-default-features` — green.
- `cargo build --example actix_authz_minimal -p secure_authz --features actix-web` — green.
- `cargo build --example actix_error_minimal -p secure_errors --features actix-web` — green.
- `cargo clippy -p secure_authz --all-features --no-deps -- -D warnings` — clean.
- `cargo clippy -p secure_errors --all-features --no-deps -- -D warnings` — clean.
- `cargo doc -p secure_authz --no-deps --all-features` — zero warnings.
- `cargo doc -p secure_errors --no-deps --all-features` — zero warnings.
- `cargo test -p secure_authz --doc --all-features` — 26 doctests passing.
- `cargo test -p secure_errors --doc --all-features` — 11 doctests passing.
- `grep -r 'use secure_identity' crates/secure_authz/src/` — no matches. Identity-agnostic invariant preserved.

## Documentation updated
- `secure_authz/src/lib.rs` — crate-level Feature Overview.
- `secure_authz/src/actix/mod.rs` — module doc with runnable example.
- `secure_authz/src/actix/middleware.rs` — rustdoc on every public item.
- `secure_authz/src/enforce.rs` — new framework-neutral module with full rustdoc.
- `secure_errors/src/lib.rs` — crate-level Feature Overview.
- `secure_errors/src/actix.rs` — rustdoc on the new `ResponseError` integration.
- `docs/dev-guide/secure_authz-actix.md` — integration guide.
- `docs/dev-guide/secure_errors-actix.md` — integration guide.

## .gitignore changes
- None required.

## Test artifact cleanup verified
- `git status` clean except for staged/unstaged source and doc files from this milestone.

## Deferred follow-ups
- Add an obligation-fulfillment parity scenario (currently tested per-framework but not as parity across both).
- Consider whether to expose `enforce::run_check` as a `pub` item for downstream crates that want to build custom middleware (currently `pub` within the crate, `pub` in the module tree — already accessible; just not documented as a stable API). If downstream needs it, upgrade to documented-stable in M4 or a later runbook.

## Known non-blocking limitations
- Pre-existing workspace-wide clippy/fmt issues in `security_events` (flagged in M1 lessons) remain outside this milestone's allow-list.
- `impl ResponseError for AppError` forwards through Actix's default response-body pipeline; if a downstream wants a different body serialisation, they'd need to wrap `AppError` in their own type. Not a regression — the axum path has the same constraint.

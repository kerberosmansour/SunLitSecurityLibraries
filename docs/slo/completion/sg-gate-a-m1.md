# Completion Summary — sg-gate-a Milestone 1

## Goal completed
Actix-web 4 consumers can now depend on `secure_boundary` with `features = ["actix-web"]` and get drop-in adapters for `SecureJson<T>`, `SecurityHeadersLayer`, and `FetchMetadataLayer`. Every rejection code, HTTP status, security-header value, and allow/block classification is byte-for-byte identical to the axum path on the same input — verified by seven cross-framework parity tests.

## Files changed
- `crates/secure_boundary/Cargo.toml` — feature flags (`axum` default, `actix-web` additive, both compose); optional `actix-web` and `actix-http` deps; example `required-features` entry.
- `crates/secure_boundary/src/lib.rs` — Feature Overview table, feature-gated re-exports, new `actix` module doc.
- `crates/secure_boundary/src/extract.rs` — factored out `validate_json_bytes` + `validate_parsed` framework-neutral helpers; axum impls in `axum_impl` submodule gated on `#[cfg(feature = "axum")]`.
- `crates/secure_boundary/src/headers.rs` — factored out `security_header_pairs`; axum tower `Service` impl gated on `axum`.
- `crates/secure_boundary/src/fetch_metadata.rs` — factored out `classify` + `emit_cross_site_block`; axum `Layer`/`Service` gated on `axum`.
- `crates/secure_boundary/src/cors.rs`, `src/xml.rs` — file-level `#![cfg(feature = "axum")]` (tower-http / axum-only).
- `crates/secure_boundary/src/error.rs` — removed axum imports from top; axum `IntoResponse` gated on `axum`.
- `crates/secure_boundary/src/actix/mod.rs` — NEW: module doc + submodule declarations.
- `crates/secure_boundary/src/actix/extract.rs` — NEW: `impl FromRequest for SecureJson<T>` + local `BoundaryRejectionError` newtype for Actix `ResponseError`.
- `crates/secure_boundary/src/actix/headers.rs` — NEW: `SecurityHeadersTransform` + `SecurityHeadersMiddleware`.
- `crates/secure_boundary/src/actix/fetch_metadata.rs` — NEW: `FetchMetadataTransform` + `FetchMetadataMiddleware` with `EitherBody` response.
- `crates/secure_boundary/examples/actix_minimal.rs` — NEW: runnable minimal service.
- `crates/secure_smoke_service/Cargo.toml` — dev-dep on `secure_boundary` with `actix-web` feature + dev `actix-web = "4"`.
- `docs/dev-guide/secure_boundary-actix.md` — NEW: integration guide.
- `docs/slo/completed/RUNBOOK-sunlit-guardian-gate-a.md` — Milestone Tracker: M1 set to `done`.

## Tests added
- `crates/secure_boundary/tests/sg_gate_a_actix_extract.rs` — 8 Actix `SecureJson<T>` scenarios (happy path, wrong content-type, malformed JSON, oversize body, deep nesting, many fields, semantic failure, per-route limits).
- `crates/secure_boundary/tests/sg_gate_a_actix_headers.rs` — 4 Actix `SecurityHeadersTransform` scenarios (all defaults, CSP override, CSP nonce, headers still set on inner error).
- `crates/secure_boundary/tests/sg_gate_a_actix_fetch_metadata.rs` — 6 Actix `FetchMetadataTransform` scenarios (same-origin, none, missing-default, cross-site block, cross-site top-nav, strict mode block).
- `crates/secure_boundary/tests/sg_gate_a_parity_boundary.rs` — 7 cross-framework parity scenarios (happy path, bad content type, malformed JSON, semantic rejection, security-header set equality, fetch-metadata block match, fetch-metadata allow match).

Total new tests: **25**.

## Runtime validations added
- `crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs` — 5 E2E runtime validations (boot, happy path, malformed rejection, cross-site block, wrong content-type rejection) against a real Actix `App` with all three adapters wrapped.

## Compatibility checks performed
- `cargo test --workspace` — 1055 passing, 0 failing.
- `cargo test -p secure_boundary --features axum` — green.
- `cargo test -p secure_boundary --features actix-web` — green.
- `cargo test -p secure_boundary --features "axum actix-web"` — green.
- `cargo check -p secure_boundary --no-default-features` — green.
- `cargo build --workspace --release` — green.
- `cargo build --example actix_minimal -p secure_boundary --features actix-web` — green.
- `cargo clippy -p secure_boundary --all-features --no-deps -- -D warnings` — zero warnings.
- `cargo doc -p secure_boundary --no-deps --all-features` — zero warnings.
- `cargo test -p secure_boundary --doc --all-features` — 45 doctests passing.

## Documentation updated
- `crates/secure_boundary/src/lib.rs` — crate-level "Feature Overview" table; "Framework selection quickstart" block.
- `crates/secure_boundary/src/actix/mod.rs` — module-level overview + runnable doctest minimal example.
- `crates/secure_boundary/src/actix/extract.rs`, `actix/headers.rs`, `actix/fetch_metadata.rs` — per-module rustdoc with runnable doctests on every public item.
- `docs/dev-guide/secure_boundary-actix.md` — NEW integration guide.

## .gitignore changes
- None required — Cargo's `target/` already covered.

## Test artifact cleanup verified
- `git status` is clean of test artifacts. Only staged/unstaged source and doc files remain; no generated test output.

## Deferred follow-ups
- `SecureQuery<T>` and `SecurePath<T>` Actix adapters — explicitly deferred; Gate A only asks for `SecureJson`. If Sunlit Guardian later needs query/path extractors on Actix, open a follow-up runbook.
- Add a parity test specifically for CSP nonce-value equality across frameworks (currently each framework's nonce is verified in its own suite).
- Update `IMPROVEMENT_PROPOSAL.md` and `ARCHITECTURE.md` if either asserts axum-only framework coupling (reviewed at end of runbook).

## Known non-blocking limitations
- `rustc` / Rust edition on the workspace still declared as 2021, but each file explicitly targets edition 2021. No impact.
- Pre-existing lint issue in `crates/security_events/src/mobile_redaction.rs:228` (clippy::len-zero) and a pre-existing `cargo fmt --all` diff across unrelated mobile crates — both untouched by M1. These were baseline issues before the milestone started and are orthogonal to Actix adapter work; fixing them widens scope. Flagging for a future small cleanup PR.

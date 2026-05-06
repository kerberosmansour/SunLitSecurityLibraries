# Completion Summary — fv Milestone 1

## Goal completed
Kani is wired into the workspace as an advisory CI lane (15-minute cap, `continue-on-error: true`). The `secure_data` crate ships two bootstrap proof harnesses in `src/proofs.rs` (gated by `#![cfg(kani)]` so regular builds are unaffected): `nonce_non_zero` and `aes_256_gcm_nonce_len_is_12`. A consumer-facing dev-guide explains the proof catalogue, planned M2–M5 proofs, the local-run procedure, and the promotion criteria for advisory → blocking. Formal-verification status is now visible in the README.

## Files changed
- `crates/secure_data/src/proofs.rs` (NEW; `#![cfg(kani)]`).
- `crates/secure_data/src/lib.rs` — `#[cfg(kani)] mod proofs;`.
- `crates/secure_data/Cargo.toml` — `[lints.rust] unexpected_cfgs` for `cfg(kani)`.
- `.github/workflows/kani.yml` (NEW; advisory; Kani pin managed in the workflow env).
- `docs/dev-guide/formal-verification.md` (NEW).
- `README.md` — Supply-Chain Security policy summary.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/fv-m1.md` (NEW).
- `docs/slo/completion/fv-m1.md` (NEW; this file).
- `docs/slo/future/RUNBOOK-formal-verification-kani-tla.md` — M1 marked done.

## Tests added
- `crates/secure_data/src/proofs.rs::nonce_non_zero` — Kani harness; runs only under `cargo kani`.
- `crates/secure_data/src/proofs.rs::aes_256_gcm_nonce_len_is_12` — Kani harness; build-time invariant guard.

## Runtime validations added
- `.github/workflows/kani.yml` runs on every PR and push to main; produces a per-harness pass/fail summary in the run log.

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo build -p secure_data` — clean (no `unexpected_cfgs` warning after the lints config).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test --workspace` — 22 final-target tests pass; existing 24-test secure_data suite unchanged.
- `cargo audit && cargo deny check` — clean.

## Compatibility checks performed
- All existing `secure_data` tests remain green (the `#![cfg(kani)]` gate is the load-bearing isolation).
- All existing CI lanes are unchanged.
- No production code modified — `proofs.rs` is excluded from regular builds.
- `forbid(unsafe_code)` regression test (from fug M1) still passes.

## Invariants/assertions added
- See lessons file §"Invariants/assertions added or strengthened".

## Resource bounds added or verified
- CI runtime cap: 15 minutes per matrix-dim (per crate).
- Pinned Kani version: workflow env `KANI_VERSION`.

## Documentation updated
- `docs/dev-guide/formal-verification.md` (NEW; load-bearing for fv M2–M5).
- `README.md` — Adversarial-testing bullet.
- `CHANGELOG.md` — Unreleased entry.
- Rustdoc on the proofs module + each harness.

## .gitignore changes
- None required. `target/kani/` is already covered by `target/`.

## Test artifact cleanup verified
- `git status` clean.

## Deferred follow-ups
- fv M2 (#12): add `secure_authz` deny-by-default + `secure_boundary` depth/size/field-limit proofs; extend the matrix.
- fv M3 (#13): add `secure_data` nonce-uniqueness + `secure_errors` no-internal-detail-leak proofs.
- fv M4 (#14): new `secure_resilience::circuit_breaker` module + TLA+ Naive+Hardened spec.
- fv M5 (#15): TLA+ spec for `secure_identity` session+step-up; `tla.yml` CI lane.
- Promotion of the Kani lane from advisory → blocking — separate runbook after ≥1 release cycle of stable signal.

## Known non-blocking limitations
- The bootstrap proof is intentionally minimal (validates the pipeline). M3 will add the substantive proofs on actual nonce-construction logic.
- `pq::sizes::AES_256_GCM_NONCE_LEN` is duplicated as a local `const` in `proofs.rs` because pq M1 (#24) is not yet merged; once both PRs land on main, future fv harnesses can import the canonical constant.

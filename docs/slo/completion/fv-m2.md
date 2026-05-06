# Completion Summary — fv Milestone 2

## Goal completed
Kani harnesses on `secure_authz` and `secure_boundary` land. The `Decision` discriminant invariants (deny-by-default, mutual exclusivity) are proven; the `RequestLimits` comparison invariants (depth, field count, body size, default-non-zero) are proven within bounded ranges. CI matrix extended from one crate to three, and the pinned verifier is bumped to 0.67.0 for current dependency compatibility.

## Files changed
- `crates/secure_authz/src/proofs.rs`, `crates/secure_authz/src/lib.rs`, `crates/secure_authz/Cargo.toml`.
- `crates/secure_boundary/src/proofs.rs`, `crates/secure_boundary/src/lib.rs`, `crates/secure_boundary/Cargo.toml`.
- `.github/workflows/kani.yml` — matrix extended.
- `docs/dev-guide/formal-verification.md` — proof catalogue (was 2 rows; now 8).
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/fv-m2.md`, `docs/slo/completion/fv-m2.md` (NEW).
- Runbook tracker — M2 done.

## Tests added
- 6 new Kani harnesses across `secure_authz` and `secure_boundary`. See lessons file for the full list.

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test --workspace` — green.
- `cargo build -p secure_authz -p secure_boundary` — clean (no `unexpected_cfgs` warnings after the lints config).
- `cargo kani -p secure_authz --output-format old --no-assertion-reach-checks` — clean.
- `cargo kani -p secure_boundary --output-format old --no-assertion-reach-checks` — clean.

## Compatibility checks performed
- All existing `secure_authz` and `secure_boundary` tests pass; the `#![cfg(kani)]` gate excludes the new modules from regular builds.
- All other CI lanes unchanged.

## Documentation updated
- `docs/dev-guide/formal-verification.md` proof catalogue.
- `CHANGELOG.md` Unreleased entry.
- Rustdoc on every harness.

## Deferred follow-ups
- fv M3 (#13): `secure_data` nonce-uniqueness within encrypt-call path; `secure_errors` no-internal-detail-leak.
- fv M4 (#14): new `secure_resilience::circuit_breaker` module + TLA+ Naive+Hardened spec.
- fv M5 (#15): TLA+ session+step-up + `tla.yml` lane.

## Known non-blocking limitations
- Discriminant-level proofs for `secure_authz::decision::Decision` — full-engine proofs await M3+ with extracted-helper functions on the policy engine.
- Boundary proofs use bounded-range inputs; monotonicity argument covers larger inputs (documented in each harness).

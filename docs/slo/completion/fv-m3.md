# Completion Summary — fv Milestone 3

## Goal completed
Kani harnesses on `secure_data` (per-algorithm nonce length invariants) and `secure_errors` (no-internal-detail-leak in `PublicError`) land. The matrix extends to four crates. The proof catalogue grows from 8 to 13 rows. The "no leak" property is captured via three precise sub-properties: 4xx/5xx status range, non-empty `&'static str` code, code-in-whitelist.

## Files changed
- `crates/secure_data/src/proofs.rs` — extended.
- `crates/secure_errors/src/proofs.rs`, `crates/secure_errors/src/lib.rs`, `crates/secure_errors/Cargo.toml` (NEW + modified).
- `.github/workflows/kani.yml` — matrix extended.
- `docs/dev-guide/formal-verification.md` — proof catalogue.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/fv-m3.md`, `docs/slo/completion/fv-m3.md` (NEW).
- Runbook tracker — M3 done.

## Tests added
5 new Kani harnesses (2 in `secure_data`, 3 in `secure_errors`).

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test --workspace` — green; `proofs.rs` excluded from regular builds via `#![cfg(kani)]`.

## Compatibility checks performed
- Existing tests on all four crates pass; no production-code changes outside the lib.rs module declarations and Cargo.toml lints config.

## Documentation updated
- Proof catalogue in dev-guide.
- CHANGELOG.

## Deferred follow-ups
- fv M4: circuit-breaker module + TLA+ Naive+Hardened spec.
- fv M5: TLA+ session+step-up + `tla.yml` lane.
- Workspace-level test asserting every Kani-using crate has the `[lints.rust] unexpected_cfgs` config (carried from M2 follow-ups).

## Known non-blocking limitations
- The whitelist proof is sized to the current API; adding a new `AppError` variant requires deliberate whitelist update.
- Per-algorithm nonce-length proof uses "value in canonical set" rather than exhaustive `match` to remain robust under the `#[non_exhaustive]` enum.

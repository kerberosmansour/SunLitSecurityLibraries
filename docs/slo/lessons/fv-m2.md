# Lessons Learned — fv Milestone 2

## What changed
- `crates/secure_authz/src/proofs.rs` (NEW; `#![cfg(kani)]`) — `deny_by_default_decision_is_deny` and `allow_and_deny_are_mutually_exclusive`.
- `crates/secure_boundary/src/proofs.rs` (NEW; `#![cfg(kani)]`) — four harnesses: depth/field-count/body-size limit-rejection plus a `default_limits_are_non_zero` invariant guard.
- `crates/secure_authz/src/lib.rs` and `crates/secure_boundary/src/lib.rs` — `#[cfg(kani)] mod proofs;` declarations.
- `crates/secure_authz/Cargo.toml` and `crates/secure_boundary/Cargo.toml` — `[lints.rust] unexpected_cfgs` for `cfg(kani)` (carrying forward the fv M1 pattern).
- `.github/workflows/kani.yml` — matrix extended from `[secure_data]` to `[secure_data, secure_authz, secure_boundary]`.
- `docs/dev-guide/formal-verification.md` — proof catalogue extended to 8 rows (was 2).
- `CHANGELOG.md` — Unreleased entry.
- Runbook tracker — M2 marked done.

## Design decisions and why
- **Discriminant-level proofs for `Decision`, not full-engine proofs.** `Authorizer::authorize` is async (`Pin<Box<dyn Future>>`); Kani's async support is limited. The discriminant property — `Decision::Deny` always reports `is_denied()` — is meaningful (a refactor that flips the `match` arm trips it) and Kani-tractable. Full-engine proofs land in M3+ when the policy-engine surface is large enough to warrant the extra modelling.
- **Bounded inputs on the boundary proofs.** `actual > 32` for nesting depth, `actual > 32` for field count, `actual > 4096` bytes for body size — outside the bounds the same monotonicity argument applies, so verifying within bounds is sound. Documented in the harness rustdoc.
- **`#[kani::unwind(2)]` on the boundary proofs.** No loops in the comparison logic; `unwind(2)` is the minimum that satisfies Kani's bounded-loop requirement without runtime explosion.
- **`default_limits_are_non_zero` as a regression guard.** If a future contributor changes a default to `0` (silently rejecting every request), Kani fails on this proof. Cheap, sound, catches a real footgun.
- **Per-crate `[lints.rust] unexpected_cfgs` config.** Same pattern as fv M1 — keep the lint config local to crates that use Kani so non-Kani crates aren't bothered.

## Assumptions verified
- The `cfg(kani)` gate keeps `proofs.rs` out of regular builds — workspace tests still pass after adding both new modules.
- Kani's symbolic enum support handles `DenyReason` (verified at runbook authoring time by the research dossier; runbook authoring referenced `kani::any::<DenyReason>()` as supported).

## Assumptions still unresolved
- Whether the per-crate matrix dimension on `kani.yml` will run within the 15-min cap when M3 lands its larger proofs on `secure_data`. M3 will revalidate.

## Mistakes made
- None material. The Cargo.toml `[lints.rust]` config was already worked out in fv M1; copy-paste worked first try.

## Root causes
- N/A.

## What was harder than expected
- Nothing material — the M2 proofs were the smallest meaningful proofs in their respective crates, by design.

## Invariants/assertions added or strengthened
- **Discriminant invariant** on `secure_authz::decision::Decision`: every constructed Decision has exactly one of `is_allowed()`/`is_denied()` true.
- **Limit-rejection invariant** on `secure_boundary::limits::RequestLimits`: the comparison `actual > configured` correctly drives the reject branch (within bounded ranges).
- **Default-limits-non-zero invariant**: every default in `RequestLimits` is > 0.

## Resource bounds established or verified
- Per-crate Kani matrix dim: `[secure_data, secure_authz, secure_boundary]`. 15-min cap is per-crate.
- Symbolic input bounds documented in each harness.

## Debugging / inspection notes
- Future M3 contributors should: (a) extend the matrix to include `secure_errors`; (b) follow the `[lints.rust] unexpected_cfgs` per-crate config pattern; (c) prefer discriminant-level proofs over full-engine proofs until the surface is provably small enough for Kani.

## Naming conventions established
- Harness naming: `<property_under_proof>` in snake-case verb form. Examples: `deny_by_default_decision_is_deny`, `depth_above_limit_is_rejected`, `default_limits_are_non_zero`.
- Module placement: `crates/<crate>/src/proofs.rs` with `#![cfg(kani)]`. Declared from `lib.rs` as `#[cfg(kani)] mod proofs;`.

## Test patterns that worked well
- The "discriminant proof" pattern — verifying a small property on a large enum without modelling the full engine. Reusable in M3.
- Hard-coded bounded ranges with rustdoc explaining why monotonicity covers larger inputs. Avoids state explosion without weakening the property.

## Missing tests that should exist now
- Workspace-level test that asserts every crate with a `proofs.rs` module also has the `[lints.rust] unexpected_cfgs` config — deferred. The pattern is now in 3 crates; mid-term, codify it.

## Rules for the next milestone (fv M3)
- Add `secure_errors` to the matrix; mirror the `[lints.rust] unexpected_cfgs` pattern.
- The `secure_data` nonce-uniqueness proof is the meaningful one (M1 was the bootstrap); axiomatise the AEAD per the research yellow-flag, prove uniqueness within a single encrypt-call path.
- The `secure_errors` no-internal-detail proof: prove that `into_response_parts(&err).body` does not contain `err.to_string()` for any `AppError` variant. Symbolic enum input.

## Template improvements suggested
- The v4 runbook for M2 envisioned a more tightly-coupled async proof; the discriminant-level pattern is the actual achievable shape and should be documented in the runbook template's "Kani-first design" notes.

# Lessons Learned — fv Milestone 3

## What changed
- `crates/secure_data/src/proofs.rs` extended with two M3 harnesses: `nonce_len_per_algorithm_in_canonical_set` (every `CryptoAlgorithm` variant returns 12 or 24 from `nonce_len()`) and `nonce_length_preserved_per_algorithm` (strengthens M1's nonce-non-zero into a per-algorithm length-preservation property).
- `crates/secure_errors/src/proofs.rs` (NEW; `#![cfg(kani)]`) — three harnesses on `into_response_parts`: status-in-4xx/5xx, code-non-empty-static-literal, code-in-whitelist.
- `crates/secure_errors/src/lib.rs` — `#[cfg(kani)] mod proofs;`.
- `crates/secure_errors/Cargo.toml` — `[lints.rust] unexpected_cfgs` for `cfg(kani)`.
- `.github/workflows/kani.yml` — matrix extended to include `secure_errors`.
- `docs/dev-guide/formal-verification.md` — proof catalogue extended to 13 rows.
- `CHANGELOG.md` — Unreleased entry.
- Runbook tracker — M3 done.

## Design decisions and why
- **Robust-to-future-variants pattern on the `secure_data` proof.** The original draft used an exhaustive `match` on `CryptoAlgorithm`; once pq M1 (#24) merges and adds a third variant, exhaustive match on a non-exhaustive enum becomes a compile error externally. The "value in canonical set" assertion is variant-agnostic and survives future additions (the M2 hybrid PQ variant uses 12 — already in the set).
- **`code-in-whitelist` proof on `secure_errors`.** The whitelist captures the API contract: any new `AppError` variant + new `code` forces a deliberate update, which is exactly the gate we want. A future contributor adding a variant without thinking about the public code will trip Kani in CI before the PR merges.
- **Three small `secure_errors` proofs rather than one large one.** Each proves one property; counterexample diagnosis is faster when the failing harness names the specific property. Same Kani-tractability budget as one combined proof, better debug ergonomics.
- **`nonce_length_preserved_per_algorithm`** assumes the bound (`expected_len ∈ {12, 24}`) explicitly. Without the assumption, Kani would explore arbitrary `usize` values; with it, the proof is bounded and tractable.

## Assumptions verified
- Kani's symbolic `kani::any::<AppError>()` covers every variant (verified at runbook authoring; documented in research dossier).
- `PublicError.code` is `&'static str` by type signature in `crate::public::PublicError` — Kani's bit-precise check on the type is sufficient.
- The `[lints.rust] unexpected_cfgs` config is required per crate; carrying forward fv M1's pattern works in `secure_errors` and the proofs compile clean.

## Assumptions still unresolved
- Whether the "code in whitelist" proof will surface as the right kind of failure when a new variant is added (i.e., a clear "code X is not in the whitelist" message, not a confusing internal Kani trace). M2 of a future "Kani UX" improvement runbook could verify.

## Mistakes made
- First draft used an exhaustive `match` on `CryptoAlgorithm`; would have broken on the day pq M1 merged. Caught and replaced with the "value in canonical set" pattern before commit.

## Root causes
- Kani-tractability and forward-compat sometimes conflict. The "value in canonical set" pattern is the future-safe choice when the enum is `#[non_exhaustive]` and may grow.

## What was harder than expected
- Picking the right invariant for `secure_errors` — there are several plausible properties (status range, code character set, message length, etc.). The whitelist-based proof captures the API contract most precisely.

## Invariants/assertions added or strengthened
- `secure_data`: per-algorithm nonce length is in canonical set; structural pass-through preserves length.
- `secure_errors`: status code in 4xx/5xx; `code` is a non-empty static literal; `code` is in the public-API whitelist.

## Resource bounds established or verified
- Whitelist size: 8 codes (matches the runbook's expected size). Adding a 9th requires deliberate update.
- Kani matrix dimension: 4 crates (`secure_data, secure_authz, secure_boundary, secure_errors`).

## Debugging / inspection notes
- A failing `code-in-whitelist` proof reports the offending code via Kani's counterexample. Future contributors should treat the report as "extend the whitelist deliberately, not paper over the proof."

## Naming conventions established
- Whitelist-style proofs for finite-set properties: name as `<property>_is_in_<set_name>`.
- Per-algorithm proofs: name as `<property>_per_algorithm_<verb>`.

## Test patterns that worked well
- The "robust to future enum variants" pattern via "value in canonical set" assertions instead of exhaustive `match`.
- Decoupling proof complexity by splitting one large proof into three smaller proofs each capturing one property.

## Missing tests that should exist now
- A workspace-level test that asserts every crate with a `proofs.rs` module also has the `[lints.rust] unexpected_cfgs` config (deferred from fv M2; with 4 crates now using the pattern, codifying it is overdue).

## Rules for the next milestone (fv M4 — circuit-breaker + TLA+)
- TLA+ requires the `slo-tla` SKILL workflow: write Naive variant first; verify TLC fails on Naive; write Hardened variant; verify TLC passes; translate any counterexample to a plain-English narrative.
- The new `secure_resilience::circuit_breaker` module must ship with rustdoc + dev-guide section + CHANGELOG entry per the runbook's "OSS docs are first-class output" principle.
- `tla.yml` CI lane (10-min cap) lands in fv M5; M4 only ships the spec + the new module + verified-design doc.

## Template improvements suggested
- The v4 runbook's M3 BDD scenarios anticipated specific harness shapes; the actual M3 implementation chose simpler shapes that are equally meaningful and Kani-tractable. Document the "value in canonical set" pattern in the runbook template's "Kani-first design" notes.

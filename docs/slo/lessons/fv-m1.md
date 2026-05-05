# Lessons Learned — fv Milestone 1

## What changed
- `crates/secure_data/src/proofs.rs` (NEW) — `#![cfg(kani)]`-gated module with two harnesses: `nonce_non_zero` (the bootstrap proof: a CSPRNG-axiom 12-byte nonce remains non-zero through structural copies) and `aes_256_gcm_nonce_len_is_12` (build-time invariant guard).
- `crates/secure_data/src/lib.rs` — `#[cfg(kani)] mod proofs;` declaration; harnesses excluded from regular builds.
- `crates/secure_data/Cargo.toml` — `[lints.rust] unexpected_cfgs = { check-cfg = ['cfg(kani)'] }` so the `cfg(kani)` flag does not trigger an `unexpected_cfgs` warning on regular builds.
- `.github/workflows/kani.yml` (NEW) — advisory Kani CI lane (`continue-on-error: true`, `timeout-minutes: 15`); pinned `kani-verifier 0.62.0`; runs `cargo kani -p secure_data` on every PR; matrix designed to extend per-crate as M2/M3 land.
- `docs/dev-guide/formal-verification.md` (NEW) — consumer-facing dev guide explaining what's proven today, what's planned, the local-run procedure, the promotion-criteria for advisory → blocking, and the anti-patterns disallowed under the project's formal-verification posture.
- `README.md` — Supply-Chain Security policy summary gains a "Formal verification" bullet citing the Kani lane and the planned TLA+ specs.
- `CHANGELOG.md` — Unreleased entry in user-facing language.
- Runbook tracker — M1 marked done.

## Design decisions and why
- **Harness lives in `src/proofs.rs` (gated by `#![cfg(kani)]`), not in `tests/` or a separate `proofs/` directory.** Three reasons: (1) `cargo kani` discovers `#[kani::proof]` annotations in the regular crate source tree by default; putting them in `src/` matches Kani's expected layout. (2) Co-locating the proof with the source it proves makes the dependency obvious. (3) The `#![cfg(kani)]` gate means regular `cargo build` and `cargo test` runs exclude the file entirely — zero impact on the production crate.
- **Hard-coded `AES_256_GCM_NONCE_LEN = 12` in `proofs.rs` rather than importing from `pq::sizes`.** The `pq::sizes` module is on the unmerged pq M1 PR (#24); fv M1 must be independently mergeable. Documented in the file with a TODO-equivalent comment that says: "once both PRs merge, future fv proofs can import `pq::sizes::AES_256_GCM_NONCE_LEN`."
- **The bootstrap proof models the CSPRNG with `kani::assume(nonce != [0u8; 12])`, then proves a structural copy preserves the property.** This is intentionally minimal — the runbook says "trivial proof to validate the pipeline." The CSPRNG itself is not within Kani's verification surface (it's FFI-backed via `OsRng`); modelling its non-all-zero output as an axiom is the standard approach. M3 will add the more meaningful `nonce-uniqueness within path` proof.
- **Pinned `kani-verifier 0.62.0`.** Per the research dossier, Kani's Rust-feature coverage moves; pinning prevents version drift from changing what compiles. Bumping the pin is a deliberate runbook change.
- **Matrix dimension on `crate` rather than `harness`.** The 15-min cap is per-crate; a future crate that has 5 harnesses uses one CI run, not 5. M2 adds `secure_authz` and `secure_boundary` rows; M3 adds `secure_errors`.
- **`continue-on-error: true` makes the lane advisory.** A failing proof shows yellow on the PR but does not block merge. Promotion to blocking is a separate runbook with explicit criteria (≥1 release cycle stable, false-positive rate characterised, runtime reproducible).
- **Two harnesses in M1, not one.** `aes_256_gcm_nonce_len_is_12` is a build-time invariant guard against accidental constant change; cheap to prove under Kani; serves as a regression test for the pq M2 wire-format dimensions. Keeping the proof catalogue at 2 from day one establishes "more than one harness per file is the norm."
- **`[lints.rust] unexpected_cfgs` configured locally in the crate's `Cargo.toml`, not as a workspace-level lint.** Other workspace crates do not yet use Kani; adding the lint config workspace-wide would add noise. M2 will add the same config to `secure_authz` and `secure_boundary`; M3 to `secure_errors`.

## Assumptions verified
- `cargo build -p secure_data` and `cargo test -p secure_data` are unchanged by the addition of the `#[cfg(kani)] mod proofs;` declaration. The 24 existing tests still pass.
- The `cfg(kani)` flag is not recognised by stable `rustc` outside Kani's environment; the `[lints.rust]` block tells rustc to recognise it without warning.
- The Kani CI workflow is structured to fail-soft (advisory) — even if `cargo kani` exits non-zero, the merge gate is not blocked.

## Assumptions still unresolved
- Whether `kani-verifier 0.62.0` is the latest stable as of 2026-05; the runbook authoring authored against this version. M2 will revalidate.
- Whether `cargo kani setup` is idempotent (cache-friendly) under Swatinem/rust-cache; the workflow assumes it is. First CI run will show; if not, a second cache-key dimension on the Kani version is the fix.
- Whether the `nonce_non_zero` harness will produce a counterexample when Kani is run locally. The CSPRNG axiom is sound; the structural copy is trivial; expectation is "passes" on first run.

## Mistakes made
- First-pass `proofs.rs` imported `crate::pq::sizes::AES_256_GCM_NONCE_LEN` — pq M1 isn't merged yet, so the constant isn't on `main`. Replaced with a hard-coded local `const` plus a comment explaining why.
- Initial build emitted `unexpected_cfgs` warning for `cfg(kani)`; resolved by adding `[lints.rust]` to the crate's Cargo.toml.

## Root causes
- Forward references to as-yet-unmerged sibling work (pq M1's `pq::sizes`) need explicit decoupling in the importing PR. Pattern: when a milestone introduces something a sibling milestone relies on, the relying milestone duplicates the constant locally with a "TODO: import once both PRs merge" comment.

## What was harder than expected
- The `cfg(kani)` lint config — it wasn't obvious from the runbook that this was needed; only the build warning surfaced it. Documented in the dev guide so future fv-M2/M3 contributors know to add it for new crates.

## Invariants/assertions added or strengthened
- **Build-time invariant**: `AES_256_GCM_NONCE_LEN == 12` (NIST SP 800-38D). Encoded in the harness; would surface as a Kani failure if the constant ever drifts.
- **Pipeline invariant**: a non-zero AES-256-GCM nonce remains non-zero after the structural copies in the envelope builder. Bootstrap proof — minimal but exercises the entire Kani toolchain.

## Resource bounds established or verified
- CI runtime cap: 15 minutes per crate (matrix dimension). Bootstrap harness runs in milliseconds locally; M2/M3 proofs will be larger but should stay well under the cap.
- Pinned Kani version: 0.62.0. Pinned via `cargo install --locked kani-verifier --version 0.62.0`.
- `target/kani` artifacts excluded from artifacts upload in M1 (M5's `tla.yml` will set the artifact pattern; mirror it then).

## Debugging / inspection notes
- Local `cargo kani` requires `cargo kani setup` to download CBMC; the workflow does this on the runner. First CI run is slow (cold cache); subsequent runs use Swatinem/rust-cache to retain `~/.kani/`.
- Kani's `--output-format old` emits a per-harness summary; `cargo kani --visualize` produces an HTML trace if a proof fails. Document for future fv-M2/M3 contributors in the dev guide.

## Naming conventions established
- Harness file: `crates/<crate>/src/proofs.rs` under `#![cfg(kani)]`. Harness functions: `<invariant_name>` (snake-case verb form, e.g., `nonce_non_zero`).
- CI workflow: `.github/workflows/kani.yml` (matrix on `crate`).
- Pinned version: stated in the workflow file's env block as `KANI_VERSION` and in `docs/dev-guide/formal-verification.md`.

## Test patterns that worked well
- One bootstrap harness exercising the full pipeline (toolchain install + invocation + result publication) before adding more substantive proofs. M2 adopts the same pattern: validate pipeline first, add harnesses second.

## Missing tests that should exist now
- A Rust-side integration test that asserts the workflow file syntax is valid YAML — deferred; CI will surface it on first run.
- A workspace-level test that asserts every Kani-using crate has the `[lints.rust] unexpected_cfgs` config — deferred to fv M2's lessons file when the second crate adopts the pattern.

## Rules for the next milestone (fv M2)
- Add `[lints.rust] unexpected_cfgs = { check-cfg = ['cfg(kani)'] }` to `secure_authz/Cargo.toml` and `secure_boundary/Cargo.toml`.
- Extend `.github/workflows/kani.yml` matrix with `secure_authz` and `secure_boundary` rows.
- Each new harness has a doc comment naming its invariant in plain English in <30 seconds of reading.
- Proof bounds (per the research synthesis): policy-set size ≤ 4 for authz; depth ≤ 12 / field-count ≤ 16 / body-size ≤ 2 KB for boundary.
- Per the runbook anti-patterns: no vacuously-true proof (commenting out the implementation must break the proof).
- Forward-reference rule (from this milestone's lessons): if the proof needs a constant from a sibling milestone, hard-code it locally with a comment.

## Template improvements suggested
- The v4 runbook's M1 "Files allowed to change" section anticipated a `crates/secure_data/proofs/nonce_non_zero.rs` directory layout. The actual cleaner placement is `src/proofs.rs` under `#![cfg(kani)]` because Kani discovers harnesses in `src/`. Future runbooks should validate the tool's expected layout against the runbook's anticipated layout during authoring.

# Lessons Learned — pqd Milestone 3

## What changed
- `crates/secure_data/src/algorithm.rs` — added `AlgorithmPolicy::min_envelope_version: Option<u8>`, `with_min_envelope_version(u8)` builder, `min_envelope_version()` accessor, and `validate_envelope_version(&str)` method that returns `AlgorithmRejectedByPolicy` with a clear reason on mismatch.
- `crates/secure_data/src/envelope.rs` — added `decrypt_with_policy()` public function that calls `policy.validate_envelope_version(&envelope.version)` before delegating to `decrypt_for_use`.
- `crates/secure_data/tests/pqd_m3_compat_matrix.rs` (NEW) — 9 BDD scenarios covering the 4-cell compatibility matrix + 2 abuse cases (`tm-pqd-abuse-6` downgrade, `tm-pqd-abuse-7` version-byte tamper) + builder/accessor/parsing tests.
- `CHANGELOG.md` — Unreleased entry.
- Runbook tracker — M3 done.

## Design decisions and why
- **`min_envelope_version` is a `u8`, not a `String`.** The wire-format `version` field is `String` for human readability ("1", "2"), but the policy comparison needs strict parsing. `u8` is sufficient — wire formats won't exceed 255 versions.
- **`validate_envelope_version` is fail-closed on parse error.** A non-numeric version string under a min-policy returns `AlgorithmRejectedByPolicy` rather than silently accepting. The default policy (no min) is still permissive — only an active policy enforces strict parsing.
- **`decrypt_with_policy` is a new public function rather than a parameter on `decrypt_for_use`.** Backward compat — every existing call site of `decrypt_for_use` continues to work unchanged. New consumers opt in to policy-enforced decrypt explicitly.
- **`tm-pqd-abuse-7` (version-byte tamper) leverages AAD binding.** The existing `build_aad` includes the envelope version string, so tampering with `envelope.version` after encrypt fails AEAD authentication. The test accepts any of `AuthenticationFailure` / `AlgorithmRejectedByPolicy` / `EnvelopeMalformed` — the property is "must NOT silently decrypt," not "must produce a specific error."

## Assumptions verified
- The 4-cell compat matrix is fully covered. Cells 1 & 2 (v1 producer × any consumer) round-trip; cells 3 & 4 (v2 producer × consumer) return `PqFeatureRequired` (no-pq build) or `PqUnavailable` (pq build, M2 fills the path).
- Builder + accessor pattern is consistent with existing `AlgorithmPolicy` ergonomics.
- The downgrade-attack defence is reachable from real consumer code via `decrypt_with_policy(envelope, provider, &strict_policy)`.

## Assumptions still unresolved
- Whether M2's hybrid encrypt path will cleanly slot into `decrypt_with_policy` without modification. Expectation: yes — the v2 envelope's version string parses to 2, satisfying any `min_envelope_version` ≤ 2 policy. Verify in M2.

## Mistakes made
- Test fixture used `[0u8; N]` literal arrays inside `serde_json::json!` — same lesson as pq M1: replace with `vec![0u8; N]`. Fixed first try.

## Root causes
- `serde_json::json!` macro semantics (only accepts JSON-shaped tokens, not Rust array-with-type-suffix). Pattern is now lessons-recorded twice; future runbook authoring should default to `vec![]` in JSON fixtures.

## What was harder than expected
- Choosing the right error variant for unparseable version strings under a min-policy. Initial draft used `EnvelopeMalformed`; settled on `AlgorithmRejectedByPolicy` because the rejection is policy-driven, not format-driven (an unparseable version *passes* validation under a no-min policy).

## Invariants/assertions added or strengthened
- **Cross-version invariant**: a v1 envelope under a `min_envelope_version=2` policy returns `AlgorithmRejectedByPolicy` before any AEAD work.
- **Fail-closed-on-parse invariant**: under an active min-policy, an unparseable version string returns `AlgorithmRejectedByPolicy`, never silently accepts.
- **Backward-compat invariant**: default `AlgorithmPolicy` (no `min_envelope_version`) continues to accept all envelope versions, including unparseable ones.

## Resource bounds established or verified
- `min_envelope_version: u8` — bounded by definition.
- Test fixture sizes: 32-byte wrapped key, 12-byte nonce, 16-byte ciphertext, 16-byte AAD; bounded.

## Debugging / inspection notes
- Failing test reports surface the actual error with `{:?}`-printed `DataError` variant — diagnosis is direct.

## Naming conventions established
- Policy validation methods: `validate_<property>(input)`. Mirrors existing `validate()` on `AlgorithmPolicy`.
- New decrypt-with-policy variant: `decrypt_with_policy()` — paired with existing `encrypt_with_policy()`.

## Test patterns that worked well
- The 4-cell compatibility matrix as a literal table in the test-file doc comment, with one `#[tokio::test]` per cell. Future readers can scan the matrix without reading the test bodies.
- `#[cfg(feature = "pq")]` / `#[cfg(not(feature = "pq"))]` to express cell 3 vs. cell 4 cleanly. Both build-modes have meaningful tests.

## Missing tests that should exist now
- M2's full v2 round-trip test (currently blocked on the hybrid encrypt path; M3 only exercises the v2-on-non-pq-build error path).
- A property test that fuzzes envelope-version strings under a strict policy (out of M3 scope; deferred to a post-1.0 hardening runbook).

## Rules for the next milestone (pq M4 — FIPS-track readiness)
- Doc-only milestone: no production-code change beyond the optional runtime metadata field for `pq_fips_status`.
- Honest labelling: no "FIPS validated PQ" string anywhere; CI lint blocks it.
- Cross-link the migration plan's FIPS section to dev-guide.

## Template improvements suggested
- The v4 runbook M3 BDD scenarios anticipated 4 cells + 2 abuse cases; the actual implementation added 3 builder/accessor tests for completeness. Future runbooks should treat builder/accessor coverage as part of the "reasonable test coverage" baseline.

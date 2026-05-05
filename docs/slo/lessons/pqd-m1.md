# Lessons Learned — pqd Milestone 1

## What changed
- `crates/secure_data/src/algorithm.rs` — added `CryptoAlgorithm::HybridX25519MlKem768` variant; extended `as_str()`, `from_envelope_str()`, `nonce_len()`, `rank()`; added `is_post_quantum()` predicate.
- `crates/secure_data/src/envelope.rs` — added `combiner_id: Option<u8>` field with `#[serde(default, skip_serializing_if = "Option::is_none")]`; added `EnvelopeEncrypted::validate_structure()` method; routed hybrid algorithm to `DataError::PqUnavailable` in `encrypt_with_policy` and `decrypt_for_use`; added defense-in-depth match arms in `encrypt_with_algorithm` / `decrypt_with_algorithm` helpers.
- `crates/secure_data/src/error.rs` — added `PqUnavailable`, `PqFeatureRequired`, `AlgorithmRejectedByPolicy { reason }`, `EnvelopeMalformed { reason }` variants.
- `crates/secure_data/src/lib.rs` — declared `pub mod pq;` (always available).
- `crates/secure_data/src/pq/mod.rs` — NEW module declaring `sizes` submodule, `COMBINER_ID_X25519_ML_KEM_768 = 0x01`, `COMBINER_ID_RESERVED_FUTURE_MIN = 0x80`, `COMBINER_ID_FAIL_CLOSED = 0xFF`, `is_recognised_combiner()`.
- `crates/secure_data/src/pq/sizes.rs` — NEW module with 7 size constants (FIPS 203, RFC 7748, RFC 5869, RFC 6234) plus 4 sanity-check unit tests.
- `crates/secure_data/Cargo.toml` — added `pq = []` feature flag (no deps in M1; M2 fills with `ml-kem`, `x25519-dalek`, `hkdf`, `sha2`).
- `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` — NEW BDD suite (12 scenarios covering happy path, backward compat, abuse cases tm-pqd-abuse-1/2, sizes module, error variant ergonomics, migration-plan-doc invariant).
- `docs/slo/design/pq-migration-plan.md` — NEW, authoritative migration plan (≥9000 chars; references FIPS 203, RFC 7748, RFC 5869, RustCrypto/ml-kem v0.3.0, AWS-LC, the threat-model framing, the rollout playbook, the FIPS-track posture).
- `docs/dev-guide/secure-data.md` — added "Post-Quantum Readiness" section between Crypto Agility and Full Integration Example.
- `README.md` — `secure_data` Feature Flags table gains a `pq` row.
- `CHANGELOG.md` — Unreleased entry in user-facing language.
- `docs/slo/future/RUNBOOK-pq-readiness-secure-data.md` — M1 marked done.

## Design decisions and why
- **`combiner_id: Option<u8>`, not a wire-format version byte.** The runbook envisioned a `version: u8` for v1/v2 distinction, but the existing code already has `version: String` (semver-style). Adding a separate `u8` would create dual versioning and confusion. Instead: `combiner_id` carries the PQ KEM combiner identifier — `None` for classical, `Some(0x01)` for hybrid. `version: String` stays as the human-readable wire-format version (M2 will bump to "2"). Documented in the migration plan.
- **`#[serde(default, skip_serializing_if = "Option::is_none")]` on `combiner_id`.** Two contracts: (1) pre-M1 envelopes (without the field on the wire) deserialize cleanly with `combiner_id == None` (proven by `pre_m1_envelope_without_combiner_id_field_deserializes_with_none`); (2) classical envelopes serialised post-M1 don't emit the field, keeping bytes-per-envelope unchanged for the dominant case.
- **`Some(0)` accepted as synonym for `None` in `validate_structure`.** A permissive third-party serde codec might emit `Some(0)` instead of `None` for an absent optional. The `(false, Some(0)) => Ok(())` arm absorbs this without weakening the rejection of any other non-zero combiner.
- **`pq::sizes` module is always available.** The size constants come from FIPS 203 / RFC 7748 / RFC 5869 — they're public knowledge and don't require any dependency. Making them gated behind `pq` would needlessly hide the wire-format dimensions from non-PQ consumers reviewing the design.
- **`pq` feature is `[]` in M1, not `pq = ["dep:ml-kem"]`.** The hybrid KEM implementation lands in M2; M1 reserves the flag so:
  - `cargo build -p secure_data --features pq` succeeds today (no missing deps).
  - The `cfg(feature = "pq")` gates I added in `validate_structure` compile cleanly.
  - Future M2 PR adds `ml-kem`, `x25519-dalek`, `hkdf`, `sha2` deps to the `pq` feature without breaking the flag's existing meaning.
- **Defense-in-depth match arms in `encrypt_with_algorithm` / `decrypt_with_algorithm`.** The dispatch in the public functions (`encrypt_with_policy`, `decrypt_for_use`) already filters out PQ via `is_post_quantum()`, but the helper match needed an arm to satisfy non-exhaustive coverage. Returning `Err(DataError::PqUnavailable)` instead of `unreachable!()` is the safer choice — if a future caller forgets the dispatch, we fail closed with a structured error rather than panic.
- **`HybridX25519MlKem768` ranks above `XChaCha20Poly1305` (rank 3 vs. 2).** This means a policy `min_algorithm = XChaCha20Poly1305` accepts hybrid; a policy `min_algorithm = HybridX25519MlKem768` rejects classical. Forward-compat for downgrade prevention.
- **Migration plan is load-bearing — substantive doc with locked-in decisions.** The plan is referenced by every M2/M3/M4 PR in this runbook; every "Locked-in decision" row binds future work. The test `migration_plan_doc_exists_and_is_non_trivial` is a build-time invariant that catches accidental deletion or trivialisation.
- **No production-code references to the migration plan via doc-link `[\`...\`]` syntax.** Rustdoc treats `[\`docs/slo/...\`]` as a link target and emits a warning. Used plain backticks `\`docs/...\`` instead.

## Assumptions verified
- The existing `EnvelopeEncrypted` struct already carries a `version: String` field — adding a numeric version would conflict; chose `combiner_id: Option<u8>` instead.
- `#[non_exhaustive]` on `CryptoAlgorithm` allowed adding the new variant without forcing every downstream `match` to gain an arm. (Internal matches in `encrypt_with_algorithm`/`decrypt_with_algorithm` did need the new arm — fixed.)
- The existing `AlgorithmBelowPolicyMinimum` variant covers AEAD-rank rejection; the new `AlgorithmRejectedByPolicy { reason }` covers the higher-level policy decisions M3 will introduce (e.g., `min_envelope_version`).
- Serde's `#[serde(default, skip_serializing_if = "Option::is_none")]` cleanly handles forward and backward compat for the new optional field.
- `cargo build -p secure_data` and `cargo build -p secure_data --features pq` both succeed in M1.

## Assumptions still unresolved
- Whether `RustCrypto/ml-kem` v0.3.0 will be the still-current recommendation when M2 lands. The migration plan locks the decision; M2 will revalidate against the latest research before adding the dep.
- Whether the `combiner_id` byte will remain sufficient for forward-compat or whether a future combiner family will require a multi-byte identifier. Locked-in for M2; reservable bits in `0x80–0xFE` give room.

## Mistakes made
- First-pass test file used em-dash (`—`) inside a `b"..."` byte literal — non-ASCII; compile error. Replaced with `--`.
- First-pass test file used `[5u8; 12]` inside `serde_json::json!` macro — the macro doesn't accept the type suffix. Replaced with the explicit literal array.
- First-pass rustdoc used `[\`docs/slo/.../pq-migration-plan.md\`]` link form — rustdoc warning ("unresolved link"). The repo's CI gate is `RUSTDOCFLAGS="-D warnings" cargo doc`, so warnings = build failure. Fixed by using plain backticks.

## Root causes
- Macro DSLs (serde_json) and rustdoc's link parser have specific syntax expectations that aren't always obvious from the API. Pattern: when adding new doc-comment text or in-test JSON, build first before assuming it works.

## What was harder than expected
- Reconciling the runbook's idealised `version: u8` envelope versioning with the existing `version: String` semver-style field. The chosen `Option<u8> combiner_id` is a cleaner solution and sidesteps a redundant version byte. Documented in the migration plan so future readers don't ask why.
- Keeping the `validate_structure` match arms exhaustive while also gating PQ-specific cases on `cfg(feature = "pq")`. The `(true, _)` arm without the feature and the `(true, None)` / `(true, Some(_))` arms with the feature is the right shape but took two iterations to land.

## Invariants/assertions added or strengthened
- **Wire-format invariant**: classical envelopes have `combiner_id == None` (or `Some(0)` for permissive serialisers). Non-zero combiner on a classical algorithm is rejected at validate time with `EnvelopeMalformed`.
- **Build-skew invariant**: a v2 hybrid envelope on a non-`pq` build returns `PqFeatureRequired`. No silent fallback; no panic.
- **Feature-flag invariant**: encrypting with `HybridX25519MlKem768` on any M1 build returns `PqUnavailable`. M2 will fill the `pq`-feature path; the M1 contract is "fails fast with structured error."
- **Combiner-id invariant**: `0xFF` is the permanent fail-closed sentinel. Reserved-future combiners (`0x02`–`0xFE` excluding the recognised set) return `AlgorithmRejectedByPolicy`.
- **Migration-plan invariant**: the doc must exist, be substantive, and reference the locked-in `ml-kem`, FIPS, and HKDF-SHA-256 choices. Build-time test enforces.

## Resource bounds established or verified
- ML-KEM-768 ciphertext: 1088 bytes (FIPS 203). Encoded as `pq::sizes::ML_KEM_768_CIPHERTEXT_LEN`.
- ML-KEM-768 public key: 1184 bytes; shared secret: 32 bytes.
- X25519 share / shared secret: 32 bytes each (RFC 7748).
- HKDF-SHA-256 output: 32 bytes (RFC 5869 + RFC 6234).
- AES-256-GCM nonce: 12 bytes (NIST SP 800-38D).

All bounded; encoded as `const usize`; sanity-checked by unit tests in `pq::sizes::tests`.

## Debugging / inspection notes
- `cargo expand -p secure_data` confirms `#[serde(default, skip_serializing_if)]` macro expansion does not introduce unsafe (no `forbid(unsafe_code)` regression).
- The error-message format strings include the relevant wire-format identifier (algorithm string, combiner_id hex byte) without leaking sensitive material.

## Naming conventions established
- `CryptoAlgorithm::HybridX25519MlKem768` — reads as "hybrid X25519 + ML-KEM-768"; matches the FIPS 203 / IETF naming. The `as_str()` form `"X25519+ML-KEM-768/HKDF-SHA-256"` is the wire-format identifier.
- `pq::COMBINER_ID_X25519_ML_KEM_768 = 0x01` — combiner identifier convention is `COMBINER_ID_<scheme>` for recognised, `COMBINER_ID_RESERVED_FUTURE_MIN` / `COMBINER_ID_FAIL_CLOSED` for sentinels.
- Test naming: `pqd_m<N>_<feature>.rs` — matches the `prefix-m<N>` pattern from the runbook.

## Test patterns that worked well
- BDD tests that bind to the migration plan doc via a build-time invariant (`migration_plan_doc_exists_and_is_non_trivial`). Catches accidental doc deletion.
- Pre-M1 envelope JSON fixture as a test case proves backward compat without needing a binary file.
- Mutation-test pattern for rejection cases: construct a valid envelope, mutate the field under test, assert rejection with the expected error.

## Missing tests that should exist now
- M2 will add: KAT round-trip (FIPS 203 vectors), tamper-resistance on `wrapped_data_key`, `combiner_id == 0xFF` rejection (live path), v2 envelope on non-PQ build.
- A workspace-level test that asserts no docstring contains the literal "FIPS validated PQ" string (M4-scoped, but the lint is small enough to land alongside).

## Rules for the next milestone (pq M2 — hybrid KEM impl)
- Use `RustCrypto/ml-kem` v0.3.0 (locked in migration plan §2). Don't re-litigate.
- Wire-format version bumps from `"1"` to `"2"` for hybrid envelopes; `combiner_id == Some(0x01)`.
- Every new dep (`ml-kem`, `x25519-dalek`, `hkdf`, `sha2`) gets a `cargo deny licenses` check + a `cargo vet` audit row in the same PR.
- KAT fixtures live in `crates/secure_data/tests/fixtures/ml_kem_768_kat.bin`. Regenerate from FIPS 203 reference if the upstream `ml-kem` crate ships them.
- Decrypt path runs `validate_structure` first (already wired in M1).
- AAD for hybrid envelopes binds the `combiner_id` byte (M2 task — the M1 `build_aad` does not yet include it; M2 must extend).
- `cargo geiger` baseline will tick up when `ml-kem` lands; document the delta in the M2 lessons file.

## Template improvements suggested
- The v4 runbook M1 BDD section assumed a `version: u8` field; the actual existing schema used `version: String`. Future runbooks should validate the assumed schema against `git grep` for the relevant struct definition during the runbook authoring step, not during execution.
- The runbook's "Files allowed to change" list referenced `EncryptionEnvelope`; the actual struct is `EnvelopeEncrypted`. Same lesson — verify the struct name during runbook authoring.

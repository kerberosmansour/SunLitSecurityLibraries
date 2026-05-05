# Completion Summary — pqd Milestone 1

## Goal completed
`secure_data` now reserves the public surface for a post-quantum migration path: `CryptoAlgorithm::HybridX25519MlKem768` enum slot, `EncryptionEnvelope::combiner_id: Option<u8>` wire-format field with backward-compat default, four new structured error variants (`PqUnavailable`, `PqFeatureRequired`, `AlgorithmRejectedByPolicy`, `EnvelopeMalformed`), the `pq` feature flag (no deps in M1), and the `pq` module with size constants from FIPS 203 / RFC 7748 / RFC 5869 plus combiner identifiers. The migration plan at `docs/slo/design/pq-migration-plan.md` documents the locked-in decisions (RustCrypto `ml-kem` v0.3.0, concat + HKDF-SHA-256 wire format, monitor-only FIPS posture) and is the authoritative source for M2/M3/M4 design decisions. Existing classical encrypt/decrypt is unchanged; pre-M1 envelopes deserialize cleanly with `combiner_id == None`.

## Files changed
- `crates/secure_data/src/algorithm.rs` — new variant; extended dispatch.
- `crates/secure_data/src/envelope.rs` — new field + `validate_structure()`; PQ short-circuits in `encrypt_with_policy` and `decrypt_for_use`; defense-in-depth helper arms.
- `crates/secure_data/src/error.rs` — 4 new variants.
- `crates/secure_data/src/lib.rs` — `pub mod pq;`
- `crates/secure_data/src/pq/mod.rs` — NEW; combiner constants + `is_recognised_combiner()`.
- `crates/secure_data/src/pq/sizes.rs` — NEW; 7 size constants + 4 sanity unit tests.
- `crates/secure_data/Cargo.toml` — `pq = []` feature.
- `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` — NEW; 12 BDD scenarios.
- `docs/slo/design/pq-migration-plan.md` — NEW; migration plan (≥9000 chars).
- `docs/dev-guide/secure-data.md` — new "Post-Quantum Readiness" section.
- `README.md` — Feature Flags table gains a `pq` row.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/pqd-m1.md` — NEW.
- `docs/slo/completion/pqd-m1.md` — NEW (this file).
- `docs/slo/future/RUNBOOK-pq-readiness-secure-data.md` — M1 marked done.

## Tests added
- `crates/secure_data/tests/pqd_m1_envelope_versioning.rs::*` — 12 scenarios:
  - `classical_envelope_round_trips_unchanged` (happy path)
  - `xchacha_envelope_round_trips_unchanged` (happy path)
  - `pre_m1_envelope_without_combiner_id_field_deserializes_with_none` (backward compat)
  - `hybrid_kem_request_returns_pq_unavailable_in_m1` (abuse case `tm-pqd-abuse-1`)
  - `classical_envelope_with_non_zero_combiner_is_rejected` (abuse case `tm-pqd-abuse-2`)
  - `classical_envelope_with_zero_combiner_id_is_accepted` (permissive serialiser interop)
  - `pq_sizes_module_is_publicly_available_without_pq_feature`
  - `combiner_id_constants_match_migration_plan`
  - `hybrid_algorithm_round_trips_via_envelope_string`
  - `classical_algorithms_are_not_post_quantum`
  - `new_data_error_variants_format_intelligibly`
  - `migration_plan_doc_exists_and_is_non_trivial`
- `crates/secure_data/src/pq/sizes.rs::tests::*` — 4 unit tests on size constants.

## Runtime validations added
- `EnvelopeEncrypted::validate_structure()` runs on every `decrypt_for_use` invocation as the pre-flight step. Rejects v1 envelopes carrying combiner_id, v2 envelopes on non-PQ builds, and reserved/fail-closed combiner identifiers — all before any cryptographic operation.

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test -p secure_data` — 24 tests pass (unit + integration, no `pq` feature).
- `cargo test -p secure_data --features pq` — 24 tests pass.
- `cargo test --workspace` — 22 final-target tests pass.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p secure_data --no-deps --all-features` — clean.
- `cargo audit && cargo deny check` — clean.

## Compatibility checks performed
- Pre-M1 envelope JSON deserializes cleanly with `combiner_id == None`.
- AES-256-GCM and XChaCha20-Poly1305 round-trip unchanged.
- AES-256-GCM remains the default `CryptoAlgorithm`.
- All existing `KeyProvider` implementations unchanged.
- All existing feature flags (`vault`, `aws-kms`, `fips`, `password`, `azure-kv`, `mobile-storage`) unchanged in shape and meaning.
- No public type rename in `algorithm` / `envelope` modules.
- Workspace-wide `forbid(unsafe_code)` regression test (from fug M1) still passes.

## Invariants/assertions added
- See lessons file §"Invariants/assertions added or strengthened".

## Resource bounds added or verified
- All M2 wire-format dimensions encoded as `const usize` in `pq::sizes`. See lessons file §"Resource bounds established or verified".

## Documentation updated
- `docs/slo/design/pq-migration-plan.md` (NEW).
- `docs/dev-guide/secure-data.md` — new "Post-Quantum Readiness" section.
- `README.md` — Feature Flags table.
- `CHANGELOG.md` — Unreleased entry.
- Rustdoc on every new public item.

## .gitignore changes
- None required.

## Test artifact cleanup verified
- `git status` clean of any test artifacts.

## Deferred follow-ups
- M2 (issue #8): hybrid X25519 + ML-KEM-768 / HKDF-SHA-256 KEM implementation behind `pq` feature.
- M3 (issue #9): cross-version compatibility matrix + `AlgorithmPolicy::min_envelope_version`.
- M4 (issue #10): FIPS-track readiness note + `fips` × `pq` interaction documentation.

## Known non-blocking limitations
- The M1 hybrid encrypt path returns `PqUnavailable` even on a `--features pq` build because the implementation lands in M2; documented in the dev-guide and migration plan.
- The migration plan locks `ml-kem` v0.3.0; M2 will revalidate against latest research before adding the dep.

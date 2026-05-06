# Completion Summary — pqd Milestone 2

## Goal completed
`secure_data` now has an executable hybrid X25519 + ML-KEM-768 envelope key-wrap path behind `--features pq`. Hybrid encryption emits v2 envelopes with `combiner_id = Some(0x01)` and a `wrapped_data_key` blob shaped as `ML-KEM-768 ciphertext || X25519 share || AES-GCM-wrapped DEK`. Hybrid decrypt validates the envelope structure first, unwraps the provider-protected hybrid-recipient seed, decapsulates the hybrid KEM, unwraps the data-encryption key, and returns byte-identical plaintext. Classical AES-256-GCM and XChaCha20-Poly1305 paths remain unchanged.

## Files changed
- `crates/secure_data/Cargo.toml` — `pq` feature now enables `ml-kem`, `x25519-dalek`, `hkdf`, and `sha2`.
- `crates/secure_data/src/pq/combiner.rs` — NEW HKDF-SHA-256 combiner and AAD binding helper.
- `crates/secure_data/src/pq/kem.rs` — NEW hybrid encapsulation/decapsulation implementation.
- `crates/secure_data/src/pq/mod.rs` — hybrid exports and `fips_status()`.
- `crates/secure_data/src/envelope.rs` — v2 hybrid encrypt/decrypt dispatch.
- `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` — M1 no-feature regression adjusted for the now-implemented pq build path.
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs` — NEW M2 BDD suite.
- `crates/secure_data/tests/fixtures/ml_kem_768_kat.bin` — NEW pinned KAT fixture.
- `docs/dev-guide/secure-data-pq.md` — NEW dedicated PQ guide.
- `docs/dev-guide/secure-data.md`, `README.md`, `CHANGELOG.md`, `docs/slo/design/pq-migration-plan.md`, and `docs/slo/future/RUNBOOK-pq-readiness-secure-data.md` — M2 documentation updates.
- `docs/dev-guide/unsafe-budget.md` — records the secure_data+pq geiger attempt.
- `supply-chain/audits.toml` and `supply-chain/config.toml` — cargo-vet coverage for the new dependency graph.

## Tests added
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs::v2_hybrid_envelope_round_trips_with_pq_feature`
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs::tm_pqd_abuse_3_tampered_ml_kem_ciphertext_fails_cleanly`
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs::tm_pqd_abuse_4_fail_closed_combiner_is_rejected`
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs::hybrid_encapsulation_uses_fresh_x25519_share`
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs::ml_kem_768_acvp_kat_decapsulates_through_hybrid_combiner`
- no-`pq` regression for `tm-pqd-abuse-5`: v2 hybrid envelope returns `DataError::PqFeatureRequired`.

## Static analysis and formatter evidence
- `cargo check -p secure_data --features pq` — clean.
- `cargo check -p secure_data` — clean.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test --workspace` — clean.
- `cargo test -p secure_data --features pq --test pqd_m2_hybrid_kem` — clean.
- `cargo test -p secure_data --features pq` — clean.
- `cargo audit` — clean.
- `cargo deny check` — pass; emitted existing warning-only duplicate/advisory-not-detected noise.
- `cargo vet` — clean after direct audit rows and transitive safe-to-deploy exemptions.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` — clean.
- Borrowed M4 FIPS/PQ claim grep — clean.
- `bash scripts/audit.sh` — hard supply-chain checks passed; cargo-geiger advisory step was terminated after repeating the known registry matching noise and the wrapper still reported "All supply-chain checks passed."

## Compatibility checks performed
- Pre-M1/M1 classical envelopes continue to round-trip without the `pq` feature.
- Selecting `HybridX25519MlKem768` without the `pq` feature returns `DataError::PqUnavailable`.
- Reading a v2 hybrid envelope without the `pq` feature returns `DataError::PqFeatureRequired`.
- Tampering `combiner_id`, ML-KEM ciphertext, X25519 share, or wrapped DEK fails closed.
- `pq::fips_status()` returns `Some("pending_cmvp")`; no FIPS-validation claim is made.

## Supply-chain evidence
- Direct dependency audit rows added for `ml-kem` 0.3.0, `x25519-dalek` 2.0.1, `hkdf` 0.12.4, and `sha2` 0.10.9.
- Transitive cargo-vet exemptions added for `keccak` 0.2.0, `kem` 0.3.0, `module-lattice` 0.2.2, and `sha3` 0.11.0.
- Workspace first-party crates now explicitly set `audit-as-crates-io = false`, which resolves cargo-vet ambiguity after package version bumps.

## Known non-blocking limitations
- The local secure_data+pq `cargo-geiger` run timed out with cargo-geiger v0.13.0 before producing a number. This is recorded in `docs/dev-guide/unsafe-budget.md`; the existing reference-service advisory CI lane remains the tracked workspace baseline.
- The provider-protected hybrid-recipient seed is stored in v2 hybrid envelope metadata to keep the `KeyProvider` trait unchanged. This is an implementation detail of the M2 path, not a new public provider API.

## Deferred follow-ups
- pq M3 should update its compatibility matrix expectation for v2 producer / pq consumer from `PqUnavailable` to successful round-trip after rebasing on M2.
- pq M4 remains responsible for the final FIPS-track runtime/CI documentation and lint integration.

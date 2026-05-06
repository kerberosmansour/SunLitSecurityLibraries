# Lessons Learned — pqd Milestone 2

## What changed
- `crates/secure_data/Cargo.toml` — `pq` now enables `ml-kem`, `x25519-dalek`, `hkdf`, and `sha2`.
- `crates/secure_data/src/pq/combiner.rs` — NEW HKDF-SHA-256 combiner with info string `sunlit-pq-x25519-ml-kem-768/v1` and helper AAD binding for `combiner_id`.
- `crates/secure_data/src/pq/kem.rs` — NEW hybrid X25519 + ML-KEM-768 encapsulation and decapsulation helpers.
- `crates/secure_data/src/pq/mod.rs` — exports the hybrid helpers and `fips_status()`.
- `crates/secure_data/src/envelope.rs` — routes `CryptoAlgorithm::HybridX25519MlKem768` through a v2 hybrid envelope path when `--features pq` is enabled; keeps classical paths unchanged.
- `crates/secure_data/tests/pqd_m2_hybrid_kem.rs` — NEW BDD and regression suite for round-trip, tamper handling, no-feature behavior, and KAT drift.
- `crates/secure_data/tests/fixtures/ml_kem_768_kat.bin` — NEW pinned NIST ACVP ML-KEM-768 KAT fixture.
- `docs/dev-guide/secure-data-pq.md` — NEW consumer guide for enabling and using the PQ feature.
- `docs/dev-guide/secure-data.md`, `README.md`, `CHANGELOG.md`, and `docs/slo/design/pq-migration-plan.md` — M2-facing docs updated.
- `supply-chain/audits.toml` and `supply-chain/config.toml` — direct dependency audit rows plus transitive exemptions required by cargo-vet.

## Design decisions and why
- **The public `KeyProvider` trait stayed unchanged.** The runbook required the hybrid path to use the existing provider shape and keep `wrapped_data_key` equal to `ML-KEM ciphertext || X25519 share || AES-GCM-wrapped DEK`. M2 therefore stores a provider-wrapped per-envelope hybrid-recipient seed in hybrid envelope metadata and derives the ML-KEM/X25519 recipient key material from that seed. The actual data-encryption key is wrapped only by the hybrid-derived AES-256-GCM key.
- **`key_version` carries hybrid metadata only for v2 PQ envelopes.** Classical envelopes continue to use provider key versions exactly as before. The hybrid parser rejects malformed metadata before decapsulation.
- **AAD now includes `combiner_id` for v2 envelopes.** This binds the combiner choice into authentication; tampering the byte changes the AEAD tag input and fails before plaintext is returned.
- **The KAT helper accepts either seed-form or expanded ML-KEM secret keys.** The local runtime path uses seed-derived key material; the NIST ACVP decapsulation fixture publishes an expanded 2400-byte secret key, so the test-only fixture validates both the upstream representation and SunLit's combiner.

## KAT fixture surprises
- The NIST ACVP fixture used here is an ML-KEM encap/decap vector, not a complete hybrid vector. The test combines the published ML-KEM shared secret with an RFC 7748 X25519 test vector and verifies SunLit's HKDF combiner output.
- The ACVP vector publishes the expanded ML-KEM-768 decapsulation key. Supporting that format in `hybrid_decapsulate` makes the KAT a direct regression test instead of a fixture translation exercise.
- A first-pass X25519 expected shared secret was transcribed incorrectly; the round-trip test caught it immediately. The committed value is the RFC 7748 scalar multiplication result for the fixture pair.

## Supply-chain notes
- `x25519-dalek` v2.0.1 is BSD-3-Clause, not MIT/Apache like the other direct PQ dependencies. The workspace deny policy already permits BSD-3-Clause, and the audit note records the actual license instead of repeating the prompt shorthand.
- `ml-kem` brings four previously unvetted transitive crates into the graph: `keccak`, `kem`, `module-lattice`, and `sha3`. They are recorded as cargo-vet safe-to-deploy exemptions, while the four direct dependencies have explicit audit rows.

## Cargo geiger note
- The M2-specific invocation `cd crates/secure_data && timeout 60 cargo geiger --features pq --update-readme=false` did not produce a number locally. `cargo-geiger` v0.13.0 emitted repeated `Failed to match (ignoring source)` lines and timed out with exit 124. A 180-second JSON run was also attempted as post-milestone evidence.
- Because the tool did not produce a reliable secure_data+pq number locally, `docs/dev-guide/unsafe-budget.md` records the timeout and keeps the existing reference-service baseline as the main tracked metric. CI's advisory geiger lane remains the source of truth for the workspace artifact.

## Divergence from the locked design
- The locked `wrapped_data_key` wire shape is unchanged: `ML-KEM_ct || X25519_share || AES-GCM-wrapped DEK`.
- The only implementation detail not spelled out in the design plan is where the provider-protected hybrid-recipient seed lives while keeping `KeyProvider` unchanged. M2 stores it in v2 hybrid metadata so provider implementations do not need PQ-specific methods.

## Invariants/assertions added or strengthened
- v2 hybrid envelopes produced with `--features pq` round-trip byte-identical plaintext.
- v2 hybrid envelopes carry `version == "2"` and `combiner_id == Some(0x01)`.
- Tampered ML-KEM ciphertext fails decapsulation cleanly.
- `combiner_id = 0xFF` remains fail-closed through `validate_structure()`.
- A v2 hybrid envelope on a build without `--features pq` returns `DataError::PqFeatureRequired`.
- Pre-M1/M1 classical envelope behavior is unchanged.

## Deferred follow-ups
- pq M3 should update the v2-producer by pq-consumer compatibility cell from `PqUnavailable` to a successful round-trip once it rebases over M2.
- KMS-side hybrid wrapping remains out of scope until providers expose PQ or hybrid wrap APIs.
- The cargo-geiger secure_data+pq timeout should be revisited if cargo-geiger releases a version that handles the current dependency graph more reliably.

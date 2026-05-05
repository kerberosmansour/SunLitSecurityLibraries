# Changelog

All notable user-facing changes should be recorded here once the crates are
published.

This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/)
and uses Cargo-compatible semantic versioning. Pre-1.0 releases may still make
breaking API changes, but security fixes and migration notes should be explicit.

## Unreleased

- Published the per-rule ANSSI Rust Secure Coding Guidelines mapping. All 61
  pinned rules now carry a posture (`compliant`, `partial`, `waived`, or
  `N/A`) with concrete evidence pointers or named compensating controls, so EU
  consumers can cite the mapping in procurement reviews and IEC 62443-4-1 SD-3
  audit support.
- New CI lint at `scripts/anssi-mapping-lint.sh` gates the ANSSI Rust
  compliance mapping at `docs/compliance/anssi-rust.md`. Validates that
  the ANSSI commit pin matches, the rule count is exactly 61, every
  Status column is populated, and every `compliant` row's Evidence
  pointer resolves to a real artifact (file:line, clippy lint, docs
  path, or test name). The lint is no-op while rows remain `unfilled`
  (M1 placeholder) and becomes gating once M2 populates evidence. Wired
  into the supply-chain CI job. Closes #20.
- You can now opt into hybrid X25519 + ML-KEM-768 envelope key wrap in
  `secure_data` with `--features pq`. New writes that select
  `CryptoAlgorithm::HybridX25519MlKem768` produce v2 envelopes whose data key
  is wrapped as `ML-KEM-768 ciphertext || X25519 share || AES-GCM-wrapped DEK`
  with `combiner_id = 0x01`; existing classical v1 envelopes continue to
  decrypt unchanged. The `pq` path is labelled `pending_cmvp` and makes no
  FIPS-validation claim. Closes #8.
- `secure_data::pq::fips_status() -> Option<&'static str>` reports the
  runtime FIPS posture of the PQ path. `None` when `pq` is not enabled;
  `Some("pending_cmvp")` when `pq` is enabled (no CMVP cert covers
  ML-KEM-768 as of 2026-05, so the honest label is validation-pending).
  A future `pq-aws-lc` feature will return `Some("validated")` after a
  CMVP cert lands. CI lint at `scripts/lint-fips-pq-claims.sh` blocks any
  regression of the documentation posture by failing the build on
  forbidden phrasings. Closes #10.
- `secure_data` adds `AlgorithmPolicy::with_min_envelope_version(u8)` and
  `secure_data::envelope::decrypt_with_policy` for downgrade-attack
  defence on the decrypt side. A consumer that requires v2-or-higher
  envelopes can now reject v1 envelopes at the structural boundary
  before any AEAD work; v1 envelopes return
  `DataError::AlgorithmRejectedByPolicy { reason }`. Default
  `AlgorithmPolicy` continues to accept every envelope. Closes #9.
- `secure_data` reserves a post-quantum migration path. The crate now exposes a
  `CryptoAlgorithm::HybridX25519MlKem768` enum slot, an optional
  `EncryptionEnvelope::combiner_id: Option<u8>` wire-format field, and a public `pq` module with
  size constants and combiner identifiers. The migration plan
  (`docs/slo/design/pq-migration-plan.md`) is the authoritative source for the
  wire format, the hybrid-KEM design (X25519 ⊕ ML-KEM-768 / HKDF-SHA-256 per
  research), the FIPS-track posture (monitor only — no CMVP cert covers
  ML-KEM as of 2026-05), and the rollout playbook for downstream consumers.
  Existing classical envelopes continue to encrypt and decrypt unchanged;
  `combiner_id` is omitted from the wire for classical envelopes (serde
  `skip_serializing_if`). Pre-M1 envelopes deserialize cleanly with
  `combiner_id == None`. Hybrid encryption returns `DataError::PqUnavailable`
  on builds without `--features pq`; v2 hybrid envelopes presented to a non-`pq` build return `DataError::PqFeatureRequired`
  with no silent fallback. Closes #7.
- The supply-chain CI lane now runs `cargo-geiger` (pinned to `0.13.0`) on
  every PR and uploads the JSON artifact (30-day retention). The advisory step
  surfaces transitive `unsafe` usage in the dependency tree; deltas are
  visible to reviewers on the PR via artifact diff. Local parity is
  available via `bash scripts/audit.sh` (or `pwsh scripts/audit.ps1`).
  The current measured baseline (root = `secure_reference_service`,
  `--all-features`) is **22 636 transitive unsafe expressions used / 48 192
  available**; SunLit crates contribute zero. Threshold = baseline + 10 %
  headroom. Promotion of the threshold to a blocking gate is a separate
  future runbook. See `docs/dev-guide/unsafe-budget.md`.
- All workspace crates are now `#![forbid(unsafe_code)]` (added to
  `secure_smoke_service`; the other 13 crates already had the attribute). The
  posture is regression-tested by `crates/security_core/tests/no_unsafe_code.rs`
  — any future removal fails the build with a named-crate error. A companion
  scan also asserts no `unsafe ` keyword appears anywhere in `crates/*/src/`.
- Added public open-source governance files: license, notice, trademarks,
  contributing guide, security policy, code of conduct, issue templates, and PR
  template.
- Normalized runbooks and milestone artifacts under `docs/slo/`.

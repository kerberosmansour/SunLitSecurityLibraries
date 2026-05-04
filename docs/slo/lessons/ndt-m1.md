# Lessons — ndt M1

## What Changed

- Added `secure_device_trust` as the official typed device trust policy crate.
- Added BDD coverage for fresh supported attestation, unsupported platforms,
  malformed evidence, and shared app bootstrap rejection in production.
- Added dev-guide and README entries for the new crate.

## Evidence

- Baseline before M1: `cargo test --workspace` passed.
- BDD-first: `cargo test -p secure_device_trust` failed with four expected
  behavior failures while the evaluator was still a placeholder.
- `cargo test -p secure_device_trust`: pass after implementation.

## Rules For The Next Milestone

- M2 must not add a filesystem CA signer outside an explicit test profile.
- M2 should consume `DeviceTrustDecision`; it should not reimplement bootstrap,
  platform, or attestation-mode policy.
- Keep raw attestation payloads out of public errors, logs, and decision
  structs. Use redacted summaries only.
- Preserve the stable public names introduced in M1 unless an explicit migration
  is added to both runbooks.

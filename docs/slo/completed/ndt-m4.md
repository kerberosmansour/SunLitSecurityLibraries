# Completion Summary - ndt Milestone 4

## Goal completed

- `secure_authz` now treats native device trust as a first-class authorization input through `DeviceTrustContext`.
- Route policies can require hardware-backed trust, test-only software-bound trust, or software-bound trust, and deny by default when context is absent or insufficient.
- User sessions are checked against the authorized mTLS identity before route authorization allows access.
- Actix Web services can enforce device-trust route policy with `DeviceTrustTransform`.

## Files changed

- `crates/secure_authz/Cargo.toml`
- `crates/secure_authz/src/decision.rs`
- `crates/secure_authz/src/decision_log.rs`
- `crates/secure_authz/src/device_trust.rs`
- `crates/secure_authz/src/lib.rs`
- `crates/secure_authz/src/actix/middleware.rs`
- `crates/secure_authz/src/actix/mod.rs`
- `crates/secure_authz/tests/e2e_sunlit_ndt_m4.rs`
- `crates/secure_reference_service/Cargo.toml`
- `crates/secure_reference_service/src/lib.rs`
- `crates/secure_reference_service/src/routes/mod.rs`
- `crates/secure_reference_service/src/routes/device_trust.rs`
- `crates/secure_reference_service/tests/e2e_sunlit_ndt_m4.rs`
- `docs/slo/future/RUNBOOK-native-device-trust.md`
- `docs/slo/verify/ndt-m4.md`
- `docs/slo/lessons/ndt-m4.md`
- `docs/slo/completed/ndt-m4.md`

## Tests added

- `crates/secure_authz/tests/e2e_sunlit_ndt_m4.rs`
- `crates/secure_reference_service/tests/e2e_sunlit_ndt_m4.rs`

## Runtime validations added

- BDD runtime coverage for hardware-trust denial/allow, CI/test trust profile gating, revoked trust denial, untrusted edge spoof rejection, and sender-constrained session mismatch.
- Actix Web middleware runtime coverage for allowed, missing-context, and untrusted-edge contexts.
- Reference-service route coverage for hardware and CI/test trust tiers.
- Verification report: `docs/slo/verify/ndt-m4.md`

## Compatibility checks performed

- `cargo fmt --all -- --check`
- `cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features`
- `cargo test -p secure_reference_service --test e2e_sunlit_ndt_m4`
- `cargo test -p secure_authz -p secure_reference_service --all-features`
- `cargo test -p secure_identity -p secure_authz -p secure_network --all-features`
- `cargo test --workspace`
- `cargo check --workspace --all-features`
- `cargo check --workspace --no-default-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo audit`
- `cargo deny check`

## Documentation updated

- `docs/slo/future/RUNBOOK-native-device-trust.md` tracker and M4 evidence log.
- `docs/slo/verify/ndt-m4.md` verification report.
- `docs/slo/lessons/ndt-m4.md` lessons for S9/M5.

## .gitignore changes

- No new M4 ignore patterns were required; the existing native-device-trust ignore coverage still applies to generated artifacts.

## Test artifact cleanup verified

- `git status --short --branch` shows only expected source, test, and SLO documentation changes on `native-device-trust-libraries`; no generated M4 test artifacts were left behind.

## Deferred follow-ups

- S9/M5 must add external conformance and release gates across ZeroTrustAuth and SunLitSecurityLibraries.
- Guardian should consume the Actix Web adapter path and add a product-shaped route stack integration test.
- The multi-adapter crate docs should keep Actix Web marked as the Guardian primary path and Axum as reference-harness/optional adapter material.

## Known non-blocking limitations

- `cargo audit` and `cargo deny check` pass with configured warnings for existing transitive dependency posture; they are not newly introduced by M4 but must remain visible in release evidence.
- The reference service remains Axum-based; Actix Web behavior is covered through `DeviceTrustTransform` tests.

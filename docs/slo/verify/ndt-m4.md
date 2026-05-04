# Verification Report - ndt Milestone 4

## What was exercised

| Scenario | Category | How exercised | Result | Evidence |
|---|---|---|---|---|
| high-trust route | runtime BDD | `cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features` evaluated a hardware-backed route with a software-bound device context | pass | denied with `DenyReason::DeviceTrustTierTooLow` |
| high-trust route allow | runtime BDD | same test evaluated the hardware-backed route with a hardware-backed, cert-bound user session | pass | allowed with `device-trust:hardware-backed` obligation |
| low-trust route | runtime BDD | same test evaluated a CI/test route with a software-bound identity in `DeviceTrustProfile::Test` | pass | allowed with `device-trust:software-bound` obligation |
| low-trust production guard | runtime BDD | same test evaluated the CI/test route with the same software-bound identity in `DeviceTrustProfile::Production` | pass | denied with `DenyReason::TestTrustProfileRequired` |
| revoked session | runtime BDD | same test marked the trust context as revoked before route evaluation | pass | denied with `DenyReason::DeviceTrustRevoked` |
| header spoof | runtime BDD | same test evaluated context extracted from untrusted edge metadata | pass | denied with `DenyReason::UntrustedDeviceMetadata` |
| sender-constrained session | runtime BDD | same test paired a `BoundUserSession` with a different `MtlsClientIdentity` | pass | denied with `DenyReason::DeviceSessionBindingMismatch` |
| Actix adapter allow | runtime adapter | same test wrapped an Actix service in `DeviceTrustTransform` with a trusted context in request extensions | pass | request reached handler and returned 200 |
| Actix adapter missing context | runtime adapter | same test called the Actix service without device-trust context | pass | short-circuited with 403 |
| Actix adapter spoof rejection | runtime adapter | same test injected an untrusted-edge context into the Actix service | pass | short-circuited with 403 |
| reference service hardware route | runtime E2E | `cargo test -p secure_reference_service --test e2e_sunlit_ndt_m4` called `/device-trust/hardware` with hardware and software contexts | pass | hardware context returned 200; software context returned 403 |
| reference service CI route | runtime E2E | same test called `/device-trust/ci` with test and production profiles | pass | test profile returned 200; production profile returned 403 |
| missing context route denial | runtime E2E | same test called device-trust routes without context | pass | missing context returned 403 |
| focused regression | regression | `cargo test -p secure_authz -p secure_reference_service --all-features` | pass | authz and reference-service tests/doctests passed |
| Guardian cross-crate path | regression | `cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | identity, authz, network tests/doctests passed together |
| full workspace | regression | `cargo test --workspace` | pass | workspace tests and doctests passed |
| feature matrix | regression | `cargo check --workspace --all-features` and `cargo check --workspace --no-default-features` | pass | both feature configurations compiled |
| lint | static | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | passed after removing a redundant `#[must_use]` attribute |
| supply chain | static | `cargo audit` | pass | command exited 0 with configured allowed warnings for `rand` and yanked `fastrand` transitive paths |
| supply chain policy | static | `cargo deny check` | pass | command exited 0 with configured warnings and final `advisories ok, bans ok, licenses ok, sources ok` |

## Bugs found

| id | severity | scenario | regression test | status |
|----|----------|----------|-----------------|--------|
| N/A | N/A | N/A | N/A | no verification bugs found |

## Environment

- OS: Darwin 25.4.0 arm64
- Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
- Cargo: `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- Browser/UI: N/A, pure Rust library and backend adapter milestone

## Coverage gaps

- The existing `secure_reference_service` remains the repo's Axum runtime harness; Guardian's primary path is covered through the new Actix Web `DeviceTrustTransform` tests.
- External GitHub/public endpoint conformance is deliberately deferred to S9/M5.

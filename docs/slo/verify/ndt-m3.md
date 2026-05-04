# Verification Report - ndt Milestone 3

## What was exercised

| Scenario | Category | How exercised | Result | Evidence |
|---|---|---|---|---|
| happy path | runtime BDD | `cargo test -p secure_identity --test e2e_sunlit_ndt_m3` issued a passkey challenge after valid session mTLS and completed a `BoundUserSession` | pass | challenge and session both carried `sha256:session-cert-1` |
| replay | runtime BDD | same test completed a passkey proof with a different `MtlsClientIdentity` | pass | rejected with `PasswordlessError::CertificateBindingMismatch` |
| unsupported passkey | runtime BDD | same test requested passkey-first login with `PasskeySupport::Unsupported` | pass | fallback challenge selected `PasswordlessMethod::DeepLink` and session remained mTLS-bound |
| no cert | runtime BDD | same test requested a challenge with `None` for mTLS identity | pass | rejected with `PasswordlessError::MissingClientCertificate` |
| denied device trust | runtime BDD | same test requested a challenge with a revoked-bootstrap `DeviceTrustDecision` | pass | rejected with `PasswordlessError::DeniedDeviceTrust` |
| redaction | runtime BDD | same test formatted challenge, proof, and session with `Debug` | pass | token, proof material, serial, and fingerprint were not present |
| feature compatibility | regression | `cargo test -p secure_identity --all-features` | pass | identity crate tests and doctests passed |
| cross-crate compatibility | regression | `cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | identity/authz/network tests and doctests passed |
| full workspace | regression | `cargo test --workspace` | pass | workspace tests and doctests passed |
| feature matrix | regression | `cargo check --workspace --all-features` and `cargo check --workspace --no-default-features` | pass | both feature configurations compiled |
| lint | static | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | no warnings |
| supply chain | static | `cargo audit` | pass | command exited 0 with existing allowed warnings |
| supply chain policy | static | `cargo deny check` | pass | command exited 0 with configured warnings |

## Bugs found

| id | severity | scenario | regression test | status |
|----|----------|----------|-----------------|--------|
| N/A | N/A | N/A | N/A | no verification bugs found |

## Environment

- OS: Darwin 25.4.0 arm64
- Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
- Cargo: `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- Browser/UI: N/A, pure Rust library milestone

## Coverage gaps

- ZeroTrustAuth route-level runtime conversion is not part of S6; it is the next sequenced step, S7.
- Real passkey/WebAuthn cryptographic verification remains adapter-owned through `PasswordlessProofVerifier`; this milestone verifies the library contract, ordering, and mTLS binding policy.

# Native Device Trust — SunLitSecurityLibraries (AI-First Runbook)

> **Purpose**: Ship official supported libraries for native-client device trust,
> passwordless user authentication binding, and authorization predicates, with
> ZeroTrustAuth as the external conformance harness.
> **Audience**: AI coding agents first, humans second.
> **Prerequisite reading**: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`,
> and `../future/RUNBOOK-native-device-trust.md` consumers in the ZeroTrustAuth
> repo.

---

## Runbook Metadata

- **Runbook ID**: `native-device-trust`
- **Prefix for tests and lessons**: `ndt`
- **Primary stack**: Rust 2021, Cargo workspace, Actix Web-first server
  consumers for Sunlit Guardian, reqwest/rustls clients, x509 parsing,
  WebAuthn/passkey integration surface. Existing axum adapters remain supported
  where the library already exposes them, but this runbook validates the
  Guardian Actix Web path first.
- **Primary crates**:
  - New: `secure_device_trust`
  - Changed: `secure_identity`, `secure_authz`, `secure_network`,
    `security_events`, `secure_reference_service`
- **Default test commands**:
  - Format: `cargo fmt --all -- --check`
  - Workspace tests: `cargo test --workspace`
  - Device trust crate: `cargo test -p secure_device_trust --all-features`
  - Identity/authz/network compatibility: `cargo test -p secure_identity -p secure_authz -p secure_network --all-features`
  - Feature matrix: `cargo check --workspace --all-features` and `cargo check --workspace --no-default-features`
  - Lints: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - Conformance: run ZeroTrustAuth `make smoke` against local library-backed services
- **Allowed new dependencies by default**: none; each milestone must name them.
- **Schema/config migration allowed by default**: no.
- **Public interfaces that must remain stable once introduced**:
  - `secure_device_trust::{BootstrapIdentity, DeviceAttestationEvidence, TrustTier, SessionCertificateRequest, SessionCertificateIssuer, RevocationChecker}`
  - `secure_identity::{PasswordlessChallengeService, BoundUserSession}`
  - `secure_authz::DeviceTrustContext`
  - `secure_network::MtlsClientIdentity`

---

## Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Device trust core crate and threat-model tests | `done` | 2026-05-04 | 2026-05-04 | `docs/slo/lessons/ndt-m1.md` | `secure_device_trust` now exposes typed trust requests, decisions, tiers, reason codes, attestation-mode handling, and production shared-bootstrap rejection. |
| 2 | Session certificate lifecycle and revocation | `done` | 2026-05-04 | 2026-05-04 | `docs/slo/lessons/ndt-m2.md` | `secure_device_trust` now exposes session certificate request/profile/issuer/revocation APIs, and `secure_network` validates trusted-edge mTLS identity expiry and revocation state. |
| 3 | Passwordless user login bound to device trust | `done` | 2026-05-04 | 2026-05-04 | `docs/slo/lessons/ndt-m3.md` | `secure_identity` now exposes passwordless challenge issuance and `BoundUserSession` APIs pinned to verified session mTLS and allowing device trust decisions. |
| 4 | Authorization predicates and service adapters | `done` | 2026-05-04 | 2026-05-04 | `docs/slo/lessons/ndt-m4.md` | `secure_authz` now exposes `DeviceTrustContext`, trust-tier route policies, and an Actix Web `DeviceTrustTransform` adapter. |
| 5 | ZeroTrustAuth conformance and external release gates | `in_progress` | 2026-05-04 | | | Library release-gate workflow and developer handoff docs are implemented; external non-dry-run conformance remains blocked on the ZeroTrustAuth staging endpoint and CI bootstrap issuer. |

---

## Cross-Repo Execution Sequence

This runbook is the official library producer. `ZeroTrustAuth` is the
conformance consumer that proves the supported APIs end to end. Execute the
two runbooks in this order unless the user explicitly overrides it:

| Step | Repo | Work item | Gate before moving on |
|---|---|---|---|
| S0 | `SunLitSecurityLibraries` | TLA+ gate for native device trust invariants | TLC passes and invariants are linked from this runbook |
| S1 | `ZeroTrustAuth` | M1 — certificate-only executable spec for device-before-user and token binding | `make smoke` proves no-cert/bootstrap-only/replay negatives and happy path |
| S2 | `SunLitSecurityLibraries` | M1 — `secure_device_trust` core crate and typed trust decisions | library tests prove trust tiers, client type/platform, and attestation mode |
| S3 | `SunLitSecurityLibraries` | M2 — session certificate issuance, refresh, and revocation | CSR policy and revocation tests pass |
| S4 | `ZeroTrustAuth` | M2 — replace handwritten trust lifecycle with library-backed adapters | `make smoke` remains green using supported APIs |
| S5 | `ZeroTrustAuth` | M3 — attestation conformance profiles and backend `off`/`monitor`/`enforce` modes | `make smoke-attestation` and fixture tests prove policy outcomes |
| S6 | `SunLitSecurityLibraries` | M3 — passwordless challenge and `BoundUserSession` APIs | passkey/deep-link session binding tests pass |
| S7 | `ZeroTrustAuth` | M4 — use library-backed passwordless login and device-pinned user sessions | token replay with a different mTLS cert is rejected |
| S8 | `SunLitSecurityLibraries` | M4 — `secure_authz::DeviceTrustContext` and service adapters | route predicates deny by default and trust-tier tests pass |
| S9 | Both | M5 — external conformance endpoint and release gates | GitHub/external conformance evidence is uploaded for releases |

**Sequencing rule**: ZeroTrustAuth may move ahead only to create executable
acceptance evidence. Production contracts and reusable policy logic must move
back into SunLitSecurityLibraries before Guardian consumes them.

---

## Target Architecture

```
Native client
  -> secure_network mTLS + pinning
  -> CDN / Cloudflare-like public edge
  -> AWS origin edge
  -> EKS Istio ingress
  -> Actix Web enrollment service
  -> secure_device_trust validates bootstrap + client type/platform + attestation mode + CSR
  -> short-lived session certificate
  -> Actix Web protected API edge
  -> secure_identity passkey/deeplink challenge bound to mTLS cert
  -> secure_authz policies require DeviceTrustContext
  -> Sunlit Guardian services

ZeroTrustAuth:
  local Compose + public mTLS-only conformance endpoint + GitHub Actions tests
```

## TLA+ Gate

TLA+ is required before implementation begins. The model must cover:

- bootstrap identity states: authorised, revoked;
- session certificate states: absent, issued, expired, revoked;
- attestation evidence states: off, monitor, enforce, fresh, stale, unsupported;
- actions: enroll, refresh, revoke bootstrap, revoke session, authenticate user,
  call protected API;
- invariants: no protected call without a valid non-revoked session cert; no
  refresh after bootstrap revocation; user sessions are bound to the mTLS
  certificate that obtained the login challenge.

**S0 status**: complete. See:

- `specs/NativeDeviceTrust.tla`
- `specs/NativeDeviceTrust.cfg`
- `specs/NativeDeviceTrustNaive.cfg`
- `specs/NativeDeviceTrust.trace.md`
- `docs/slo/design/native-device-trust-verified.md`

TLC evidence on 2026-05-04:

- Naive config failed with `ChallengeRequiresSessionMtls` at depth 2.
- Hardened config passed with 263,953 generated states, 16,200 distinct states,
  depth 13, and zero invariant violations.

---

## M1 — Device Trust Core Crate

**Goal**: Add `secure_device_trust` with typed trust evidence and validation
policy, without issuing certificates yet.

**Contract Block**

| Row | Contract |
|---|---|
| Inputs | bootstrap certificate metadata, client type, platform, app id, release channel, backend attestation mode, optional attestation evidence |
| Outputs | `DeviceTrustDecision` with trust tier, reason codes, freshness, and audit classification |
| Interfaces touched | new `secure_device_trust`; exports from workspace root |
| Files allowed to change | `Cargo.toml`, `crates/secure_device_trust/**`, docs/dev-guide, README crate table |
| Data classification | Confidential for device identifiers and attestation summaries; Restricted for private key material, which must never enter APIs |
| Proactive controls | C1 security requirements, C6 digital identity, C8 protect data, C9 logging |
| Abuse acceptance scenarios | `tm-native-device-trust-abuse-1`, `tm-native-device-trust-abuse-3` |
| Forbidden shortcuts | no stringly typed trust tiers; no production use of shared app cert as trusted device identity |

**BDD Acceptance**

| Scenario | Given | When | Then |
|---|---|---|---|
| happy path | valid platform evidence and authorised bootstrap identity | trust policy evaluates | decision is `Trusted` with expected tier |
| unsupported platform | platform cannot attest | policy evaluates | decision is lower tier and routes can deny it |
| malformed evidence | hostile evidence payload | parser runs | safe error, no panic, no raw payload logged |
| abuse | copied shared app cert without per-install binding | policy evaluates in production profile | rejected |

**E2E Runtime Validation**: `secure_reference_service` exposes a test route that
returns only the redacted `DeviceTrustDecision`.

---

## M2 — Session Certificate Lifecycle And Revocation

**Goal**: Implement CSR validation, short-lived session certificate issuance
policy, refresh windows, and revocation hooks.

**Contract Block**

| Row | Contract |
|---|---|
| Inputs | `SessionCertificateRequest`, validated `DeviceTrustDecision`, CA signer profile |
| Outputs | session certificate bundle, expiry, refresh-after, revocation handle |
| Interfaces touched | `secure_device_trust::SessionCertificateIssuer`, `RevocationChecker`; `secure_network::MtlsClientIdentity` compatibility |
| Files allowed to change | `crates/secure_device_trust/**`, `crates/secure_network/src/**`, tests |
| Data classification | Confidential for cert serial/fingerprint/device id; Restricted for signer keys |
| Proactive controls | C6 identity, C8 data protection, C9 audit, C10 safe errors |
| Abuse acceptance scenarios | `tm-native-device-trust-abuse-2`, `tm-native-device-trust-abuse-3`, `tm-native-device-trust-abuse-7` |
| Forbidden shortcuts | no filesystem CA signer outside test profile; no signing arbitrary CSR extensions |

**BDD Acceptance**

| Scenario | Given | When | Then |
|---|---|---|---|
| happy path | trusted device request with valid CSR | issuer signs | cert has clientAuth EKU, allowed SANs, bounded TTL |
| invalid CSR | CSR asks for forbidden extension | issuer validates | request rejected |
| revoked bootstrap | bootstrap identity revoked | client refreshes | no new session cert issued |
| expired session | session cert expired | API identity validator runs | rejected |

**E2E Runtime Validation**: ZeroTrustAuth enrollment service is converted to use
library issuer APIs and `make smoke` remains green.

**S3 status**: complete for the library gate. ZeroTrustAuth conversion and
`make smoke` evidence are intentionally sequenced as S4 in the cross-repo
runbook so the conformance harness proves consumption of these supported APIs.

**Evidence Log**

| Command | Expected | Actual | Pass/Fail | Notes |
|---|---|---|---|---|
| Repo hygiene | branch is not default/protected | branch before/after `native-device-trust-libraries`; origin default `origin/feature/milestone-automation`; dirty tree contains current S0-S3 docs/code work | Pass | no branch remediation needed |
| Carry-forward check | prior retro items surfaced if present | `gh issue list --label retro-derived --search "ndt" --state open --json number,title,body,url` returned `[]` | Pass | no carry-forward scope candidates |
| Baseline: `cargo test --workspace` | pass before M2 code changes | passed before M2 code changes | Pass | confirmed S2 workspace state was green |
| BDD-first M2 tests | fail for expected behavior gaps | `cargo test -p secure_device_trust --test e2e_sunlit_ndt_m2` failed 6 tests: issuance stub rejected valid CSR, CSR policy did not detect forbidden extension, refresh ignored revocation, mTLS validator accepted expired identity | Pass | failures were behavioral, not compile errors |
| `cargo test -p secure_device_trust --test e2e_sunlit_ndt_m2` | pass | passed 7 tests | Pass | issuance, CSR extension/SAN policy, revoked bootstrap, revoked session, denied trust, expired identity |
| `cargo test -p secure_network --test mtls_identity_tests` | pass | passed 3 tests | Pass | valid trusted edge, untrusted edge, revoked identity |
| `cargo test -p secure_device_trust --all-features` | pass | passed | Pass | M1 and M2 device trust tests |
| `cargo test -p secure_network` | pass | passed | Pass | existing network tests plus mTLS identity tests |
| `cargo fmt --all -- --check && cargo test --workspace` | pass | passed | Pass | full workspace regression |
| `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | pass | passed | Pass | feature matrix |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | passed | Pass | lint gate |
| ZeroTrustAuth conversion | defer to S4 | not run in S3 | Pass | next sequenced step is ZeroTrustAuth M2 adapters |

---

## M3 — Passwordless User Login Bound To Device Trust

**Goal**: Add supported identity APIs for passkey-first login after mTLS device
trust and bind the resulting user session to the session certificate.

**Contract Block**

| Row | Contract |
|---|---|
| Inputs | verified `MtlsClientIdentity`, `DeviceTrustDecision`, passkey or deep-link proof |
| Outputs | passwordless challenge, completed `BoundUserSession` |
| Interfaces touched | `secure_identity::PasswordlessChallengeService`, `secure_identity::BoundUserSession` |
| Files allowed to change | `crates/secure_identity/**`, `crates/security_events/**`, tests |
| Data classification | Restricted for user auth proof material; Confidential for session fingerprint |
| Proactive controls | C6 identity, C7 access control, C8 protect data, C9 security logging |
| Abuse acceptance scenarios | `tm-native-device-trust-abuse-4`, `tm-native-device-trust-abuse-5` |
| Forbidden shortcuts | no challenge route before mTLS; no bearer token without cert/channel binding |

**BDD Acceptance**

| Scenario | Given | When | Then |
|---|---|---|---|
| happy path | valid session mTLS | challenge requested | challenge includes binding to cert fingerprint |
| replay | passkey result from a different mTLS cert | completion attempted | rejected |
| unsupported passkey | platform lacks passkey support | fallback challenge requested | deep-link proof still bound to mTLS |
| no cert | browser-like caller requests challenge | route executes | rejected before challenge generation |

**E2E Runtime Validation**: ZeroTrustAuth `GET /v1/login/challenge` and planned
`POST /v1/login/complete` use the library API.

**S6 status**: complete for the library gate. ZeroTrustAuth route conversion is
intentionally sequenced as S7 so the conformance harness proves consumption of
these supported APIs.

**Evidence Log**

| Command | Expected | Actual | Pass/Fail | Notes |
|---|---|---|---|---|
| Repo hygiene | branch is not default/protected | branch before/after `native-device-trust-libraries`; origin default `origin/feature/milestone-automation`; dirty tree contains current S0-S6 docs/code work | Pass | no branch remediation needed |
| Carry-forward check | prior retro items surfaced if present | `gh issue list --label retro-derived --search ndt --state open --json number,title,body,url` returned `[]` | Pass | no carry-forward scope candidates |
| Baseline: `cargo test --workspace` | pass before M3 code changes | passed before M3 code changes | Pass | confirmed S5/S6 starting state was green |
| BDD-first M3 tests | fail for expected behavior gaps | `cargo test -p secure_identity --test e2e_sunlit_ndt_m3` failed 5 tests: challenge issuance returned `ProviderUnavailable`, no-cert and denied-device paths were not enforced yet | Pass | failures were behavioral after the API skeleton compiled |
| `cargo test -p secure_identity --test e2e_sunlit_ndt_m3` | pass | passed 6 tests | Pass | cert-bound challenge/session, replay rejection, deep-link fallback, no-cert rejection, denied trust rejection, Debug redaction |
| `cargo test -p secure_identity --all-features` | pass | passed | Pass | identity compatibility with biometric, OIDC, Redis-session features |
| `cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | passed | Pass | integration compatibility across identity, authz, and mTLS identity crates |
| `cargo fmt --all -- --check` | pass | passed | Pass | formatting gate |
| `cargo test --workspace` | pass | passed | Pass | full workspace regression |
| `cargo check --workspace --all-features` | pass | passed | Pass | all-feature matrix |
| `cargo check --workspace --no-default-features` | pass | passed | Pass | no-default-feature matrix |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | passed | Pass | lint gate |
| `cargo audit` | pass or allowed warnings only | passed with existing allowed warnings for `rand` and yanked `fastrand` transitive paths | Pass | no new blocking advisory from M3 |
| `cargo deny check` | pass or configured warnings only | passed with configured warnings about duplicate crates, advisory ignores not encountered, and yanked `fastrand` | Pass | no new blocking deny finding from M3 |
| ZeroTrustAuth route conversion | defer to S7 | not run in S6 | Pass | next sequenced step is ZeroTrustAuth M4 library-backed passwordless login |

---

## M4 — Authorization Predicates And Service Adapters

**Goal**: Make device trust a first-class authorization input, not only an
authentication side effect.

**Contract Block**

| Row | Contract |
|---|---|
| Inputs | `BoundUserSession`, `DeviceTrustDecision`, route/action/resource |
| Outputs | deny-by-default authz decision with device-trust obligations |
| Interfaces touched | `secure_authz::DeviceTrustContext`, policy fixtures/testkit |
| Files allowed to change | `crates/secure_authz/**`, `crates/secure_reference_service/**`, tests; extended on 2026-05-04 to include root `Cargo.lock` because `secure_authz` must depend on local `secure_device_trust`, `secure_identity`, and `secure_network` types for first-class device-trust authorization. This repo currently ignores `Cargo.lock`, so no tracked lockfile artifact is expected. |
| New dependencies allowed | local workspace/path dependencies on `secure_device_trust`, `secure_identity`, and `secure_network` only |
| Data classification | Confidential for device trust context |
| Proactive controls | C7 access control, C9 audit, C10 safe errors |
| Abuse acceptance scenarios | `tm-native-device-trust-abuse-6`, `tm-native-device-trust-abuse-7` |
| Forbidden shortcuts | no route may treat device trust as optional unless policy explicitly allows lower tier |

**BDD Acceptance**

| Scenario | Given | When | Then |
|---|---|---|---|
| high-trust route | route requires hardware/platform trust | software-bound device calls | deny |
| low-trust route | route allows CI/test trust | CI conformance identity calls | allow only in test profile |
| revoked session | authz receives revoked trust context | policy evaluates | deny and audit |
| header spoof | caller injects fake identity headers | adapter extracts context | trusted edge metadata only is accepted |

**E2E Runtime Validation**: reference service has routes requiring distinct
trust tiers and tests assert expected allow/deny outcomes.

**S8 status**: complete. `secure_authz` now exposes typed device-trust route
policy APIs and an Actix Web adapter suitable for Guardian's primary stack.
The existing `secure_reference_service` remains the repo's Axum runtime harness
and now includes device-trust tier routes for conformance coverage.

**Evidence Log**

| Command | Expected | Actual | Pass/Fail | Notes |
|---|---|---|---|---|
| Repo hygiene | branch is not default/protected | branch before/after `native-device-trust-libraries`; origin default `origin/feature/milestone-automation`; dirty tree contains current S0-S8 docs/code work | Pass | no branch remediation needed |
| Carry-forward check | prior retro items surfaced if present | `gh issue list --label retro-derived --search ndt --state open --json number,title,body,url` returned `[]` | Pass | no carry-forward scope candidates |
| Baseline: `cargo test -p secure_authz -p secure_reference_service --all-features` | pass before M4 code changes | passed before M4 code changes | Pass | confirmed S8 starting state was green |
| BDD-first M4 authz tests | fail for expected behavior gaps | `cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features` failed 7 tests with `Deny { reason: NoPolicyMatch }` after the skeleton compiled | Pass | failures were behavioral, not the final implementation |
| BDD-first M4 reference-service tests | fail until routes exist | initial reference-service integration failed before device-trust route implementation was complete | Pass | route and decision matching were added after the red phase |
| `cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features` | pass | passed 10 tests | Pass | hardware trust, CI/test trust, production guard, revoked context, untrusted edge spoofing, session binding mismatch, Actix adapter allow/deny |
| `cargo test -p secure_reference_service --test e2e_sunlit_ndt_m4` | pass | passed 5 tests | Pass | hardware and CI/test trust routes allow/deny as expected |
| `cargo test -p secure_authz -p secure_reference_service --all-features` | pass | passed | Pass | authz and reference-service regression suite |
| `cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | passed | Pass | Guardian-relevant identity/authz/network typed path |
| `cargo fmt --all -- --check` | pass | passed | Pass | formatting gate |
| `cargo test --workspace` | pass | passed | Pass | full workspace regression |
| `cargo check --workspace --all-features` | pass | passed | Pass | all-feature matrix |
| `cargo check --workspace --no-default-features` | pass | passed | Pass | no-default-feature matrix |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | passed after removing redundant `#[must_use]` on `DeviceTrustRoutePolicy::evaluate` | Pass | lint-only cleanup, no behavior change |
| `cargo audit` | pass or allowed warnings only | passed with existing allowed warnings for `rand` and yanked `fastrand` transitive paths | Pass | no new blocking advisory from M4 |
| `cargo deny check` | pass or configured warnings only | passed with configured warnings and final `advisories ok, bans ok, licenses ok, sources ok` | Pass | no new blocking deny finding from M4 |
| Runtime verification report | `docs/slo/verify/ndt-m4.md` written | written | Pass | all BDD/E2E rows recorded |
| Lessons and completion docs | M4 closeout docs written | `docs/slo/lessons/ndt-m4.md` and `docs/slo/completed/ndt-m4.md` written | Pass | rules for S9/M5 captured |

---

## M5 — ZeroTrustAuth Conformance And External Release Gates

**Goal**: Replace ZeroTrustAuth handwritten trust logic with supported library
APIs and add external conformance tests that release pipelines can run.

**Contract Block**

| Row | Contract |
|---|---|
| Inputs | library-backed harness, GitHub OIDC CI identity, public mTLS-only endpoint |
| Outputs | local and external conformance evidence for every release |
| Interfaces touched | ZeroTrustAuth routes, GitHub Actions workflow contracts, docs |
| Files allowed to change | ZeroTrustAuth repo, `.github/workflows/**`, docs |
| Data classification | Confidential for CI cert metadata; no production secrets in GitHub |
| Proactive controls | C1 security requirements, C6 identity, C7 access control, C9 monitoring |
| Abuse acceptance scenarios | all `tm-native-device-trust-abuse-*` rows |
| Forbidden shortcuts | no long-lived production client key in GitHub secrets; no public route that bypasses mTLS |

**BDD Acceptance**

| Scenario | Given | When | Then |
|---|---|---|---|
| local conformance | Compose harness running | `make smoke` runs | no-cert and bootstrap-only fail; session succeeds |
| external conformance | GitHub hosted runner | workflow obtains CI bootstrap via OIDC | protected route succeeds only after enrollment |
| revocation | test session cert revoked | workflow calls API | rejected |
| native package | Tauri desktop/mobile build | release smoke runs | packaged client enrolls and obtains login challenge |

**E2E Runtime Validation**: release workflows in ZeroTrustAuth and Sunlit
Guardian call the public mTLS-only endpoint and upload evidence logs.

**Current Status**

M5 is implemented up to the reusable release-gate contract. The SecurityLibraries
workflow runs the library contract tests and can call the ZeroTrustAuth external
workflow in dry-run or real staging mode. The milestone stays open until
ZeroTrustAuth has a real public test/staging endpoint and the non-dry-run
external conformance artifact is uploaded.

**Evidence Log**

| Command | Expected | Actual | Pass/Fail | Notes |
|---|---|---|---|---|
| Repo hygiene | branch is not default/protected | SecurityLibraries branch `native-device-trust-libraries`; origin default `origin/feature/milestone-automation` | Pass | no branch remediation needed |
| Release workflow contract | library tests plus optional external ZeroTrustAuth workflow | `.github/workflows/native-device-trust-conformance.yml` added with `workflow_dispatch`, `workflow_call`, and `id-token: write` | Pass | external job is opt-in until staging exists |
| Developer handoff docs | Guardian/SecurityLibraries release consumers know the gate shape | `docs/dev-guide/native-device-trust-release-gate.md` added and linked from `docs/dev-guide/README.md` | Pass | documents CDN/AWS/EKS/Istio/Actix path and no-production-key rule |
| workflow YAML parse | pass | `native-device-trust-conformance.yml` parsed with Ruby YAML | Pass | syntax sanity check only; GitHub execution still required |
| `cargo fmt --all -- --check && cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features && cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | passed | Pass | matches the release-gate library contract job |
| ZeroTrustAuth external dry-run | pass | ZeroTrustAuth contract and dry-run harness passed | Pass | proves reusable workflow shape before staging exists |
| External non-dry-run artifact | uploaded for release | not run | Blocked | requires ZeroTrustAuth public test/staging endpoint and CI bootstrap issuer |

---

## Global Red Lines

- No browser-accessible protected login surface.
- No production dependency on shared app bootstrap certificates.
- No handwritten authn/authz/device-trust logic in Guardian when a supported
  SunLitSecurityLibraries API exists.
- No production CA private key in a container filesystem.
- No GitHub secret containing production client private key material.
- No raw private key, passkey proof, attestation payload, or user token in logs.

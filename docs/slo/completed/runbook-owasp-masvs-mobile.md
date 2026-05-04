# OWASP MASVS Mobile Security Enhancements — SunLit Security Libraries (AI-First Runbook v3)

> **Purpose**: Extend the SunLit Security Libraries workspace with mobile application security capabilities aligned to OWASP MASVS v2, covering network transport security, secure local storage, biometric authentication, platform interaction safety, resilience against reverse engineering, and privacy controls — each adversarially tested with smoke tests for end-to-end validation.
> **Audience**: AI coding agents first, humans second. This document is written to reduce ambiguity, prevent scope drift, and improve code quality with the same model capability.  
> **How to use**: Work through milestones sequentially. Before starting any milestone, read its full section and the Global Execution Rules. After completing it, follow the Global Exit Rules. Never skip ahead. Never silently widen scope.  
> **Prerequisite reading**: [ARCHITECTURE.md](../../../ARCHITECTURE.md), [README.md](../../../README.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), [IMPROVEMENT_PROPOSAL.md](../lessons/IMPROVEMENT_PROPOSAL.md)

---

## Runbook Metadata

- **Runbook ID**: `sunlit-masvs`
- **Prefix for test files and lessons files**: `sunlit-masvs`
- **Primary stack**: `Rust (Cargo workspace) + axum + tower`
- **Primary package/app names**: `secure_boundary`, `secure_data`, `secure_identity`, `security_events`, `secure_output`, `secure_errors`, `security_core`, `secure_authz`, `secure_network` (new), `secure_resilience` (new), `secure_privacy` (new), `secure_smoke_service`
- **Default test commands**:
  - Backend: `cargo test --workspace`
  - Backend (specific crate): `cargo test -p <crate_name>`
  - E2E backend: `cargo test -p secure_smoke_service --test '*'`
  - Build/boot: `cargo build --workspace && cargo run -p secure_smoke_service`
- **Allowed new dependencies by default**: `none`
- **Schema/config migration allowed by default**: `no`
- **Public interfaces that must remain stable unless explicitly listed otherwise**:
  - `security_core::IdentitySource` trait
  - `security_core::DataClassification` enum
  - `secure_boundary::SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>`, `SecureXml<T>` extractors
  - `secure_errors::AppError` variants and `PublicError` shape
  - `security_events::SecurityEvent` struct and `SecuritySink` trait
  - `secure_data::SecretBox<T>`, `encrypt_for_storage`, `decrypt_for_use`
  - `secure_identity::TokenValidator`, `SessionManager` trait
  - `secure_authz::Authorizer` trait and `Decision` enum
  - `secure_output::OutputEncoder` trait and all encoder implementations
  - All existing smoke service routes (`/smoke/*`, `/health`)

---

## Milestone Tracker

Update this table as each milestone is completed. This is the single source of truth for progress.

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | `secure_network` — TLS & Certificate Pinning (MASVS-NETWORK) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m1.md` | `docs/slo/completion/sunlit-masvs-m1.md` |
| 2 | `secure_data` Mobile Storage Extensions (MASVS-STORAGE) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m2.md` | `docs/slo/completion/sunlit-masvs-m2.md` |
| 3 | `secure_identity` Biometric & Device-Bound Auth (MASVS-AUTH) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m3.md` | `docs/slo/completion/sunlit-masvs-m3.md` |
| 4 | `secure_boundary` Mobile Platform Safety (MASVS-PLATFORM) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m4.md` | `docs/slo/completion/sunlit-masvs-m4.md` |
| 5 | `secure_resilience` — Anti-Tampering & Environment Detection (MASVS-RESILIENCE) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m5.md` | `docs/slo/completion/sunlit-masvs-m5.md` |
| 6 | `secure_privacy` — Data Minimization & Privacy Controls (MASVS-PRIVACY) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m6.md` | `docs/slo/completion/sunlit-masvs-m6.md` |
| 7 | `security_events` Mobile Log Sanitization (MASVS-STORAGE/CODE) | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m7.md` | `docs/slo/completion/sunlit-masvs-m7.md` |
| 8 | Smoke Service Mobile Routes & E2E Validation | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m8.md` | `docs/slo/completion/sunlit-masvs-m8.md` |
| 9 | Adversarial Testing — Fuzz, Property Tests & CVE Regression | `done` | 2026-04-12 | 2026-04-12 | `docs/slo/lessons/sunlit-masvs-m9.md` | `docs/slo/completion/sunlit-masvs-m9.md` |

<!-- Status values: not_started | in_progress | blocked | done -->
<!-- Lessons files go in docs/slo/lessons/sunlit-masvs-m<N>.md -->
<!-- Completion summaries go in docs/slo/completion/sunlit-masvs-m<N>.md -->

---

## End-to-End Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                 SunLit Security Libraries — MASVS Extension                       │
│                                                                                 │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐  ┌──────────────────┐ │
│  │ Mobile App   │──▶│ secure_network│──▶│ secure_boundary│──▶│ secure_identity │ │
│  │ (Android/iOS)│  │ (M1) - - -    │  │ (M4 ext) - -  │  │ (M3 ext) - -   │ │
│  └──────────────┘  └───────────────┘  └────────────────┘  └──────────────────┘ │
│         │                 │                    │                    │            │
│         │                 ▼                    ▼                    ▼            │
│         │          ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐ │
│         │          │ secure_data  │    │secure_output │    │  secure_authz    │ │
│         │          │ (M2 ext) - - │    │ (existing)   │    │  (existing)      │ │
│         │          └──────────────┘    └──────────────┘    └──────────────────┘ │
│         │                 │                    │                    │            │
│         ▼                 ▼                    ▼                    ▼            │
│  ┌───────────────┐ ┌──────────────┐   ┌───────────────┐  ┌──────────────────┐ │
│  │secure_resili- │ │secure_privacy│   │security_events│  │  secure_errors   │ │
│  │ence (M5)- - - │ │ (M6) - - -  │   │ (M7 ext) - -  │  │  (existing)      │ │
│  └───────────────┘ └──────────────┘   └───────────────┘  └──────────────────┘ │
│         │                 │                    │                    │            │
│         └─────────────────┴────────────────────┴────────────────────┘            │
│                                    │                                            │
│                                    ▼                                            │
│                           ┌──────────────────┐                                  │
│                           │  security_core   │                                  │
│                           │  (shared types)  │                                  │
│                           └──────────────────┘                                  │
│                                    │                                            │
│                                    ▼                                            │
│                    ┌────────────────────────────────┐                            │
│                    │    secure_smoke_service (M8)   │                            │
│                    │    + mobile security routes    │                            │
│                    │    + adversarial tests (M9)    │                            │
│                    └────────────────────────────────┘                            │
│                                                                                 │
│  Legend:                                                                        │
│  ─── existing    - - - new/extended    ▶ data flow                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Milestone Introduced/Changed | Key Interfaces |
|---|---|---|---|
| `secure_network` (NEW) | TLS config validation, certificate pinning, cleartext detection | M1 | `TlsPolicy`, `CertPinValidator`, `NetworkSecurityConfig` |
| `secure_data` (EXTENDED) | Mobile encrypted storage, backup exclusion markers, memory wiping | M2 | `MobileStoragePolicy`, `BackupExclusion`, `SensitiveBuffer` |
| `secure_identity` (EXTENDED) | Biometric auth validation, device credential binding | M3 | `BiometricResult`, `DeviceBinding`, `StepUpPolicy` |
| `secure_boundary` (EXTENDED) | Deep link validation, clipboard security, WebView URL safety | M4 | `SafeDeepLink`, `ClipboardPolicy`, `SafeWebViewUrl` |
| `secure_resilience` (NEW) | Root/jailbreak detection, emulator detection, app integrity | M5 | `EnvironmentSignal`, `IntegrityPolicy`, `RaspEngine` |
| `secure_privacy` (NEW) | PII classification, pseudonymization, consent, data retention | M6 | `PrivacyClassifier`, `Pseudonymizer`, `ConsentPolicy`, `RetentionPolicy` |
| `security_events` (EXTENDED) | Mobile-specific log sanitization, device ID scrubbing | M7 | `MobileRedactionPolicy`, `LogLevelEnforcer` |
| `secure_smoke_service` (EXTENDED) | Mobile security smoke test routes, DAST targets | M8 | `/smoke/mobile/*` routes |
| Adversarial testing | Fuzz targets, property tests, CVE regression | M9 | `fuzz/`, `proptest`, `tests/cve_*` |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Milestone |
|---|---|---|---|---|
| TLS handshake validation | Mobile App | `secure_network` | TLS 1.2+/1.3 | M1 |
| Certificate pin check | `secure_network` | Pin store | In-process | M1 |
| Encrypted local storage | App logic | `secure_data` | Platform keystore API | M2 |
| Biometric auth result | Platform API | `secure_identity` | In-process validation | M3 |
| Deep link validation | OS intent/URL | `secure_boundary` | URL parsing | M4 |
| Environment detection | Platform APIs | `secure_resilience` | In-process signals | M5 |
| PII classification | Data pipeline | `secure_privacy` | In-process analysis | M6 |
| Mobile log scrubbing | `security_events` sinks | Output | Sink pipeline | M7 |
| Smoke test validation | DAST scanner | `secure_smoke_service` | HTTP | M8 |

---

## High-Level Design for Formal Verification (TLA+ Section)

**N/A** — This runbook extends existing library crates with new types and validation functions. There are no concurrent actors, distributed state, or ordering guarantees that introduce new correctness risks beyond those already modeled in the existing STRIDE threat model. The new capabilities are stateless validation functions and policy engines that compose with existing crate patterns.

---

## Global Execution Rules

These rules apply to every milestone without exception.

### 1) Stay inside scope

- Only change files listed in the current milestone unless a listed step explicitly requires one additional file.
- Do not refactor unrelated code.
- Do not rename public APIs, commands, routes, events, persisted state shapes, or config keys unless the milestone explicitly says so.
- Do not introduce a new dependency unless the milestone explicitly allows it.
- Do not change database schema, file formats, or migration behavior unless the milestone explicitly includes migration work and migration tests.

### 2) Tests define the contract

- Write BDD tests before production code.
- Write E2E runtime validation stubs before production code.
- Confirm new tests fail for the right reason before implementing.
- A milestone is not done when code compiles. It is done when the declared contract is satisfied and evidence is recorded.

### 3) No placeholders in production paths

The following are not allowed unless explicitly permitted in the milestone:

- TODO or placeholder logic in production code
- silent fallbacks that hide errors
- swallowed errors without structured logging or user-visible handling
- fake implementations left in place after tests pass
- commented-out dead code
- temporary mocks in production paths
- hard-coded secrets, test keys, or unsafe defaults

### 4) Preserve backwards compatibility

Every milestone must explicitly verify that previously working user flows, commands, routes, persisted state, and public interfaces still work unless the milestone explicitly replaces them.

### 5) Prefer smallest safe change

- Prefer narrow, local modifications over broad rewrites.
- Prefer extending existing patterns over inventing new abstractions.
- Prefer deleting complexity over adding new layers.
- If a refactor is required, keep it minimal and directly justified by the milestone goal.

### 6) Record evidence, not claims

All meaningful checks must be recorded in the milestone Evidence Log:

- command run
- relevant file or test
- expected result
- actual result
- pass/fail
- notes

### 7) Keep .gitignore current and clean up test artifacts

- If a milestone introduces new build outputs, generated files, test fixtures, scratch directories, or tool-specific caches, add matching patterns to `.gitignore` before committing.
- Review `.gitignore` at the end of every milestone for staleness — remove patterns that no longer apply.
- Never commit test output data, temporary fixtures, scratch files, or generated artifacts to source control.
- Every test that creates files on disk must clean up after itself (use `tempdir`, `tempfile`, `afterEach` cleanup, or equivalent). Tests must not leave residual data in the working tree.
- Record the `.gitignore` review in the Evidence Log.

---

## Global Entry Rules (Pre-Milestone Protocol)

Do this before every milestone.

1. Read the lessons file from the previous milestone, if one exists. Apply any design corrections, naming rules, test strategy improvements, and failure-mode coverage it calls for before writing new code.
2. Read the current milestone fully: goal, context, contract block, out-of-scope block, file list, BDD scenarios, regression tests, E2E tests, smoke tests, and definition of done.
3. Run the full existing test suite and confirm it passes. Record the baseline in the Evidence Log.
   ```
   cargo test --workspace
   ```
   If any tests fail before you start, stop and fix the baseline first. Do not begin a milestone on a red baseline.
4. Read the files listed in "Files Allowed To Change" and "Files To Read Before Changing Anything". Understand their current shape before editing.
5. Update the Milestone Tracker in this file: set the current milestone status to `in_progress` and record the Started date.
6. Create BDD test files first.
7. Create E2E runtime validation test stubs first.
8. Copy the milestone's Evidence Log template into working notes and begin filling it out as work happens.
9. Re-state the milestone constraints in your own words before coding:
   - goal
   - allowed files
   - forbidden changes
   - compatibility requirements
   - tests that must pass

---

## Global Exit Rules (Post-Milestone Protocol)

Do this after every milestone.

1. Run the full test suite. Every pre-existing test must still pass. Every new BDD scenario must pass.
   ```
   cargo test --workspace
   ```
2. Run the milestone E2E runtime validation tests.
   ```
   cargo test -p secure_smoke_service --test '*'
   ```
3. Verify the workspace builds cleanly.
   ```
   cargo build --workspace
   ```
4. Run the smoke tests listed in the milestone. Check off each item in the runbook.
5. Verify backward compatibility for all items listed in the milestone Compatibility Checklist.
6. Complete the Self-Review Gate.
7. **Clean up test artifacts**: Verify no test output files, temporary fixtures, or generated data remain in the working tree. Run `git status` and confirm no untracked test artifacts exist.
8. **Review .gitignore**: Ensure any new build outputs, generated files, or tool caches introduced in this milestone have matching `.gitignore` patterns. Remove stale patterns that no longer apply.
9. Update ARCHITECTURE.md following the Documentation Update Table.
10. Update README.md if user-facing capabilities changed.
11. Write a lessons-learned file at `docs/slo/lessons/sunlit-masvs-m<N>.md`.
12. Write a completion summary at `docs/slo/completion/sunlit-masvs-m<N>.md`.
13. Update the Milestone Tracker in this file: set status to `done`, record Completed date, and fill in the lessons and completion summary paths.
14. Re-read the next milestone with fresh eyes and record any assumption changes in the lessons file.

---

## Background Context

### Current State

The SunLit Security Libraries workspace has completed 26 milestones implementing OWASP Proactive Controls C1/C2/C4/C5/C6/C7/C8/C9/C10 for Rust web services. The eight security crates (`security_core`, `secure_errors`, `security_events`, `secure_boundary`, `secure_output`, `secure_identity`, `secure_authz`, `secure_data`) provide production-grade defenses against web application attacks, with a smoke test service (`secure_smoke_service`) exercising 39 routes against known attack classes.

However, the current coverage is web-service-centric. The OWASP Mobile Application Security Verification Standard (MASVS v2) identifies eight control categories for mobile applications — STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY — several of which require capabilities not yet present in the workspace.

### Problem

The following OWASP MASVS v2 gaps exist in the current SunLit libraries:

1. **MASVS-NETWORK (Transport Security)**: No TLS configuration validation, certificate pinning verification, or cleartext traffic detection. The existing `secure_boundary` handles HTTP-layer security headers but not transport-layer enforcement. References: MASWE-0048, MASWE-0050, MASWE-0052.

2. **MASVS-STORAGE (Mobile Secure Storage)**: `secure_data` provides encryption and key management but lacks mobile-specific abstractions: encrypted local storage with platform keystore integration patterns, backup exclusion metadata, sensitive buffer wiping beyond `zeroize`-on-drop for `SecretBox`. References: MASWE-0001, MASWE-0002, MASWE-0004, MASWE-0006.

3. **MASVS-AUTH (Biometric & Device-Bound Auth)**: `secure_identity` covers JWT, OIDC, session, MFA/TOTP, but lacks biometric authentication result validation, device credential binding patterns, and step-up authentication policy enforcement for mobile. References: MASWE-0028, MASWE-0032, MASWE-0036, MASWE-0043.

4. **MASVS-PLATFORM (Platform Interaction Safety)**: `secure_boundary` handles HTTP input validation but not mobile-specific platform interactions: deep link / universal link URL validation, clipboard/pasteboard security policies, and WebView URL safety checks. References: MASWE-0053, MASWE-0055, MASWE-0058, MASWE-0068, MASWE-0069.

5. **MASVS-RESILIENCE (Anti-Tampering)**: No crate addresses reverse engineering resistance: root/jailbreak detection, emulator detection, debugger detection, or app integrity verification. References: MASWE-0095, MASWE-0097, MASWE-0098, MASWE-0099, MASWE-0100, MASWE-0107.

6. **MASVS-PRIVACY (Data Minimization)**: `security_events` redaction engine handles event-level data classification but no crate provides comprehensive PII discovery, data pseudonymization, consent tracking, or data retention policy enforcement. References: MASWE-0109, MASWE-0110, MASWE-0113, MASWE-0115.

7. **MASVS-STORAGE/CODE (Mobile Log Sanitization)**: `security_events` sanitizes log injection but lacks mobile-specific device identifier scrubbing (IMEI, IDFV, advertising IDs) and compile-time log level enforcement for release builds. References: MASWE-0001, MASTG-BEST-0002, MASTG-BEST-0022.

### Target Architecture

After all milestones, the workspace gains three new crates (`secure_network`, `secure_resilience`, `secure_privacy`) and extends four existing crates (`secure_data`, `secure_identity`, `secure_boundary`, `security_events`) with mobile security capabilities. The `secure_smoke_service` gains mobile-specific routes for DAST validation.

### Key Design Principles

1. **Platform-agnostic core, platform-specific integration**: All new types and validation logic are pure Rust with no Android/iOS SDK dependencies. Platform integration happens at the FFI boundary in consuming applications. The libraries provide the security policy engine; the mobile app provides platform API bindings.

2. **Extend, don't fork**: New mobile capabilities are added as feature-gated modules within existing crates where the domain aligns (e.g., `secure_data` feature `mobile-storage`), or as new crates where the domain is genuinely new (e.g., `secure_resilience`).

3. **Adversarial-first testing**: Every new type and validation function must have fuzz targets, property tests, and negative test cases proving security boundaries hold. The smoke service must exercise each new capability against known MASWE attack patterns.

4. **Security events integration**: Every validation failure or policy violation must emit a `SecurityEvent` via `security_events`, maintaining the existing telemetry pattern.

### What to Keep

- All existing crate public APIs — no breaking changes
- All existing smoke service routes — new routes are additive
- The `IdentitySource` trait architecture — `secure_authz` remains identity-agnostic
- The `SecurityEvent` schema — new `EventKind` variants are additive
- The `DataClassification` enum — extended with new mobile-relevant variants if needed
- Supply-chain hardening (`deny.toml`, `supply-chain/`)
- DAST pipeline (ZAP + Dastardly)

### What to Change

- **`security_core/src/lib.rs`** — Add new shared types for mobile security signals
- **`secure_data/src/`** — Add `mobile_storage` module with backup exclusion + sensitive buffer types
- **`secure_identity/src/`** — Add `biometric` module with biometric result validation
- **`secure_boundary/src/`** — Add `platform` module with deep link, clipboard, WebView URL types
- **`security_events/src/`** — Add `mobile_redaction` module and new `EventKind` variants
- **`secure_smoke_service/src/`** — Add `/smoke/mobile/*` routes
- **New crate `secure_network/`** — TLS policy, cert pinning, cleartext detection
- **New crate `secure_resilience/`** — Environment detection signals, integrity checks
- **New crate `secure_privacy/`** — PII classifier, pseudonymizer, consent/retention policies

### Global Red Lines

These are forbidden unless explicitly overridden inside a milestone.

- No unrelated refactors
- No new dependencies unless milestone explicitly allows them
- No schema migrations
- No config key renames
- No public API/event/route renames
- No production placeholders
- No silent error swallowing
- No secrets in source control
- No test output data committed to source control
- No Android/iOS SDK dependencies (pure Rust only)
- No `unsafe` blocks unless explicitly justified and documented

---

## BDD and Runtime Validation Rules

Every milestone follows these rules.

### Write Tests Before Production Code

For each milestone:
1. Read the BDD acceptance table.
2. Create the test file(s) first.
3. Confirm the tests fail for the expected reason.
4. Write production code to make the tests pass.
5. Re-run tests after any refactor.

### Required Test Coverage Categories

Every milestone must explicitly cover the categories that apply:

- happy path
- invalid input
- empty state / first-run state
- adversarial / attack input
- dependency failure / partial failure
- backward compatibility behavior

If a category does not apply, state why.

### Test File Naming

| Layer | Convention | Location |
|---|---|---|
| Unit tests | `#[cfg(test)] mod tests` inside the source file | Same file as production code |
| Integration/BDD tests | `tests/<prefix>_<feature>.rs` | `crates/<crate>/tests/` |
| Fuzz targets | `fuzz_targets/<target>.rs` | `crates/<crate>/fuzz/` |
| E2E smoke tests | `tests/e2e_sunlit_masvs_m<N>.rs` | `crates/secure_smoke_service/tests/` |

### Test Artifact Cleanup Rules

Every test that creates files, directories, or temporary data on disk must:
1. Use `tempdir()` / `tempfile::TempDir` or OS temp locations.
2. Clean up on completion and failure via RAII `Drop`.
3. Leave no untracked files after `git status`.

---

## Dependency, Migration, and Refactor Policy

### Dependency policy

A new dependency is allowed only if the milestone explicitly includes:
- package/crate name
- why existing dependencies are insufficient
- security and maintenance rationale
- build/runtime cost rationale
- tests covering the new integration

### Migration policy

No migrations are expected in this runbook. All changes are additive library extensions.

### Refactor budget

Each milestone states its refactor budget explicitly.

---

## OWASP MASVS Coverage Matrix

This table maps each MASVS control to the SunLit crate and milestone that addresses it.

| MASVS Control | Control Description | SunLit Crate | Milestone | Notes |
|---|---|---|---|---|
| MASVS-STORAGE-1 | App securely stores sensitive data | `secure_data` | M2 | Encrypted storage, backup exclusion |
| MASVS-STORAGE-2 | App prevents leakage of sensitive data | `security_events` | M7 | Mobile log sanitization, device ID scrubbing |
| MASVS-CRYPTO-1 | App employs strong cryptography | `secure_data` | (Existing) | AES-256-GCM, XChaCha20-Poly1305, Argon2id |
| MASVS-CRYPTO-2 | App performs key management per best practices | `secure_data` | (Existing) | KeyProvider trait, Azure KV, key rotation |
| MASVS-AUTH-1 | Secure auth protocols and best practices | `secure_identity` | (Existing) | JWT, OIDC, session, API key |
| MASVS-AUTH-2 | Secure local authentication per platform best practices | `secure_identity` | M3 | Biometric validation, device binding |
| MASVS-AUTH-3 | Sensitive operations secured with additional auth | `secure_identity` | M3 | Step-up authentication policy |
| MASVS-NETWORK-1 | Secure network communication (data-in-transit) | `secure_network` | M1 | TLS policy, cert pinning, cleartext detection |
| MASVS-NETWORK-2 | Secure connection configuration | `secure_network` | M1 | TLS version/cipher enforcement |
| MASVS-PLATFORM-1 | Secure platform API usage | `secure_boundary` | M4 | Deep link validation, WebView URL safety |
| MASVS-PLATFORM-2 | Secure IPC mechanisms | `secure_boundary` | M4 | Clipboard policy, data sharing controls |
| MASVS-PLATFORM-3 | Secure UI mechanisms | `secure_boundary` | M4 | Screenshot prevention signals |
| MASVS-CODE-1 | App is up to date | (Existing) | — | cargo-audit, cargo-deny |
| MASVS-CODE-2 | App has strong code quality | (Existing) | — | Rust memory safety, clippy |
| MASVS-CODE-3 | Safe deserialization | `secure_boundary` | (Existing) | StrictDeserialize, depth limits |
| MASVS-CODE-4 | Secure dependency management | (Existing) | — | cargo-vet, supply-chain/ |
| MASVS-RESILIENCE-1 | App detects and responds to reverse engineering | `secure_resilience` | M5 | Root/jailbreak, emulator, debugger detection |
| MASVS-RESILIENCE-2 | Integrity verification mechanisms | `secure_resilience` | M5 | App integrity, code signing validation |
| MASVS-RESILIENCE-3 | Anti-tampering mechanisms | `secure_resilience` | M5 | RASP signal aggregation |
| MASVS-RESILIENCE-4 | Obfuscation | N/A | — | Not applicable to Rust compiled code |
| MASVS-PRIVACY-1 | App minimizes access to sensitive data | `secure_privacy` | M6 | PII classifier, data minimization policy |
| MASVS-PRIVACY-2 | App prevents identification of the user | `secure_privacy` | M6 | Pseudonymizer, identifier anonymization |
| MASVS-PRIVACY-3 | App is transparent about data collection | `secure_privacy` | M6 | Consent policy, data manifest |
| MASVS-PRIVACY-4 | App offers user control over their data | `secure_privacy` | M6 | Retention policy, data deletion |

---

## Evidence Log Template

Copy this table into each milestone section and fill it in during execution.

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all pre-existing tests green | | | |
| BDD tests created | `[files]` | compile or fail for expected reason | | | |
| E2E stubs created | `[files]` | compile or fail for expected reason | | | |
| Implementation | `[summary]` | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test -p secure_smoke_service --test '*'` | green | | | |
| Build/boot | `cargo build --workspace` | builds cleanly | | | |
| Smoke tests | `[steps]` | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current, no stale entries | | | |
| Compatibility checks | `[checks]` | no regressions | | | |

---

## Self-Review Gate

Before marking a milestone done, answer every question.

- Did I change only allowed files?
- Did I avoid unrelated refactors?
- Did I preserve all listed public interfaces and compatibility requirements?
- Did I add tests for failure modes, not just happy paths?
- Did I remove temporary debug code, mocks, placeholders, and commented-out dead code?
- Did I update documentation to match the implementation?
- Is every assumption either verified or explicitly documented as unresolved?
- Do all tests clean up their output artifacts? Does `git status` show a clean working tree?
- Is `.gitignore` up to date with any new generated files or build outputs?
- Is the milestone truly done according to its Definition of Done?

If any answer is "no", the milestone is not complete.

---

## Milestone Plan

---

### Milestone 1 — `secure_network`: TLS & Certificate Pinning (MASVS-NETWORK)

**Goal**: Create a new `secure_network` crate providing TLS configuration validation, certificate pinning verification, and cleartext traffic detection — enabling mobile apps using Rust backends or shared libraries to enforce MASVS-NETWORK-1 and MASVS-NETWORK-2 controls.

**Context**: The existing `secure_boundary` crate handles HTTP-layer security (headers, CORS, CSP) but has no transport-layer security enforcement. MASVS-NETWORK requires that apps encrypt all network traffic using TLS with strong configuration, verify server certificates (including pinning for high-security scenarios), and detect/prevent cleartext HTTP traffic. MASWE-0048 (insecure machine-to-machine communication), MASWE-0050 (cleartext traffic), and MASWE-0052 (insecure certificate validation) are the primary weaknesses addressed.

**Important design rule**: All TLS types are pure Rust policy objects and validators — they do not perform TLS handshakes themselves. The consuming mobile app provides the raw certificate chain and TLS parameters; this crate provides the validation logic.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | TLS version, cipher suite, certificate chain (DER bytes), pinned hashes (SHA-256), URL scheme |
| Outputs | `TlsValidationResult` (Allow/Deny with reason), `SecurityEvent` on violation |
| Interfaces touched | New crate `secure_network`, `security_core` (new types), `security_events` (new `EventKind`) |
| Files allowed to change | `Cargo.toml` (workspace), `security_core/src/lib.rs`, `security_events/src/event.rs` |
| Files to read before changing anything | `ARCHITECTURE.md`, `security_core/src/lib.rs`, `security_events/src/event.rs` |
| New files allowed | `crates/secure_network/Cargo.toml`, `crates/secure_network/src/lib.rs`, `crates/secure_network/src/tls_policy.rs`, `crates/secure_network/src/cert_pin.rs`, `crates/secure_network/src/cleartext.rs`, `crates/secure_network/src/error.rs`, `crates/secure_network/tests/` |
| New dependencies allowed | `sha2` (SHA-256 for cert pin hashing), `x509-parser` (certificate chain parsing) |
| Migration allowed | `no` |
| Compatibility commitments | All existing crate APIs unchanged, all existing tests pass |
| Forbidden shortcuts | No actual TLS handshake implementation, no platform SDK imports |

#### Out of Scope / Must Not Do

- Do not implement a TLS library or perform handshakes
- Do not add Android/iOS platform bindings
- Do not modify existing `secure_boundary` security headers
- Do not implement OCSP stapling or CRL checking (future work)

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `Cargo.toml` (workspace root) | Add `secure_network` to workspace members |
| `crates/secure_network/Cargo.toml` | NEW: crate manifest |
| `crates/secure_network/src/lib.rs` | NEW: module root with public re-exports |
| `crates/secure_network/src/tls_policy.rs` | NEW: `TlsPolicy`, `TlsVersion`, `CipherSuite` enforcement |
| `crates/secure_network/src/cert_pin.rs` | NEW: `CertPinValidator`, `PinSet`, SPKI hash comparison |
| `crates/secure_network/src/cleartext.rs` | NEW: `CleartextDetector` — URL scheme and port checks |
| `crates/secure_network/src/error.rs` | NEW: `NetworkSecurityError` (`#[non_exhaustive]`) |
| `crates/secure_network/tests/tls_policy_tests.rs` | NEW: BDD tests |
| `crates/secure_network/tests/cert_pin_tests.rs` | NEW: BDD tests |
| `crates/secure_network/tests/cleartext_tests.rs` | NEW: BDD tests |
| `crates/security_core/src/lib.rs` | Add `TlsVersion` and `CipherSuiteId` shared types if needed |
| `crates/security_events/src/event.rs` | Add `EventKind::TlsViolation`, `EventKind::CertPinFailure`, `EventKind::CleartextBlocked` |
| `.gitignore` | Add patterns for any new generated files |

#### BDD Acceptance Scenarios

**Feature: TLS Policy Enforcement**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| TLS 1.3 connection allowed | happy path | `TlsPolicy` configured with min version TLS 1.2 | Connection reports TLS 1.3 | `TlsValidationResult::Allow` returned |
| TLS 1.0 connection rejected | invalid input | `TlsPolicy` configured with min version TLS 1.2 | Connection reports TLS 1.0 | `TlsValidationResult::Deny` with `TlsVersion` reason |
| TLS 1.1 connection rejected | invalid input | `TlsPolicy` configured with min version TLS 1.2 | Connection reports TLS 1.1 | `TlsValidationResult::Deny` with `TlsVersion` reason |
| Weak cipher suite rejected | invalid input | `TlsPolicy` with cipher allowlist | Connection uses RC4/DES cipher | Deny with `WeakCipher` reason |
| Strong cipher suite allowed | happy path | `TlsPolicy` with cipher allowlist | Connection uses AES-256-GCM | Allow |
| TLS violation emits security event | adversarial | Any TLS policy violation | Violation detected | `SecurityEvent` with `EventKind::TlsViolation` emitted |

**Feature: Certificate Pinning**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Pinned cert matches SPKI hash | happy path | `PinSet` with known SHA-256 hash | Server cert SPKI matches pin | `CertPinResult::Valid` |
| Pinned cert does not match | adversarial | `PinSet` with known SHA-256 hash | Server cert SPKI differs | `CertPinResult::PinMismatch` + security event |
| Multiple pins — one matches | happy path | `PinSet` with 3 hashes (primary + backup) | Server cert matches backup pin | `CertPinResult::Valid` |
| Empty pin set always allows | empty state | `PinSet` with no pins configured | Any cert presented | `CertPinResult::NoPinsConfigured` (warn) |
| Expired cert detected | adversarial | `CertPinValidator` with expiry check enabled | Expired cert presented | `CertPinResult::Expired` + security event |
| Certificate chain validation | happy path | `CertPinValidator` with chain validation | Valid chain with pinned leaf | `CertPinResult::Valid` |

**Feature: Cleartext Traffic Detection**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| HTTPS URL allowed | happy path | `CleartextDetector` enabled | URL scheme is `https` | `CleartextResult::Secure` |
| HTTP URL blocked | adversarial | `CleartextDetector` enabled | URL scheme is `http` | `CleartextResult::CleartextBlocked` + security event |
| localhost HTTP exempted | happy path | `CleartextDetector` with localhost exemption | `http://127.0.0.1` | `CleartextResult::ExemptedLocalhost` |
| Custom port cleartext detected | adversarial | `CleartextDetector` enabled | `http://api.example.com:8080` | `CleartextResult::CleartextBlocked` |
| FTP scheme blocked | adversarial | `CleartextDetector` enabled | URL scheme is `ftp` | `CleartextResult::InsecureScheme` |

#### Regression Tests

- `cargo test --workspace` — all existing tests pass
- All `secure_boundary` safe type tests unchanged
- All `security_events` event emission tests unchanged

#### Compatibility Checklist

- [x] All existing `security_core` types unchanged
- [x] All existing `security_events::EventKind` variants unchanged (new variants are additive, `#[non_exhaustive]`)
- [x] All existing crate public APIs unchanged
- [x] `secure_smoke_service` builds and all existing routes work

#### E2E Runtime Validation

**File**: `crates/secure_network/tests/e2e_sunlit_masvs_m1.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_tls_policy_rejects_weak_version_at_runtime` | TLS version enforcement works end-to-end | TLS 1.0/1.1 connections are rejected with correct `Deny` result |
| `test_cert_pin_validates_real_cert_chain` | Certificate pinning validates DER certificate chains | Known-good cert matches pin; known-bad cert fails |
| `test_cleartext_detector_blocks_http_urls` | Cleartext detection works for URL validation | HTTP URLs blocked, HTTPS allowed, localhost exempted |
| `test_violations_emit_security_events` | Security event integration works | Each violation type emits the correct `EventKind` with `InMemorySink` |

#### Smoke Tests

- [x] `cargo test -p secure_network` passes
- [x] `cargo test --workspace` passes
- [x] `cargo build --workspace` succeeds
- [x] `git status` shows no untracked test artifacts
- [x] `.gitignore` covers all new generated files

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests are checked off
- compatibility checklist is complete
- no forbidden shortcuts remain in production code
- `git status` is clean after test run
- `.gitignore` is up to date
- ARCHITECTURE.md updated with `secure_network` component
- README.md updated with MASVS-NETWORK coverage
- lessons file written at `docs/slo/lessons/sunlit-masvs-m1.md`
- completion summary written at `docs/slo/completion/sunlit-masvs-m1.md`

---

### Milestone 2 — `secure_data` Mobile Storage Extensions (MASVS-STORAGE)

**Goal**: Extend `secure_data` with mobile-specific secure storage capabilities — encrypted local storage policy types, backup exclusion markers, and sensitive memory buffer management — enabling mobile apps to satisfy MASVS-STORAGE-1.

**Context**: `secure_data` already provides `SecretBox<T>`, envelope encryption, and `zeroize`-on-drop for key material. Mobile apps need additional patterns: metadata to mark data as backup-excluded (MASWE-0004), encrypted storage policies that enforce platform keystore usage (MASWE-0006), and explicit sensitive buffer management for transient data like biometric templates or PIN entries (MASWE-0001). These capabilities are pure Rust policy types — the actual platform keystore integration happens at the FFI boundary.

**Important design rule**: New types are feature-gated behind `mobile-storage` to avoid adding weight for non-mobile consumers. All types follow existing `secure_data` patterns (newtype wrappers, no `Debug`/`Display` for secret data).

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Sensitive data buffers, storage location metadata, backup configuration |
| Outputs | `SensitiveBuffer<T>` (zeroize-on-drop, zeroize-on-read), `BackupExclusion` markers, `MobileStoragePolicy` |
| Interfaces touched | `secure_data` (new module), `security_core` (possible new `StorageLocation` type) |
| Files allowed to change | `crates/secure_data/Cargo.toml`, `crates/secure_data/src/lib.rs` |
| Files to read before changing anything | `crates/secure_data/src/lib.rs`, `crates/secure_data/src/secret.rs`, `ARCHITECTURE.md` |
| New files allowed | `crates/secure_data/src/mobile_storage.rs`, `crates/secure_data/tests/mobile_storage_tests.rs`, `crates/secure_data/fuzz/fuzz_targets/fuzz_sensitive_buffer.rs` |
| New dependencies allowed | `none` (uses existing `zeroize` dependency) |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_data` APIs unchanged |
| Forbidden shortcuts | No platform-specific code, no `unsafe` for memory wiping |

#### Out of Scope / Must Not Do

- Do not implement Android Keystore or iOS Keychain bindings
- Do not modify existing `SecretBox<T>` or encryption APIs
- Do not add database-specific storage (SQLite, SharedPreferences)
- Do not implement file I/O — storage policies are metadata, not persistence

#### BDD Acceptance Scenarios

**Feature: Sensitive Buffer Management**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| SensitiveBuffer zeroes on drop | happy path | `SensitiveBuffer` holding secret bytes | Buffer is dropped | Memory is zeroed via `zeroize` |
| SensitiveBuffer no Debug output | adversarial | `SensitiveBuffer` holding secret | `format!("{:?}", buf)` called | Output shows `[REDACTED]`, not secret content |
| SensitiveBuffer no Display output | adversarial | `SensitiveBuffer` holding secret | `format!("{}", buf)` called | Compile error or `[REDACTED]` |
| SensitiveBuffer explicit wipe | happy path | `SensitiveBuffer` holding PIN digits | `wipe()` called explicitly | Buffer zeroed, subsequent reads return empty/zeroed data |
| SensitiveBuffer bounded lifetime | happy path | `SensitiveBuffer` with max TTL | TTL expires | Buffer auto-wipes |

**Feature: Backup Exclusion**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| BackupExclusion marker set | happy path | Data item with `BackupExclusion::Exclude` | Policy checked | `should_exclude_from_backup()` returns true |
| BackupExclusion default is exclude | empty state | Data item with no explicit backup policy | Policy checked | Defaults to `Exclude` (secure by default) |
| BackupExclusion serializable | happy path | `BackupExclusion` marker | Serialized to JSON | Produces valid metadata for platform integration |

**Feature: Mobile Storage Policy**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Policy requires encryption | happy path | `MobileStoragePolicy::encrypted()` | Data classified as `Confidential` | `requires_encryption()` returns true |
| Policy requires hardware keystore | happy path | `MobileStoragePolicy::hardware_backed()` | Storage policy checked | `requires_hardware_keystore()` returns true |
| Policy violation emits event | adversarial | Policy requires encryption | Unencrypted storage attempted | `SecurityEvent` with violation emitted |
| Public data has relaxed policy | happy path | `MobileStoragePolicy` for `Public` data | Policy checked | Does not require hardware keystore |

#### Fuzz Targets

- `fuzz_sensitive_buffer` — fuzz `SensitiveBuffer` construction, read, and drop with arbitrary byte inputs to verify memory safety and zeroization.

#### Smoke Tests

- [ ] `cargo test -p secure_data --features mobile-storage` passes
- [ ] `cargo test --workspace` passes (feature not enabled by default)
- [ ] `.gitignore` updated

---

### Milestone 3 — `secure_identity` Biometric & Device-Bound Auth (MASVS-AUTH)

**Goal**: Extend `secure_identity` with biometric authentication result validation, device credential binding types, and step-up authentication policy enforcement — enabling mobile apps to satisfy MASVS-AUTH-2 and MASVS-AUTH-3.

**Context**: `secure_identity` handles JWT validation, OIDC, sessions, and TOTP MFA but has no concept of platform-local biometric authentication (fingerprint, face recognition) or device-bound credentials. MASVS-AUTH-2 requires secure local authentication per platform best practices (MASWE-0032: platform-provided authentication APIs, MASWE-0043: PIN not bound to keystore). MASVS-AUTH-3 requires step-up authentication for sensitive operations (MASWE-0029). Best practices include: MASTG-BEST-0031 (enforce strong biometrics), MASTG-BEST-0036 (cryptographic binding), MASTG-BEST-0037 (invalidate keys on enrollment change), MASTG-BEST-0038 (require explicit user confirmation).

**Important design rule**: The biometric module validates the *result* of platform biometric authentication (e.g., a signed attestation, a cryptographic proof), not the biometric data itself. No biometric templates or raw sensor data should ever touch these types. Feature-gated behind `biometric`.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `BiometricAuthResult` (from platform API), `DeviceCredentialClaim`, step-up context |
| Outputs | `BiometricValidation` (validated/rejected), `StepUpDecision`, `SecurityEvent` on failure |
| Interfaces touched | `secure_identity` (new modules), `security_events` (new `EventKind`) |
| Files allowed to change | `crates/secure_identity/Cargo.toml`, `crates/secure_identity/src/lib.rs` |
| Files to read before changing anything | `crates/secure_identity/src/lib.rs`, `crates/secure_identity/src/mfa.rs`, `ARCHITECTURE.md` |
| New files allowed | `crates/secure_identity/src/biometric.rs`, `crates/secure_identity/src/device_binding.rs`, `crates/secure_identity/src/step_up.rs`, `crates/secure_identity/tests/biometric_tests.rs`, `crates/secure_identity/tests/step_up_tests.rs`, `crates/secure_identity/fuzz/fuzz_targets/fuzz_biometric.rs` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_identity` APIs unchanged, `Authenticator` trait stable |
| Forbidden shortcuts | No raw biometric data handling, no platform SDK imports |

#### Out of Scope / Must Not Do

- Do not implement Android BiometricPrompt or iOS LocalAuthentication bindings
- Do not store or process raw biometric templates
- Do not modify existing `Authenticator` trait or `TokenValidator`
- Do not implement FIDO2/WebAuthn (separate future work)

#### BDD Acceptance Scenarios

**Feature: Biometric Authentication Validation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Strong biometric result accepted | happy path | `BiometricAuthResult` with `Class3` (strong) biometric and cryptographic binding | Validation called | `BiometricValidation::Accepted` |
| Weak biometric result rejected | adversarial | `BiometricAuthResult` with `Class1` (convenience) | Policy requires `Class3` minimum | `BiometricValidation::Rejected(WeakBiometric)` + security event |
| No cryptographic binding rejected | adversarial | `BiometricAuthResult` without crypto proof | Policy requires binding | `BiometricValidation::Rejected(NoCryptoBinding)` |
| Enrollment change invalidates keys | adversarial | `BiometricAuthResult` with stale enrollment ID | Enrollment ID changed since key creation | `BiometricValidation::Rejected(EnrollmentChanged)` |
| Device credential (PIN/pattern) accepted when allowed | happy path | `BiometricAuthResult` with device credential fallback | Policy allows device credential | `BiometricValidation::Accepted` |

**Feature: Step-Up Authentication**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Sensitive operation requires step-up | happy path | `StepUpPolicy` for "transfer_funds" | User last authenticated 10 min ago, threshold is 5 min | `StepUpDecision::Required` |
| Recent auth skips step-up | happy path | `StepUpPolicy` for "transfer_funds" | User authenticated 1 min ago, threshold is 5 min | `StepUpDecision::NotRequired` |
| Step-up always required for critical ops | adversarial | `StepUpPolicy::always()` for "delete_account" | Any auth freshness | `StepUpDecision::Required` |
| Step-up failure emits security event | adversarial | Step-up authentication fails | Failure detected | `SecurityEvent` with `EventKind::StepUpAuthFailure` emitted |

#### Smoke Tests

- [ ] `cargo test -p secure_identity --features biometric` passes
- [ ] `cargo test --workspace` passes
- [ ] `.gitignore` updated

---

### Milestone 4 — `secure_boundary` Mobile Platform Safety (MASVS-PLATFORM)

**Goal**: Extend `secure_boundary` with mobile platform interaction safety types — deep link / universal link URL validation, clipboard/pasteboard security policy, WebView URL safety checks, and screenshot prevention signals — enabling mobile apps to satisfy MASVS-PLATFORM-1, MASVS-PLATFORM-2, and MASVS-PLATFORM-3.

**Context**: `secure_boundary` handles HTTP-layer input validation (safe types, extractors, normalization) but has no concept of mobile platform interactions. MASVS-PLATFORM requires validation of deep links (MASWE-0058), secure IPC/clipboard handling (MASWE-0053, MASWE-0065), WebView URL restrictions (MASWE-0069), and screenshot prevention (MASWE-0055). These are pure Rust validation types; platform-level enforcement (e.g., `FLAG_SECURE` on Android) happens in the consuming app.

**Important design rule**: All new types follow the existing `safe_types` pattern — newtypes with `TryFrom<&str>` and serde `Deserialize`, `into_inner()` / `as_inner()`, no `Deref`, security event emission on rejection.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Deep link URLs, clipboard content metadata, WebView target URLs |
| Outputs | `SafeDeepLink`, `ClipboardPolicy`, `SafeWebViewUrl`, `ScreenshotPolicy`, `SecurityEvent` on violation |
| Interfaces touched | `secure_boundary` (new module), `security_events` (new `EventKind`) |
| Files allowed to change | `crates/secure_boundary/Cargo.toml`, `crates/secure_boundary/src/lib.rs` |
| Files to read before changing anything | `crates/secure_boundary/src/safe_types.rs`, `crates/secure_boundary/src/lib.rs`, `ARCHITECTURE.md` |
| New files allowed | `crates/secure_boundary/src/platform.rs`, `crates/secure_boundary/tests/platform_tests.rs`, `crates/secure_boundary/fuzz/fuzz_targets/fuzz_deep_link.rs` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_boundary` safe types unchanged, all extractors unchanged |
| Forbidden shortcuts | No platform SDK imports, no actual clipboard access |

#### Out of Scope / Must Not Do

- Do not implement Android Intent or iOS URL scheme handling
- Do not implement actual clipboard read/write
- Do not modify existing `SafeUrl`, `SafeRedirectUrl`, or other safe types
- Do not implement WebView rendering or JavaScript bridge security (separate future work)

#### BDD Acceptance Scenarios

**Feature: Deep Link Validation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Registered scheme accepted | happy path | `SafeDeepLink` with allowed schemes `["myapp", "myapp-debug"]` | URL `myapp://profile/123` | Valid `SafeDeepLink` returned |
| Unknown scheme rejected | adversarial | Allowed schemes `["myapp"]` | URL `evil://steal-data` | Rejected with `InvalidScheme` |
| JavaScript scheme in deep link blocked | adversarial | Any configuration | URL `javascript:alert(1)` | Rejected with `DangerousScheme` + security event |
| Data URI in deep link blocked | adversarial | Any configuration | URL `data:text/html,...` | Rejected with `DangerousScheme` |
| Path traversal in deep link blocked | adversarial | Any configuration | URL `myapp://../../etc/passwd` | Rejected with `PathTraversal` |
| Host validation enforced | happy path | Allowed hosts `["example.com"]` | URL `https://example.com/path` | Valid |
| Host validation rejects mismatch | adversarial | Allowed hosts `["example.com"]` | URL `https://evil.com/path` | Rejected with `UntrustedHost` |

**Feature: Clipboard Security Policy**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Sensitive data requires local-only clipboard | happy path | `ClipboardPolicy` for `Confidential` data | Policy checked | `restrict_to_local_device()` returns true |
| Clipboard expiration set for secrets | happy path | `ClipboardPolicy` for `Secret` data | Policy checked | `expiration_seconds()` returns 60 |
| Public data has no clipboard restrictions | happy path | `ClipboardPolicy` for `Public` data | Policy checked | No restrictions |

**Feature: WebView URL Safety**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| HTTPS URL allowed in WebView | happy path | `SafeWebViewUrl` | URL `https://trusted.com/page` | Valid |
| File URL blocked in WebView | adversarial | `SafeWebViewUrl` | URL `file:///etc/passwd` | Rejected with `FileAccessBlocked` + security event |
| JavaScript URL blocked in WebView | adversarial | `SafeWebViewUrl` | URL `javascript:void(0)` | Rejected with `DangerousScheme` |
| Data URL blocked in WebView | adversarial | `SafeWebViewUrl` | URL `data:text/html,<script>` | Rejected with `DangerousScheme` |
| Blob URL blocked in WebView | adversarial | `SafeWebViewUrl` | URL `blob:https://...` | Rejected with `DangerousScheme` |
| Domain allowlist enforced | happy path | `SafeWebViewUrl` with allowlist | URL matches allowlist | Valid |

**Feature: Screenshot Prevention Signal**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Sensitive screen marked for prevention | happy path | `ScreenshotPolicy::prevent()` | Policy checked | `should_prevent_screenshot()` returns true |
| Non-sensitive screen allows screenshots | happy path | `ScreenshotPolicy::allow()` | Policy checked | `should_prevent_screenshot()` returns false |
| Default is prevent for sensitive data | empty state | No explicit policy, data classified `Confidential` | Policy inferred | Defaults to prevent |

#### Fuzz Targets

- `fuzz_deep_link` — fuzz `SafeDeepLink::try_from` with arbitrary URL strings.

#### Smoke Tests

- [ ] `cargo test -p secure_boundary --features mobile-platform` passes
- [ ] `cargo test --workspace` passes
- [ ] All existing safe type tests unchanged

---

### Milestone 5 — `secure_resilience`: Anti-Tampering & Environment Detection (MASVS-RESILIENCE)

**Goal**: Create a new `secure_resilience` crate providing environment detection signal types (root/jailbreak, emulator, debugger), app integrity verification, and RASP (Runtime Application Self-Protection) signal aggregation — enabling mobile apps to satisfy MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, and MASVS-RESILIENCE-3.

**Context**: No existing SunLit crate addresses reverse engineering resilience. MASVS-RESILIENCE requires detecting compromised environments (MASWE-0097: root/jailbreak, MASWE-0098: virtualization, MASWE-0099: emulator, MASWE-0100: debugger), verifying app integrity (MASWE-0105: resource integrity, MASWE-0106: official store verification, MASWE-0107: runtime code integrity), and implementing RASP signals that can trigger defensive responses (MASTG-BEST-0029, MASTG-BEST-0030).

**Important design rule**: This crate provides the policy engine, signal types, and response decision logic — not the actual detection routines. The mobile app implements platform-specific detection (e.g., checking for `su` binary, Magisk, Frida, Substrate) and feeds signals into this crate. Responses are configurable policies (warn, block, degrade), not hardcoded actions.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `EnvironmentSignal` (type + confidence + evidence), `IntegrityCheckResult` |
| Outputs | `RaspDecision` (Allow/Warn/Block/Degrade), `SecurityEvent`, `ThreatLevel` aggregate |
| Interfaces touched | New crate `secure_resilience`, `security_core` (new types), `security_events` (new `EventKind`) |
| Files allowed to change | `Cargo.toml` (workspace), `security_core/src/lib.rs`, `security_events/src/event.rs` |
| Files to read before changing anything | `ARCHITECTURE.md`, `security_core/src/lib.rs`, `security_events/src/event.rs` |
| New files allowed | `crates/secure_resilience/Cargo.toml`, `crates/secure_resilience/src/lib.rs`, `crates/secure_resilience/src/environment.rs`, `crates/secure_resilience/src/integrity.rs`, `crates/secure_resilience/src/rasp.rs`, `crates/secure_resilience/src/error.rs`, `crates/secure_resilience/tests/` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing crate APIs unchanged |
| Forbidden shortcuts | No actual detection routines (pure policy engine), no `unsafe` |

#### Out of Scope / Must Not Do

- Do not implement actual root detection, file system checks, or process enumeration
- Do not implement binary obfuscation or code packing
- Do not add Android/iOS platform bindings
- Do not implement anti-debugging logic (ptrace, sysctl) — provide signal types only

#### BDD Acceptance Scenarios

**Feature: Environment Signal Processing**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Root detection signal processed | happy path | `EnvironmentSignal::RootDetected` with high confidence | Signal processed by `RaspEngine` | `ThreatLevel` updated, security event emitted |
| Emulator detected | happy path | `EnvironmentSignal::EmulatorDetected` with medium confidence | Signal processed | `ThreatLevel` updated appropriately |
| Debugger attached | adversarial | `EnvironmentSignal::DebuggerAttached` with high confidence | Signal processed | Highest priority threat, immediate response recommended |
| Multiple signals aggregate | happy path | Root + emulator + debugger signals | All processed | `ThreatLevel` reflects combined risk |
| Unknown signal type handled | empty state | `EnvironmentSignal::Unknown` | Signal processed | Logged but does not trigger response |

**Feature: RASP Policy Engine**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Warn policy on root detection | happy path | `RaspPolicy` with `root_response: Warn` | Root signal received | `RaspDecision::Warn` returned |
| Block policy on debugger | adversarial | `RaspPolicy` with `debugger_response: Block` | Debugger signal received | `RaspDecision::Block` returned |
| Degrade policy on emulator | happy path | `RaspPolicy` with `emulator_response: Degrade` | Emulator signal received | `RaspDecision::Degrade { capabilities_removed }` |
| Allow policy (permissive mode) | happy path | `RaspPolicy::permissive()` | Any signal received | `RaspDecision::Allow` with informational event |
| Default policy is warn | empty state | `RaspPolicy::default()` | Root detected | `RaspDecision::Warn` (secure but not disruptive default) |

**Feature: App Integrity Verification**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid app signature verified | happy path | `IntegrityCheck` with known-good signing cert hash | App signature matches | `IntegrityResult::Valid` |
| Tampered app signature detected | adversarial | `IntegrityCheck` with expected hash | Hash mismatch | `IntegrityResult::Tampered` + critical security event |
| Sideloaded app detected | adversarial | `IntegrityCheck` with store verification | App not from official store | `IntegrityResult::SideLoaded` + security event |
| Resource integrity verified | happy path | `IntegrityCheck` with resource hashes | All resources match expected hashes | `IntegrityResult::Valid` |

#### Smoke Tests

- [ ] `cargo test -p secure_resilience` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `.gitignore` updated

---

### Milestone 6 — `secure_privacy`: Data Minimization & Privacy Controls (MASVS-PRIVACY)

**Goal**: Create a new `secure_privacy` crate providing PII discovery/classification, data pseudonymization, consent tracking abstractions, and data retention policy enforcement — enabling mobile apps to satisfy MASVS-PRIVACY-1 through MASVS-PRIVACY-4.

**Context**: MASVS-PRIVACY addresses minimizing access to sensitive data (MASVS-PRIVACY-1), preventing user identification (MASVS-PRIVACY-2), transparency about data collection (MASVS-PRIVACY-3), and user control over data (MASVS-PRIVACY-4). The existing `security_events` redaction engine handles event-level data classification but provides no tools for: systematic PII discovery (MASWE-0109), identifier pseudonymization (MASWE-0110), consent management (MASWE-0115), or data retention enforcement (MASWE-0113).

**Important design rule**: Privacy controls are policy engines and data transformations — not user interfaces or storage systems. Consent tracking provides the state machine and validation; the mobile app provides the UI and persistence.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Data fields, user consent decisions, retention periods, identifiers to pseudonymize |
| Outputs | `PiiClassification`, `PseudonymizedValue`, `ConsentDecision`, `RetentionStatus`, `SecurityEvent` |
| Interfaces touched | New crate `secure_privacy`, `security_core` (possible new types) |
| Files allowed to change | `Cargo.toml` (workspace), `security_core/src/lib.rs` |
| Files to read before changing anything | `ARCHITECTURE.md`, `security_core/src/lib.rs`, `security_events/src/redaction.rs` |
| New files allowed | `crates/secure_privacy/Cargo.toml`, `crates/secure_privacy/src/lib.rs`, `crates/secure_privacy/src/classifier.rs`, `crates/secure_privacy/src/pseudonymizer.rs`, `crates/secure_privacy/src/consent.rs`, `crates/secure_privacy/src/retention.rs`, `crates/secure_privacy/src/error.rs`, `crates/secure_privacy/tests/` |
| New dependencies allowed | `none` (uses existing `sha2` from workspace, `regex` for pattern matching) |
| Migration allowed | `no` |
| Compatibility commitments | All existing crate APIs unchanged |
| Forbidden shortcuts | No GDPR legal advice in code comments, no actual data deletion implementation |

#### Out of Scope / Must Not Do

- Do not implement GDPR/CCPA compliance tooling (legal scope, not technical)
- Do not implement data deletion — retention policies signal intent, they don't delete
- Do not implement consent UI components
- Do not store consent state (provide state machine and validation only)

#### BDD Acceptance Scenarios

**Feature: PII Classification**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Email address classified as PII | happy path | Input string `user@example.com` | `PiiClassifier::classify()` called | Returns `PiiClassification::Email` |
| Phone number classified as PII | happy path | Input string `+1-555-0123` | Classified | Returns `PiiClassification::PhoneNumber` |
| UUID not classified as PII | happy path | Input string (UUID format) | Classified | Returns `PiiClassification::None` |
| IP address classified as PII | happy path | Input string `192.168.1.100` | Classified | Returns `PiiClassification::IpAddress` |
| Device ID (IMEI) classified as PII | happy path | Input string matching IMEI pattern | Classified | Returns `PiiClassification::DeviceIdentifier` |
| Custom PII pattern added | happy path | Custom regex for credit card | Classified | Returns `PiiClassification::Custom("credit_card")` |

**Feature: Data Pseudonymization**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Email pseudonymized consistently | happy path | Email `user@example.com` with salt | Pseudonymized twice | Same `PseudonymizedValue` both times (deterministic) |
| Different salt produces different pseudonym | happy path | Same email with different salts | Pseudonymized | Different `PseudonymizedValue` |
| Pseudonymized value is not reversible | adversarial | `PseudonymizedValue` output | Attempt to reverse | Cannot recover original (uses HMAC-based approach) |
| Batch pseudonymization supported | happy path | List of 100 identifiers | `pseudonymize_batch()` called | All pseudonymized efficiently |

**Feature: Consent Policy**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Consent granted allows data processing | happy path | `ConsentPolicy` for "analytics", consent granted | Processing check | `ConsentDecision::Allowed` |
| Consent denied blocks data processing | adversarial | `ConsentPolicy` for "analytics", consent not granted | Processing check | `ConsentDecision::Denied` + security event |
| Consent not yet collected blocks processing | empty state | No consent record for purpose | Processing check | `ConsentDecision::NotCollected` (deny by default) |
| Consent withdrawal invalidates prior grant | happy path | Consent granted then withdrawn | Processing check | `ConsentDecision::Withdrawn` |
| Purpose limitation enforced | adversarial | Consent for "analytics" only | Data used for "marketing" | `ConsentDecision::PurposeMismatch` |

**Feature: Data Retention Policy**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Data within retention period | happy path | `RetentionPolicy` with 90 days, data is 30 days old | Status checked | `RetentionStatus::Active` |
| Data past retention period | happy path | `RetentionPolicy` with 90 days, data is 100 days old | Status checked | `RetentionStatus::Expired` (signal for deletion) |
| No retention policy defaults to indefinite | empty state | No explicit policy | Status checked | `RetentionStatus::NoPolicy` (warn) |
| Retention event emitted on expiry | happy path | Data expires | Expiry detected | `SecurityEvent` with retention violation emitted |

#### Smoke Tests

- [ ] `cargo test -p secure_privacy` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `.gitignore` updated

---

### Milestone 7 — `security_events` Mobile Log Sanitization (MASVS-STORAGE/CODE)

**Goal**: Extend `security_events` with mobile-specific log sanitization — device identifier scrubbing (IMEI, IDFV, advertising IDs), compile-time log level enforcement for release builds, and enhanced mobile data redaction patterns — to satisfy MASVS-STORAGE-2 (log leakage prevention) and MASVS-CODE-2 (code quality).

**Context**: `security_events` already provides classification-driven redaction (`RedactionEngine`), log injection prevention, and rate limiting. Mobile apps generate additional sensitive data in logs: device identifiers (MASWE-0001), hardware serial numbers, advertising IDs (GAID/IDFA), and location coordinates. MASTG-BEST-0002 (remove logging code) and MASTG-BEST-0022 (disable verbose/debug logging in production) address this gap. The enhancement adds mobile-aware redaction patterns and a compile-time `LogLevelEnforcer` that strips debug/trace logs from release builds.

**Important design rule**: New redaction patterns integrate with the existing `RedactionEngine` and `RedactionPolicy` architecture — no parallel system.

**Refactor budget**: `Minimal local refactor permitted in listed files only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Log event labels, device identifier strings, build configuration |
| Outputs | Redacted events, scrubbed device IDs, log level filtering |
| Interfaces touched | `security_events` (extended modules) |
| Files allowed to change | `crates/security_events/Cargo.toml`, `crates/security_events/src/redaction.rs`, `crates/security_events/src/lib.rs` |
| Files to read before changing anything | `crates/security_events/src/redaction.rs`, `crates/security_events/src/event.rs`, `ARCHITECTURE.md` |
| New files allowed | `crates/security_events/src/mobile_redaction.rs`, `crates/security_events/tests/mobile_redaction_tests.rs`, `crates/security_events/fuzz/fuzz_targets/fuzz_mobile_redaction.rs` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing `RedactionEngine` behavior unchanged, existing `RedactionPolicy` extended not replaced |
| Forbidden shortcuts | No conditional compilation that silently drops errors |

#### Out of Scope / Must Not Do

- Do not modify existing redaction strategies for non-mobile data
- Do not implement log aggregation or log shipping
- Do not strip all logging (only verbose/debug in release)

#### BDD Acceptance Scenarios

**Feature: Mobile Device ID Scrubbing**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| IMEI in log label redacted | happy path | Event label value containing IMEI pattern | Mobile redaction applied | IMEI replaced with `[DEVICE_ID_REDACTED]` |
| IDFV in log label redacted | happy path | Event label containing iOS IDFV (UUID format with known key) | Redaction applied | IDFV redacted |
| Advertising ID (GAID/IDFA) redacted | happy path | Event label containing ad identifier | Redaction applied | Ad ID replaced with `[AD_ID_REDACTED]` |
| MAC address redacted | happy path | Event label containing MAC address pattern | Redaction applied | MAC redacted |
| Non-device data preserved | happy path | Event label with normal application data | Redaction applied | Data unchanged |
| Location coordinates scrubbed | adversarial | Event label containing GPS coordinates | Redaction applied | Coordinates replaced with `[LOCATION_REDACTED]` |

**Feature: Log Level Enforcement**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Debug log stripped in release mode | happy path | `LogLevelEnforcer::release()` | Debug-level event submitted | Event suppressed (not emitted to any sink) |
| Info log preserved in release mode | happy path | `LogLevelEnforcer::release()` | Info-level event submitted | Event emitted normally |
| All log levels in debug mode | happy path | `LogLevelEnforcer::debug()` | Debug-level event submitted | Event emitted |

#### Fuzz Targets

- `fuzz_mobile_redaction` — fuzz mobile redaction patterns with arbitrary strings to verify no panics and correct pattern matching.

#### Smoke Tests

- [ ] `cargo test -p security_events` passes
- [ ] `cargo test --workspace` passes
- [ ] Existing redaction tests unchanged
- [ ] `.gitignore` updated

---

### Milestone 8 — Smoke Service Mobile Routes & E2E Validation

**Goal**: Add mobile security smoke test routes to `secure_smoke_service` — one route per MASVS control area — for DAST scanning validation and end-to-end testing of all new mobile security capabilities from milestones M1–M7.

**Context**: The existing smoke service has 39 routes covering web security controls. This milestone adds mobile-specific routes that exercise the new `secure_network`, `secure_resilience`, `secure_privacy` crates and the mobile extensions to `secure_data`, `secure_identity`, `secure_boundary`, and `security_events`. The routes serve as DAST targets when the OpenAPI spec is updated.

**Important design rule**: Each route tests exactly one mobile security control. Routes follow the existing `/smoke/` prefix pattern but use a `/smoke/mobile/` sub-path.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | HTTP requests with attack payloads targeting mobile controls |
| Outputs | HTTP responses demonstrating control enforcement, security events |
| Interfaces touched | `secure_smoke_service` routes, `openapi.yaml` |
| Files allowed to change | `crates/secure_smoke_service/Cargo.toml`, `crates/secure_smoke_service/src/lib.rs`, `crates/secure_smoke_service/openapi.yaml` |
| Files to read before changing anything | `crates/secure_smoke_service/src/lib.rs`, `ARCHITECTURE.md` |
| New files allowed | `crates/secure_smoke_service/src/mobile_routes.rs`, `crates/secure_smoke_service/tests/e2e_sunlit_masvs_m8.rs` |
| New dependencies allowed | `secure_network`, `secure_resilience`, `secure_privacy` (workspace crates) |
| Migration allowed | `no` |
| Compatibility commitments | All existing 39 routes unchanged, `/health` unchanged |
| Forbidden shortcuts | No placeholder routes, no TODO responses |

#### Out of Scope / Must Not Do

- Do not modify existing smoke routes
- Do not change authentication mechanism (keep HS256 JWT)
- Do not implement mobile-specific HTTP clients

#### New Routes (15 routes)

| Route | Method | MASVS Control | What It Tests |
|---|---|---|---|
| `/smoke/mobile/tls-version` | POST | MASVS-NETWORK-1 | TLS version validation (accept TLS version claim, validate against policy) |
| `/smoke/mobile/cert-pin` | POST | MASVS-NETWORK-1 | Certificate pin verification (accept cert hash, validate against pin set) |
| `/smoke/mobile/cleartext` | POST | MASVS-NETWORK-2 | Cleartext traffic detection (accept URL, validate scheme) |
| `/smoke/mobile/storage-policy` | POST | MASVS-STORAGE-1 | Mobile storage policy enforcement |
| `/smoke/mobile/sensitive-buffer` | POST | MASVS-STORAGE-1 | Sensitive buffer handling (verify no secret in response) |
| `/smoke/mobile/biometric` | POST | MASVS-AUTH-2 | Biometric result validation |
| `/smoke/mobile/step-up` | POST | MASVS-AUTH-3 | Step-up authentication enforcement |
| `/smoke/mobile/deep-link` | POST | MASVS-PLATFORM-1 | Deep link URL validation |
| `/smoke/mobile/webview-url` | POST | MASVS-PLATFORM-1 | WebView URL safety check |
| `/smoke/mobile/clipboard` | POST | MASVS-PLATFORM-2 | Clipboard security policy check |
| `/smoke/mobile/root-detect` | POST | MASVS-RESILIENCE-1 | Environment detection signal processing |
| `/smoke/mobile/app-integrity` | POST | MASVS-RESILIENCE-2 | App integrity verification |
| `/smoke/mobile/pii-classify` | POST | MASVS-PRIVACY-1 | PII classification |
| `/smoke/mobile/pseudonymize` | POST | MASVS-PRIVACY-2 | Data pseudonymization |
| `/smoke/mobile/consent` | POST | MASVS-PRIVACY-3 | Consent policy enforcement |

#### BDD Acceptance Scenarios

**Feature: Mobile Smoke Routes**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| TLS version validation rejects TLS 1.0 | adversarial | POST `/smoke/mobile/tls-version` with `{"version": "TLS1.0"}` | Route processes request | 422 response with `tls_version_rejected` code |
| Cert pin validates known hash | happy path | POST `/smoke/mobile/cert-pin` with valid hash | Route processes request | 200 response with `pin_valid` |
| Deep link validates safe URL | happy path | POST `/smoke/mobile/deep-link` with `{"url": "myapp://profile/1"}` | Route processes request | 200 response with `valid_deep_link` |
| Deep link rejects javascript scheme | adversarial | POST `/smoke/mobile/deep-link` with `{"url": "javascript:alert(1)"}` | Route processes request | 422 response with `dangerous_scheme` |
| PII classifier detects email | happy path | POST `/smoke/mobile/pii-classify` with `{"data": "user@test.com"}` | Route processes request | 200 response with `classification: email` |
| Pseudonymizer returns consistent hash | happy path | POST `/smoke/mobile/pseudonymize` twice with same data | Both requests processed | Same pseudonymized value returned |
| Root detection signal processed | happy path | POST `/smoke/mobile/root-detect` with root signal | Route processes request | 200 response with RASP decision |
| All existing routes still work | backward compat | GET `/health` | Route processes | 200 OK |

#### E2E Runtime Validation

**File**: `crates/secure_smoke_service/tests/e2e_sunlit_masvs_m8.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_all_mobile_routes_respond` | All 15 mobile routes are mounted and respond | Each route returns expected status code |
| `test_mobile_routes_require_auth` | Mobile routes require JWT auth | Unauthenticated requests get 401 |
| `test_attack_payloads_rejected` | Security controls block malicious input | Known-bad payloads return 422/403 |
| `test_security_events_emitted` | Violations produce security events | `InMemorySink` captures expected event kinds |

#### Smoke Tests

- [ ] `cargo test -p secure_smoke_service --test '*'` passes
- [ ] `cargo run -p secure_smoke_service` boots and serves `/health`
- [ ] All 39 existing routes respond correctly
- [ ] All 15 new mobile routes respond correctly
- [ ] OpenAPI spec updated with mobile routes
- [ ] `.gitignore` updated

---

### Milestone 9 — Adversarial Testing: Fuzz, Property Tests & CVE Regression

**Goal**: Add comprehensive adversarial testing for all new mobile security crates and extensions — fuzz targets for every parser/validator, property-based tests for safety invariants, and CVE regression tests for known mobile security vulnerabilities — ensuring security boundaries hold under hostile input.

**Context**: Existing SunLit crates have fuzz targets (`secure_boundary`, `secure_data`, `secure_identity`, `secure_output`, `security_events`). This milestone ensures all new M1–M7 code receives equivalent adversarial coverage. Each new safe type, validator, and policy engine gets a fuzz target. Property tests verify invariants like: "no input to `SafeDeepLink::try_from` produces a value that contains `javascript:` scheme." CVE regression tests encode known MASWE weaknesses as concrete test cases.

**Important design rule**: Every fuzz target must run for at least 60 seconds without panic or assertion failure. Property tests must use `proptest` with at least 1000 cases per property.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Arbitrary byte vectors, random strings, adversarial payloads |
| Outputs | No panics, no assertion failures, correct rejection of invalid input |
| Interfaces touched | `fuzz/` directories in each crate, `tests/` directories |
| Files allowed to change | `crates/*/fuzz/Cargo.toml`, `crates/*/fuzz/fuzz_targets/` |
| Files to read before changing anything | Existing fuzz targets in each crate, `ARCHITECTURE.md` |
| New files allowed | Fuzz target files, property test files, CVE regression test files in each crate's `tests/` and `fuzz/` |
| New dependencies allowed | `proptest` (dev-dependency for property tests, if not already present) |
| Migration allowed | `no` |
| Compatibility commitments | No production code changes, testing only |
| Forbidden shortcuts | No `#[ignore]` on fuzz or property tests |

#### Out of Scope / Must Not Do

- Do not modify production code (test-only milestone)
- Do not add new features
- Do not change public APIs

#### Fuzz Targets (New)

| Crate | Target | What It Fuzzes |
|---|---|---|
| `secure_network` | `fuzz_tls_policy` | Arbitrary TLS parameters against `TlsPolicy::validate()` |
| `secure_network` | `fuzz_cert_pin` | Arbitrary DER bytes against `CertPinValidator::validate()` |
| `secure_network` | `fuzz_cleartext` | Arbitrary URLs against `CleartextDetector::check()` |
| `secure_boundary` | `fuzz_deep_link` | Arbitrary URLs against `SafeDeepLink::try_from()` |
| `secure_boundary` | `fuzz_webview_url` | Arbitrary URLs against `SafeWebViewUrl::try_from()` |
| `secure_resilience` | `fuzz_rasp_signals` | Arbitrary signal sequences against `RaspEngine::process()` |
| `secure_privacy` | `fuzz_pii_classifier` | Arbitrary strings against `PiiClassifier::classify()` |
| `secure_privacy` | `fuzz_pseudonymizer` | Arbitrary identifiers against `Pseudonymizer::pseudonymize()` |
| `secure_data` | `fuzz_sensitive_buffer` | Arbitrary bytes against `SensitiveBuffer` lifecycle |
| `security_events` | `fuzz_mobile_redaction` | Arbitrary strings against mobile redaction patterns |

#### Property Tests

| Crate | Property | Invariant |
|---|---|---|
| `secure_network` | `prop_tls_rejects_below_min_version` | No `TlsVersion < min` ever returns `Allow` |
| `secure_network` | `prop_cleartext_never_allows_http` | No `http://` URL ever returns `Secure` (except localhost exemption) |
| `secure_boundary` | `prop_deep_link_rejects_dangerous_schemes` | No `javascript:`, `data:`, `vbscript:` ever produces a valid `SafeDeepLink` |
| `secure_boundary` | `prop_webview_url_rejects_file_urls` | No `file://` URL ever produces a valid `SafeWebViewUrl` |
| `secure_resilience` | `prop_rasp_block_stops_processing` | After `Block` decision, no subsequent `Allow` possible until reset |
| `secure_privacy` | `prop_pseudonymize_deterministic` | Same input + same salt always produces same output |
| `secure_privacy` | `prop_pseudonymize_not_reversible` | Output cannot produce original input via any tested reversal |

#### CVE Regression Tests (MASWE-based)

| Test File | MASWE Reference | What It Tests |
|---|---|---|
| `tests/cve_maswe_0050_cleartext.rs` | MASWE-0050 | Cleartext traffic variants (HTTP, custom ports, FTP) are always detected |
| `tests/cve_maswe_0052_cert_validation.rs` | MASWE-0052 | Insecure certificate validation patterns are caught |
| `tests/cve_maswe_0058_deep_links.rs` | MASWE-0058 | Insecure deep link patterns (scheme hijacking, path traversal) |
| `tests/cve_maswe_0069_webview_files.rs` | MASWE-0069 | WebView file access patterns (file://, content://) |
| `tests/cve_maswe_0097_root_detection.rs` | MASWE-0097 | Root/jailbreak detection signal processing |
| `tests/cve_maswe_0109_pii_leakage.rs` | MASWE-0109 | PII in log/event data detected by classifier |
| `tests/cve_maswe_0001_sensitive_logs.rs` | MASWE-0001 | Sensitive data in log labels scrubbed by mobile redaction |

#### Smoke Tests

- [ ] `cargo test --workspace` passes (all new tests)
- [ ] `cargo fuzz list` shows all new fuzz targets for each crate
- [ ] Each fuzz target runs 60 seconds without crash: `cargo fuzz run <target> -- -max_total_time=60`
- [ ] `.gitignore` updated for fuzz corpus directories

#### Definition of Done

- all fuzz targets run 60+ seconds without crash
- all property tests pass with 1000+ cases
- all CVE regression tests pass
- full existing test suite remains green
- no production code changed
- `.gitignore` covers fuzz corpus directories
- lessons file written at `docs/slo/lessons/sunlit-masvs-m9.md`
- completion summary written at `docs/slo/completion/sunlit-masvs-m9.md`

---

## Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | Add `secure_network` component description | Add MASVS-NETWORK coverage | Fuzz corpus patterns | THREAT_MODEL.md: network threats |
| 2 | Update `secure_data` with mobile storage section | Add MASVS-STORAGE coverage | None expected | dev-guide: secure-data.md |
| 3 | Update `secure_identity` with biometric section | Add MASVS-AUTH mobile coverage | None expected | dev-guide: secure-identity.md |
| 4 | Update `secure_boundary` with platform section | Add MASVS-PLATFORM coverage | None expected | dev-guide: secure-boundary.md |
| 5 | Add `secure_resilience` component description | Add MASVS-RESILIENCE coverage | None expected | THREAT_MODEL.md: resilience threats |
| 6 | Add `secure_privacy` component description | Add MASVS-PRIVACY coverage | None expected | dev-guide: new secure-privacy.md |
| 7 | Update `security_events` with mobile redaction | Update existing events section | None expected | dev-guide: security-events.md |
| 8 | Update `secure_smoke_service` route table | Add mobile smoke routes | None expected | openapi.yaml |
| 9 | Update adversarial testing section | Add fuzz/property test counts | Fuzz corpus directories | None |

---

## Lessons-Learned File Template

Path: `docs/slo/lessons/sunlit-masvs-m<N>.md`

```md
# Lessons Learned — sunlit-masvs Milestone <N>

## What changed
- [summary]

## Design decisions and why
- [decision] — [reason]

## Mistakes made
- [mistake]

## Root causes
- [root cause]

## What was harder than expected
- [note]

## Naming conventions established
- [types, files, tests, events, commands]

## Test patterns that worked well
- [pattern]

## Missing tests that should exist now
- [test]

## Rules for the next milestone
- [rule]

## Template improvements suggested
- [improvement]
```

---

## Completion Summary Template

Path: `docs/slo/completion/sunlit-masvs-m<N>.md`

```md
# Completion Summary — sunlit-masvs Milestone <N>

## Goal completed
- [what capability now exists]

## Files changed
- [file]

## Tests added
- [test file]

## Runtime validations added
- [e2e file]

## Compatibility checks performed
- [check]

## Documentation updated
- [doc and section]

## .gitignore changes
- [patterns added or removed]

## Test artifact cleanup verified
- [confirmation that git status is clean after test run]

## Deferred follow-ups
- [follow-up]

## Known non-blocking limitations
- [limitation]
```

---

## Optional Fast-Fail Review Prompt for Agents

Use this before writing production code:

> Restate the milestone goal, allowed files, forbidden changes, compatibility requirements, tests that must be written first, and the exact Definition of Done. Then list the smallest implementation approach that satisfies the contract without widening scope.

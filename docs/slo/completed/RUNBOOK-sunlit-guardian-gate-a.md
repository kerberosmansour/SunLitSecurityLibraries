# Sunlit Guardian Gate A — SunLitSecurityLibraries (AI-First Runbook v3)

> **Purpose**: Ship the two blocking features Sunlit Guardian's v4 migration runbook needs before `/slo-execute M1` can start: (A1) Actix-web 4 adapters for five framework-coupled types across `secure_boundary`, `secure_authz`, and `secure_errors`, and (A2) `SafeUrl` blocked-CIDR coverage extension. Close out the nice-to-have housekeeping (A4/A5/C1/C3) in a fourth milestone so Sunlit Guardian can pin a single commit SHA workspace-wide.
> **Audience**: AI coding agents first, humans second. This document is written to reduce ambiguity, prevent scope drift, and improve code quality with the same model capability.
> **How to use**: Work through milestones sequentially. Before starting any milestone, read its full section and the Global Execution Rules. After completing it, follow the Global Exit Rules. Never skip ahead. Never silently widen scope.
> **Prerequisite reading**: [ARCHITECTURE.md](../../../ARCHITECTURE.md), [README.md](../../../README.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), and the Sunlit Guardian v4 feedback document (dated 2026-04-24) that triggered this runbook.

---

## Runbook Metadata

- **Runbook ID**: `sg-gate-a`
- **Prefix for test files and lessons files**: `sg-gate-a`
- **Primary stack**: Rust 2021, Cargo workspace of 13 crates
- **Primary package/app names**: `secure_boundary`, `secure_authz`, `secure_errors`, `secure_identity` (cross-crate integration tested via `secure_reference_service` and `secure_smoke_service`)
- **Default test commands**:
  - Backend (full workspace): `cargo test --workspace`
  - Backend (per-crate default features): `cargo test -p <crate>`
  - Backend (per-crate Actix feature): `cargo test -p <crate> --features actix-web`
  - Backend (per-crate both frameworks composed): `cargo test -p <crate> --features "axum actix-web"`
  - Feature matrix build: `cargo check --workspace --all-features` and `cargo check --workspace --no-default-features`
  - Frontend: `n/a` — library workspace, no frontend
  - E2E backend: `cargo test -p secure_smoke_service -- --include-ignored`
  - E2E frontend: `n/a`
  - Build/boot: `cargo build --workspace --release`
  - Lints: `cargo clippy --workspace --all-features -- -D warnings`
  - Format: `cargo fmt --all --check`
  - Supply chain: `cargo audit`, `cargo deny check`, `cargo vet` (all three must pass)
- **Allowed new dependencies by default**: `none`
- **Schema/config migration allowed by default**: `no`
- **Public interfaces that must remain stable unless explicitly listed otherwise**:
  - `secure_boundary::{SecureJson, SecureQuery, SecurePath, SecurityHeadersLayer, FetchMetadataLayer, SafeUrl, SafeRedirectUrl, BoundaryRejection}` — existing axum-facing signatures, extractor traits, and `SafeUrl::try_from(&str)` acceptance set
  - `secure_authz::{AuthzLayer, Authorizer, Decision, Subject, ResourceRef, Action, ObligationFulfillment}` — existing axum layer signature and public trait surface
  - `secure_errors::{ErrorMappingLayer, AppError, PublicError, http::{into_response_parts, retry_after_seconds}}` — existing mapping rules and axum `IntoResponse` impl
  - `secure_identity::{TokenValidator, IdentitySource, AuthenticatedIdentity}` public API — no breaking changes; new helper in M4 is additive only
  - `security_core` types (`AuthenticatedIdentity`, `IdentitySource`, `ActorId`, `TenantId`, `RequestId`, etc.)
  - `secure_reference_service` and `secure_smoke_service` must continue to compile + test green against unchanged axum paths at every milestone boundary

---

## Milestone Tracker

Update this table as each milestone is completed. This is the single source of truth for progress.

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | `secure_boundary` Actix adapters (SecureJson + SecurityHeadersLayer + FetchMetadataLayer) | `done` | 2026-04-24 | 2026-04-24 | [sg-gate-a-m1.md](../lessons/sg-gate-a-m1.md) | [sg-gate-a-m1.md](../completion/sg-gate-a-m1.md) |
| 2 | `secure_authz::AuthzLayer` + `secure_errors::ErrorMappingLayer` Actix adapters | `done` | 2026-04-24 | 2026-04-24 | [sg-gate-a-m2.md](../lessons/sg-gate-a-m2.md) | [sg-gate-a-m2.md](../completion/sg-gate-a-m2.md) |
| 3 | `SafeUrl` blocked-CIDR coverage extension + per-CIDR tests + rustdoc | `done` | 2026-04-24 | 2026-04-24 | [sg-gate-a-m3.md](../lessons/sg-gate-a-m3.md) | [sg-gate-a-m3.md](../completion/sg-gate-a-m3.md) |
| 4 | Secure-by-default helpers (A4/A5), license reconciliation (C1), deny.toml publishing (C3), CI feature-matrix gate | `done` | 2026-04-24 | 2026-04-24 | [sg-gate-a-m4.md](../lessons/sg-gate-a-m4.md) | [sg-gate-a-m4.md](../completion/sg-gate-a-m4.md) |

<!-- Status values: not_started | in_progress | blocked | done -->
<!-- Lessons files go in docs/slo/lessons/sg-gate-a-m<N>.md -->
<!-- Completion summaries go in docs/slo/completion/sg-gate-a-m<N>.md -->

---

## End-to-End Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       SunLitSecurityLibraries — End State                      │
│                                                                              │
│  ┌──────────────────────────┐             ┌──────────────────────────┐       │
│  │  secure_reference_service │  existing   │  secure_smoke_service    │       │
│  │  (axum, unchanged)        │◀────────────│  (axum, unchanged)       │       │
│  └──────────────┬────────────┘             └──────────────┬───────────┘       │
│                 │ uses                                    │ uses              │
│                 ▼                                         ▼                   │
│    ┌──────────────────────────────────────────────────────────────────┐       │
│    │  Framework-coupled crates (after Gate A)                         │       │
│    │  ┌────────────────────┐   ┌────────────────────┐                 │       │
│    │  │  secure_boundary   │   │  secure_authz      │                 │       │
│    │  │  ─────────────     │   │  ─────────────     │                 │       │
│    │  │  [axum]  default   │   │  [axum]  default   │                 │       │
│    │  │  ╔════════════╗    │   │  ╔════════════╗    │                 │       │
│    │  │  ║[actix-web] ║NEW │   │  ║[actix-web] ║NEW │                 │       │
│    │  │  ╚════════════╝    │   │  ╚════════════╝    │                 │       │
│    │  └────────────────────┘   └────────────────────┘                 │       │
│    │  ┌────────────────────┐   ┌────────────────────┐                 │       │
│    │  │  secure_errors     │   │  secure_identity   │                 │       │
│    │  │  ─────────────     │   │  ─────────────     │                 │       │
│    │  │  [axum]  default   │   │  (no HTTP coupling)│                 │       │
│    │  │  ╔════════════╗    │   │  + assert_no_dev_..│                 │       │
│    │  │  ║[actix-web] ║NEW │   │    helper (A4) NEW │                 │       │
│    │  │  ╚════════════╝    │   │                    │                 │       │
│    │  └────────────────────┘   └────────────────────┘                 │       │
│    └──────────────────────────────────────────────────────────────────┘       │
│                                                                              │
│                                                                              │
│  ┌──────────────────────────┐                                                │
│  │  Sunlit Guardian         │   pins git rev — consumes both axum and       │
│  │  (platform-api, etc.)    │   actix-web features                           │
│  │  Actix-web 4 services    │◀───────────────────────────────────────────── │
│  └──────────────────────────┘                                                │
│                                                                              │
│  Legend:                                                                     │
│  ───  existing (axum path, untouched)                                        │
│  ═══  new feature flag (actix-web adapters)                                  │
│  ▶    dependency direction                                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Milestone Introduced/Changed | Key Interfaces |
|---|---|---|---|
| `secure_boundary::actix` (NEW module) | Actix-web 4 adapters for `SecureJson`, `SecurityHeadersLayer`, `FetchMetadataLayer` | M1 | `impl FromRequest for SecureJson<T>`, `actix_web::middleware::Transform` for headers & fetch-metadata |
| `secure_boundary` feature flags `axum` / `actix-web` | Compile-time selection of framework adapters; composable | M1 | `Cargo.toml [features]` block |
| `secure_authz::actix` (NEW module) | Actix-web 4 `AuthzLayer` adapter reading `AuthenticatedIdentity` from extensions | M2 | Actix `Transform` that returns 403 on Deny |
| `secure_errors::actix` (NEW module) | Actix-web 4 `ErrorMappingLayer` — maps `AppError` → `HttpResponse` via existing `into_response_parts` | M2 | Actix `ResponseError` impl for `AppError` behind `actix-web` feature |
| `secure_boundary::safe_types::SafeUrl` extensions | Rejects `fe80::/10`, `224.0.0.0/4`, `ff00::/8`, `::/128` in addition to existing set | M3 | `TryFrom<&str>` unchanged; internal `is_private_ipv4`/`is_private_ipv6` extended |
| `secure_identity::assert_no_dev_identity_in_production` (NEW) | Boot-time panic helper for production-mode misconfiguration (A4) | M4 | `fn assert_no_dev_identity_in_production(app_env: &str, validator: &TokenValidator) -> Result<(), ProductionModeViolation>` |
| `secure_authz::testing::assert_every_route_has_policy` (NEW) | Test helper that asserts every registered route has a policy mapping (A5) | M4 | `fn assert_every_route_has_policy(routes: &[RouteDescriptor], fixtures: &[PolicyFixture]) -> Result<(), Vec<UnmappedRoute>>` |
| CI feature-matrix gate (NEW) | GitHub Actions job that builds and tests every crate with each feature combination; prevents backsliding per Google's presubmit pattern | M4 | `.github/workflows/ci.yml` new job |
| `deny.toml` publishing | Cleanly separable supply-chain policy doc (C3) | M4 | `deny.toml` at repo root; linked in README |
| License reconciliation | Verify Cargo.toml `license = "MIT"` matches README statement (C1) | M4 | `README.md` License section |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Milestone |
|---|---|---|---|---|
| HTTP request (axum service) | Sunlit reference service | `SecureJson<T>::from_request` (axum) | `axum::extract::FromRequest` (unchanged) | existing |
| HTTP request (Actix service) | Sunlit Guardian platform-api | `SecureJson<T>::from_request` (actix-web) | `actix_web::FromRequest` | M1 |
| Response (axum) | Handler | `SecurityHeadersService` (axum) | tower `Service` chain (unchanged) | existing |
| Response (Actix) | Handler | `SecurityHeadersTransform` (actix-web) | Actix `Transform`/`Service` chain | M1 |
| Authz decision (axum) | Upstream auth layer sets `AuthenticatedIdentity` ext → `AuthzLayer` | 403 or inner service | tower Layer (unchanged) | existing |
| Authz decision (Actix) | Upstream auth middleware sets `AuthenticatedIdentity` ext → Actix `AuthzTransform` | 403 or inner | Actix `Transform` | M2 |
| Error mapping (Actix) | Handler returns `Result<_, AppError>` | `HttpResponse` with JSON `PublicError` body | `impl ResponseError for AppError` behind `actix-web` feature | M2 |
| SSRF guard (all callers) | User input string | `SafeUrl::try_from` | `TryFrom<&str>` — now rejects 4 additional CIDR families | M3 |
| Production-boot check | Service `main()` | `assert_no_dev_identity_in_production` | Rust panic if misconfigured | M4 |
| CI presubmit | Git push | Feature-matrix job | GitHub Actions | M4 |

---

## High-Level Design for Formal Verification (TLA+ Section)

**When to fill this section**: Skip if the system does not involve concurrent actors, distributed state, ordering guarantees, resource ownership, or failure recovery.

**Decision**: **N/A**. This runbook is purely additive library work: HTTP framework adapters that re-wrap existing synchronous control flow, a set-membership extension to `SafeUrl`'s CIDR guard, and two non-concurrent helper functions. There are no new state machines, no ordering guarantees beyond what tower/Actix already provide, no distributed state, and no failure recovery logic. The `/slo-architect` upstream deliberately leaves `tla_required = false` for pure-library changes of this shape, and `/slo-tla`'s skill description explicitly says "Skip for simple CRUD systems with no real concurrency risk" — adapter code has even less concurrency surface than CRUD.

If a reviewer disagrees, the natural TLA+ target would be the existing tower/Actix middleware composition semantics — which is upstream framework behavior, not this runbook's scope.

---

## Global Execution Rules

These rules apply to every milestone without exception.

### 1) Stay inside scope

- Only change files listed in the current milestone unless a listed step explicitly requires one additional file.
- Do not refactor unrelated code.
- Do not rename public APIs, commands, routes, events, persisted state shapes, or config keys unless the milestone explicitly says so.
- Do not introduce a new dependency unless the milestone explicitly allows it.
- Do not change database schema, file formats, or migration behavior unless the milestone explicitly includes migration work and migration tests.
- **Sunlit Guardian-specific**: do not introduce any code that imports or depends on Sunlit Guardian's repo. Adapters must be generic across all Actix consumers, not SG-specific.

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

Every milestone must explicitly verify that previously working user flows, commands, routes, persisted state, and public interfaces still work unless the milestone explicitly replaces them. The axum adapters are the incumbent and must remain behavior-identical after each milestone.

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
- Every test that creates files on disk must clean up after itself (use `tempdir`, `tempfile`, or equivalent). Tests must not leave residual data in the working tree.
- Record the `.gitignore` review in the Evidence Log.

### 8) Feature-flag discipline (runbook-specific)

- Existing axum adapters become gated behind a new `axum` feature, which is `default = ["axum"]`.
- New Actix adapters are gated behind an additive `actix-web` feature.
- Both features must compose: `--features "axum actix-web"` must build and pass tests.
- `--no-default-features` must also build (the crate with neither HTTP framework is a legitimate use case for pure validation logic).
- No public item may appear only when both features are enabled; every new public item is gated on exactly one feature or on neither.

### 9) Documentation-as-contract (runbook-specific)

The audience for this library is other engineers and security agents. Docs are a deliverable, not a side-effect.

- Every new public item has a rustdoc comment that answers three questions: *what does this do*, *what problem does it solve*, *when should I use it (vs. alternatives)*.
- Every new public function, type, trait, or module gets a `/// # Examples` block containing a runnable code snippet. The snippet compiles as a doctest (not `ignore` and not `no_run` unless the type really can't execute in a doctest harness — and in that case, a backing integration test covers the same code).
- Each milestone produces or extends an "Integration Guide" at `docs/dev-guide/<topic>.md` aimed at a downstream engineer who has never seen this library. The guide includes: "what you get", "how to add the dependency", "minimal working example (copy-paste)", "how to extend / customise", "common pitfalls", "how this composes with other crates in the workspace".
- `cargo doc --workspace --no-deps` builds with **zero warnings** at every milestone exit. `--deny=warnings` is not applied globally but the milestone DoD treats rustdoc warnings as failures.
- Broken intra-doc links are failures. `cargo doc --workspace --no-deps 2>&1 | grep -E 'warning|error'` must produce no output for new or modified items.
- Any code block in `docs/dev-guide/*.md` or `README.md` that is meant to compile is backed by either a `/// ```` doctest on the API being shown, an entry in `crates/<crate>/examples/`, or a BDD test that constructs the same code. Drift between docs and code breaks the milestone.
- README's Feature Flags table and the per-crate `lib.rs` "Feature Overview" section are the single source of truth for what features exist, what they gate, and what composes with what.

---

## Global Entry Rules (Pre-Milestone Protocol)

Do this before every milestone.

1. Read the lessons file from the previous milestone, if one exists. Apply any design corrections, naming rules, test strategy improvements, and failure-mode coverage it calls for before writing new code.
2. Read the current milestone fully: goal, context, contract block, out-of-scope block, file list, BDD scenarios, regression tests, E2E tests, smoke tests, and definition of done.
3. Run the full existing test suite and confirm it passes. Record the baseline in the Evidence Log.
   ```
   cargo test --workspace
   cargo clippy --workspace --all-features -- -D warnings
   cargo fmt --all --check
   ```
   If any tests fail before you start, stop and fix the baseline first. Do not begin a milestone on a red baseline.
4. Read the files listed in "Files Allowed to Change" and "Files To Read Before Changing Anything". Understand their current shape before editing.
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
   cargo test -p secure_smoke_service -- --include-ignored
   ```
3. Verify the workspace builds cleanly under every advertised feature combination.
   ```
   cargo build --workspace --release
   cargo check --workspace --all-features
   cargo check --workspace --no-default-features
   ```
4. Run the smoke tests listed in the milestone. Check off each item in the runbook.
5. Verify backward compatibility for all items listed in the milestone Compatibility Checklist.
6. Run supply-chain gates (no regressions in audit/deny/vet):
   ```
   cargo audit
   cargo deny check
   cargo vet
   ```
7. Complete the Self-Review Gate.
8. **Clean up test artifacts**: Verify no test output files, temporary fixtures, or generated data remain in the working tree. Run `git status` and confirm no untracked test artifacts exist.
9. **Review .gitignore**: Ensure any new build outputs, generated files, or tool caches introduced in this milestone have matching `.gitignore` patterns. Remove stale patterns that no longer apply.
10. Update ARCHITECTURE.md following the Documentation Update Table.
11. Update README.md if user-facing capabilities changed.
12. Write a lessons-learned file at `docs/slo/lessons/sg-gate-a-m<N>.md`.
13. Write a completion summary at `docs/slo/completion/sg-gate-a-m<N>.md`.
14. Update the Milestone Tracker in this file: set status to `done`, record Completed date, and fill in the lessons and completion summary paths.
15. Re-read the next milestone with fresh eyes and record any assumption changes in the lessons file.

---

## Background Context

### Current State

- `SunLitSecurityLibraries` is a 13-crate Rust workspace (8 security crates + 2 services + `security_core` + `security_events` + `secure_privacy`). Milestones M0–M21 (and mobile-security additions) are complete per ARCHITECTURE.md.
- Every HTTP adapter today targets axum/tower. `secure_boundary::extract::SecureJson` at [crates/secure_boundary/src/extract.rs](../../../crates/secure_boundary/src/extract.rs) implements `axum::extract::FromRequest`. `SecurityHeadersLayer` at [crates/secure_boundary/src/headers.rs](../../../crates/secure_boundary/src/headers.rs) and `FetchMetadataLayer` at [crates/secure_boundary/src/fetch_metadata.rs](../../../crates/secure_boundary/src/fetch_metadata.rs) are tower `Layer`s built against `axum::body::Body`.
- `secure_authz::AuthzLayer` at [crates/secure_authz/src/middleware.rs](../../../crates/secure_authz/src/middleware.rs) is a tower `Layer` that pulls `AuthenticatedIdentity` out of axum request extensions and short-circuits with 403 on Deny.
- `secure_errors::ErrorMappingLayer` at [crates/secure_errors/src/middleware.rs](../../../crates/secure_errors/src/middleware.rs) is a pass-through tower `Layer` whose real work happens in `impl IntoResponse for AppError`; it depends on `axum_core::response::Response`.
- `secure_boundary::safe_types::SafeUrl` at [crates/secure_boundary/src/safe_types.rs:263-377](../../../crates/secure_boundary/src/safe_types.rs#L263) enforces SSRF blocking for a subset of the CIDRs Sunlit Guardian requires. Verified on 2026-04-24: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `127.0.0.0/8`, `0.0.0.0/32`, `::1/128`, `fc00::/7` are covered. Four are missing: `fe80::/10`, `224.0.0.0/4`, `ff00::/8`, `::/128`.
- Every crate `Cargo.toml` declares `license = "MIT"`. No `Apache-2.0` dual-license is currently present. The v4 feedback doc's claim of `MIT OR Apache-2.0` was based on a stale snapshot; M4 verifies and reconciles.

### Problem

1. **Sunlit Guardian cannot consume the library on Actix-web 4** — every public adapter is axum-shaped, and the SG v4 runbook's "no rewrites" principle forbids a framework migration. Five types (`SecureJson`, `SecurityHeadersLayer`, `FetchMetadataLayer`, `AuthzLayer`, `ErrorMappingLayer`) must exist in Actix-web 4 form, with Cargo feature flags so both frameworks can live in the same crate.
2. **`SafeUrl` does not reject four CIDRs on SG's blocked-CIDR list** — `fe80::/10` (IPv6 link-local, IPv6 analogue of the AWS IMDS attack vector), `224.0.0.0/4` (IPv4 multicast, lateral-movement response surface), `ff00::/8` (IPv6 multicast), and `::/128` (IPv6 unspecified). A bare `TryFrom<&str>` today will silently accept URLs pointing at these ranges.
3. **No boot-time check catches dev-mode identity sources shipping to production** — every downstream service has to reinvent `if env == "production" && validator_has_dev_source { panic }`. Sunlit Guardian will write it locally if upstream declines; putting it upstream is one audit, one test, one upgrade path (per SG's v4 feedback doc, section A4).
4. **No test helper asserts route-policy coverage** — `secure_authz` has no ergonomic way to say "boot the app, enumerate every registered route, confirm each one resolves to a non-empty policy against a fixture subject/resource/action set, fail the test if any route returns 403-from-missing-policy." Sunlit Guardian will write it locally if upstream declines (feedback doc, A5).
5. **License posture inconsistency risk** — the feedback doc reports a README/Cargo.toml divergence. The snapshot may be stale; M4 verifies and normalises. No visible Apache-2.0 dual-license currently, so if the intent is `MIT OR Apache-2.0` the manifests need updating; if the intent is MIT only, the README's License section needs to say so plainly.
6. **No CI gate on the new feature matrix** — Google's "preventing backsliding" pattern (from Sharma's bug-class remediation talk) demands that presubmit blocks any config that regresses a fix class. Once Actix adapters exist, CI must build + test every (crate × feature-set) combination on every PR.

### Target Architecture

See the architecture diagram above. In short:

- Three HTTP-adapter crates (`secure_boundary`, `secure_authz`, `secure_errors`) gain an `actix-web` feature alongside today's `axum` feature. Both compose.
- Each crate grows a new `actix/` module, gated on the `actix-web` feature. Items inside reuse all non-HTTP logic (validation, authz decisions, error mapping) from the existing code paths.
- `SafeUrl` grows four new rejection branches plus rustdoc listing the full blocked set.
- `secure_identity` grows one new public function: `assert_no_dev_identity_in_production`.
- `secure_authz::testing` grows one new public function: `assert_every_route_has_policy`.
- CI gains one new matrix job covering (crate × feature-set × stable toolchain).

### Key Design Principles

These are system-wide rules the AI agent must follow when making implementation decisions.

1. **Framework parity, not framework translation**: Every Actix adapter must be behaviorally equivalent to its axum counterpart on the same input. If the axum adapter returns 415 for an unknown `Content-Type`, the Actix adapter does too. If the axum `SecurityHeadersLayer` emits `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, the Actix one emits the same bytes. Tests compare header bytes, status codes, and body JSON for identity.
2. **Secure-by-default carries across frameworks** (Google pattern): an Actix service that imports `secure_boundary` without naming any knobs must get the same secure defaults an axum service would. No knob that weakens security can be easier to toggle on Actix than on axum.
3. **Variant analysis, one test per CIDR** (Google pattern): the CIDR coverage extension (M3) writes one `#[test]` per blocked CIDR. Regressions cannot silently remove a single range — any removal fails a named test.
4. **Additive, never substitutive**: no public item is renamed, moved, or removed in this runbook. Every new item is additive. Sunlit Guardian pins a commit SHA; breakage at HEAD breaks their migration. All changes are additive until Gate A is satisfied.
5. **Feature flags as escape hatch, not as configuration surface**: the `actix-web` feature exists so Actix consumers don't have to compile axum. It is not a runtime switch, not a policy knob, and not a way to weaken security in one framework vs the other.
6. **Shared core, thin adapters**: every Actix adapter is a thin wrapper over pre-existing (framework-neutral) logic. If a milestone's adapter grows non-trivial logic unique to Actix, that's a code smell — the core needs to be lifted into a framework-neutral module first, then wrapped twice.
7. **Presubmit gates beat post-hoc policy** (Google pattern): the M4 CI gate runs every (crate × feature-set) combination on every PR. A new feature flag that isn't gated in CI is not done.
8. **Documentation is product, not epilogue** (user directive, 2026-04-24): the customers of this library are other engineers and security agents. Every new public item must ship with (a) a rustdoc paragraph explaining what it is and what problem it solves, (b) a runnable `/// # Examples` block that compiles as a doctest, (c) an entry in the matching crate-level "Feature Overview" section of `lib.rs` docs, and (d) an "Integration Guide" dev doc at `docs/dev-guide/<topic>.md` that walks a downstream engineer from zero to working code. A feature that compiles and tests green but has no runnable example and no integration guide is **not done**. `cargo doc --no-deps --workspace` must build with zero warnings at every milestone exit.
9. **Every example must execute** (user directive, 2026-04-24): no hand-written code snippets in markdown that are never compiled. Integration-guide code blocks are backed by a matching file in `examples/` or by a `#[test]` that executes the exact snippet. If the markdown shows `let app = App::new()...`, a test somewhere builds that `App` and exercises it. Docs that drift are worse than missing docs, so structural coupling is required.

### What to Keep

- All public items re-exported from `crates/*/src/lib.rs` today. Every `pub use` stays. Every trait impl on axum types stays.
- The three-layer error model in `secure_errors` (internal → mapped → public). The existing `http::into_response_parts` and `http::retry_after_seconds` are the single source of truth; Actix adapters reuse them.
- The `secure_authz` identity-agnostic invariant: `secure_authz` depends only on `security_core::IdentitySource`, never on `secure_identity`. The Actix adapter preserves this invariant.
- `SafeUrl`'s existing rejection set. M3 extends, never shrinks.
- `secure_reference_service` and `secure_smoke_service` as axum-based integration targets. Those services continue to exist and to pass all existing tests at every milestone boundary.
- The OWASP-referenced default header values in `secure_boundary::headers::defaults` — byte-for-byte identical on Actix.

### What to Change

- **`crates/secure_boundary/Cargo.toml`** — add `axum` (default) and `actix-web` feature flags; move `axum = "0.8"` and `axum-core = "0.5"` under `axum` feature; add optional `actix-web = "4"` and `actix-http = "3"` under `actix-web` feature.
- **`crates/secure_boundary/src/lib.rs`** — re-export `actix` submodule behind `#[cfg(feature = "actix-web")]`; gate existing axum re-exports behind `#[cfg(feature = "axum")]`.
- **`crates/secure_boundary/src/extract.rs`** — gate existing impls on `axum` feature; factor the validation pipeline into a framework-neutral helper if duplication demands it.
- **`crates/secure_boundary/src/headers.rs`** — gate existing `Layer`/`Service` impls on `axum` feature.
- **`crates/secure_boundary/src/fetch_metadata.rs`** — gate existing impls on `axum` feature.
- **`crates/secure_boundary/src/actix/` (NEW)** — Actix `FromRequest` for `SecureJson<T>`, Actix `Transform` for `SecurityHeadersLayer`, Actix `Transform` for `FetchMetadataLayer`.
- **`crates/secure_authz/Cargo.toml` and `crates/secure_authz/src/middleware.rs`** — same axum-feature-gating + new `actix/` module (M2).
- **`crates/secure_errors/Cargo.toml` and `crates/secure_errors/src/middleware.rs`** — same axum-feature-gating + new `actix/` module + `impl ResponseError for AppError` behind `actix-web` (M2).
- **`crates/secure_boundary/src/safe_types.rs`** — extend `is_private_ipv4` and `is_private_ipv6`; add one `#[test]` per CIDR (M3). Update rustdoc.
- **`crates/secure_identity/src/lib.rs`** or `boot.rs` (NEW) — `assert_no_dev_identity_in_production` helper (M4).
- **`crates/secure_authz/src/testkit.rs`** — extend with `assert_every_route_has_policy` (M4).
- **`.github/workflows/ci.yml`** — feature-matrix job (M4).
- **`README.md`, `Cargo.toml` (workspace), `deny.toml`** — license reconciliation and deny.toml publication notes (M4).
- **`ARCHITECTURE.md`** — updated per the Documentation Update Table at the bottom of this runbook, at every milestone exit.

### Global Red Lines

These are forbidden unless explicitly overridden inside a milestone.

- No framework-rewrite of existing axum code paths (adapters are additive; axum is the default feature)
- No new direct dependency on Sunlit Guardian's repo, code, or types
- No dependency on `secure_identity` from `secure_authz` (identity-agnostic invariant preserved)
- No change to `SafeUrl`'s public surface beyond rustdoc and semantic set extension
- No change to three-layer error model in `secure_errors`
- No new runtime dependencies without explicit milestone approval; `actix-web = "4"` and `actix-http = "3"` are approved only behind the `actix-web` feature in M1/M2
- No unrelated refactors
- No schema migrations (library workspace — no schema)
- No config key renames
- No public API/event/route renames
- No production placeholders
- No silent error swallowing
- No secrets in source control
- No test output data committed to source control
- No `#[cfg(feature = "…")]` on items where the gate weakens security in one path vs another

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
- dependency failure / partial failure
- retry or rollback behavior if relevant
- concurrency or race behavior if relevant
- persistence / restore behavior if relevant
- backward compatibility behavior
- **cross-framework parity (runbook-specific)**: every BDD scenario in M1/M2 runs against both the axum and Actix adapters and asserts identical observable behavior.

If a category does not apply, state why.

### Scenario Structure

Every BDD scenario uses Given/When/Then:

```rust
#[test]
fn descriptive_test_name() {
    // Given: [precondition]
    // When: [action]
    // Then: [expected outcome]
}
```

### Test File Naming

| Layer | Convention | Location |
|---|---|---|
| Backend unit tests | `#[cfg(test)] mod tests` inside the source file | Same file as production code |
| Backend integration/BDD tests | `tests/sg_gate_a_<feature>.rs` | `crates/<crate>/tests/` |
| Cross-framework parity tests | `tests/sg_gate_a_parity_<feature>.rs` | `crates/<crate>/tests/` |
| E2E runtime validation | `tests/e2e_sg_gate_a_m<N>.rs` | `crates/secure_smoke_service/tests/` |

### Test Artifact Cleanup Rules

Every test that creates files, directories, or temporary data on disk must follow these rules:

1. **Use temporary directories**: Prefer `tempfile::TempDir` or `tempfile::NamedTempFile`. Never write test output into the source tree.
2. **Clean up on completion and failure**: Use RAII (`Drop`) to ensure cleanup runs even when tests fail.
3. **No residual state**: After the full test suite runs, `git status` must show no untracked files from test execution.
4. **CI parity**: Test cleanup behavior must be identical locally and in CI. Do not rely on CI ephemeral filesystems as an excuse to skip cleanup.

### End-to-End Runtime Validation

Every milestone must include E2E tests that go beyond compilation and verify that the system works correctly at runtime. For M1 and M2 the E2E target is a small Actix service in `secure_smoke_service/tests/` that boots, handles a request through the adapter chain, and asserts a specific response.

### E2E Test Design Rules

1. Test runtime behavior, not just types.
2. Cross the HTTP boundary: send a real request via `actix_web::test::call_service` or axum `TestClient`, receive a real response.
3. Test degraded and failure states (invalid JSON, missing identity, SSRF attempt), not just happy path.
4. Assert against observable behavior: status codes, header bytes, body JSON.
5. Every M1/M2 E2E test has an axum twin and an Actix twin with the same assertion and the same inputs.

---

## Dependency, Migration, and Refactor Policy

### Dependency policy

A new dependency is allowed only if the milestone explicitly includes:

- package/crate name
- why existing dependencies are insufficient
- security and maintenance rationale
- build/runtime cost rationale
- tests covering the new integration

Approved new dependencies for this runbook:
- `actix-web = "4"` — M1/M2, behind `actix-web` feature only. Rationale: core Actix framework; Sunlit Guardian is on Actix 4; no third-party shim exists.
- `actix-http = "3"` — M1/M2, behind `actix-web` feature only. Rationale: header types and body shaping; transitively required by `actix-web` but explicitly listed to avoid surprise on `cargo deny`.

### Migration policy

Any schema, config, or persisted-state change requires:

- migration plan
- backward compatibility strategy
- migration tests
- rollback strategy if relevant
- documentation updates

This runbook does not introduce migrations (library-only workspace).

### Refactor budget

Each milestone states one of the following:

- `No refactor permitted beyond direct implementation`
- `Minimal local refactor permitted in listed files only`
- `Targeted refactor permitted for [specific reason]`

Targeted refactors in M1/M2 are permitted **only** to lift framework-neutral logic out of axum-coupled files into helper modules so both the axum and Actix adapters can share it. Any such lift must be byte-for-byte behavior-preserving (verified by the existing axum tests continuing to pass).

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
| Feature matrix | `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | green | | | |
| E2E runtime | `cargo test -p secure_smoke_service -- --include-ignored` | green | | | |
| Build/boot | `cargo build --workspace --release` | green | | | |
| Clippy | `cargo clippy --workspace --all-features -- -D warnings` | no warnings | | | |
| Fmt | `cargo fmt --all --check` | clean | | | |
| Supply chain | `cargo audit && cargo deny check && cargo vet` | all pass | | | |
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
- For M1/M2: did I add a cross-framework parity test that asserts identical observable behavior between axum and Actix adapters on the same input?
- Did I remove temporary debug code, mocks, placeholders, and commented-out dead code?
- Did I update documentation to match the implementation?
- Is every assumption either verified or explicitly documented as unresolved?
- Do all tests clean up their output artifacts? Does `git status` show a clean working tree?
- Is `.gitignore` up to date with any new generated files or build outputs?
- Does the feature matrix (`--all-features`, `--no-default-features`, each framework alone, both together) build and test green?
- Is the milestone truly done according to its Definition of Done?

If any answer is "no", the milestone is not complete.

---

## Lessons-Learned File Template

Path: `docs/slo/lessons/sg-gate-a-m<N>.md`

```md
# Lessons Learned — sg-gate-a Milestone <N>

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

Path: `docs/slo/completion/sg-gate-a-m<N>.md`

```md
# Completion Summary — sg-gate-a Milestone <N>

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

## Milestone Plan

### Milestone 1 — `secure_boundary` Actix-web 4 adapters (`SecureJson<T>` + `SecurityHeadersLayer` + `FetchMetadataLayer`)

**Goal**: Introduce Actix-web 4 adapters for the three framework-coupled types that live in `secure_boundary`, behind a new `actix-web` Cargo feature that composes with the existing (now-explicit) `axum` feature. By end of M1, a downstream Actix-web 4 consumer can `cargo add secure_boundary --features actix-web` and get framework-native `SecureJson<T>` extraction, secure default headers middleware, and Fetch Metadata cross-site protection — with behavior byte-for-byte equivalent to the axum path on the same input.

**Context**: `SecureJson<T>` today is an `axum::extract::FromRequest` implementation in [crates/secure_boundary/src/extract.rs:65](../../../crates/secure_boundary/src/extract.rs#L65). `SecurityHeadersLayer` is a tower `Layer<S>` with `S: Service<Request<axum::body::Body>, Response = Response<axum::body::Body>>` in [crates/secure_boundary/src/headers.rs:219](../../../crates/secure_boundary/src/headers.rs#L219). `FetchMetadataLayer` is analogous in [crates/secure_boundary/src/fetch_metadata.rs:61](../../../crates/secure_boundary/src/fetch_metadata.rs#L61). Sunlit Guardian's services are Actix-web 4 and cannot consume these as-is. The four-stage validation pipeline inside `SecureJson` (transport → syntactic → semantic → authz-adjacent), the OWASP-default header values in `headers::defaults`, and the Fetch-Metadata allow/block semantics are all framework-neutral and must be the single source of truth for both adapters.

**Important design rule**: **Shared core, thin adapters.** The Actix adapters must not duplicate the four-stage validation logic, the header value table, or the Fetch-Metadata allow/block decision. If duplication is the only obvious path, the milestone's first task is to lift the shared logic into a framework-neutral helper module (`extract::core`, `headers::apply`, `fetch_metadata::classify`) and then wrap it twice. The axum tests must remain byte-identical in output to prove the lift was behavior-preserving.

**Refactor budget**: `Targeted refactor permitted for factoring framework-neutral logic out of axum-coupled files so axum and actix-web adapters share it.` Any such lift is behavior-preserving and verified by existing axum tests. No other refactor permitted.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | An HTTP request body (bytes + `Content-Type`), an HTTP response (via either axum's `Response<Body>` or Actix's `HttpResponse`), request headers including `Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest`. |
| Outputs | For `SecureJson`: `Result<SecureJson<T>, BoundaryRejection>` in axum, `Result<SecureJson<T>, actix_web::Error>` in Actix (with identical rejection reasons mapped to identical HTTP status codes). For `SecurityHeadersLayer`: an outgoing response with all OWASP headers set byte-for-byte identically across frameworks. For `FetchMetadataLayer`: pass-through on allowed requests, 403 on blocked. |
| Interfaces touched | `secure_boundary::{SecureJson, SecurityHeadersLayer, FetchMetadataLayer, BoundaryRejection}` — all stable under the `axum` feature. New public module `secure_boundary::actix` gated on `actix-web` feature. |
| Files allowed to change | `crates/secure_boundary/Cargo.toml`, `crates/secure_boundary/src/lib.rs`, `crates/secure_boundary/src/extract.rs`, `crates/secure_boundary/src/headers.rs`, `crates/secure_boundary/src/fetch_metadata.rs`, `crates/secure_boundary/src/actix/mod.rs` (NEW), `crates/secure_boundary/src/actix/extract.rs` (NEW), `crates/secure_boundary/src/actix/headers.rs` (NEW), `crates/secure_boundary/src/actix/fetch_metadata.rs` (NEW), `crates/secure_boundary/tests/sg_gate_a_actix_extract.rs` (NEW), `crates/secure_boundary/tests/sg_gate_a_actix_headers.rs` (NEW), `crates/secure_boundary/tests/sg_gate_a_actix_fetch_metadata.rs` (NEW), `crates/secure_boundary/tests/sg_gate_a_parity_boundary.rs` (NEW), `crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs` (NEW), `.gitignore` (as needed). |
| Files to read before changing anything | `crates/secure_boundary/src/lib.rs`, `crates/secure_boundary/src/extract.rs`, `crates/secure_boundary/src/headers.rs`, `crates/secure_boundary/src/fetch_metadata.rs`, `crates/secure_boundary/src/error.rs`, `crates/secure_boundary/src/validate.rs`, `crates/secure_boundary/src/limits.rs`, `crates/secure_boundary/src/attack_signal.rs`. |
| New files allowed | `crates/secure_boundary/src/actix/mod.rs`, `crates/secure_boundary/src/actix/extract.rs`, `crates/secure_boundary/src/actix/headers.rs`, `crates/secure_boundary/src/actix/fetch_metadata.rs`, the four test files listed above, the smoke-service E2E file. |
| New dependencies allowed | `actix-web = "4"` and `actix-http = "3"` in `[dependencies]` marked `optional = true`; gated by the `actix-web` feature. `actix-web = "4"` in `[dev-dependencies]` with `rt` feature for the test harness. No other new deps. |
| Migration allowed | `no` |
| Compatibility commitments | All existing axum tests in `secure_boundary` pass unchanged. `secure_reference_service` and `secure_smoke_service` continue to compile + test green against their axum-based integration points. The `axum` feature is the default; existing consumers that do `secure_boundary = "0.1"` without specifying features see no behavior change. Every existing `pub use` in `secure_boundary::lib` remains available (re-exported under `#[cfg(feature = "axum")]` when framework-coupled, unconditional otherwise). |
| Forbidden shortcuts | Duplicating the four-stage pipeline into Actix code; letting axum and Actix adapters diverge in header bytes, status codes, or rejection semantics; adding `actix-web` to default features; using `unwrap()` on user-controlled input paths; silent fallback from Actix to axum or vice versa; introducing a new rejection variant that only one framework can emit. |

#### Out of Scope / Must Not Do

- Do not touch `SecureQuery` or `SecurePath` — Gate A asks only for `SecureJson`. Query/Path Actix adapters are a follow-up runbook.
- Do not touch `crates/secure_authz/` or `crates/secure_errors/` — those are M2.
- Do not extend `SafeUrl`'s blocked CIDR set — that is M3.
- Do not change any default behavior of the existing axum adapters. Byte-for-byte parity is a test assertion.
- Do not introduce runtime reflection, dynamic dispatch, or a "generic HTTP adapter" abstraction layer. Two thin wrappers over a shared core.
- Do not add `actix-web` to `default` features; do not add any new default feature.
- Do not modify `secure_reference_service` or `secure_smoke_service`'s existing test files except to add the new M1 E2E file.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. There is no prior milestone lessons file; skip lesson application.
3. Read the allowed files before editing.
4. Copy the Evidence Log template into this milestone section or working notes.
5. Re-state the milestone constraints before coding: "add Actix-web 4 adapters for three types, behind a new feature flag, with byte-for-byte parity and a shared core — nothing else."

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/Cargo.toml` | Add `[features]` block: `default = ["axum"]`, `axum = ["dep:axum", "dep:axum-core", "dep:tower", "dep:tower-http"]`, `actix-web = ["dep:actix-web", "dep:actix-http"]`; move `axum`, `axum-core`, `tower`, `tower-http` under `optional = true`; add `actix-web = { version = "4", optional = true }` and `actix-http = { version = "3", optional = true }`. Add Actix to `dev-dependencies` with `rt` feature for tests. |
| `crates/secure_boundary/src/lib.rs` | Gate `pub mod extract;`, `pub mod headers;`, `pub mod fetch_metadata;` and their `pub use` re-exports on `#[cfg(feature = "axum")]`. Add `#[cfg(feature = "actix-web")] pub mod actix;`. Leave framework-neutral modules (`safe_types`, `validate`, `limits`, etc.) unconditional. |
| `crates/secure_boundary/src/extract.rs` | Add `#![cfg(feature = "axum")]` guard at file top OR `#[cfg(feature = "axum")]` on the axum impls. Factor the four-stage pipeline (Content-Type check → body-bytes collect → `check_json_limits` → serde parse → `SecureValidate`) into a framework-neutral `pub(crate) mod core` or `pub(crate) fn validate_json_bytes` helper that both frameworks call. Axum impl becomes a thin wrapper that collects bytes and delegates. |
| `crates/secure_boundary/src/headers.rs` | Gate existing `Layer<S>`/`Service<Request<Body>>` impls on `#[cfg(feature = "axum")]`. Factor the header-value computation (`csp_value`, per-header defaults) into framework-neutral helpers (`pub(crate) fn apply_defaults(headers: &mut HeaderMap, layer: &SecurityHeadersLayer, nonce: Option<&CspNonce>)`) that both frameworks call. |
| `crates/secure_boundary/src/fetch_metadata.rs` | Gate existing `Layer`/`Service` impls on `#[cfg(feature = "axum")]`. Factor the allow/block classification (`classify(method: &Method, site: Option<&HeaderValue>, mode: Option<&HeaderValue>, dest: Option<&HeaderValue>, allow_missing: bool) -> Decision`) into a framework-neutral helper. |
| `crates/secure_boundary/src/actix/mod.rs` | NEW: `pub mod extract; pub mod headers; pub mod fetch_metadata;` plus crate-level docs linking to the actix-web-4 integration path. |
| `crates/secure_boundary/src/actix/extract.rs` | NEW: `impl FromRequest for SecureJson<T>` targeting Actix's `FromRequest` trait; same rejection semantics. Reuses `crate::extract::core::validate_json_bytes`. Maps `BoundaryRejection` → `actix_web::Error` with identical HTTP status codes. |
| `crates/secure_boundary/src/actix/headers.rs` | NEW: `pub struct SecurityHeadersTransform` implementing `actix_web::dev::Transform` for the same `SecurityHeadersLayer` configuration. Calls `crate::headers::apply_defaults` on the outgoing response. `CspNonce` is inserted into request extensions identically. |
| `crates/secure_boundary/src/actix/fetch_metadata.rs` | NEW: `pub struct FetchMetadataTransform` implementing `actix_web::dev::Transform`. Calls `crate::fetch_metadata::classify` and short-circuits with 403 on block. |
| `crates/secure_boundary/tests/sg_gate_a_actix_extract.rs` | NEW: integration tests for Actix `SecureJson<T>` — happy path, bad Content-Type, malformed JSON, oversized body, nesting too deep, too many fields, `SecureValidate` reject. |
| `crates/secure_boundary/tests/sg_gate_a_actix_headers.rs` | NEW: integration tests asserting every OWASP default header is set byte-identically to the axum path. |
| `crates/secure_boundary/tests/sg_gate_a_actix_fetch_metadata.rs` | NEW: integration tests for allow on `same-origin`, allow on missing headers (default), allow on top-level nav, block on cross-site fetch. |
| `crates/secure_boundary/tests/sg_gate_a_parity_boundary.rs` | NEW: cross-framework parity harness. For each scenario, run through axum `TestClient` and Actix `test::call_service` and assert identical status code, header bytes, and body JSON. |
| `crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs` | NEW: boot a tiny Actix service that uses all three adapters, hit it over a real TCP loopback, assert end-to-end behavior. |
| `crates/secure_boundary/examples/actix_minimal.rs` | NEW: complete, runnable, copy-paste-ready minimal Actix-web 4 service demonstrating all three adapters (SecureJson, SecurityHeaders, FetchMetadata) composed in one `App`. Must compile with `cargo build --example actix_minimal -p secure_boundary --features actix-web`. |
| `docs/dev-guide/secure_boundary-actix.md` | NEW: integration guide targeted at downstream Actix engineers. Sections: "What you get", "Adding the dependency", "Minimal working example" (copy-paste, must match `examples/actix_minimal.rs` byte-for-byte or reference it directly), "How each adapter composes", "Per-route RequestLimits override", "CSP nonce usage", "Common pitfalls", "Comparison with axum adapters for services that mix frameworks". Every code block that is meant to compile is exercised by a `#[test]` or an example. |
| `.gitignore` | Add any new build outputs as needed (probably none — Cargo already handles `target/`). |

#### Step-by-Step

1. Write BDD test stubs in all four test files listed above. Each starts as `#[test] fn name() { todo!() }` or with compile errors against not-yet-existing Actix adapters.
2. Write E2E runtime validation stub in `e2e_sg_gate_a_m1.rs`.
3. Update `crates/secure_boundary/Cargo.toml` with the feature flag block and optional deps.
4. Factor the three framework-neutral helpers (`extract::core::validate_json_bytes`, `headers::apply_defaults`, `fetch_metadata::classify`) while keeping existing axum tests green. Confirm parity with `cargo test -p secure_boundary --features axum`.
5. Gate the existing axum impls in `extract.rs`, `headers.rs`, `fetch_metadata.rs` on `#[cfg(feature = "axum")]`. Confirm `cargo test -p secure_boundary --features axum` still green.
6. Implement `crates/secure_boundary/src/actix/extract.rs`.
7. Implement `crates/secure_boundary/src/actix/headers.rs`.
8. Implement `crates/secure_boundary/src/actix/fetch_metadata.rs`.
9. Make all BDD tests pass: `cargo test -p secure_boundary --features actix-web`.
10. Run the full matrix: `cargo test -p secure_boundary --features axum`, `cargo test -p secure_boundary --features actix-web`, `cargo test -p secure_boundary --features "axum actix-web"`, `cargo check -p secure_boundary --no-default-features`.
11. Run cross-framework parity tests and E2E runtime validation.
12. **Verify test artifact cleanup**: `git status` clean.
13. **Update .gitignore** if any new generated files appear.
14. Run smoke tests.
15. Complete the Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: `SecureJson<T>` as an Actix-web 4 `FromRequest` extractor**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| actix_secure_json_happy_path | happy path | A valid JSON body with `Content-Type: application/json` and fields that pass `SecureValidate` | Handler extracts `SecureJson<T>` | Status 200, handler sees fully validated `T` via `.into_inner()` |
| actix_secure_json_rejects_wrong_content_type | invalid input | A valid JSON body with `Content-Type: application/xml` | Handler tries to extract `SecureJson<T>` | Status 415, rejection code `invalid_content_type`, a `BoundaryViolation::InvalidContentType` is emitted once |
| actix_secure_json_rejects_malformed_json | invalid input | A body that is not valid JSON with `Content-Type: application/json` | Handler tries to extract | Status 400, rejection code `malformed_json`, body is JSON with `PublicError` shape |
| actix_secure_json_rejects_oversize_body | invalid input | A JSON body exceeding `RequestLimits.max_body_bytes` | Handler tries to extract | Status 413, rejection code `body_too_large` |
| actix_secure_json_rejects_nested_json | invalid input | A JSON body whose nesting depth exceeds `max_nesting_depth` | Handler tries to extract | Status 400, rejection code `nesting_too_deep`, no serde parse attempted |
| actix_secure_json_rejects_many_fields | invalid input | A JSON body with more `:` separators than `max_field_count` | Handler tries to extract | Status 400, rejection code `too_many_fields` |
| actix_secure_json_rejects_semantic_failure | invalid input | A JSON body that parses but fails `SecureValidate::validate_semantics` | Handler tries to extract | Status 400, rejection code matches the `&'static str` the validator returned |
| actix_secure_json_respects_per_route_limits | happy path | `RequestLimits` inserted into Actix extensions by a prior middleware | Handler extracts | Per-route override applies; default is overridden |

**Feature: `SecurityHeadersTransform` as Actix-web 4 middleware**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| actix_security_headers_sets_all_defaults | happy path | A response from a handler wrapped with `SecurityHeadersTransform::default()` | Client receives response | All 11 default headers present with byte-identical values to `secure_boundary::headers::defaults` |
| actix_security_headers_overrides_csp | happy path | `SecurityHeadersTransform` with `.with_csp("default-src 'self'")` | Client receives response | `Content-Security-Policy` header equals `default-src 'self'` |
| actix_security_headers_csp_nonce | happy path | `.with_csp_nonce()` enabled | Client receives response; handler reads `CspNonce` from request extensions | `Content-Security-Policy` includes `'nonce-<nonce>'`; handler-seen nonce matches response header |
| actix_security_headers_no_leak_on_error | partial failure | Inner handler panics | Middleware response | All security headers still set (no degradation of defense-in-depth); 500 returned |

**Feature: `FetchMetadataTransform` as Actix-web 4 middleware**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| actix_fetch_metadata_allows_same_origin | happy path | Request with `Sec-Fetch-Site: same-origin` | Middleware forwards | Inner handler is called; status 200 |
| actix_fetch_metadata_allows_none | happy path | Request with `Sec-Fetch-Site: none` | Middleware forwards | Inner handler called |
| actix_fetch_metadata_allows_missing_headers_by_default | backward compat | Request without any `Sec-Fetch-*` headers | Middleware forwards | Inner handler called (older browsers work) |
| actix_fetch_metadata_blocks_cross_site | invalid input | Request with `Sec-Fetch-Site: cross-site` and `Sec-Fetch-Mode: cors` (non-navigation) | Middleware blocks | Status 403; inner handler not called; `BoundaryViolation` emitted |
| actix_fetch_metadata_allows_cross_site_top_nav | happy path | Request with `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: navigate`, GET method | Middleware forwards | Inner handler called |
| actix_fetch_metadata_blocks_when_strict | invalid input | `FetchMetadataTransform::new().allow_missing_headers(false)` with request missing all Sec-Fetch-* | Middleware blocks | Status 403 |

**Feature: Cross-framework parity**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| parity_secure_json_rejection_bytes_match | cross-framework parity | A body that fails at each rejection stage (content-type, size, depth, syntax, semantic) | Send the same body to both axum and Actix adapters | Both return identical status code, identical rejection code, and identical JSON body shape |
| parity_security_headers_match | cross-framework parity | A handler that returns 200 with empty body wrapped in `SecurityHeadersLayer`/`Transform` with default config | Hit both | Both emit the same 11 headers with the same values (order may differ but set is equal) |
| parity_fetch_metadata_blocks_match | cross-framework parity | A cross-site CORS request | Hit both | Both return 403 with no body |

#### Regression Tests

- All existing tests in `crates/secure_boundary/tests/` pass unchanged when run with default features.
- All existing doctests in `extract.rs`, `headers.rs`, `fetch_metadata.rs`, `safe_types.rs`, `validate.rs` still pass (still under `axum` feature).
- `secure_reference_service` compiles and all its tests pass unchanged.
- `secure_smoke_service` compiles and all its existing tests pass unchanged.
- `cargo check -p secure_boundary --no-default-features` compiles (framework-neutral subset — `validate`, `safe_types`, `limits`, etc. — still works).
- `BoundaryViolation` emission counts match across frameworks (one violation per rejection, not two).

#### Compatibility Checklist

- [ ] `secure_boundary` default features build and all existing tests pass with `cargo test -p secure_boundary`.
- [ ] `secure_boundary` with `--features axum` is identical in API surface to before this milestone (verified by a doc-test that `use`s every public item).
- [ ] `secure_boundary` with `--features actix-web` adds exactly the items listed in the contract.
- [ ] `secure_boundary` with `--features "axum actix-web"` builds (both adapters coexist).
- [ ] `secure_boundary` with `--no-default-features` builds (framework-neutral subset).
- [ ] `secure_reference_service` and `secure_smoke_service` compile unchanged and their existing tests pass.
- [ ] `cargo deny check` passes (new deps `actix-web`/`actix-http` in allow-list already per supply-chain policy).
- [ ] `cargo audit` passes on the extended dep tree.

#### E2E Runtime Validation

**File**: `crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `actix_service_boots_with_all_three_adapters` | An Actix-web 4 `App` wrapping `SecurityHeadersTransform`, `FetchMetadataTransform`, and a handler that takes `SecureJson<TestDto>` starts up without panicking | `App::configure(...)` completes; test binds to an ephemeral port via `actix_web::test::init_service`. |
| `actix_e2e_happy_path_json_to_handler` | A real request crosses the adapter chain and reaches the handler | POST `/dto` with valid JSON returns 200; response has all security headers |
| `actix_e2e_malformed_json_is_rejected` | The rejection path also works end-to-end, not just the extractor | POST `/dto` with invalid JSON returns 400 with `PublicError` body; security headers still set |
| `actix_e2e_cross_site_request_blocked` | `FetchMetadataTransform` short-circuits the chain | POST `/dto` with `Sec-Fetch-Site: cross-site` + mode `cors` returns 403 before the handler runs |
| `actix_e2e_no_extractor_without_content_type` | `SecureJson` still rejects even when FetchMetadata would allow | POST `/dto` with `Content-Type: text/plain` returns 415 |

#### Smoke Tests

- [ ] `cargo test -p secure_boundary --features axum` passes
- [ ] `cargo test -p secure_boundary --features actix-web` passes
- [ ] `cargo test -p secure_boundary --features "axum actix-web"` passes
- [ ] `cargo check -p secure_boundary --no-default-features` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-features -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo deny check` passes (new Actix deps allowed)
- [ ] `cargo audit` passes
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` covers any new generated files

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | | | |
| BDD tests created | the 4 new test files | compile or fail with missing-symbol errors for not-yet-existing Actix adapters | | | |
| E2E stubs created | `tests/e2e_sg_gate_a_m1.rs` | compile or fail for expected reason | | | |
| Cargo.toml feature flags | `cargo check -p secure_boundary --no-default-features` | builds | | | |
| Axum gating | `cargo test -p secure_boundary --features axum` | existing tests still green | | | |
| Actix implementation | `cargo test -p secure_boundary --features actix-web` | all new BDD tests pass | | | |
| Both features composed | `cargo test -p secure_boundary --features "axum actix-web"` | green | | | |
| Parity tests | parity test file | axum and Actix return identical bytes | | | |
| E2E runtime | `cargo test -p secure_smoke_service --test e2e_sg_gate_a_m1` | green | | | |
| Feature matrix | `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | both green | | | |
| Build/boot | `cargo build --workspace --release` | green | | | |
| Clippy | `cargo clippy --workspace --all-features -- -D warnings` | no warnings | | | |
| Fmt | `cargo fmt --all --check` | clean | | | |
| Supply chain | `cargo audit && cargo deny check` | both pass | | | |
| Smoke tests | steps in Smoke Tests section | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current | | | |
| Compatibility checks | checklist above | no regressions | | | |

#### Definition of Done

The milestone is done only when all of the following are true:

- All listed BDD scenarios pass on both framework features.
- All listed E2E runtime validations pass.
- Full existing test suite remains green on default features.
- Cross-framework parity tests pass (axum and Actix return identical bytes on identical inputs).
- All four feature matrix configurations (`--features axum`, `--features actix-web`, `--features "axum actix-web"`, `--no-default-features`) build.
- Smoke tests are checked off.
- Compatibility checklist is complete.
- No forbidden shortcuts remain in production code.
- All tests clean up their output artifacts — `git status` is clean.
- `.gitignore` is up to date with any new generated files or build outputs.
- Docs updated: `secure_boundary/src/lib.rs` crate-level docs mention the `actix-web` feature and link to the `actix` module; README's Feature Flags section lists `actix-web` for `secure_boundary`.
- **Every new public item has a rustdoc paragraph + runnable `/// # Examples` doctest.** `cargo test --doc -p secure_boundary --features actix-web` passes.
- **`cargo doc --workspace --no-deps` builds with zero rustdoc warnings on the modified items.** No broken intra-doc links.
- **`crates/secure_boundary/examples/actix_minimal.rs` compiles and runs** via `cargo build --example actix_minimal -p secure_boundary --features actix-web` and is referenced from the integration guide.
- **`docs/dev-guide/secure_boundary-actix.md` exists, covers every new public item, and its code blocks are all backed by doctests, the example, or an integration test.** A human reader can go from zero to a working Actix service in under 10 minutes using only the guide.
- Lessons file is written at `docs/slo/lessons/sg-gate-a-m1.md`.
- Completion summary is written at `docs/slo/completion/sg-gate-a-m1.md`.
- Milestone Tracker is updated.

#### Post-Flight

Complete the Global Exit Rules above. Key documentation updates:

- **ARCHITECTURE.md**: Add `secure_boundary` row to a new "HTTP Framework Adapters" table noting `axum` (default) and `actix-web` feature flags. Note which public items appear under which feature.
- **README.md**: Under the feature-flag documentation, add `secure_boundary = { features = ["actix-web"] }` usage example and note that both features compose.
- **`secure_boundary/src/lib.rs`**: Crate-level docs gain a "Framework Support" section linking to both `axum` and `actix-web` adapter modules.
- **Other docs**: IMPROVEMENT_PROPOSAL.md — delete any line that asserts axum-only framework coupling.

#### Notes

- Concurrency/persistence test categories are N/A: adapters are stateless per-request wrappers around framework-neutral logic. Call-out per BDD rules.
- `SecureQuery` and `SecurePath` Actix adapters are explicitly deferred; Gate A only asks for `SecureJson`.
- If the shared-core refactor turns out larger than expected, stop and ask before widening scope. The contract budget is "framework-neutral helpers that are byte-for-byte behavior-preserving of the current axum impls" — not "rewrite the validation pipeline."

---

### Milestone 2 — `secure_authz::AuthzLayer` + `secure_errors::ErrorMappingLayer` Actix-web 4 adapters

**Goal**: Ship the remaining two of five framework-coupled types Sunlit Guardian blocks on: an Actix-web 4 `AuthzLayer` equivalent (reads `AuthenticatedIdentity` from request extensions, short-circuits with 403 on `Decision::Deny`, enforces obligations) and an Actix-web 4 `ErrorMappingLayer` equivalent (maps `AppError` → HTTP response via `into_response_parts`). After M2, all five Gate A types work on Actix-web 4 under the `actix-web` feature, with full byte-for-byte parity to the axum path.

**Context**: `AuthzLayer<A>` in [crates/secure_authz/src/middleware.rs:25](../../../crates/secure_authz/src/middleware.rs#L25) boxes a tower `Service` and performs the authorization check inside a `Pin<Box<Future>>`. The real logic — extract identity, resolve subject, call `authorizer.authorize`, check obligations — is already framework-neutral except for the response type. `ErrorMappingLayer` in [crates/secure_errors/src/middleware.rs:32](../../../crates/secure_errors/src/middleware.rs#L32) is an empty pass-through whose real work happens in `impl IntoResponse for AppError` at line 45; the authoritative mapping lives in `http::into_response_parts` (framework-neutral today).

**Important design rule**: **Preserve the identity-agnostic invariant.** `secure_authz` must not depend on `secure_identity` even in the Actix adapter. `AuthenticatedIdentity` is in `security_core`; both the axum and Actix adapters read it from request extensions via that type only. Any temptation to import anything from `secure_identity` into `secure_authz/src/actix/` is a forbidden shortcut.

**Refactor budget**: `Targeted refactor permitted for factoring framework-neutral authz enforcement logic and error-mapping logic out of the axum-only middleware modules into framework-neutral helpers that both adapters call.` The authz decision path (resolve subject, call authorizer, check obligations, return allow/deny) must move into a framework-neutral `enforce::run_check` helper so only the HTTP wiring differs between axum and Actix.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | HTTP request with `AuthenticatedIdentity` (and optionally `ObligationFulfillment`) in extensions; handler returning `Result<impl Responder, AppError>` for error-mapping scenarios. |
| Outputs | For authz: pass-through on Allow, 403 on Deny. For error-mapping: HTTP response with status from `into_response_parts`, JSON `PublicError` body, `Retry-After` header when `RateLimit`. Both byte-identical to the axum path. |
| Interfaces touched | `secure_authz::{AuthzLayer, Authorizer, Decision, Subject, ResourceRef, Action, ObligationFulfillment}` — stable under `axum` feature. New `secure_authz::actix::{AuthzTransform, AuthzMiddleware}` under `actix-web` feature. `secure_errors::{AppError, PublicError, ErrorMappingLayer}` — stable under `axum` feature. New `secure_errors::actix::{ErrorMappingTransform}` and `impl actix_web::ResponseError for AppError` under `actix-web` feature. |
| Files allowed to change | `crates/secure_authz/Cargo.toml`, `crates/secure_authz/src/lib.rs`, `crates/secure_authz/src/middleware.rs`, `crates/secure_authz/src/enforce.rs` (NEW), `crates/secure_authz/src/actix/mod.rs` (NEW), `crates/secure_authz/src/actix/middleware.rs` (NEW), `crates/secure_errors/Cargo.toml`, `crates/secure_errors/src/lib.rs`, `crates/secure_errors/src/middleware.rs`, `crates/secure_errors/src/actix.rs` (NEW), `crates/secure_authz/tests/sg_gate_a_actix_authz.rs` (NEW), `crates/secure_errors/tests/sg_gate_a_actix_errors.rs` (NEW), `crates/secure_authz/tests/sg_gate_a_parity_authz.rs` (NEW), `crates/secure_errors/tests/sg_gate_a_parity_errors.rs` (NEW), `crates/secure_smoke_service/tests/e2e_sg_gate_a_m2.rs` (NEW), `.gitignore` (as needed). |
| Files to read before changing anything | `crates/secure_authz/src/middleware.rs`, `crates/secure_authz/src/enforcer.rs`, `crates/secure_authz/src/resolver.rs`, `crates/secure_authz/src/decision.rs`, `crates/secure_authz/src/resource.rs`, `crates/secure_authz/src/action.rs`, `crates/secure_authz/src/subject.rs`, `crates/secure_authz/src/testkit.rs`, `crates/secure_errors/src/middleware.rs`, `crates/secure_errors/src/http.rs`, `crates/secure_errors/src/kind.rs`, `crates/secure_errors/src/public.rs`, `crates/security_core/src/identity.rs`. |
| New files allowed | `crates/secure_authz/src/enforce.rs`, `crates/secure_authz/src/actix/mod.rs`, `crates/secure_authz/src/actix/middleware.rs`, `crates/secure_errors/src/actix.rs`, the five test files. |
| New dependencies allowed | `actix-web = "4"` and `actix-http = "3"` as `optional = true` in `[dependencies]` gated by `actix-web` feature, in both `secure_authz` and `secure_errors`. Dev-dep `actix-web = "4"` with `rt` feature. No other deps. |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_authz` and `secure_errors` tests pass unchanged under default features. `secure_reference_service` and `secure_smoke_service` compile and test green. `secure_authz` does not import `secure_identity`. `ErrorMappingLayer` remains a pass-through Tower layer; `AppError`'s axum `IntoResponse` impl is unchanged (still under `axum` feature). |
| Forbidden shortcuts | Duplicating the authz decision path into Actix code instead of sharing via `enforce::run_check`; depending on `secure_identity` from `secure_authz/src/actix/`; bypassing `into_response_parts` to compute status codes twice; letting the Actix adapter emit a different `PublicError` JSON shape than axum; mapping `AppError::Internal` to 500 on Actix while axum uses something else. |

#### Out of Scope / Must Not Do

- Do not touch `secure_boundary` — that was M1.
- Do not change `Authorizer` trait or `Decision` enum.
- Do not change three-layer error model or `into_response_parts` mapping rules.
- Do not add any runtime configuration that would let a service opt into weaker defaults on one framework vs the other.
- Do not extend `AppError` variants in this milestone.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sg-gate-a-m1.md` and apply any patterns or rules it establishes (e.g., where the shared-core module lives, how cross-framework parity tests are structured).
3. Read the allowed files.
4. Copy the Evidence Log template.
5. Re-state constraints: "Actix adapters for two more types, shared core via framework-neutral helpers, identity-agnostic invariant preserved, byte parity verified."

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_authz/Cargo.toml` | Add `[features]` with `default = ["axum"]`, `axum = ["dep:axum", "dep:axum-core", "dep:tower"]`, `actix-web = ["dep:actix-web", "dep:actix-http"]`; mark axum/axum-core/tower as optional; add optional actix-web/actix-http. Dev-deps gain actix-web with `rt` feature. |
| `crates/secure_authz/src/lib.rs` | Gate framework-coupled re-exports on `#[cfg(feature = "axum")]`; add `#[cfg(feature = "actix-web")] pub mod actix;`. |
| `crates/secure_authz/src/middleware.rs` | Gate existing axum `Layer`/`Service` impls on `#[cfg(feature = "axum")]`. Move shared logic (extract identity, resolve subject, call authorizer, check obligations) into `crate::enforce`. |
| `crates/secure_authz/src/enforce.rs` | NEW: framework-neutral helper — `pub(crate) async fn run_check<A: Authorizer>(authorizer: &A, identity: Option<&AuthenticatedIdentity>, action: &Action, resource: &ResourceRef, fulfilled: Option<&ObligationFulfillment>) -> EnforceOutcome` where `enum EnforceOutcome { Allow, Deny }`. |
| `crates/secure_authz/src/actix/mod.rs` | NEW: `pub mod middleware;` + crate docs. |
| `crates/secure_authz/src/actix/middleware.rs` | NEW: `pub struct AuthzTransform<A>` implementing `actix_web::dev::Transform`. Reads `AuthenticatedIdentity` from `ServiceRequest::extensions()`, calls `crate::enforce::run_check`, returns 403 on `Deny`. |
| `crates/secure_errors/Cargo.toml` | Same feature-flag pattern as `secure_authz`. Add optional actix-web/actix-http. |
| `crates/secure_errors/src/lib.rs` | Gate axum-coupled re-exports on `#[cfg(feature = "axum")]`; add `#[cfg(feature = "actix-web")] pub mod actix;`. |
| `crates/secure_errors/src/middleware.rs` | Gate existing axum `IntoResponse for AppError` and `ErrorMappingLayer` impls on `#[cfg(feature = "axum")]`. |
| `crates/secure_errors/src/actix.rs` | NEW: `impl actix_web::ResponseError for AppError` — delegates to `crate::http::into_response_parts` and `retry_after_seconds`. Also `pub struct ErrorMappingTransform` that is a pass-through (exists for feature-parity with axum's `ErrorMappingLayer`). |
| `crates/secure_authz/tests/sg_gate_a_actix_authz.rs` | NEW: Actix integration tests — allow on Authorizer::allow, 403 on Deny, 403 on missing identity, obligations fulfilled allow, obligations unfulfilled deny. |
| `crates/secure_errors/tests/sg_gate_a_actix_errors.rs` | NEW: Actix integration tests — every `AppError` variant maps to the correct status + JSON body; `RateLimit` emits `Retry-After`. |
| `crates/secure_authz/tests/sg_gate_a_parity_authz.rs` | NEW: cross-framework parity for authz outcomes. |
| `crates/secure_errors/tests/sg_gate_a_parity_errors.rs` | NEW: cross-framework parity for every `AppError` variant. |
| `crates/secure_smoke_service/tests/e2e_sg_gate_a_m2.rs` | NEW: boot an Actix service with `AuthzTransform` + `ErrorMappingTransform` + a handler that returns `Err(AppError::Forbidden)` or `Err(AppError::RateLimit{..})` to verify E2E. |
| `crates/secure_authz/examples/actix_authz_minimal.rs` | NEW: minimal runnable Actix service showing `AuthzTransform` usage — how to install an identity-setting middleware ahead of it, how to configure `Action`/`ResourceRef`, how to assert Allow vs Deny. Compiles with `cargo build --example actix_authz_minimal -p secure_authz --features actix-web`. |
| `crates/secure_errors/examples/actix_error_minimal.rs` | NEW: minimal runnable Actix service demonstrating `impl ResponseError for AppError`, including the `RateLimit`→`Retry-After` case. Compiles with `cargo build --example actix_error_minimal -p secure_errors --features actix-web`. |
| `docs/dev-guide/secure_authz-actix.md` | NEW integration guide: "What `AuthzTransform` gives you", "Wiring identity upstream", "Declaring the action/resource for a route", "Obligations (MFA, step-up)", "Cross-reference with axum adapter for mixed-framework services", "Common pitfalls" (e.g., forgetting the upstream identity layer). Every code block is backed by the example or a doctest. |
| `docs/dev-guide/secure_errors-actix.md` | NEW integration guide: "The three-layer error model in 60 seconds", "Using `AppError` in Actix handlers", "Status-code mapping table (the full 8-variant table)", "Retry-After header behaviour", "How this composes with `SecureJson` rejections", "Cross-reference with axum". |
| `.gitignore` | As needed. |

#### Step-by-Step

1. Write BDD test stubs in the four test files + E2E stub.
2. Update both `Cargo.toml` files with feature flags.
3. Lift `enforce::run_check` out of axum-only `secure_authz/src/middleware.rs`; confirm existing axum tests still green.
4. Gate existing axum impls in `secure_authz/src/middleware.rs` on `#[cfg(feature = "axum")]`.
5. Implement `secure_authz/src/actix/middleware.rs` using `enforce::run_check`.
6. In `secure_errors`: gate axum `IntoResponse for AppError` and `ErrorMappingLayer` on `axum` feature.
7. Implement `secure_errors/src/actix.rs` — `impl ResponseError for AppError` delegating to `into_response_parts`.
8. Run full test matrix (both features, each alone, neither).
9. Run parity tests.
10. Run E2E.
11. Verify cleanup + gitignore + smoke.
12. Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: `AuthzTransform` as Actix-web 4 middleware**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| actix_authz_allow_pass_through | happy path | `Authorizer` returns `Decision::Allow { obligations: [] }`; identity in extensions | Request reaches inner handler | 200 from handler |
| actix_authz_deny_returns_403 | invalid input | `Authorizer` returns `Decision::Deny { .. }` | Middleware short-circuits | 403, inner handler not called |
| actix_authz_missing_identity_returns_403 | invalid input | No `AuthenticatedIdentity` in extensions | Middleware short-circuits | 403, inner handler not called |
| actix_authz_obligations_fulfilled_allow | happy path | Allow with `["mfa"]` obligation; `ObligationFulfillment { fulfilled: ["mfa"] }` in extensions | Middleware checks | 200 from inner |
| actix_authz_obligations_unfulfilled_deny | invalid input | Allow with `["mfa"]` obligation; no `ObligationFulfillment` in extensions | Middleware checks | 403, inner not called |
| actix_authz_no_dependency_on_secure_identity | compatibility | `secure_authz/src/actix/` source | `grep -r 'secure_identity' crates/secure_authz/src/actix/` | No matches; identity-agnostic invariant preserved |

**Feature: `ErrorMappingTransform` + `ResponseError for AppError` on Actix-web 4**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| actix_error_validation_maps_to_400 | happy path | Handler returns `Err(AppError::Validation { .. })` | Middleware catches | Status 400; JSON body `{"code":"validation_error","message":<safe>,"request_id":<uuid>}`; no internal details leaked |
| actix_error_forbidden_maps_to_403 | happy path | `Err(AppError::Forbidden { .. })` | | Status 403; JSON `PublicError` body |
| actix_error_not_found_maps_to_404 | happy path | `Err(AppError::NotFound { .. })` | | Status 404 |
| actix_error_conflict_maps_to_409 | happy path | `Err(AppError::Conflict { .. })` | | Status 409 |
| actix_error_rate_limit_maps_to_429_with_header | happy path | `Err(AppError::RateLimit { retry_after_seconds: 30 })` | | Status 429; `Retry-After: 30` header; JSON body |
| actix_error_internal_maps_to_500 | partial failure | `Err(AppError::Internal { .. })` | | Status 500; JSON body says "internal_error" with a stable request_id; no SQL/hostname/policy names leaked |
| actix_error_public_body_identical_to_axum | cross-framework parity | Same `AppError` variant on both frameworks | | Identical JSON bytes |

**Feature: Cross-framework parity**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| parity_authz_decision_bytes_match | cross-framework parity | Same Authorizer decision on both frameworks | Hit both | Identical status, identical body |
| parity_error_mapping_bytes_match | cross-framework parity | Each of the 8 `AppError` variants | Hit both | Identical status, identical JSON body, identical `Retry-After` when applicable |

#### Regression Tests

- All existing `secure_authz` tests pass unchanged under default features.
- All existing `secure_errors` tests pass unchanged under default features.
- `secure_reference_service` compiles and its existing tests pass.
- `secure_smoke_service` compiles and its existing tests pass.
- No source file under `crates/secure_authz/src/actix/` imports `secure_identity` (grep-based regression test in CI).
- `cargo check -p secure_authz --no-default-features` and `cargo check -p secure_errors --no-default-features` build.
- `into_response_parts`'s mapping table is unchanged.

#### Compatibility Checklist

- [ ] `secure_authz` default features build and existing tests pass.
- [ ] `secure_authz` with `--features actix-web` adds exactly the items listed.
- [ ] `secure_authz` with `--features "axum actix-web"` builds.
- [ ] `secure_authz` with `--no-default-features` builds.
- [ ] Same four configurations for `secure_errors` build/test green.
- [ ] `secure_reference_service` and `secure_smoke_service` compile unchanged.
- [ ] `cargo deny check` passes.
- [ ] `cargo audit` passes.
- [ ] Identity-agnostic invariant: `grep -r 'secure_identity' crates/secure_authz/src/` returns matches only in documentation strings, never in source `use` statements.

#### E2E Runtime Validation

**File**: `crates/secure_smoke_service/tests/e2e_sg_gate_a_m2.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `actix_service_boots_with_authz_and_error_mapping` | Both new Actix adapters compose in an `App` | `App` starts; test harness binds successfully |
| `actix_e2e_authz_deny_returns_403` | Real request deny | Request without identity returns 403 |
| `actix_e2e_authz_allow_reaches_handler` | Real request allow | Request with identity in extensions reaches handler returning 200 |
| `actix_e2e_handler_error_maps_to_response` | `ResponseError` impl fires end-to-end | Handler returning `Err(AppError::RateLimit { retry_after_seconds: 30 })` yields 429 with `Retry-After: 30` |
| `actix_e2e_public_error_body_shape` | No internal details leak on Actix | Body is `{"code":..,"message":..,"request_id":..}` with exactly those three fields |

#### Smoke Tests

- [ ] `cargo test -p secure_authz --features actix-web` passes
- [ ] `cargo test -p secure_errors --features actix-web` passes
- [ ] `cargo test -p secure_authz --features "axum actix-web"` passes
- [ ] `cargo test -p secure_errors --features "axum actix-web"` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-features -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo deny check` and `cargo audit` pass
- [ ] Identity-agnostic invariant grep-check passes
- [ ] `git status` clean

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | | | |
| BDD tests created | 4 new test files | compile or fail for expected reason | | | |
| E2E stubs created | `e2e_sg_gate_a_m2.rs` | fail for expected reason | | | |
| `enforce::run_check` lift | `cargo test -p secure_authz` | still green | | | |
| Actix authz impl | `cargo test -p secure_authz --features actix-web` | new BDD tests pass | | | |
| Actix errors impl | `cargo test -p secure_errors --features actix-web` | new BDD tests pass | | | |
| Parity tests | `cargo test -p secure_authz --test sg_gate_a_parity_authz && cargo test -p secure_errors --test sg_gate_a_parity_errors` | axum and Actix return identical bytes | | | |
| E2E runtime | `cargo test -p secure_smoke_service --test e2e_sg_gate_a_m2` | green | | | |
| Feature matrix | `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | both green | | | |
| Build/boot | `cargo build --workspace --release` | green | | | |
| Clippy/fmt | `cargo clippy --workspace --all-features -- -D warnings && cargo fmt --all --check` | pass | | | |
| Identity-agnostic invariant | `! grep -rn 'use secure_identity' crates/secure_authz/src/` | no matches | | | |
| Supply chain | `cargo audit && cargo deny check` | pass | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | | patterns current | | | |
| Compatibility checks | checklist | no regressions | | | |

#### Definition of Done

- All M2 BDD scenarios pass on both framework features.
- E2E runtime validations pass.
- Full existing test suite remains green.
- Parity tests pass.
- All four feature matrix configurations build for both crates.
- Identity-agnostic invariant grep-check passes.
- Smoke tests are checked off.
- Compatibility checklist is complete.
- No forbidden shortcuts remain.
- Tests clean up; `git status` clean.
- Docs updated: `secure_authz/src/lib.rs` and `secure_errors/src/lib.rs` crate docs mention the `actix-web` feature.
- **Every new public item has a rustdoc paragraph + runnable `/// # Examples` doctest.** `cargo test --doc -p secure_authz --features actix-web` and `cargo test --doc -p secure_errors --features actix-web` both pass.
- **`cargo doc --workspace --no-deps` builds with zero new rustdoc warnings.**
- **Both minimal Actix examples build** (`cargo build --example actix_authz_minimal -p secure_authz --features actix-web`, `cargo build --example actix_error_minimal -p secure_errors --features actix-web`).
- **Both integration guides exist** at `docs/dev-guide/secure_authz-actix.md` and `docs/dev-guide/secure_errors-actix.md`, every code block is backed by examples or doctests, and a reader can go from zero to a working Actix handler with authz + error-mapping in under 15 minutes.
- Lessons file written at `docs/slo/lessons/sg-gate-a-m2.md`.
- Completion summary at `docs/slo/completion/sg-gate-a-m2.md`.
- Milestone Tracker updated.

#### Post-Flight

- **ARCHITECTURE.md**: Extend the HTTP Framework Adapters table to include `secure_authz` and `secure_errors` rows.
- **README.md**: Extend the Actix usage example to cover all three crates (`secure_boundary`, `secure_authz`, `secure_errors`).
- **Crate-level docs**: Both `lib.rs` files get a "Framework Support" section.

#### Notes

- Concurrency/persistence categories N/A for the same reason as M1.
- If `enforce::run_check` ends up needing an owning-reference to `Decision` while axum's middleware today clones, leave the cloning behavior unchanged in axum and use the same clone semantics in Actix — parity matters more than micro-optimizing either path.

---

### Milestone 3 — `SafeUrl` blocked-CIDR coverage extension + per-CIDR tests + rustdoc

**Goal**: Extend `SafeUrl`'s `is_private_ipv4` and `is_private_ipv6` to reject the four CIDRs currently missing from Sunlit Guardian's required blocked set — `fe80::/10`, `224.0.0.0/4`, `ff00::/8`, `::/128` — and publish the full blocked-CIDR list in `SafeUrl`'s rustdoc. Add one `#[test]` per CIDR on the Gate A list (12 tests total, one for each of the 12 CIDRs) so that any regression removing a single range fails a named test. By end of M3, `SafeUrl::try_from` rejects every IP on the SG v3-K2 required blocked list.

**Context**: `SafeUrl` today in [crates/secure_boundary/src/safe_types.rs:263](../../../crates/secure_boundary/src/safe_types.rs#L263) uses a hand-rolled parser and delegates IP classification to `is_private_ipv4` (lines 356–370) and `is_private_ipv6` (lines 372–377). `is_private_ipv4` covers `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, and `0.0.0.0/32`. `is_private_ipv6` covers `::1/128` (via `is_loopback()`) and `fc00::/7`. Missing: `fe80::/10` (IPv6 link-local — the IPv6 analogue of the AWS IMDS attack), `224.0.0.0/4` (IPv4 multicast), `ff00::/8` (IPv6 multicast), `::/128` (IPv6 unspecified). The rustdoc on `SafeUrl` currently says "private or loopback IP" without enumerating the full blocked set; Sunlit Guardian's feedback asks for the explicit list.

**Important design rule**: **One test per CIDR, named by CIDR, at the public API level.** Each test calls `SafeUrl::try_from("http://<representative-ip-in-cidr>/")` and asserts `.is_err()`. This is variant analysis (Google pattern): a future edit that removes one line from `is_private_ipv4` or `is_private_ipv6` fails a specific named test, so the regression is obvious from the test output, not a generic "SSRF test failed."

**Refactor budget**: `No refactor permitted beyond direct implementation.` The four new rejection branches slot into the existing `is_private_ipv4`/`is_private_ipv6` functions. The existing `TryFrom<&str>` control flow is unchanged. No parser rewrite.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | A string URL via `SafeUrl::try_from(&str)`. |
| Outputs | `Err(BoundaryRejection::SsrfAttempt)` for any URL whose host resolves to an IP in the 12 CIDRs on the Gate A list. `Ok(SafeUrl(_))` for all URLs the current implementation accepts. |
| Interfaces touched | `secure_boundary::safe_types::SafeUrl` — rustdoc only (public API unchanged). Internal `is_private_ipv4` / `is_private_ipv6` functions extended. |
| Files allowed to change | `crates/secure_boundary/src/safe_types.rs`, `crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs` (NEW), `.gitignore` (as needed). |
| Files to read before changing anything | `crates/secure_boundary/src/safe_types.rs`, `crates/secure_boundary/src/error.rs`, `crates/secure_boundary/src/attack_signal.rs`. |
| New files allowed | `crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs`. |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | Every URL that currently passes `SafeUrl::try_from` still passes. Every URL that currently fails still fails. The 4 new CIDRs are additive-reject only. The error variant (`BoundaryRejection::SsrfAttempt`) is unchanged. Existing doctests pass unchanged. `BoundaryViolation` emission behavior is unchanged. |
| Forbidden shortcuts | Rewriting the URL parser; replacing `is_private_ipv4`/`is_private_ipv6` with a dependency-based `ip_network` or similar crate; changing the error variant. |

#### Out of Scope / Must Not Do

- Do not rewrite the URL parser. The existing hand-rolled parser has known minor quirks (IPv6 bracket handling, port-pattern edge cases) but those are not Gate A asks and are explicitly out of scope for this runbook. Note any observed quirks in the lessons file as follow-ups.
- Do not add IPv4-mapped IPv6 detection (`::ffff:<ipv4>`) in this milestone. Sunlit Guardian can ask for it in a follow-up if needed; adding it here widens the contract.
- Do not change `SafeRedirectUrl` or any other safe type.
- Do not add any new Cargo dependency (e.g., `ip_network`, `cidr`, `ipnet`).

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sg-gate-a-m2.md` and apply any rules.
3. Read `safe_types.rs` in full, especially the `is_private_ipv4` / `is_private_ipv6` functions and the `TryFrom<&str>` impl.
4. Copy the Evidence Log template.
5. Re-state constraints: "extend two internal functions to reject 4 CIDRs, add 12 `#[test]`s, update rustdoc — nothing else."

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/src/safe_types.rs` | `is_private_ipv4`: add `// 224.0.0.0/4 multicast` branch `o[0] >= 224 && o[0] <= 239`. `is_private_ipv6`: add `fe80::/10` (first 10 bits = `1111 1110 10`), `ff00::/8` (first octet = `0xff`), `::/128` (`addr.is_unspecified()`). Rustdoc on `SafeUrl` expanded to list all 12 CIDRs explicitly. |
| `crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs` | NEW: 12 `#[test]` functions, one per CIDR, each named `rejects_cidr_<slug>` (e.g. `rejects_cidr_10_slash_8`, `rejects_cidr_169_254_slash_16`, `rejects_cidr_fe80_slash_10`). Each picks a representative IP from inside the range and asserts `SafeUrl::try_from(&format!("http://{host}/"))` returns `Err`. Plus tests confirming acceptable public IPs (`8.8.8.8`, `1.1.1.1`, `2606:4700:4700::1111`) still pass, as negative controls. |
| `docs/dev-guide/safe-url-ssrf.md` | NEW integration guide: "What SSRF is and why `SafeUrl` exists", the full 12-CIDR table with one-line explanation per row (matches the rustdoc), "How to use SafeUrl (copy-paste)", "Serde integration (reject at deserialize time)", "What SafeUrl does NOT do" (DNS rebinding, IPv4-mapped IPv6), "How to extend if you need stricter rules". Every code block has a matching doctest. |
| `.gitignore` | As needed (likely no change). |

#### Step-by-Step

1. Write `sg_gate_a_safeurl_cidrs.rs` with 12 `#[test]` stubs + negative controls. Run it; `rejects_cidr_fe80_slash_10`, `rejects_cidr_224_slash_4`, `rejects_cidr_ff00_slash_8`, `rejects_cidr_ipv6_unspecified_slash_128` should fail. The other 8 should pass immediately against the current implementation (confirming variant-analysis hypothesis).
2. Extend `is_private_ipv4` with the 224/4 branch.
3. Extend `is_private_ipv6` with the three new branches.
4. Re-run tests; all 12 pass.
5. Expand the `SafeUrl` rustdoc to list the full blocked set with both CIDR notation and one-line explanation of why each is dangerous.
6. Run the full test suite + parity matrix (M3 doesn't change framework behavior, but confirming nothing else breaks is cheap).
7. Verify cleanup + gitignore.
8. Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: `SafeUrl` blocks every CIDR on the Gate A list**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| rejects_cidr_10_slash_8 | invalid input | URL with host `10.0.0.1` | `SafeUrl::try_from` | `Err(BoundaryRejection::SsrfAttempt)`; `BoundaryViolation` emitted |
| rejects_cidr_172_16_slash_12 | invalid input | `172.16.0.1` | `try_from` | `Err` |
| rejects_cidr_172_31_slash_12_upper | invalid input | `172.31.255.1` (upper edge of /12) | `try_from` | `Err` |
| rejects_cidr_192_168_slash_16 | invalid input | `192.168.1.1` | `try_from` | `Err` |
| rejects_cidr_169_254_slash_16 | invalid input | `169.254.169.254` (AWS IMDS) | `try_from` | `Err` |
| rejects_cidr_127_slash_8 | invalid input | `127.0.0.1` | `try_from` | `Err` |
| rejects_cidr_224_slash_4 | invalid input | `224.0.0.1` | `try_from` | `Err` |
| rejects_cidr_239_255 | invalid input | `239.255.255.255` (upper edge of 224/4) | `try_from` | `Err` |
| rejects_cidr_0_slash_32 | invalid input | `0.0.0.0` | `try_from` | `Err` |
| rejects_cidr_fc00_slash_7 | invalid input | `[fc00::1]` | `try_from` | `Err` |
| rejects_cidr_fd00_slash_7_upper | invalid input | `[fdff::1]` (upper edge of fc00::/7) | `try_from` | `Err` |
| rejects_cidr_fe80_slash_10 | invalid input | `[fe80::1]` | `try_from` | `Err` |
| rejects_cidr_fe80_slash_10_upper | invalid input | `[febf::1]` (upper edge of fe80::/10) | `try_from` | `Err` |
| rejects_cidr_loopback_v6 | invalid input | `[::1]` | `try_from` | `Err` |
| rejects_cidr_ff00_slash_8 | invalid input | `[ff02::1]` | `try_from` | `Err` |
| rejects_cidr_ipv6_unspecified_slash_128 | invalid input | `[::]` | `try_from` | `Err` |
| accepts_public_ipv4_8_8_8_8 | happy path (negative control) | `8.8.8.8` | `try_from` | `Ok` |
| accepts_public_ipv4_1_1_1_1 | happy path (negative control) | `1.1.1.1` | `try_from` | `Ok` |
| accepts_public_ipv6_2606 | happy path (negative control) | `[2606:4700:4700::1111]` (Cloudflare DNS) | `try_from` | `Ok` |
| accepts_public_hostname | happy path (negative control) | `example.com` | `try_from` | `Ok` |

> Note: 20 scenarios total (12 CIDR rejection + 4 near-edge tests + 4 negative controls). Every CIDR on the Gate A list has at least one rejection test; /12, /10, /7 CIDRs get an extra upper-bound test to prevent off-by-one.

#### Regression Tests

- All existing `secure_boundary` tests pass unchanged.
- The existing doctest on `SafeUrl` (`http://127.0.0.1/admin` rejection) still passes.
- `SafeRedirectUrl` tests unchanged.
- `cargo check -p secure_boundary --no-default-features` builds.

#### Compatibility Checklist

- [ ] Every URL accepted by pre-M3 `SafeUrl` is still accepted post-M3 (spot-check negative-control tests).
- [ ] Error variant for SSRF rejection is unchanged (`BoundaryRejection::SsrfAttempt`).
- [ ] Emission count: exactly one `BoundaryViolation::SyntaxViolation` per rejected URL.
- [ ] Public API of `SafeUrl` unchanged.
- [ ] Rustdoc lists all 12 CIDRs and briefly explains each.
- [ ] `secure_reference_service` and `secure_smoke_service` tests unaffected.

#### E2E Runtime Validation

**File**: reuse `crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs` (or add a small assertion to `e2e_sg_gate_a_m3.rs` if preferred).

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `safe_url_blocks_imds_at_runtime` | Service boot + outbound URL validation uses `SafeUrl` and rejects `169.254.169.254` at runtime | Calling a handler that constructs `SafeUrl::try_from("http://169.254.169.254/latest/meta-data")` returns 4xx via the extractor path |
| `safe_url_blocks_ipv6_link_local_at_runtime` | Same for `[fe80::1]` | 4xx rejection at runtime |

If no runtime surface needs an E2E (unit tests at the type level may suffice), state that in Notes and justify.

#### Smoke Tests

- [ ] `cargo test -p secure_boundary --test sg_gate_a_safeurl_cidrs` — all 20 scenarios pass
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-features -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo doc -p secure_boundary --no-deps` builds (rustdoc update has no broken intra-doc links)
- [ ] `git status` clean
- [ ] `.gitignore` current

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | green | | | |
| New test file | `cargo test -p secure_boundary --test sg_gate_a_safeurl_cidrs` | 4 tests fail (exactly the 4 missing CIDRs) | | | Confirms variant-analysis hypothesis |
| IPv4 extension | `cargo test -p secure_boundary --test sg_gate_a_safeurl_cidrs -- rejects_cidr_224` | pass | | | |
| IPv6 extension | same, for fe80/ff00/:: | all pass | | | |
| Full file | `cargo test -p secure_boundary --test sg_gate_a_safeurl_cidrs` | all 20 pass | | | |
| Rustdoc | `cargo doc -p secure_boundary --no-deps` | builds | | | |
| Full workspace | `cargo test --workspace` | green | | | |
| Feature matrix | `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | green | | | |
| Clippy/fmt | | pass | | | |
| Supply chain | `cargo audit && cargo deny check` | pass | | | |
| Test artifact cleanup | `git status` | clean | | | |
| .gitignore review | | current | | | |
| Compatibility checks | checklist | no regressions | | | |

#### Definition of Done

- All 20 BDD scenarios pass.
- `SafeUrl` rustdoc explicitly lists all 12 CIDRs with a brief reason per CIDR.
- Full existing test suite remains green.
- Smoke tests checked.
- Compatibility checklist complete.
- No forbidden shortcuts.
- Clean working tree.
- **`SafeUrl` rustdoc enumerates all 12 CIDRs explicitly, with a one-line reason per CIDR, and includes a runnable `# Examples` doctest showing acceptance of a public URL and rejection of a private one.**
- **`cargo doc -p secure_boundary --no-deps` builds with zero new rustdoc warnings.**
- **`docs/dev-guide/safe-url-ssrf.md` exists and every code block is backed by a doctest on `SafeUrl` or a test in `sg_gate_a_safeurl_cidrs.rs`.**
- Lessons file at `docs/slo/lessons/sg-gate-a-m3.md`.
- Completion summary at `docs/slo/completion/sg-gate-a-m3.md`.
- Milestone Tracker updated.

#### Post-Flight

- **ARCHITECTURE.md**: Add a note under the `secure_boundary` component section listing the 12 blocked CIDRs.
- **README.md**: If the README has an "SSRF prevention" bullet, update it to mention the explicit 12-CIDR set.
- **THREAT_MODEL.md**: If applicable, note that Gate A's required-blocked-CIDR set is now covered by a per-CIDR regression test suite.

#### Notes

- Concurrency/persistence categories N/A: pure-function input validation.
- Empty-state: N/A (no state).
- Dependency-failure: N/A (no dependencies).
- If during implementation the agent notices other pre-existing quirks in the URL parser (e.g., IPv4-mapped IPv6, DNS-rebinding surface, hostname resolution), record them in the lessons file as Sunlit-Guardian-follow-up candidates — do NOT fix them in this runbook.

---

### Milestone 4 — Secure-by-default helpers (A4/A5), license reconciliation (C1), `deny.toml` publishing (C3), CI feature-matrix gate

**Goal**: Close out the remaining Gate A nice-to-have asks in one milestone: (A4) `secure_identity::assert_no_dev_identity_in_production` so no downstream service has to re-implement the production-boot check; (A5) `secure_authz::testing::assert_every_route_has_policy` so downstream CI can assert route-policy coverage ergonomically; (C1) verify and reconcile the license posture between `Cargo.toml` manifests and `README.md`; (C3) publish `deny.toml` as a cleanly-consumable canonical file (documented in README, referenced in docs). Finally, add a CI matrix job that builds and tests every (crate × feature-combination) on every PR — this is the Google "preventing backsliding" presubmit gate that ensures M1/M2's feature flags cannot silently rot.

**Context**: SG's v4 feedback explicitly asks A4 and A5 as "nice to have — we'll build locally if you decline" helpers, but these are exactly the kind of infrastructure that benefits from living upstream (one audit, one test matrix, one upgrade path — same rationale as Actix adapters). C1 needs verification: every crate `Cargo.toml` currently says `license = "MIT"` and `README.md` has no "Private — all rights reserved" string today — the feedback doc's premise may be stale; this milestone verifies and normalises. C3's `deny.toml` is already at repo root; making it cleanly consumable means documenting the canonical path and noting in README that downstream consumers may `curl` it directly. The CI gate applies Google's presubmit pattern: once the `actix-web` feature exists, CI must gate on it, otherwise future edits can silently break the Actix compile path.

**Important design rule**: **The CI gate is load-bearing.** Without it, M1/M2's feature flags atrophy the first time a contributor pushes an axum-only change that happens to break Actix compilation. The gate is the presubmit equivalent of the variant-analysis tests in M3.

**Refactor budget**: `No refactor permitted beyond direct implementation.` Each of the four sub-items is additive.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | For A4: an `app_env: &str` and a `&TokenValidator`. For A5: `&[RouteDescriptor]` + `&[PolicyFixture]`. For C1: repo-wide license state. For C3: `deny.toml` content. For CI gate: existing `ci.yml` file (or equivalent). |
| Outputs | For A4: `Result<(), ProductionModeViolation>` where `ProductionModeViolation` is a new error type with a `ReasonCode` pointer. For A5: `Result<(), Vec<UnmappedRoute>>` with a diagnostic vector. For C1: consistent license declaration across manifests + README. For C3: README section + docs page pointing to `deny.toml`. For CI: a new matrix job in `ci.yml`. |
| Interfaces touched | `secure_identity::{assert_no_dev_identity_in_production, ProductionModeViolation}` — NEW public items, additive. `secure_authz::testing::{assert_every_route_has_policy, RouteDescriptor, PolicyFixture, UnmappedRoute}` — NEW public items, additive. `README.md` License section, Supply-Chain section. `.github/workflows/ci.yml` NEW feature-matrix job. |
| Files allowed to change | `crates/secure_identity/src/lib.rs`, `crates/secure_identity/src/boot.rs` (NEW), `crates/secure_identity/tests/sg_gate_a_boot_assert.rs` (NEW), `crates/secure_authz/src/testkit.rs` (existing — extend), `crates/secure_authz/tests/sg_gate_a_policy_coverage.rs` (NEW), `README.md`, `crates/*/Cargo.toml` (only the `license = ` line, only if reconciliation is needed), `deny.toml` (at most documentation comments), `.github/workflows/ci.yml` (NEW file if absent; otherwise extend), `.gitignore` (as needed). |
| Files to read before changing anything | `crates/secure_identity/src/lib.rs`, `crates/secure_identity/src/token.rs`, every `crates/*/Cargo.toml`, `README.md`, `Cargo.toml` (workspace), existing `.github/workflows/` if any, `deny.toml`. |
| New files allowed | `crates/secure_identity/src/boot.rs`, `crates/secure_identity/tests/sg_gate_a_boot_assert.rs`, `crates/secure_authz/tests/sg_gate_a_policy_coverage.rs`, `.github/workflows/ci.yml` if it does not exist. |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing tests pass unchanged. Existing public items in `secure_identity` and `secure_authz::testing` retain signatures; only additions. `deny.toml` content unchanged beyond optional clarifying comments — no policy changes. License reconciliation: if manifests already agree with README (current state), this sub-item is a docs-only confirmation. `ci.yml` new job does not slow existing CI gates — it runs in parallel and does not block if other jobs also need to pass. |
| Forbidden shortcuts | Making the CI gate only run on a nightly schedule rather than on every PR; letting `assert_no_dev_identity_in_production` take an `Option<&TokenValidator>` (makes misuse trivial); returning `bool` instead of `Result<(), Diagnostic>` from the helpers; modifying `deny.toml` policy content (scope says docs only); silently changing any crate's `license` field. |

#### Out of Scope / Must Not Do

- Do not document an HMAC key rotation pattern for `security_events` (C2 — explicitly deferred in the feedback doc).
- Do not introduce a new test framework or assertion library.
- Do not add a new release or packaging workflow; CI gate is a PR presubmit, not a release job.
- Do not switch the workspace license or introduce dual-licensing without explicit user approval — verify first, and if the intent is to change, open a plan discussion.
- Do not change any existing workflow jobs' config (triggers, runner versions); extend only.

#### Pre-Flight

1. Global Entry Rules.
2. Read `docs/slo/lessons/sg-gate-a-m3.md` and apply.
3. Read all the files listed.
4. Run `grep -rn 'license' crates/*/Cargo.toml Cargo.toml` and `grep -n -i "license\\|rights reserved\\|private" README.md` and paste the output into the Evidence Log. That's the ground truth before any edit.
5. Copy Evidence Log template.
6. Re-state constraints: "A4 helper, A5 helper, license docs verification, deny.toml docs, CI feature-matrix gate — no other scope."

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_identity/src/boot.rs` | NEW: `pub struct ProductionModeViolation { reason: ReasonCode, message: &'static str }` (implements `std::error::Error` + `Display`). `pub fn assert_no_dev_identity_in_production(app_env: &str, validator: &TokenValidator) -> Result<(), ProductionModeViolation>`. Logic: if `app_env` is exactly `"production"` (case-sensitive), inspect the validator's registered identity sources; if any source implements a `is_dev_mode()` marker (adding a provided-default-`false` method on the `IdentitySource` trait, with `impl … for DevBearerSource` overriding to `true`), return Err. |
| `crates/secure_identity/src/lib.rs` | Add `pub mod boot;`, `pub use boot::{assert_no_dev_identity_in_production, ProductionModeViolation};`. |
| `crates/secure_identity/tests/sg_gate_a_boot_assert.rs` | NEW: tests — (1) staging + dev source → Ok; (2) production + dev source → Err with stable reason; (3) production + prod source → Ok; (4) production + both dev and prod sources → Err (any dev presence in prod fails). |
| `crates/secure_authz/src/testkit.rs` | Extend (not replace). Add `pub struct RouteDescriptor { method: Method, path: String, action: Action, resource: ResourceRef }`, `pub struct PolicyFixture { subject: Subject, action: Action, resource: ResourceRef }`, `pub struct UnmappedRoute { route: RouteDescriptor, reason: String }`, and `pub fn assert_every_route_has_policy<A: Authorizer>(authorizer: &A, routes: &[RouteDescriptor], fixtures: &[PolicyFixture]) -> Result<(), Vec<UnmappedRoute>>`. Any route-action-resource combination that returns `Deny` when evaluated against every fixture subject is flagged as `UnmappedRoute`. |
| `crates/secure_authz/tests/sg_gate_a_policy_coverage.rs` | NEW: tests — (1) all routes have policies → Ok; (2) one route missing policy → Err with that route in the vector; (3) one route denies for all fixtures → Err (suspected missing policy); (4) route with conditional allow (obligations) → Ok. |
| `README.md` | Update the License section to state MIT (current manifest truth). Add a section near Supply Chain reading: "Canonical supply-chain policy: `deny.toml` at repo root; downstream consumers may copy or `curl` it directly." Add a Feature Flags section entry for `actix-web` across `secure_boundary`, `secure_authz`, `secure_errors` — pointing to the Actix adapter modules added in M1/M2. |
| `crates/*/Cargo.toml` | Verification only: `license = "MIT"` today on every manifest. Change only if a divergence is found. Record the finding in Evidence Log either way. |
| `deny.toml` | Optional clarifying comments only (e.g., header comment noting this file is the canonical policy and OK to copy downstream). No policy changes. |
| `.github/workflows/ci.yml` | NEW feature-matrix job: matrix over `crate ∈ {secure_boundary, secure_authz, secure_errors}` and `features ∈ {"", "axum", "actix-web", "axum actix-web"}`, running `cargo check` + `cargo test` for each combination. Plus a `cargo deny check` job and a `cargo doc --workspace --no-deps` job (rustdoc is a gate). |
| `docs/dev-guide/README.md` | NEW index page listing every dev-guide doc produced in M1–M4, with a one-line summary of each. Reader's entry point to the library. |
| `docs/dev-guide/production-checklist.md` | NEW: a dev-facing checklist covering A4 (call `assert_no_dev_identity_in_production` at boot), A5 (wire `assert_every_route_has_policy` into service CI), the 12-CIDR SSRF-block guarantee, and Actix/axum feature-flag choice. Copy-pasteable for downstream engineers. |
| `crates/secure_identity/examples/production_boot.rs` | NEW minimal runnable example showing the boot-time check. Compiles with `cargo build --example production_boot -p secure_identity`. |
| `crates/secure_authz/examples/route_coverage.rs` | NEW example showing how to assemble `RouteDescriptor`s and `PolicyFixture`s for a small app and call the helper. |
| `.gitignore` | As needed. |

#### Step-by-Step

1. Write test stubs in `sg_gate_a_boot_assert.rs` and `sg_gate_a_policy_coverage.rs`.
2. Implement `secure_identity::boot::{ProductionModeViolation, assert_no_dev_identity_in_production}`. If `IdentitySource` needs a `is_dev_mode()` marker method, add with default `false` — that's additive, not breaking. Update `DevBearerSource` (or equivalent) to override to `true`.
3. Implement `secure_authz::testing::assert_every_route_has_policy` and friends.
4. Run the two new test files; fix until green.
5. License reconciliation: run the `grep` commands from Pre-Flight step 4. If manifests all say MIT and README says nothing contradictory, add a plain "License: MIT" line to README if absent; otherwise make the minimal edit to reconcile. Record all findings in Evidence Log.
6. `deny.toml` documentation: add header comment + README link.
7. CI feature-matrix: if no `ci.yml` exists, create one with a minimal job. If one exists, extend. Ensure the matrix runs on every PR and blocks on failure.
8. Run full test suite + supply-chain gates.
9. Verify cleanup + gitignore.
10. Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: `secure_identity::assert_no_dev_identity_in_production`**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| staging_allows_dev_source | happy path | `app_env = "staging"`; validator has `DevBearerSource` | Call | `Ok(())` |
| production_rejects_dev_source | invalid input | `app_env = "production"`; validator has `DevBearerSource` | Call | `Err(ProductionModeViolation { reason: ReasonCode::_, message: "dev identity source registered in production" })` |
| production_allows_prod_source_only | happy path | `app_env = "production"`; validator has `OidcSource` only | Call | `Ok(())` |
| production_rejects_mixed | invalid input | `app_env = "production"`; validator has both prod and dev sources | Call | `Err` |
| development_env_no_check | happy path | `app_env = "development"`; any sources | Call | `Ok(())` (only `"production"` triggers the check) |
| empty_app_env_no_check | backward compat | `app_env = ""` (unset); dev sources present | Call | `Ok(())` — don't panic on unset env |

**Feature: `secure_authz::testing::assert_every_route_has_policy`**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| all_routes_have_policy | happy path | 5 routes, 3 fixture subjects; every (route, subject) returns Allow for at least one fixture | Call | `Ok(())` |
| one_route_missing_policy | invalid input | One route denies for every fixture subject | Call | `Err([UnmappedRoute { route: <that_route>, reason: "denies for all fixtures" }])` |
| all_routes_missing_policy | invalid input | Every route denies for every fixture | Call | `Err` with all routes listed |
| obligations_counted_as_policy_coverage | happy path | Route allows with `["mfa"]` obligation; fixture declares `mfa_fulfilled` in a helper | Call | `Ok(())` (obligation-allow counts as coverage) |

**Feature: License reconciliation (C1)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| all_manifests_agree | happy path | Every crate Cargo.toml `license = "MIT"`; README has no contradicting claim | grep audit | Evidence Log records "consistent — no edits needed"; README gains an explicit License: MIT line |

**Feature: CI feature-matrix gate**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| pr_builds_every_feature_combo | happy path | PR modifies `secure_boundary/src/actix/extract.rs` | CI runs | Feature-matrix job runs 12 combinations (3 crates × 4 feature sets) and all pass |
| pr_breaks_actix_build | invalid input | PR adds an axum-only type into a shared module | CI runs | `cargo check -p secure_boundary --features actix-web --no-default-features` fails; PR is blocked |
| pr_breaks_no_features_build | invalid input | PR introduces an axum use path in a framework-neutral module | CI runs | `cargo check -p secure_boundary --no-default-features` fails; PR is blocked |

#### Regression Tests

- All existing `secure_identity` tests pass unchanged.
- All existing `secure_authz` tests pass unchanged.
- `deny.toml` policy checks still pass (content unchanged).
- No existing `ci.yml` job is modified or disabled.
- `cargo deny check`, `cargo audit`, `cargo vet` all pass.

#### Compatibility Checklist

- [ ] Every public item in `secure_identity` pre-M4 is still exported post-M4.
- [ ] Every public item in `secure_authz::testing` pre-M4 is still exported post-M4.
- [ ] `secure_authz` still does not import `secure_identity`.
- [ ] `deny.toml` policy bytes unchanged (only comments added).
- [ ] README.md's existing content preserved; only additions.
- [ ] `ci.yml` existing jobs preserved.
- [ ] License fields in all `Cargo.toml` match the current state (MIT) or a consistent reconciled value — record final state in Evidence Log.

#### E2E Runtime Validation

**File**: `crates/secure_smoke_service/tests/e2e_sg_gate_a_m4.rs` (NEW, optional)

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `smoke_boot_assert_panics_on_misconfiguration` | `assert_no_dev_identity_in_production` correctly returns `Err` when misconfigured, and a service calling `.expect(...)` on it panics at boot | Test wraps the helper call in `std::panic::catch_unwind`; assertion confirms panic message contains `"dev identity source registered"` |
| `smoke_policy_coverage_helper_flags_missing_route` | `assert_every_route_has_policy` returns `Err` with the expected unmapped route | Vector has length 1 and matches the planted unmapped route |
| `ci_yaml_parses_as_valid_yaml` | CI config file is valid YAML | `serde_yaml::from_str` succeeds on the file content |

#### Smoke Tests

- [ ] `cargo test -p secure_identity --test sg_gate_a_boot_assert` passes
- [ ] `cargo test -p secure_authz --test sg_gate_a_policy_coverage` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-features -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo deny check && cargo audit` pass
- [ ] `.github/workflows/ci.yml` is syntactically valid YAML
- [ ] README License section is accurate and consistent with `Cargo.toml` manifests
- [ ] README Supply-Chain section points to `deny.toml` as the canonical policy
- [ ] `git status` clean

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | green | | | |
| License audit | `grep -rn 'license' crates/*/Cargo.toml Cargo.toml` | every crate says MIT | | | |
| README audit | `grep -ni 'license\|private\|rights reserved' README.md` | no contradictions | | | |
| A4 helper tests | `cargo test -p secure_identity --test sg_gate_a_boot_assert` | 6 scenarios pass | | | |
| A5 helper tests | `cargo test -p secure_authz --test sg_gate_a_policy_coverage` | 4 scenarios pass | | | |
| CI file | `cat .github/workflows/ci.yml \| yamllint -` | valid YAML | | | |
| Feature matrix (manual run) | all 12 combinations `cargo check` | green | | | Simulates presubmit |
| Workspace | `cargo test --workspace` | green | | | |
| Clippy/fmt | | pass | | | |
| Supply chain | `cargo audit && cargo deny check && cargo vet` | pass | | | |
| Test artifact cleanup | `git status` | clean | | | |
| .gitignore review | | current | | | |
| Compatibility checks | checklist | no regressions | | | |

#### Definition of Done

- All M4 BDD scenarios pass.
- CI feature-matrix job runs on every PR and blocks on failure.
- A4 and A5 helpers are publicly exported and tested.
- License posture is documented and consistent across `Cargo.toml` manifests and README.
- `deny.toml` is documented as the canonical supply-chain policy.
- No existing test regressed.
- Smoke tests checked.
- Compatibility checklist complete.
- Clean working tree.
- **Every new public item has rustdoc + runnable `# Examples`.** `cargo test --doc -p secure_identity` and `cargo test --doc -p secure_authz` pass, covering the new helpers.
- **`cargo doc --workspace --no-deps` builds with zero new rustdoc warnings** and is gated in the new CI job.
- **`docs/dev-guide/README.md` index page exists** and links every dev-guide doc produced across M1–M4.
- **`docs/dev-guide/production-checklist.md` exists**, is copy-pasteable, and references the two new helpers + the 12-CIDR SSRF block + the framework feature flags.
- **Both new examples (`production_boot.rs`, `route_coverage.rs`) build.**
- Lessons file at `docs/slo/lessons/sg-gate-a-m4.md`.
- Completion summary at `docs/slo/completion/sg-gate-a-m4.md`.
- Milestone Tracker updated.
- A short file `docs/slo/completed/sunlit-guardian-gate-a-complete.md` written to announce Gate A completion and list the commit SHA Sunlit Guardian should pin (produced at runbook close).

#### Post-Flight

- **ARCHITECTURE.md**: Add a "Supply-Chain Policy" section pointing to `deny.toml`; add an "AI-Consumable Boot Helpers" note for A4/A5.
- **README.md**: License section + Feature Flags section for `actix-web` + Supply-Chain link.
- **THREAT_MODEL.md**: If applicable, add a control-to-threat link for A4 (production misconfiguration threat) and A5 (authz coverage gap threat).
- **`crates/secure_identity/src/lib.rs`**: Crate docs mention `boot::assert_no_dev_identity_in_production`.
- **`crates/secure_authz/src/lib.rs`**: Crate docs mention `testing::assert_every_route_has_policy`.

#### Notes

- C2 (HMAC key rotation pattern for `security_events`) is explicitly deferred per the feedback doc and is NOT in this runbook.
- Concurrency/persistence N/A for A4/A5 helpers (pure functions). The CI gate is a CI-config change, not runtime code.
- If the license audit reveals actual divergence (e.g., README says "Private — all rights reserved" somewhere M4-scan missed), stop and confirm with the user which direction to reconcile before making edits. Changing license posture is not a one-shot edit.

---

## Documentation Update Table

Track which documents need updating per milestone.

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | New "HTTP Framework Adapters" section/table mentioning `secure_boundary` axum+actix-web flags; `secure_boundary` component section updated | New "Feature Flags" subsection showing `actix-web` usage for `secure_boundary`; Actix usage example | likely none | `secure_boundary/src/lib.rs` crate docs; delete axum-only assertions in `IMPROVEMENT_PROPOSAL.md` |
| 2 | Extend HTTP Framework Adapters section to include `secure_authz` and `secure_errors`; component sections updated | Extend Actix usage example to include AuthzTransform + ErrorMapping | likely none | `secure_authz/src/lib.rs` and `secure_errors/src/lib.rs` crate docs |
| 3 | `secure_boundary::SafeUrl` component text lists the 12 blocked CIDRs | SSRF-prevention bullet (if present) lists the 12 CIDRs | likely none | `THREAT_MODEL.md` if applicable |
| 4 | New Supply-Chain Policy pointer + AI-Consumable Boot Helpers note | License section clarification; Feature Flags full table; Supply-Chain section links to deny.toml; dev-guide index linked from top | CI workflow artifacts | `THREAT_MODEL.md` for A4/A5 control mapping; `secure_identity/src/lib.rs` crate docs; `secure_authz/src/lib.rs` crate docs; `docs/dev-guide/README.md` + `production-checklist.md` (NEW); `docs/slo/completed/sunlit-guardian-gate-a-complete.md` (NEW) |

---

## Optional Fast-Fail Review Prompt for Agents

Use this before writing production code:

> Restate the milestone goal, allowed files, forbidden changes, compatibility requirements, tests that must be written first, and the exact Definition of Done. Then list the smallest implementation approach that satisfies the contract without widening scope.

---

## Handoff Notes

Produced by `/slo-plan` on 2026-04-24 in response to Sunlit Guardian's v4 migration runbook feedback document (same date). The feedback doc is summarised in [Background Context → Problem](#problem). `/slo-critique` was skipped at user direction (Auto mode, user said "execute the plan this looks good at a high level"). Critique may still be run after M1 completes if desired.

**Branch strategy**: Work on `feature/sg-gate-a` (branched from `main` at Gate A start). Merge to `main` after M4. Sunlit Guardian's v4 runbook pins a `main` SHA; keep history clean to make that pin straightforward.

**Scope discipline**: Any request during execution that expands scope beyond these four milestones — including "also do `SecureQuery`/`SecurePath` adapters", "also document the HMAC key rotation", or "also fix IPv4-mapped IPv6 handling in SafeUrl" — should be rejected with a pointer to this runbook and an offer to open a follow-up runbook. The four milestones are the agreed Gate A surface; widening here invalidates Sunlit Guardian's downstream plan and requires re-critique.


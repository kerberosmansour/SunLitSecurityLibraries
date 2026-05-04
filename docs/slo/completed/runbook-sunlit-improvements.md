# SunLit Security Libraries — Post-M10 Improvements (AI-First Runbook v3)

> **Purpose**: Extend the SunLit Security Libraries workspace with missing attack-class defences (safe types, output encoders, XXE prevention), real provider integrations (AWS KMS, HashiCorp Vault, OIDC/JWKS), a purpose-built security smoke-test microservice exercising every control, and automated OWASP ZAP DAST scanning — closing the gaps identified in the post-M10 codebase audit.
> **Audience**: AI coding agents first, humans second. This document is written to reduce ambiguity, prevent scope drift, and improve code quality with the same model capability.  
> **How to use**: Work through milestones sequentially. Before starting any milestone, read its full section and the Global Execution Rules. After completing it, follow the Global Exit Rules. Never skip ahead. Never silently widen scope.  
> **Prerequisite reading**: [ARCHITECTURE.md](../../../ARCHITECTURE.md), [README.md](../../../README.md), [IMPROVEMENT_PROPOSAL.md](../lessons/IMPROVEMENT_PROPOSAL.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), [runbook-sunlit-security-libraries.md](./runbook-sunlit-security-libraries.md)

---

## Runbook Metadata

- **Runbook ID**: `sunlit-imp`
- **Prefix for test files and lessons files**: `sunlit-imp`
- **Primary stack**: `Rust 1.85+ (2024 edition)`
- **Target platforms**: Linux (x86_64, aarch64), macOS (x86_64, aarch64/Apple Silicon), Windows (x86_64). All code, tests, scripts, and CI must work on all three OSes unless a deviation is explicitly documented.
- **Primary package/app names**: `secure_boundary`, `secure_output`, `secure_data`, `secure_identity`, `secure_authz`, `secure_errors`, `security_events`, `security_core`, `secure_smoke_service`
- **Default test commands**:
  - Backend: `cargo test --workspace`
  - E2E backend: `cargo test --workspace --test 'e2e_*'`
  - Smoke tests: `cargo test -p secure_smoke_service --test 'smoke_*'`
  - Build/boot: `cargo build --workspace && cargo run -p secure_smoke_service`
  - Clippy: `cargo clippy --workspace --all-targets -- -D warnings`
  - Doc build: `cargo doc --workspace --no-deps`
  - Supply-chain: `cargo audit && cargo deny check && cargo vet`
  - ZAP scan: `bash scripts/zap_scan.sh`
- **Allowed new dependencies by default**: `none` — each milestone explicitly lists permitted crates
- **Schema/config migration allowed by default**: `no`
- **Public interfaces that must remain stable unless explicitly listed otherwise**:
  - `security_core::types::*` (shared ID types, classifications, severity)
  - `security_core::identity::*` (`IdentitySource`, `AuthenticatedIdentity`)
  - `secure_errors::public::PublicError` response shape
  - `security_events::event::SecurityEvent` schema
  - `secure_boundary::extract::SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>` extractor APIs
  - `secure_boundary::headers::SecurityHeadersLayer` API
  - `secure_identity::authenticator::Authenticator` trait
  - `secure_identity::session::SessionManager` trait
  - `secure_authz::enforcer::Authorizer` trait
  - `secure_authz::resolver::SubjectResolver` trait
  - `secure_data::kms::KeyProvider` trait
  - `secure_output::encode::OutputEncoder` trait
  - `secure_reference_service` — all existing routes and middleware ordering must be preserved

---

## Milestone Tracker

Update this table as each milestone is completed. This is the single source of truth for progress.

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 11 | Safe types + input validation hardening | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m11.md` | `docs/slo/completion/sunlit-imp-m11.md` |
| 12 | Output encoding expansion + security headers | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m12.md` | `docs/slo/completion/sunlit-imp-m12.md` |
| 13 | Real key provider integrations | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m13.md` | `docs/slo/completion/sunlit-imp-m13.md` |
| 14 | Identity & authentication hardening | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m14.md` | `docs/slo/completion/sunlit-imp-m14.md` |
| 15 | Authorization fixes + error handling middleware | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m15.md` | `docs/slo/completion/sunlit-imp-m15.md` |
| 16 | Security smoke-test microservice | `done` | 2026-04-06 | 2025-07-22 | `docs/slo/lessons/sunlit-imp-m16.md` | `docs/slo/completion/sunlit-imp-m16.md` |
| 17 | OWASP ZAP DAST integration | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-imp-m17.md` | `docs/slo/completion/sunlit-imp-m17.md` |
| 18 | Observability + advanced features | `not_started` | | | `docs/slo/lessons/sunlit-imp-m18.md` | `docs/slo/completion/sunlit-imp-m18.md` |

<!-- Status values: not_started | in_progress | blocked | done -->

---

## End-to-End Architecture Diagram

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                     SunLit Security Libraries — Post-M10 Target State                      │
│                                                                                          │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Trust Boundary (HTTP Edge)                                                        │   │
│  │                                                                                    │   │
│  │  ┌──────────┐    ┌─────────────────┐    ┌────────────────────────────────────┐     │   │
│  │  │  Client   │───▶│  axum Router +  │───▶│  secure_boundary                  │     │   │
│  │  │  (HTTP)   │    │  tower stack    │    │  ├── SecureJson<T> (depth/field   │     │   │
│  │  └──────────┘    └─────────────────┘    │  │   limits ENFORCED)             │     │   │
│  │                        │                 │  ├── SecureXml<T> (XXE blocked) - │     │   │
│  │                        │                 │  ├── SafePath (traversal blocked) -│     │   │
│  │                        │                 │  ├── SafeUrl (SSRF blocked) - - - │     │   │
│  │                        │                 │  ├── SafeFilename (cmdi blocked) -│     │   │
│  │                        │                 │  ├── SqlIdentifier (sqli guard) - │     │   │
│  │                        │                 │  ├── sanitize_header_value() - - -│     │   │
│  │                        │                 │  └── SecurityHeadersLayer         │     │   │
│  │                        │                 │      + COEP/COOP/CORP headers - - │     │   │
│  │                        │                 └──────────────┬─────────────────────┘     │   │
│  └────────────────────────┼────────────────────────────────┼──────────────────────────┘   │
│                           │                                │                              │
│                           ▼                                ▼                              │
│  ┌────────────────────┐  ┌──────────────────────────────────────────────┐                 │
│  │  secure_identity   │  │  secure_output                               │                 │
│  │  ├── RS256/ES256 - │  │  ├── HtmlEncoder (existing)                  │                 │
│  │  ├── JWKS fetch - -│  │  ├── UrlEncoder  (existing)                  │                 │
│  │  ├── OIDC disc. - -│  │  ├── JsonEncoder (existing)                  │                 │
│  │  ├── API keys - - -│  │  ├── JsStringEncoder - - - - - - - - - - - -│                 │
│  │  ├── Redis sess - -│  │  ├── CssEncoder - - - - - - - - - - - - - - │                 │
│  │  └── TokenValidator│  │  ├── XmlEncoder - - - - - - - - - - - - - - │                 │
│  └─────────┬──────────┘  │  └── sanitize_uri_scheme() - - - - - - - - -│                 │
│            │              └──────────────────────────────────────────────┘                 │
│            ▼                                                                              │
│  ┌────────────────────┐  ┌──────────────────────────────┐                                 │
│  │  secure_authz      │  │  secure_data                  │                                │
│  │  ├── cache+tenant -│  │  ├── VaultKeyProvider - - - - │──── HashiCorp Vault             │
│  │  ├── obligations - │  │  ├── AwsKmsKeyProvider - - - -│──── AWS KMS                     │
│  │  ├── hot-reload - -│  │  ├── AzureKeyVaultProvider - -│──── Azure Key Vault             │
│  │  └── Authorizer    │  │  ├── resolve_secret() - - - - │                                │
│  └────────────────────┘  │  ├── KeyRingStore (persist) - │                                │
│                          │  └── StaticDevKeyProvider      │                                │
│  ┌────────────────────┐  └──────────────────────────────┘                                 │
│  │  secure_errors     │                                                                   │
│  │  ├── auto-map mw - │                                                                   │
│  │  ├── ctx propagn - │                                                                   │
│  │  ├── retry-after - │                                                                   │
│  │  └── AppError      │                                                                   │
│  └────────────────────┘                                                                   │
│                                                                                          │
│  ┌────────────────────┐  ┌──────────────────────────────────────────────────────────┐     │
│  │  security_events   │  │  secure_smoke_service (NEW) - - - - - - - - - - - - - - │     │
│  │  ├── HMAC chain - -│  │  ├── /smoke/xss, /smoke/sqli, /smoke/cmdi, etc.        │     │
│  │  ├── more sinks - -│  │  ├── /smoke/auth/*, /smoke/authz/*, /smoke/data/*      │     │
│  │  ├── batch emit - -│  │  ├── openapi.yaml (ZAP scan target)                    │     │
│  │  ├── dist trace - -│  │  └── smoke_tests.rs (full attack-class integration)    │     │
│  │  └── AuditChain    │  └──────────────────────────────────────────────────────────┘     │
│  └────────────────────┘                                                                   │
│                                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│  │  OWASP ZAP (Checkmarx ZAP) DAST Pipeline - - - - - - - - - - - - - - - - - - - - - │ │
│  │  scripts/zap_scan.sh → Docker ZAP → API scan → report.html → CI gate              │ │
│  └──────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                          │
│  Legend:                                                                                 │
│  ─── existing (M0–M10)    - - - new (this runbook)    ═══ external    ▶ data flow        │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Milestone Introduced/Changed | Key Interfaces |
|---|---|---|---|
| `secure_boundary` safe types | Reject dangerous input patterns (traversal, injection, SSRF) at parse time | M11 | `SafePath`, `SafeFilename`, `SafeCommandArg`, `SafeUrl`, `SafeRedirectUrl`, `SqlIdentifier`, `LdapSafeString` |
| `secure_boundary` limit enforcement | Enforce JSON nesting depth and field count limits | M11 | `SecureJson<T>` (enhanced), `RequestLimits` (wired) |
| `secure_boundary` XML extractor | Parse XML with XXE prevention | M11 | `SecureXml<T>` |
| `secure_boundary` header sanitiser | Prevent CRLF header injection | M11 | `sanitize_header_value()` |
| `secure_output` new encoders | Context-aware encoding for JS, CSS, XML contexts | M12 | `JsStringEncoder`, `CssEncoder`, `XmlEncoder` |
| `secure_output` URI sanitiser | Block dangerous URI schemes | M12 | `sanitize_uri_scheme()` |
| `secure_boundary` cross-origin headers | COEP, COOP, CORP, X-DNS-Prefetch-Control | M12 | `SecurityHeadersLayer` (enhanced) |
| `secure_data` Vault provider | HashiCorp Vault Transit backend | M13 | `VaultKeyProvider` |
| `secure_data` AWS KMS provider | AWS KMS backend | M13 | `AwsKmsKeyProvider` |
| `secure_data` secret resolution | Resolve `vault://`, `kms://`, `env://` references | M13 | `resolve_secret()` |
| `secure_identity` asymmetric JWT | RS256/ES256 token verification | M14 | `TokenValidator` (enhanced) |
| `secure_identity` JWKS | Fetch and cache public keys | M14 | `JwksKeyStore` |
| `secure_identity` API keys | API key authentication with constant-time comparison | M14 | `ApiKeyAuthenticator` |
| `secure_authz` cache fix | Include tenant_id in cache key | M15 | `CacheKey` (fixed) |
| `secure_authz` obligations | Enforce allow obligations in middleware | M15 | `AuthzLayer` (enhanced) |
| `secure_errors` auto-mapping | Tower middleware for automatic AppError → HTTP mapping | M15 | `ErrorMappingLayer` |
| `secure_smoke_service` | Purpose-built service exercising every security control | M16 | 35+ routes, `smoke_tests.rs`, `openapi.yaml` |
| OWASP ZAP pipeline | DAST scanning against smoke service | M17 | `scripts/zap_scan.sh`, `scripts/zap-rules.tsv`, CI workflow |
| `security_events` HMAC chain | Signed audit entries for forgery detection | M18 | `HmacAuditChain` |
| `security_events` sinks | File, Syslog, HTTP webhook sinks | M18 | `FileSink`, `SyslogSink`, `HttpWebhookSink` |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Milestone |
|---|---|---|---|---|
| Safe type construction | `SecureJson`/`SecureQuery`/`SecurePath` extractors | `SafePath`/`SafeUrl`/etc. | `TryFrom<&str>` + serde `Deserialize` | M11 |
| Nesting/field validation | HTTP request body | `SecureJson<T>` depth/field checker | Custom serde wrapper | M11 |
| XML parsing | HTTP request body | `SecureXml<T>` extractor | `quick-xml` with safe defaults | M11 |
| JS/CSS/XML encoding | Handler response data | `JsStringEncoder`/`CssEncoder`/`XmlEncoder` | `OutputEncoder::encode()` | M12 |
| Key generation/unwrap | `secure_data` | HashiCorp Vault Transit API | HTTPS via `reqwest` | M13 |
| Key generation/unwrap | `secure_data` | AWS KMS API | HTTPS via `aws-sdk-kms` | M13 |
| Secret resolution | Config parsing | Vault/KMS/env | `resolve_secret()` | M13 |
| JWKS fetch | `secure_identity` | IdP `.well-known/jwks.json` | HTTPS via `reqwest` | M14 |
| Attack payload testing | smoke_tests.rs | `secure_smoke_service` | HTTP via axum test harness | M16 |
| ZAP scan | Docker ZAP container | `secure_smoke_service` | HTTP active/passive scan | M17 |
| HMAC-signed audit | `security_events` | Audit log | SHA256-HMAC chain | M18 |

---

## High-Level Design for Formal Verification (TLA+ Section)

The TLA+ model from the original runbook (M0–M10) remains valid. The improvements in this runbook extend the implementation depth but do not alter the abstract state-machine — new safe types strengthen the `validate` action; new providers implement the same `KeyProvider` sealed trait; new encoders extend the `encode_output` action's coverage. No new concurrency, state, or failure modes are introduced that would require model revision.

**Additions that strengthen existing properties (no model change needed):**

| Improvement | TLA+ Property Strengthened |
|---|---|
| SafePath/SafeUrl/SafeCommandArg safe types | `validate` action rejects more input classes → "No bypass" property unchanged |
| SecureXml, depth/field limits | `extract` action rejects more DoS patterns → "Request completion" liveness unchanged |
| VaultKeyProvider/AwsKmsKeyProvider | `encrypt`/`decrypt` actions gain real backends → "Key rotation safety" property unchanged |
| RS256/ES256 + JWKS | `authenticate` action accepts asymmetric tokens → "Authentication before authorization" unchanged |
| CacheKey + tenant_id | `authorize` cache lookup becomes tenant-scoped → "Deny by default" strengthened |
| HMAC-signed audit chain | "Audit chain integrity" property strengthened (detects forgery, not just tampering) |

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
   cargo clippy --workspace --all-targets -- -D warnings
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
   cargo clippy --workspace --all-targets -- -D warnings
   ```
2. Run the milestone E2E runtime validation tests.
   ```
   cargo test --workspace --test 'e2e_*'
   ```
3. Verify the workspace builds and the reference service boots.
   ```
   cargo build --workspace
   cargo run -p secure_reference_service &
   sleep 2
   curl -sf http://localhost:3000/health && echo "OK"
   kill %1
   ```
4. Run the smoke tests listed in the milestone. Check off each item in the runbook.
5. Verify backward compatibility for all items listed in the milestone Compatibility Checklist.
6. Complete the Self-Review Gate.
7. **Clean up test artifacts**: Verify no test output files, temporary fixtures, or generated data remain in the working tree. Run `git status` and confirm no untracked test artifacts exist.
8. **Review .gitignore**: Ensure any new build outputs, generated files, or tool caches introduced in this milestone have matching `.gitignore` patterns. Remove stale patterns that no longer apply.
9. Update ARCHITECTURE.md following the Documentation Update Table.
10. Update README.md if user-facing capabilities changed.
11. Write a lessons-learned file at `docs/slo/lessons/sunlit-imp-m<N>.md`.
12. Write a completion summary at `docs/slo/completion/sunlit-imp-m<N>.md`.
13. Update the Milestone Tracker in this file: set status to `done`, record Completed date, and fill in the lessons and completion summary paths.
14. Re-read the next milestone with fresh eyes and record any assumption changes in the lessons file.

---

## Background Context

### Current State

The SunLit Security Libraries workspace has completed M0–M10. Eight security crates and one reference service implement OWASP Proactive Controls C1/C4–C10 for Rust. The crate dependency graph, middleware ordering, and trait interfaces are stable and documented in `ARCHITECTURE.md`. The workspace has 100+ BDD tests, property tests, CVE regression tests, timing tests, and 7 fuzz targets across 5 crates. Supply-chain is hardened with cargo-deny, cargo-audit, and cargo-vet.

### Problem

A comprehensive post-M10 audit (see `IMPROVEMENT_PROPOSAL.md`) identified 39 concrete gaps:

1. **Missing safe types**: `secure_boundary` has no defence against directory traversal (`../`), SQL injection, OS command injection, SSRF, open redirect, LDAP injection, or CRLF header injection. The `max_nesting_depth` and `max_field_count` fields in `RequestLimits` are dead code — defined but never enforced.
2. **Missing output encoders**: `secure_output` covers HTML, URL, and JSON encoding but lacks JavaScript string, CSS, and XML encoders. No protocol URI sanitiser (`javascript:`, `data:` schemes).
3. **No production key providers**: `secure_data` only has `StaticDevKeyProvider` (XOR-based wrapping, dev-only). `SecretReference::parse()` handles `vault://`, `kms://`, `env://` but never resolves them. No AWS KMS, HashiCorp Vault, or Azure Key Vault integration.
4. **HS256-only JWT**: `secure_identity` supports only HMAC-SHA256 tokens with a static shared secret. No RS256/ES256, no JWKS rotation, no OIDC discovery, no API key auth, no persistent sessions.
5. **Authorization cache privacy risk**: `CacheKey` excludes `tenant_id` — two tenants with the same actor/resource/action share cache entries. `Decision::Allow` carries obligations but middleware ignores them.
6. **No error auto-mapping middleware**: Every handler manually calls `into_response_parts()`. No task-local context propagation for `ErrorReport`. `AppError::RateLimit` lacks `retry_after_seconds`.
7. **No security smoke-test service**: The existing `secure_reference_service` is a CRUD demo — it does not exercise every attack class or serve as a DAST scan target.
8. **No OWASP ZAP integration**: No automated DAST scanning validates the controls under adversarial HTTP traffic.

### Target Architecture

After all milestones in this runbook:

- Every OWASP Top 10 attack class has a typed defence in `secure_boundary` or `secure_output`
- `secure_data` supports HashiCorp Vault and AWS KMS for production envelope encryption
- `secure_identity` validates RS256/ES256 JWTs via JWKS endpoints and supports API key auth
- `secure_authz` cache is tenant-scoped and obligations are enforced
- A `secure_smoke_service` exercises every control with 35+ routes and full integration tests
- OWASP ZAP runs against the smoke service in CI, failing the build on high/critical findings
- `security_events` audit chain is HMAC-signed for forgery detection

### Key Design Principles

1. **Extend, don't break**: All changes add new types, encoders, providers, and routes. Existing public interfaces remain stable. No breaking changes to M0–M10 code.
2. **Feature-gated optional deps**: Cloud provider integrations (Vault, AWS KMS, Azure KV) are behind Cargo feature flags — off by default. The workspace builds without cloud SDKs.
3. **Safe types reject at construction**: Every safe type validates in `TryFrom<&str>` and serde `Deserialize`. Invalid input never reaches business logic.
4. **Smoke service proves controls**: The smoke service is not a demo — it is a verification tool. Every route maps to a specific attack class, and every test asserts the control holds.
5. **ZAP validates from outside**: DAST scanning validates controls from the attacker's perspective, catching gaps that unit tests cannot.

### What to Keep

- All existing crate public APIs, traits, and type signatures
- `secure_reference_service` routes and middleware stack
- All existing test suites (BDD, E2E, property, CVE regression, timing, fuzz)
- Supply-chain policy (`deny.toml`, `supply-chain/`)
- Architecture invariant: `secure_authz` depends only on `security_core::IdentitySource`, never on `secure_identity`

### What to Change

- **`crates/secure_boundary/src/`** — add `safe_types.rs`, `xml.rs`, `header_sanitize.rs`; enhance `extract.rs` and `limits.rs`
- **`crates/secure_output/src/`** — add `js.rs`, `css.rs`, `xml.rs`, `uri.rs`
- **`crates/secure_data/src/`** — add `providers/` directory with `vault.rs`, `aws_kms.rs`; add `resolve.rs`
- **`crates/secure_identity/src/`** — enhance `token.rs` for asymmetric algorithms; add `jwks.rs`, `api_key.rs`
- **`crates/secure_authz/src/cache.rs`** — fix `CacheKey` to include tenant
- **`crates/secure_authz/src/middleware.rs`** — add obligation enforcement
- **`crates/secure_errors/src/`** — add `middleware.rs`, enhance `kind.rs`
- **`crates/secure_smoke_service/`** — NEW crate
- **`scripts/`** — add `zap_scan.sh`, `zap_check.py`, `zap-rules.tsv`

### Global Red Lines

These are forbidden unless explicitly overridden inside a milestone.

- No unrelated refactors
- No new dependencies without explicit milestone permission
- No schema migrations
- No config key renames
- No public API/event/route renames in existing crates
- No production placeholders
- No silent error swallowing
- No secrets in source control
- No test output data committed to source control
- No changes to `secure_reference_service` routes or middleware ordering (it must continue to work as documented)
- No unsealing of sealed traits (`KeyProvider`, `SecuritySink`, `Authenticator`) unless the milestone explicitly permits it

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
| Backend BDD tests | `tests/sunlit_imp_<feature>.rs` | `crates/<crate>/tests/` |
| E2E runtime validation | `tests/e2e_sunlit_imp_m<N>.rs` | `crates/<crate>/tests/` |
| Property tests | `tests/prop_<feature>.rs` | `crates/<crate>/tests/` |
| CVE regression tests | `tests/cve_regression_<feature>.rs` | `crates/<crate>/tests/` |
| Smoke integration tests | `tests/smoke_<feature>.rs` | `crates/secure_smoke_service/tests/` |

### Test Artifact Cleanup Rules

Every test that creates files, directories, or temporary data on disk must follow these rules:

1. **Use temporary directories**: Prefer `tempdir()`, `tempfile::TempDir`, or OS-provided temp locations. Never write test output into the source tree.
2. **Clean up on completion and failure**: Use RAII patterns (Rust `Drop`) to ensure cleanup runs even when tests fail.
3. **No residual state**: After the full test suite runs, `git status` must show no untracked files from test execution.
4. **Dedicated output directories**: If a test must write to a project-relative path, that directory must be in `.gitignore` and tests must clean it between runs.
5. **CI parity**: Test cleanup behavior must be identical locally and in CI.

### End-to-End Runtime Validation

Every milestone must include E2E tests that go beyond compilation and verify that the system works correctly at runtime. These tests prove:

1. the workspace builds without errors
2. runtime contracts are met across crate boundaries
3. BDD scenarios work at runtime, not just in isolation
4. there are no runtime panics, unhandled rejections, or silent failures
5. degraded states behave safely and visibly

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

Any schema, config, or persisted-state change requires:

- migration plan
- backward compatibility strategy
- migration tests
- rollback strategy if relevant
- documentation updates

### Refactor budget

Each milestone must state one of the following:

- `No refactor permitted beyond direct implementation`
- `Minimal local refactor permitted in listed files only`
- `Targeted refactor permitted for [specific reason]`

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
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
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

## Lessons-Learned File Template

Path: `docs/slo/lessons/sunlit-imp-m<N>.md`

```md
# Lessons Learned — sunlit-imp Milestone <N>

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

Path: `docs/slo/completion/sunlit-imp-m<N>.md`

```md
# Completion Summary — sunlit-imp Milestone <N>

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

---

### Milestone 11 — Safe Types + Input Validation Hardening

**Goal**: Add type-safe wrappers (`SafePath`, `SafeFilename`, `SafeCommandArg`, `SafeUrl`, `SafeRedirectUrl`, `SqlIdentifier`, `LdapSafeString`) to `secure_boundary` that reject dangerous input at construction time, enforce the existing `max_nesting_depth` and `max_field_count` limits in `SecureJson`, add a `SecureXml` extractor with XXE prevention, and add `sanitize_header_value()` for CRLF injection prevention.

**Context**: The M4 implementation of `secure_boundary` covers strict JSON deserialization, unknown-field rejection, body size limits, and Unicode normalization. However, it does not address directory traversal, SQL injection, OS command injection, SSRF, XXE, LDAP injection, or CRLF header injection. The `max_nesting_depth` and `max_field_count` fields in `RequestLimits` (at `crates/secure_boundary/src/limits.rs`) are defined but never checked during request processing — they are dead code. These gaps map to THREAT-D-01, THREAT-E-01, and THREAT-E-04 in the threat model.

**Important design rule**: Every safe type must validate in both `TryFrom<&str>` and serde `Deserialize`. Invalid input must emit a `BoundaryViolation` security event via `security_events` before rejection. Safe types must be zero-cost wrappers (newtype over `String` or `Cow<str>`) with `into_inner()` / `as_inner()` accessors — no `Deref`, following the pattern established by `UserId`, `OrderId`, and `OpaquePublicId` in `crates/secure_boundary/src/id.rs`.

**Refactor budget**: `Minimal local refactor permitted in listed files only` — specifically `extract.rs` to wire depth/field counting.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | User-supplied strings from JSON fields, query params, path params, headers |
| Outputs | Validated safe-type instances or `BoundaryRejection` errors with security events |
| Interfaces touched | `secure_boundary` public API (additive only) |
| Files allowed to change | See "Files Allowed To Change" table below |
| Files to read before changing anything | `crates/secure_boundary/src/id.rs`, `crates/secure_boundary/src/extract.rs`, `crates/secure_boundary/src/limits.rs`, `crates/secure_boundary/src/error.rs`, `crates/secure_boundary/src/validate.rs`, `crates/secure_boundary/src/attack_signal.rs`, `crates/secure_boundary/src/lib.rs`, `crates/secure_boundary/Cargo.toml` |
| New files allowed | `crates/secure_boundary/src/safe_types.rs`, `crates/secure_boundary/src/xml.rs`, `crates/secure_boundary/src/header_sanitize.rs`, `crates/secure_boundary/tests/sunlit_imp_safe_types.rs`, `crates/secure_boundary/tests/sunlit_imp_xml.rs`, `crates/secure_boundary/tests/sunlit_imp_header_sanitize.rs`, `crates/secure_boundary/tests/sunlit_imp_depth_limits.rs`, `crates/secure_boundary/tests/e2e_sunlit_imp_m11.rs` |
| New dependencies allowed | `quick-xml = "0.36"` (for `SecureXml` extractor — no DTD, no entity expansion) |
| Migration allowed | `no` |
| Compatibility commitments | All existing `SecureJson`, `SecureQuery`, `SecurePath` extractors must continue to work unchanged. All existing tests in `crates/secure_boundary/tests/` must pass. `SecureJson` with DTOs that do not use safe types must behave identically to before. |
| Forbidden shortcuts | No `unsafe` code. No `Deref` on safe types. No `unwrap()` in production code. No allowing safe types to be constructed without validation. |

#### Out of Scope / Must Not Do

- Do not add new output encoders (that is M12)
- Do not change `secure_output` in any way
- Do not change `secure_identity`, `secure_authz`, `secure_data`, or `secure_errors`
- Do not add routes to `secure_reference_service`
- Do not create the smoke service (that is M16)
- Do not add cloud provider integrations
- Do not change the `SecurityHeadersLayer` (cross-origin headers are M12)

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m10.md` and `docs/slo/lessons/sunlit-m4.md` — apply relevant corrections.
3. Read all files in `crates/secure_boundary/src/` — understand the extractor pipeline, error types, and ID newtype patterns.
4. Copy the Evidence Log template into this milestone section or working notes.
5. Re-state the milestone constraints before coding.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/src/safe_types.rs` | NEW: `SafePath`, `SafeFilename`, `SafeCommandArg`, `SafeUrl`, `SafeRedirectUrl`, `SqlIdentifier`, `LdapSafeString` |
| `crates/secure_boundary/src/xml.rs` | NEW: `SecureXml<T>` extractor with XXE prevention |
| `crates/secure_boundary/src/header_sanitize.rs` | NEW: `sanitize_header_value()` function |
| `crates/secure_boundary/src/lib.rs` | Add `pub mod safe_types;`, `pub mod xml;`, `pub mod header_sanitize;` and re-exports |
| `crates/secure_boundary/src/extract.rs` | Wire `max_nesting_depth` and `max_field_count` checks into `SecureJson` |
| `crates/secure_boundary/src/limits.rs` | No structural change — verify limits are read by extractors |
| `crates/secure_boundary/src/error.rs` | Add `BoundaryRejection` variants for new rejection types (depth, field count, traversal, injection) |
| `crates/secure_boundary/Cargo.toml` | Add `quick-xml = "0.36"` dependency |
| `crates/secure_boundary/tests/sunlit_imp_safe_types.rs` | NEW: BDD tests for all 7 safe types |
| `crates/secure_boundary/tests/sunlit_imp_xml.rs` | NEW: BDD tests for `SecureXml` |
| `crates/secure_boundary/tests/sunlit_imp_header_sanitize.rs` | NEW: BDD tests for CRLF sanitisation |
| `crates/secure_boundary/tests/sunlit_imp_depth_limits.rs` | NEW: BDD tests for nesting depth and field count enforcement |
| `crates/secure_boundary/tests/e2e_sunlit_imp_m11.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review for new patterns |

#### Step-by-Step

1. Write BDD test stubs first for all scenarios below.
2. Write E2E runtime validation stubs.
3. Implement `SafePath` — `TryFrom<&str>` rejects `../`, `..\\`, null bytes; resolves to canonical path segments; serde `Deserialize` delegates to `TryFrom`.
4. Implement `SafeFilename` — rejects `/`, `\\`, `..`, null bytes, shell metacharacters (`;|&\`$><`).
5. Implement `SafeCommandArg` — rejects `;`, `|`, `&`, `` ` ``, `$()`, `>`, `<`, `\n`, `\r`.
6. Implement `SafeUrl` — parse with `url` crate or manual parsing; reject `file://`, `gopher://`, `javascript:`, `data:`; reject private IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, `::1`, `fc00::/7`).
7. Implement `SafeRedirectUrl` — relative paths only, or domain allowlist; reject absolute URLs to unknown hosts.
8. Implement `SqlIdentifier` — alphanumeric + underscore only, max 128 chars, must start with letter or underscore.
9. Implement `LdapSafeString` — escape `*`, `(`, `)`, `\\`, NUL per RFC 4515.
10. Implement `sanitize_header_value()` — reject or strip `\r` and `\n` from values intended for HTTP headers.
11. Wire `max_nesting_depth` into `SecureJson` — use a counting wrapper around `serde_json::from_slice` that tracks nesting depth.
12. Wire `max_field_count` into `SecureJson` — count fields during deserialization; reject bodies exceeding the limit.
13. Implement `SecureXml<T>` extractor — parse XML with `quick-xml` reader; disable DTD processing; disable entity expansion; enforce size limits from `RequestLimits`.
14. Add new `BoundaryRejection` variants for each rejection type.
15. Ensure every rejection emits `BoundaryViolation` event via `attack_signal.rs`.
16. Add re-exports in `lib.rs`.
17. Make all BDD tests pass.
18. Run the full test suite.
19. Run E2E runtime validation.
20. Verify test artifact cleanup.
21. Update `.gitignore`.
22. Run smoke tests.
23. Complete the Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: Safe type — SafePath**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid relative path accepted | happy path | input `"images/photo.png"` | `SafePath::try_from(input)` | returns `Ok(SafePath)` with inner value `"images/photo.png"` |
| Traversal with `../` rejected | invalid input | input `"../../etc/passwd"` | `SafePath::try_from(input)` | returns `Err` with `"path_traversal"` code |
| Traversal with `..\` rejected | invalid input | input `"..\\..\\windows\\system32"` | `SafePath::try_from(input)` | returns `Err` |
| Null byte in path rejected | invalid input | input `"file\x00.txt"` | `SafePath::try_from(input)` | returns `Err` |
| Absolute path rejected | invalid input | input `"/etc/passwd"` | `SafePath::try_from(input)` | returns `Err` |
| Encoded traversal rejected | invalid input | input `"%2e%2e/etc/passwd"` | `SafePath::try_from(input)` | returns `Err` |
| SafePath in SecureJson DTO | happy path | DTO field typed as `SafePath` | POST valid JSON with safe path | extracted successfully |
| SafePath violation emits event | attack signal | input `"../../etc/shadow"` | attempt construction | `BoundaryViolation` event emitted |

**Feature: Safe type — SafeUrl**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| HTTPS URL accepted | happy path | input `"https://example.com/api"` | `SafeUrl::try_from(input)` | returns `Ok` |
| Private IP rejected (127.0.0.1) | invalid input | input `"http://127.0.0.1/admin"` | `SafeUrl::try_from(input)` | returns `Err` with SSRF code |
| Private IP rejected (10.x) | invalid input | input `"http://10.0.0.1/internal"` | `SafeUrl::try_from(input)` | returns `Err` |
| Private IP rejected (192.168.x) | invalid input | input `"http://192.168.1.1/"` | `SafeUrl::try_from(input)` | returns `Err` |
| Link-local rejected (169.254.x) | invalid input | input `"http://169.254.169.254/meta"` | `SafeUrl::try_from(input)` | returns `Err` |
| file:// scheme rejected | invalid input | input `"file:///etc/passwd"` | `SafeUrl::try_from(input)` | returns `Err` |
| gopher:// scheme rejected | invalid input | input `"gopher://evil.com"` | `SafeUrl::try_from(input)` | returns `Err` |
| javascript: scheme rejected | invalid input | input `"javascript:alert(1)"` | `SafeUrl::try_from(input)` | returns `Err` |

**Feature: Safe type — SafeCommandArg**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Simple alphanumeric accepted | happy path | input `"backup-2024"` | `SafeCommandArg::try_from(input)` | returns `Ok` |
| Semicolon rejected | invalid input | input `"file; rm -rf /"` | `SafeCommandArg::try_from(input)` | returns `Err` |
| Pipe rejected | invalid input | input `"file \| cat /etc/passwd"` | `SafeCommandArg::try_from(input)` | returns `Err` |
| Backtick rejected | invalid input | input `` "file`whoami`" `` | `SafeCommandArg::try_from(input)` | returns `Err` |
| Dollar-paren rejected | invalid input | input `"$(whoami)"` | `SafeCommandArg::try_from(input)` | returns `Err` |

**Feature: Safe type — SqlIdentifier**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid identifier accepted | happy path | input `"user_name"` | `SqlIdentifier::try_from(input)` | returns `Ok` |
| SQL injection rejected | invalid input | input `"users; DROP TABLE users--"` | `SqlIdentifier::try_from(input)` | returns `Err` |
| Too long rejected | invalid input | 129-char string | `SqlIdentifier::try_from(input)` | returns `Err` |
| Empty string rejected | empty state | input `""` | `SqlIdentifier::try_from(input)` | returns `Err` |

**Feature: SecureJson depth and field limits**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Normal JSON accepted | happy path | 3-level nested JSON within limits | POST to `SecureJson<T>` handler | 200 OK |
| Deep nesting rejected | invalid input | 500-level nested JSON | POST to `SecureJson<T>` handler | 422 with `nesting_too_deep` code |
| Field flood rejected | invalid input | JSON with 10,000 fields | POST to `SecureJson<T>` handler | 422 with `too_many_fields` code |
| Default limits reasonable | happy path | JSON with 10 nested levels, 50 fields | POST to `SecureJson<T>` handler | 200 OK (within defaults) |

**Feature: SecureXml extractor**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid XML accepted | happy path | well-formed XML body | POST to `SecureXml<T>` handler | extracted successfully |
| XXE payload rejected | invalid input | XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | POST | 422 with `xxe_blocked` code |
| Billion laughs rejected | invalid input | XML with nested entity expansion | POST | 422 or 413 |
| DTD processing blocked | invalid input | XML with external DTD reference | POST | 422 |

**Feature: Header sanitisation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Normal value unchanged | happy path | input `"application/json"` | `sanitize_header_value(input)` | returns same string |
| Newline stripped | invalid input | input `"value\r\nInjected-Header: evil"` | `sanitize_header_value(input)` | returns `Err` or sanitised string without `\r\n` |
| Carriage return stripped | invalid input | input `"value\rX-Evil: yes"` | `sanitize_header_value(input)` | returns `Err` or sanitised |

#### Regression Tests

- All existing tests in `crates/secure_boundary/tests/` must pass unchanged
- `SecureJson<T>` with standard DTOs (no safe types) must behave identically
- `cargo test --workspace` must be green
- `cargo clippy --workspace --all-targets -- -D warnings` must be green

#### Compatibility Checklist

- [ ] `SecureJson<CreateUserDto>` from README example still works
- [ ] `SecureQuery<T>` still works
- [ ] `SecurePath<T>` still works
- [ ] `BoundaryRejection` variants from M4 still map to same HTTP status codes
- [ ] `SecurityHeadersLayer` unchanged
- [ ] All existing fuzz targets compile and run

#### E2E Runtime Validation

**File**: `crates/secure_boundary/tests/e2e_sunlit_imp_m11.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `e2e_safe_path_in_dto_roundtrip` | SafePath works inside SecureJson DTO end-to-end | Valid path accepted, `../../` rejected with 422 |
| `e2e_depth_limit_enforced` | max_nesting_depth is actually checked | 500-deep JSON returns 422, 5-deep returns 200 |
| `e2e_field_count_enforced` | max_field_count is actually checked | 10,000-field JSON returns 422, 10-field returns 200 |
| `e2e_xml_xxe_blocked` | SecureXml blocks XXE | XML entity expansion payload returns 422 |
| `e2e_header_crlf_blocked` | CRLF header injection blocked | Header value with `\r\n` blocked or sanitised |
| `e2e_safe_url_ssrf_blocked` | SafeUrl blocks SSRF to private IPs | `http://169.254.169.254/` rejected |

#### Smoke Tests

- [ ] `cargo test -p secure_boundary` passes (all new + existing tests)
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `SafePath::try_from("../../etc/passwd")` returns `Err`
- [ ] `SafeUrl::try_from("http://169.254.169.254/")` returns `Err`
- [ ] `SecureJson` rejects 500-level-deep JSON
- [ ] `SecureXml` rejects XXE payload
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` covers any new generated files

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | | | |
| BDD tests created | `sunlit_imp_safe_types.rs`, `sunlit_imp_xml.rs`, `sunlit_imp_header_sanitize.rs`, `sunlit_imp_depth_limits.rs` | fail for expected reason | | | |
| E2E stubs created | `e2e_sunlit_imp_m11.rs` | fail for expected reason | | | |
| Implementation | safe types, xml extractor, header sanitise, depth/field limits | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test -p secure_boundary --test 'e2e_*'` | green | | | |
| Build/boot | `cargo build --workspace` | builds cleanly | | | |
| Smoke tests | see checklist above | all checked | | | |
| Test artifact cleanup | `git status` | clean | | | |
| .gitignore review | review `.gitignore` | current | | | |
| Compatibility checks | existing extractor tests pass | no regressions | | | |

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests are checked off
- compatibility checklist is complete
- no forbidden shortcuts remain in production code
- all tests clean up their output artifacts
- `.gitignore` is up to date
- ARCHITECTURE.md updated with safe types list
- README.md updated with safe types usage example
- lessons file written
- completion summary written
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add "Safe Types" section under `secure_boundary` component description listing all 7 types and the `SecureXml` extractor. Add `sanitize_header_value()` and note the depth/field limit enforcement.
- **README.md**: Add safe types usage example in `secure_boundary` section.
- **THREAT_MODEL.md**: Update traceability matrix — THREAT-D-01 (algorithmic complexity) now mitigated by depth/field limits; THREAT-E-01 (authz bypass via path traversal) now mitigated by SafePath.

---

### Milestone 12 — Output Encoding Expansion + Security Headers

**Goal**: Add `JsStringEncoder`, `CssEncoder`, `XmlEncoder`, and `sanitize_uri_scheme()` to `secure_output`, and add Cross-Origin headers (COEP, COOP, CORP, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies) to `SecurityHeadersLayer` in `secure_boundary`.

**Context**: `secure_output` currently implements `HtmlEncoder`, `UrlEncoder`, and `JsonEncoder`. Missing encoders for JavaScript string, CSS, and XML contexts leave gaps where user-controlled data could cause XSS or injection when embedded in those contexts. The `SecurityHeadersLayer` in `secure_boundary` includes HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, and Cache-Control but lacks the newer cross-origin isolation headers.

**Important design rule**: All new encoders must implement the existing `OutputEncoder` trait (`fn encode<'a>(&self, input: &'a str) -> Cow<'a, str>`). Use the zero-copy `Cow::Borrowed` fast path for inputs that need no encoding, matching the pattern in `HtmlEncoder`.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | User-controlled strings to be output-encoded; HTTP response headers |
| Outputs | Safely encoded strings; enhanced security headers on responses |
| Interfaces touched | `secure_output` public API (additive), `secure_boundary::headers::SecurityHeadersLayer` (additive) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_output/src/html.rs`, `crates/secure_output/src/encode.rs`, `crates/secure_output/src/lib.rs`, `crates/secure_boundary/src/headers.rs` |
| New files allowed | `crates/secure_output/src/js.rs`, `crates/secure_output/src/css.rs`, `crates/secure_output/src/xml.rs`, `crates/secure_output/src/uri.rs`, test files |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | Existing `HtmlEncoder`, `UrlEncoder`, `JsonEncoder` unchanged. Existing `SecurityHeadersLayer` builder methods unchanged — new headers added to defaults. |
| Forbidden shortcuts | No `unsafe` code. No removing existing headers from defaults. |

#### Out of Scope / Must Not Do

- Do not change `secure_boundary` safe types (that was M11)
- Do not add cloud provider integrations
- Do not touch `secure_identity`, `secure_authz`, `secure_data`, or `secure_errors`

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_output/src/js.rs` | NEW: `JsStringEncoder` |
| `crates/secure_output/src/css.rs` | NEW: `CssEncoder` |
| `crates/secure_output/src/xml.rs` | NEW: `XmlEncoder` |
| `crates/secure_output/src/uri.rs` | NEW: `sanitize_uri_scheme()` |
| `crates/secure_output/src/lib.rs` | Add module declarations and re-exports |
| `crates/secure_boundary/src/headers.rs` | Add COEP, COOP, CORP, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies to defaults |
| `crates/secure_output/tests/sunlit_imp_js_encode.rs` | NEW: BDD tests |
| `crates/secure_output/tests/sunlit_imp_css_encode.rs` | NEW: BDD tests |
| `crates/secure_output/tests/sunlit_imp_xml_encode.rs` | NEW: BDD tests |
| `crates/secure_output/tests/sunlit_imp_uri_sanitize.rs` | NEW: BDD tests |
| `crates/secure_output/tests/e2e_sunlit_imp_m12.rs` | NEW: E2E runtime validation |
| `crates/secure_boundary/tests/sunlit_imp_headers.rs` | NEW: BDD tests for new headers |

#### BDD Acceptance Scenarios

**Feature: JsStringEncoder**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Single quotes escaped | happy path | input `"it's a test"` | `JsStringEncoder.encode(input)` | `"it\\'s a test"` |
| Backslash escaped | happy path | input `"path\\to"` | encode | `"path\\\\to"` |
| Newlines escaped | happy path | input `"line1\nline2"` | encode | `"line1\\nline2"` |
| Unicode line separator escaped | happy path | input contains U+2028 | encode | `\\u2028` |
| Safe string zero-copy | happy path | input `"hello"` | encode | returns `Cow::Borrowed` |
| Null bytes stripped | invalid input | input contains `\0` | encode | null removed |

**Feature: CssEncoder**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Alphanumeric unchanged | happy path | input `"red"` | `CssEncoder.encode(input)` | `"red"` (`Cow::Borrowed`) |
| Parentheses escaped | happy path | input `"expression(alert(1))"` | encode | metacharacters escaped |
| Backslash escaped | happy path | input `"a\\b"` | encode | `"a\\005cb"` or equivalent |

**Feature: XmlEncoder**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Angle brackets encoded | happy path | input `"<tag>"` | `XmlEncoder.encode(input)` | `"&lt;tag&gt;"` |
| Ampersand encoded | happy path | input `"a&b"` | encode | `"a&amp;b"` |
| Quotes encoded for attributes | happy path | input `"\"value\""` | encode | `"&quot;value&quot;"` |

**Feature: sanitize_uri_scheme**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| HTTPS allowed | happy path | input `"https://example.com"` | `sanitize_uri_scheme(input)` | returns `Ok` |
| HTTP allowed | happy path | input `"http://example.com"` | sanitize | returns `Ok` |
| mailto allowed | happy path | input `"mailto:user@example.com"` | sanitize | returns `Ok` |
| javascript: blocked | invalid input | input `"javascript:alert(1)"` | sanitize | returns `Err` |
| data: blocked | invalid input | input `"data:text/html,<script>..."` | sanitize | returns `Err` |
| vbscript: blocked | invalid input | input `"vbscript:msgbox"` | sanitize | returns `Err` |
| Case-insensitive | invalid input | input `"JAVASCRIPT:alert(1)"` | sanitize | returns `Err` |
| Relative URL allowed | happy path | input `"/path/to/resource"` | sanitize | returns `Ok` |

**Feature: Cross-origin security headers**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| COEP header present | happy path | request through SecurityHeadersLayer | inspect response | `Cross-Origin-Embedder-Policy: require-corp` |
| COOP header present | happy path | request through SecurityHeadersLayer | inspect response | `Cross-Origin-Opener-Policy: same-origin` |
| CORP header present | happy path | request through SecurityHeadersLayer | inspect response | `Cross-Origin-Resource-Policy: same-origin` |
| Existing headers preserved | backward compat | request through SecurityHeadersLayer | inspect response | HSTS, CSP, XFO, XCTO all still present |

#### Regression Tests

- All existing tests in `crates/secure_output/tests/` must pass
- All existing tests in `crates/secure_boundary/tests/` must pass
- `cargo test --workspace` must be green

#### Compatibility Checklist

- [ ] `HtmlEncoder.encode("<script>")` unchanged
- [ ] `UrlEncoder.encode("hello world")` unchanged
- [ ] `JsonEncoder.encode("</script>")` unchanged
- [ ] `SecurityHeadersLayer::default()` still includes HSTS, CSP, XFO, XCTO, Permissions-Policy, Cache-Control
- [ ] Existing header builder methods (`with_csp`, `with_hsts`) still work

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full test suite green
- compatibility checklist complete
- ARCHITECTURE.md updated with new encoders and headers
- README.md updated with new encoder examples
- lessons file written, completion summary written, tracker updated

---

### Milestone 13 — Real Key Provider Integrations

**Goal**: Implement `VaultKeyProvider` (HashiCorp Vault Transit secrets engine), `AwsKmsKeyProvider` (AWS KMS), and `resolve_secret()` for `SecretReference` resolution in `secure_data`. All cloud providers behind Cargo feature flags.

**Context**: `secure_data` currently only has `StaticDevKeyProvider` — a dev-only XOR-based key wrapping provider. `SecretReference::parse()` handles `vault://`, `kms://`, `env://` URIs but the returned struct is never resolved to actual secret values. The `KeyProvider` trait is sealed. For production deployments targeting critical infrastructure, real KMS integration is essential.

**Important design rule**: The `KeyProvider` trait is sealed — new providers must be added inside `crates/secure_data/`. Each provider is behind a Cargo feature flag (`vault`, `aws-kms`) and off by default. The workspace must build and all tests must pass without any feature enabled. `env://` resolution must NOT read environment variables at parse time — only when `resolve_secret()` is called.

**Refactor budget**: `Minimal local refactor permitted in listed files only` — specifically `kms.rs` to add provider implementations to the sealed trait system.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Key aliases, wrapped data keys, secret reference URIs, provider credentials |
| Outputs | Data encryption keys, unwrapped keys, resolved secret strings |
| Interfaces touched | `secure_data` internal modules (additive), `SecretReference` resolution (new public function) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_data/src/kms.rs`, `crates/secure_data/src/config.rs`, `crates/secure_data/src/envelope.rs`, `crates/secure_data/src/error.rs`, `crates/secure_data/src/lib.rs`, `crates/secure_data/Cargo.toml` |
| New files allowed | `crates/secure_data/src/providers/mod.rs`, `crates/secure_data/src/providers/vault.rs`, `crates/secure_data/src/providers/aws_kms.rs`, `crates/secure_data/src/resolve.rs`, test files |
| New dependencies allowed | `reqwest = { version = "0.12", features = ["json", "rustls-tls"], optional = true }` (for Vault HTTP client, behind `vault` feature), `aws-sdk-kms = { version = "1", optional = true }` + `aws-config = { version = "1", optional = true }` (behind `aws-kms` feature) |
| Migration allowed | `no` |
| Compatibility commitments | `StaticDevKeyProvider` unchanged. All existing encryption/decryption tests pass. `EnvelopeEncrypted` struct unchanged. `encrypt_for_storage()`/`decrypt_for_use()` signatures unchanged. |
| Forbidden shortcuts | No hard-coded credentials. No `unwrap()` in production code. No skipping TLS verification. `env://` must not eagerly read env vars at parse time. |

#### Out of Scope / Must Not Do

- Do not implement Azure Key Vault (deferred — can be added later following the same pattern)
- Do not change the sealed nature of `KeyProvider` to make it open
- Do not add persistent `KeyRingStore` (deferred to a future milestone)
- Do not change `secure_identity`, `secure_authz`, or `secure_boundary`

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_data/src/providers/mod.rs` | NEW: module declarations for vault, aws_kms |
| `crates/secure_data/src/providers/vault.rs` | NEW: `VaultKeyProvider` — Vault Transit `generate_data_key`, `unwrap_data_key` |
| `crates/secure_data/src/providers/aws_kms.rs` | NEW: `AwsKmsKeyProvider` — AWS KMS `GenerateDataKey`, `Decrypt` |
| `crates/secure_data/src/resolve.rs` | NEW: `resolve_secret()` function for `SecretReference` |
| `crates/secure_data/src/kms.rs` | Add `Sealed` impl for new providers |
| `crates/secure_data/src/lib.rs` | Add module declarations and conditional re-exports |
| `crates/secure_data/src/error.rs` | Add error variants for provider failures |
| `crates/secure_data/Cargo.toml` | Add feature-gated dependencies |
| `crates/secure_data/tests/sunlit_imp_vault.rs` | NEW: BDD tests for VaultKeyProvider (with mock HTTP server) |
| `crates/secure_data/tests/sunlit_imp_aws_kms.rs` | NEW: BDD tests for AwsKmsKeyProvider (with mock) |
| `crates/secure_data/tests/sunlit_imp_resolve.rs` | NEW: BDD tests for resolve_secret() |
| `crates/secure_data/tests/e2e_sunlit_imp_m13.rs` | NEW: E2E tests |

#### BDD Acceptance Scenarios

**Feature: VaultKeyProvider**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Generate data key | happy path | Vault Transit endpoint available | `generate_data_key(alias)` | returns (DEK, WrappedDEK, version) |
| Unwrap data key | happy path | previously wrapped key | `unwrap_data_key(wrapped, alias, version)` | returns original DEK |
| Vault unavailable | partial failure | Vault endpoint down | `generate_data_key(alias)` | returns `DataError::ProviderUnavailable` |
| Invalid auth token | invalid input | expired Vault token | any operation | returns `DataError::ProviderAuthError` |
| Encrypt/decrypt roundtrip via Vault | happy path | VaultKeyProvider wired to envelope API | `encrypt_for_storage` then `decrypt_for_use` | plaintext recovered |

**Feature: AwsKmsKeyProvider**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Generate data key | happy path | AWS KMS key alias exists | `generate_data_key(alias)` | returns (DEK, WrappedDEK, version) |
| Unwrap data key | happy path | previously wrapped key | `unwrap_data_key(wrapped, alias, version)` | returns original DEK |
| KMS unavailable | partial failure | AWS endpoint unreachable | any operation | returns `DataError::ProviderUnavailable` |

**Feature: resolve_secret**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Resolve env:// | happy path | env var `TEST_SECRET` set to `"my-secret"` | `resolve_secret(&ref)` where ref is `env://TEST_SECRET` | returns `SecretString("my-secret")` |
| Resolve env:// missing | invalid input | env var not set | `resolve_secret(&ref)` | returns `DataError::SecretNotFound` |
| Resolve vault:// | happy path | Vault KV endpoint available | `resolve_secret(&ref)` | returns secret value |
| Invalid scheme | invalid input | unparseable reference | `resolve_secret(&ref)` | returns `DataError::InvalidSecretReference` |

#### Regression Tests

- All existing tests in `crates/secure_data/tests/` pass without any feature flags
- `cargo test -p secure_data` passes
- `cargo test -p secure_data --features vault` passes (with mock server)
- `cargo test -p secure_data --features aws-kms` passes (with mock)

#### Definition of Done

- all BDD scenarios pass
- E2E validations pass
- full test suite green (with and without features)
- feature flags documented in README.md
- ARCHITECTURE.md updated with provider descriptions
- lessons/completion files written, tracker updated

---

### Milestone 14 — Identity & Authentication Hardening

**Goal**: Add RS256/ES256 asymmetric JWT validation, JWKS endpoint fetch with key rotation cache, and `ApiKeyAuthenticator` with constant-time comparison to `secure_identity`.

**Context**: `secure_identity` currently supports only HS256 JWT validation with a static shared secret. Real identity providers (Keycloak, Auth0, Okta) issue RS256 or ES256 tokens and publish public keys via JWKS endpoints. The `TokenKind::ApiKey` variant exists but has no implementation. Session storage is in-memory only.

**Important design rule**: `TokenValidator` must support multiple algorithms via configuration. JWKS key cache must have a configurable TTL and support background refresh. `ApiKeyAuthenticator` must use constant-time comparison (via `ring::constant_time::verify_slices_are_equal` or `subtle::ConstantTimeEq`) to prevent timing side-channels. The `Authenticator` sealed trait must have `Sealed` impl added for `ApiKeyAuthenticator`.

**Refactor budget**: `Minimal local refactor permitted in listed files only` — specifically `token.rs` to support multiple algorithm configurations.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | JWT tokens (RS256/ES256 signed), JWKS endpoints, API keys |
| Outputs | `AuthenticatedIdentity` on success, `IdentityError` on failure |
| Interfaces touched | `secure_identity` public API (additive), `TokenValidatorConfig` (extended) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_identity/src/token.rs`, `crates/secure_identity/src/authenticator.rs`, `crates/secure_identity/src/error.rs`, `crates/secure_identity/src/lib.rs`, `crates/secure_identity/Cargo.toml` |
| New files allowed | `crates/secure_identity/src/jwks.rs`, `crates/secure_identity/src/api_key.rs`, test files |
| New dependencies allowed | `reqwest = { version = "0.12", features = ["json", "rustls-tls"], optional = true }` (for JWKS fetch, behind `jwks` feature) |
| Migration allowed | `no` |
| Compatibility commitments | Existing HS256 `TokenValidator` with `TokenValidatorConfig { secret, issuer, audience }` must behave identically. All existing tests pass. `IdentitySource` impl on `TokenValidator` unchanged for HS256 usage. |
| Forbidden shortcuts | No non-constant-time key comparison. No skipping signature verification. No accepting `alg: none`. |

#### Out of Scope / Must Not Do

- Do not implement full OIDC discovery (deferred)
- Do not add persistent session backends (deferred)
- Do not implement TOTP MFA (deferred)
- Do not change `secure_authz`, `secure_boundary`, or `secure_output`

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_identity/src/token.rs` | Extend `TokenValidator` to accept RS256/ES256 `DecodingKey`; add algorithm configuration |
| `crates/secure_identity/src/jwks.rs` | NEW: `JwksKeyStore` — fetch, parse, cache JWKS with TTL |
| `crates/secure_identity/src/api_key.rs` | NEW: `ApiKeyAuthenticator` with constant-time comparison |
| `crates/secure_identity/src/authenticator.rs` | Add `Sealed` impl for `ApiKeyAuthenticator` |
| `crates/secure_identity/src/error.rs` | Add error variants if needed |
| `crates/secure_identity/src/lib.rs` | Add module declarations and re-exports |
| `crates/secure_identity/Cargo.toml` | Add optional `reqwest` dependency behind `jwks` feature |
| Test files | NEW: BDD + E2E tests |

#### BDD Acceptance Scenarios

**Feature: Asymmetric JWT validation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid RS256 token accepted | happy path | RS256-signed JWT with valid claims | `TokenValidator.authenticate(token)` | returns `AuthenticatedIdentity` |
| Valid ES256 token accepted | happy path | ES256-signed JWT with valid claims | authenticate | returns identity |
| Expired RS256 token rejected | invalid input | RS256 JWT past `exp` | authenticate | `IdentityError::TokenExpired` |
| Wrong key rejection | invalid input | RS256 JWT signed with different key | authenticate | `IdentityError::TokenMalformed` |
| HS256 still works | backward compat | HS256 JWT (existing config) | authenticate | returns identity |

**Feature: JWKS key store**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Fetch keys from endpoint | happy path | JWKS endpoint returns valid keys | `JwksKeyStore::fetch(url)` | keys cached |
| Cache hit avoids refetch | happy path | keys cached within TTL | second fetch | returns cached keys, no HTTP call |
| Cache expired triggers refetch | happy path | TTL exceeded | next validation | refreshes keys from endpoint |
| Endpoint unavailable | partial failure | JWKS endpoint down, cache warm | validation | uses cached keys, logs warning |
| Endpoint unavailable, no cache | partial failure | JWKS endpoint down, cold start | validation | `IdentityError::ProviderUnavailable` |

**Feature: API key authentication**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid API key accepted | happy path | key matches stored key | `ApiKeyAuthenticator.authenticate(key)` | returns identity |
| Invalid API key rejected | invalid input | key does not match | authenticate | `IdentityError::InvalidCredentials` |
| Empty key rejected | empty state | empty string | authenticate | `IdentityError::InvalidCredentials` |
| Timing safe | security | valid vs invalid key comparison times | measure | no significant timing difference (Welch's t-test) |

#### Definition of Done

- all BDD scenarios pass
- E2E validations pass
- existing HS256 tests unchanged and passing
- timing test for API key comparison (marked `#[ignore]`)
- ARCHITECTURE.md updated
- lessons/completion files written, tracker updated

---

### Milestone 15 — Authorization Fixes + Error Handling Middleware

**Goal**: Fix `CacheKey` in `secure_authz` to include `tenant_id`, wire obligation enforcement in `AuthzLayer` middleware, add `ErrorMappingLayer` to `secure_errors` for automatic `AppError` → HTTP response mapping, add task-local error context propagation, and add `retry_after_seconds` to `AppError::RateLimit`.

**Context**: The `CacheKey` in `crates/secure_authz/src/cache.rs` excludes `tenant_id` — two tenants with the same actor/resource/action share cache entries (privacy risk, identified in post-M10 audit). `Decision::Allow` carries `obligations: Vec<String>` but `AuthzLayer` middleware ignores them. Every handler currently calls `into_response_parts()` manually — there is no middleware for automatic error mapping. `AppError::RateLimit` provides no `retry_after` data for 429 responses.

**Important design rule**: The `CacheKey` fix is a correctness fix, not a feature — it must not break existing cache behavior for single-tenant scenarios. The `ErrorMappingLayer` must be opt-in (not forced into every middleware stack) and must work with any axum handler returning `Result<impl IntoResponse, AppError>`.

**Refactor budget**: `Minimal local refactor permitted in listed files only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Authorization decisions, error results from handlers |
| Outputs | Correctly tenant-scoped cache, obligation-checked responses, auto-mapped error responses |
| Interfaces touched | `secure_authz::cache::CacheKey` (fix), `secure_authz::middleware::AuthzLayer` (enhanced), `secure_errors` public API (additive) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_authz/src/cache.rs`, `crates/secure_authz/src/middleware.rs`, `crates/secure_authz/src/decision.rs`, `crates/secure_errors/src/http.rs`, `crates/secure_errors/src/kind.rs`, `crates/secure_errors/src/lib.rs` |
| New files allowed | `crates/secure_errors/src/middleware.rs`, `crates/secure_errors/src/context_propagation.rs`, test files |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | Existing `Authorizer` trait unchanged. Existing `AppError` variants unchanged (new field is additive). Existing `into_response_parts()` unchanged. |
| Forbidden shortcuts | No removing obligation field from Decision. No silently swallowing obligation check failures. |

#### Out of Scope / Must Not Do

- Do not add policy hot-reload (deferred)
- Do not add row-level security (deferred)
- Do not change `secure_boundary`, `secure_output`, `secure_identity`, or `secure_data`

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_authz/src/cache.rs` | Add `tenant_id: Option<String>` to `CacheKey` |
| `crates/secure_authz/src/middleware.rs` | Add obligation checking after `Decision::Allow` |
| `crates/secure_errors/src/middleware.rs` | NEW: `ErrorMappingLayer` tower middleware |
| `crates/secure_errors/src/context_propagation.rs` | NEW: task-local context for request_id, actor_id, tenant_id |
| `crates/secure_errors/src/kind.rs` | Add `retry_after_seconds: Option<u64>` to `AppError::RateLimit` |
| `crates/secure_errors/src/http.rs` | Map `retry_after_seconds` to `Retry-After` header |
| `crates/secure_errors/src/lib.rs` | Add module declarations and re-exports |
| Test files | NEW: BDD + E2E tests |

#### BDD Acceptance Scenarios

**Feature: Tenant-scoped cache**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Same actor different tenants get separate cache entries | happy path | actor A in tenant X allowed; actor A in tenant Y denied | check cache for both | different decisions returned |
| Single-tenant cache still works | backward compat | no tenant_id on subject or resource | authorization | cache works as before |

**Feature: Obligation enforcement**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Decision with no obligations passes | happy path | `Decision::Allow { obligations: vec![] }` | middleware | request proceeds |
| Decision with unmet obligation blocked | invalid input | `Decision::Allow { obligations: vec!["require_mfa"] }` | middleware, no MFA context | 403 returned |

**Feature: ErrorMappingLayer**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| AppError::Validation auto-mapped | happy path | handler returns `Err(AppError::Validation)` | through ErrorMappingLayer | 400 response with PublicError |
| AppError::Forbidden auto-mapped | happy path | handler returns `Err(AppError::Forbidden)` | through layer | 403 |
| AppError::RateLimit with retry-after | happy path | handler returns `Err(AppError::RateLimit { retry_after_seconds: Some(30) })` | through layer | 429 with `Retry-After: 30` header |
| Non-error responses pass through | happy path | handler returns `Ok(Json(...))` | through layer | 200 unchanged |

#### Definition of Done

- all BDD scenarios pass, E2E validations pass, full test suite green
- ARCHITECTURE.md updated with cache fix and error middleware
- lessons/completion files written, tracker updated

---

### Milestone 16 — Security Smoke-Test Microservice

**Goal**: Create `crates/secure_smoke_service/` — a purpose-built axum microservice with 35+ routes, each exercising a specific security control from the library crates against a known attack class. Include comprehensive integration tests (`smoke_tests.rs`) that fire every attack payload and verify every control holds. Include an `openapi.yaml` for OWASP ZAP scanning.

**Context**: The existing `secure_reference_service` is a CRUD demo with in-memory storage and `DevAuthLayer`. It proves integration but does not exercise every attack class. The smoke service is a verification tool — not a demo. Every route maps to a specific attack class from the IMPROVEMENT_PROPOSAL.md tables.

**Important design rule**: The smoke service must use `TokenValidator` (not `DevAuthLayer`) for JWT authentication on protected routes, exercising the real identity path. Safe types from M11, encoders from M12, and error middleware from M15 must all be used. Routes must follow the naming convention `/smoke/<category>/<attack-class>`.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | HTTP requests with attack payloads, valid/invalid JWTs, malicious headers |
| Outputs | Correct HTTP status codes, safe response bodies, security events, security headers |
| Interfaces touched | All library crate public APIs (consumed, not changed) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_reference_service/src/main.rs`, `crates/secure_reference_service/src/lib.rs`, all `IMPROVEMENT_PROPOSAL.md` route tables |
| New files allowed | Entire `crates/secure_smoke_service/` directory |
| New dependencies allowed | Same as `secure_reference_service` — `axum`, `tower`, `tower-http`, `tokio`, `serde`, `serde_json`, `uuid`, `time`, `tracing`, `tracing-subscriber`, `http`, `hyper`, `thiserror`. Additionally: `utoipa = "5"` for OpenAPI generation. |
| Migration allowed | `no` |
| Compatibility commitments | No changes to any existing crate. `secure_reference_service` untouched. |
| Forbidden shortcuts | No `DevAuthLayer` on protected routes (use `TokenValidator`). No placeholder routes that don't actually test the control. No `unwrap()` in production code. |

#### Out of Scope / Must Not Do

- Do not change any existing crate source code
- Do not add OWASP ZAP integration (that is M17)
- Do not add cloud provider usage to the smoke service (use `StaticDevKeyProvider`)

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_smoke_service/Cargo.toml` | NEW: crate manifest |
| `crates/secure_smoke_service/src/main.rs` | NEW: Service entrypoint |
| `crates/secure_smoke_service/src/lib.rs` | NEW: `build_router()` for tests |
| `crates/secure_smoke_service/src/routes/mod.rs` | NEW: route module declarations |
| `crates/secure_smoke_service/src/routes/input.rs` | NEW: `/smoke/xss`, `/smoke/sqli`, `/smoke/cmdi`, `/smoke/path-traversal`, `/smoke/xxe`, `/smoke/deserialization`, `/smoke/mass-assignment`, `/smoke/header-injection`, `/smoke/unicode-bypass`, `/smoke/body-bomb`, `/smoke/deep-nesting`, `/smoke/field-flood` |
| `crates/secure_smoke_service/src/routes/output.rs` | NEW: `/smoke/reflect-html`, `/smoke/reflect-url`, `/smoke/reflect-json`, `/smoke/headers` |
| `crates/secure_smoke_service/src/routes/auth.rs` | NEW: `/smoke/auth/jwt`, `/smoke/auth/expired`, `/smoke/auth/alg-none`, `/smoke/auth/tampered`, `/smoke/auth/wrong-issuer`, `/smoke/auth/session` |
| `crates/secure_smoke_service/src/routes/authz.rs` | NEW: `/smoke/authz/allow`, `/smoke/authz/deny`, `/smoke/authz/cross-tenant`, `/smoke/authz/privilege-escalation`, `/smoke/authz/idor` |
| `crates/secure_smoke_service/src/routes/data.rs` | NEW: `/smoke/encrypt`, `/smoke/decrypt`, `/smoke/decrypt-tampered`, `/smoke/secret-debug`, `/smoke/key-rotation` |
| `crates/secure_smoke_service/src/routes/errors.rs` | NEW: `/smoke/error/internal`, `/smoke/error/dependency`, `/smoke/error/panic`, `/smoke/error/validation` |
| `crates/secure_smoke_service/src/routes/events.rs` | NEW: `/smoke/events/log-injection`, `/smoke/events/redaction` |
| `crates/secure_smoke_service/src/state.rs` | NEW: `AppState` |
| `crates/secure_smoke_service/src/config.rs` | NEW: `SecurityConfig` |
| `crates/secure_smoke_service/openapi.yaml` | NEW: OpenAPI 3.1 spec |
| `crates/secure_smoke_service/tests/smoke_tests.rs` | NEW: Full attack-class integration tests |
| `crates/secure_smoke_service/tests/e2e_sunlit_imp_m16.rs` | NEW: E2E runtime validation |
| `Cargo.toml` (workspace root) | Add `secure_smoke_service` to workspace members |

#### BDD Acceptance Scenarios

The full route/attack/expected-result tables from Section 2.3 of IMPROVEMENT_PROPOSAL.md define the acceptance criteria. Each row in those tables becomes a test case in `smoke_tests.rs`. Key scenarios:

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| XSS payload HTML-encoded | happy path | POST `/smoke/xss` with `{"content": "<script>alert(1)</script>"}` | server reflects content | response body contains `&lt;script&gt;`, not raw `<script>` |
| Path traversal rejected | invalid input | GET `/smoke/path-traversal/../../etc/passwd` | server processes | 422 with safe error code |
| Deep nesting rejected | invalid input | POST `/smoke/deep-nesting` with 500-deep JSON | server processes | 422 |
| Valid JWT accepted | happy path | POST `/smoke/auth/jwt` with valid HS256 token | server validates | 200 with actor info |
| Expired JWT rejected | invalid input | POST `/smoke/auth/expired` with expired token | server validates | 401 |
| Cross-tenant blocked | invalid input | GET `/smoke/authz/cross-tenant` with tenant A token for tenant B resource | server checks authz | 403 |
| Tampered ciphertext rejected | invalid input | POST `/smoke/decrypt-tampered` with modified ciphertext | server decrypts | 400 |
| Panic caught safely | invalid input | GET `/smoke/error/panic` | handler panics | 500 with no stack trace |
| Log injection sanitised | invalid input | POST `/smoke/events/log-injection` with `"field\nInjected"` | server logs | no raw `\n` in log output |
| All security headers present | happy path | GET `/smoke/headers` | inspect response | HSTS, CSP, XFO, XCTO, COEP, COOP, CORP present |

#### Regression Tests

- `cargo test --workspace` must pass (including all M0–M15 tests)
- `secure_reference_service` tests unchanged

#### Definition of Done

- 35+ routes implemented covering every attack class in IMPROVEMENT_PROPOSAL.md
- `smoke_tests.rs` has a test for every route/attack combination
- OpenAPI spec covers all routes with request/response schemas
- `cargo test -p secure_smoke_service` passes
- `cargo build --workspace` passes
- ARCHITECTURE.md updated, README.md updated with smoke service documentation
- lessons/completion files written, tracker updated

---

### Milestone 17 — OWASP ZAP DAST Integration

**Goal**: Integrate OWASP ZAP (Checkmarx ZAP) as an automated DAST scanner against `secure_smoke_service`. Create the scan script, ZAP configuration, alert baseline, scan rules, and CI workflow. The build must fail on high/critical ZAP findings.

**Context**: ZAP is the industry-standard open-source web application security scanner. It will scan the smoke service's OpenAPI spec, perform active and passive security checks, and produce an HTML report. This validates the security controls from an external attacker's perspective. Docker is required to run ZAP.

**Important design rule**: The ZAP scan must use the API scan mode against the OpenAPI spec from M16. Authentication must be configured with a valid JWT so ZAP can test authenticated routes. A baseline file excludes known false positives. The CI workflow only runs on Linux (Docker required).

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Running `secure_smoke_service`, OpenAPI spec |
| Outputs | ZAP HTML/JSON report, CI pass/fail gate |
| Interfaces touched | CI workflow, scripts directory |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/secure_smoke_service/openapi.yaml`, `scripts/audit.sh` |
| New files allowed | `scripts/zap_scan.sh`, `scripts/zap_check.py`, `scripts/zap-rules.tsv`, `scripts/zap-baseline.json`, `.github/workflows/zap.yml` (if CI directory exists) |
| New dependencies allowed | Docker (runtime, not Cargo dependency). `python3` for report parsing. |
| Migration allowed | `no` |
| Compatibility commitments | No changes to any Rust crate. Existing CI workflows unchanged. |
| Forbidden shortcuts | No disabling high/critical findings in baseline without written justification. No running ZAP without authentication configured. |

#### Out of Scope / Must Not Do

- Do not change any Rust source code
- Do not change the smoke service
- Do not add new routes or capabilities

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `scripts/zap_scan.sh` | NEW: Script to build, start smoke service, run ZAP Docker container, collect report |
| `scripts/zap_check.py` | NEW: Parse ZAP JSON report, exit non-zero on high/critical findings |
| `scripts/zap-rules.tsv` | NEW: ZAP scan rule customisation (SQLi confidence threshold, XSS max strength, etc.) |
| `scripts/zap-baseline.json` | NEW: Known false positives with justification |
| `.github/workflows/zap.yml` | NEW: CI workflow for ZAP scan (if `.github/workflows/` exists) |

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| ZAP finds no high/critical XSS | happy path | smoke service running, ZAP scans `/smoke/reflect-html` | ZAP active scan | no high/critical XSS alerts |
| ZAP finds no missing security headers | happy path | smoke service running | ZAP passive scan | CSP, HSTS, XFO, XCTO all present |
| ZAP detects safe error handling | happy path | ZAP tests error routes | passive scan | no information disclosure alerts |
| ZAP scan script exits 0 on clean scan | happy path | all controls hold | `bash scripts/zap_scan.sh` | exit code 0 |
| ZAP scan script exits non-zero on finding | failure mode | simulated high finding | `python3 scripts/zap_check.py` | exit code 1 |

#### Definition of Done

- `scripts/zap_scan.sh` runs successfully against the smoke service
- ZAP produces HTML and JSON reports
- `scripts/zap_check.py` parses report and gates on high/critical
- baseline file documents any accepted findings with justification
- CI workflow defined (even if `.github/workflows/` doesn't exist yet — create it)
- README.md updated with ZAP scan instructions
- lessons/completion files written, tracker updated

---

### Milestone 18 — Observability + Advanced Features

**Goal**: Add HMAC-signed audit chain entries, additional security event sinks (File, HTTP webhook), async batched event emission, distributed tracing middleware, cross-origin headers documentation, and SBOM generation configuration.

**Context**: The `security_events` audit chain uses SHA-256 hash linking for tamper detection but cannot detect forgery (an attacker can recompute the chain). HMAC signing with a secret key adds forgery detection. The current sinks (`StdoutJsonSink`, `TracingSink`) are sealed — production deployments need file and webhook sinks for SIEM integration. Events are emitted synchronously one at a time — high-load services need batching.

**Important design rule**: HMAC signing key must be provided via `secure_data::SecretString` — never a raw string. Sinks must remain sealed but new implementations can be added inside the crate. The batch emitter must flush on interval AND on buffer capacity. The tracing middleware must be a Tower `Layer` that automatically sets `trace_id` and `request_id` on the security event context.

**Refactor budget**: `Minimal local refactor permitted in listed files only` — specifically `sink.rs` to add new sink implementations and `audit_chain.rs` to add HMAC variant.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Security events, HMAC signing keys, file paths, webhook URLs |
| Outputs | HMAC-signed audit chain, events written to files/webhooks, batched emission |
| Interfaces touched | `security_events` internal modules (additive) |
| Files allowed to change | See table below |
| Files to read before changing anything | `crates/security_events/src/audit_chain.rs`, `crates/security_events/src/sink.rs`, `crates/security_events/src/emit.rs`, `crates/security_events/src/lib.rs` |
| New files allowed | `crates/security_events/src/hmac_chain.rs`, `crates/security_events/src/batch.rs`, `crates/security_events/src/tracing_middleware.rs`, test files |
| New dependencies allowed | `hmac = "0.12"` and `sha2 = "0.10"` (for HMAC-SHA256 signing) |
| Migration allowed | `no` |
| Compatibility commitments | Existing `AuditChain` unchanged. Existing `StdoutJsonSink` and `TracingSink` unchanged. Existing `emit_security_event()` unchanged. |
| Forbidden shortcuts | HMAC key must not be logged or included in Debug output. File sink must handle I/O errors gracefully (log warning, do not panic). |

#### Out of Scope / Must Not Do

- Do not unseal `SecuritySink` trait (add new sealed implementations only)
- Do not change `secure_boundary`, `secure_output`, `secure_identity`, or `secure_authz`
- Do not implement Syslog sink (deferred)
- Do not implement TOTP MFA (deferred)

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/security_events/src/hmac_chain.rs` | NEW: `HmacAuditChain` — HMAC-SHA256 signed audit entries |
| `crates/security_events/src/sink.rs` | Add `FileSink` and `HttpWebhookSink` (sealed implementations) |
| `crates/security_events/src/batch.rs` | NEW: `BatchEmitter` with configurable buffer size and flush interval |
| `crates/security_events/src/tracing_middleware.rs` | NEW: Tower `Layer` that auto-populates trace_id/request_id |
| `crates/security_events/src/lib.rs` | Add module declarations and re-exports |
| `crates/security_events/Cargo.toml` | Add `hmac`, `sha2` dependencies |
| Test files | NEW: BDD + E2E tests |

#### BDD Acceptance Scenarios

**Feature: HMAC-signed audit chain**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Chain with HMAC signature | happy path | HMAC key provided | append events | each entry has HMAC signature |
| Tampered entry detected | invalid input | modify event content after signing | `verify()` | returns `Err` |
| Forged chain detected | invalid input | recompute hashes without HMAC key | `verify()` | returns `Err` |

**Feature: File sink**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Events written to file | happy path | file path configured | emit events | NDJSON lines appended to file |
| File I/O error handled | partial failure | read-only file path | emit event | warning logged, no panic |

**Feature: Batch emitter**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Buffer flushes at capacity | happy path | buffer size 10 | emit 10 events | batch flushed to sink |
| Buffer flushes at interval | happy path | interval 1 second | emit 3 events, wait 1.5s | batch flushed |

#### Definition of Done

- all BDD scenarios pass, E2E validations pass, full test suite green
- ARCHITECTURE.md updated with HMAC chain, new sinks, batch emitter, tracing middleware
- README.md updated with SBOM instructions
- lessons/completion files written, tracker updated

---

## Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 11 | Safe types section, SecureXml, depth/field limits, header sanitise | Safe types usage example | Review | THREAT_MODEL.md traceability |
| 12 | New encoder descriptions, cross-origin headers | Encoder examples | Review | — |
| 13 | VaultKeyProvider, AwsKmsKeyProvider, resolve_secret | Provider feature flags, usage examples | Review | — |
| 14 | Asymmetric JWT, JWKS, API key auth | Identity hardening section | Review | — |
| 15 | Cache fix, obligation enforcement, ErrorMappingLayer | Error middleware usage | Review | — |
| 16 | Smoke service architecture | Smoke service section, route table | `target/` patterns | IMPROVEMENT_PROPOSAL.md status |
| 17 | ZAP pipeline description | ZAP scan instructions | ZAP report patterns | — |
| 18 | HMAC chain, sinks, batch emitter, tracing middleware | Observability section | Review | — |

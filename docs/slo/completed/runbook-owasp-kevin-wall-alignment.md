# OWASP/ESAPI Alignment Improvements — SunLit Security Libraries (AI-First Runbook v3)

> **Purpose**: Align SunLit Security Libraries with the OWASP Proactive Controls 2024, ESAPI design principles (Kevin Wall, OWASP ESAPI co-lead), and close all identified security control gaps across the eight security crates.
> **Audience**: AI coding agents first, humans second. This document is written to reduce ambiguity, prevent scope drift, and improve code quality with the same model capability.
> **How to use**: Work through milestones sequentially. Before starting any milestone, read its full section and the Global Execution Rules. After completing it, follow the Global Exit Rules. Never skip ahead. Never silently widen scope.
> **Prerequisite reading**: [ARCHITECTURE.md](../../../ARCHITECTURE.md), [README.md](../../../README.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), [IMPROVEMENT_PROPOSAL.md](../lessons/IMPROVEMENT_PROPOSAL.md)

---

## Runbook Metadata

- **Runbook ID**: `sunlit-owasp-align`
- **Prefix for test files and lessons files**: `sunlit-owasp`
- **Primary stack**: `Rust + axum + tower`
- **Primary package/app names**: `security_core`, `secure_errors`, `security_events`, `secure_boundary`, `secure_output`, `secure_identity`, `secure_authz`, `secure_data`, `secure_reference_service`, `secure_smoke_service`
- **Default test commands**:
  - Backend: `cargo test --workspace`
  - E2E backend: `cargo test --workspace --test 'e2e_*'`
  - Build/boot: `cargo build --workspace`
  - Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- **Allowed new dependencies by default**: `none` (each milestone declares its own)
- **Schema/config migration allowed by default**: `no`
- **Public interfaces that must remain stable unless explicitly listed otherwise**:
  - `security_core::IdentitySource` trait
  - `secure_errors::kind::AppError` enum
  - `secure_boundary::extract::SecureJson<T>` extractor
  - `secure_output::OutputEncoder` trait
  - `secure_authz::enforcer::Authorizer` trait
  - `secure_data::envelope::encrypt_for_storage` / `decrypt_for_use` functions
  - `security_events::SecurityEvent` struct
  - All existing HTTP routes in `secure_reference_service` and `secure_smoke_service`

---

## Research Summary: Kevin Wall / ESAPI Design Principles & OWASP Proactive Controls 2024

### Kevin Wall's ESAPI Security Library Design Principles

Kevin Wall, co-lead of the OWASP ESAPI project, has shaped security library design through decades of work on the Enterprise Security API. His core principles, distilled from ESAPI's architecture and his stewardship of the project, are:

1. **Interface-first design with swappable reference implementations** — Every security control is defined as an interface (trait). Consumers code against the interface; implementations are pluggable. ESAPI provides reference implementations for each control, but organizations can swap in their own without changing calling code.

2. **Encoder must handle ALL output contexts** — ESAPI's `Encoder` interface provides `encodeForHTML()`, `encodeForHTMLAttribute()`, `encodeForCSS()`, `encodeForJavaScript()`, `encodeForURL()`, `encodeForXML()`, `encodeForXMLAttribute()`, `encodeForLDAP()`, `encodeForDN()`, `encodeForOS()`, and `encodeForSQL()`. Missing even one context leaves an injection gap. Wall has repeatedly emphasized that partial encoding coverage is worse than no library — because developers assume they are safe.

3. **Validator must support both allowlist and denylist patterns** — The reference validator supports positive validation (allowlist — "only these characters") and negative screening (denylist — "never these patterns"). Allowlisting is the primary defense; denylisting aids detection. Input validation is not a substitute for output encoding.

4. **Crypto must support algorithm agility and key rotation without code changes** — Application code should never hard-code algorithm names. The crypto subsystem should support upgrading algorithms (e.g., AES-128 → AES-256, SHA-1 → SHA-256) via configuration, and key rotation should happen transparently. Wall has advocated that libraries must handle key versioning so that old ciphertext can still be decrypted after a key rotation.

5. **Security events separated from diagnostic logging** — Security-relevant events (authentication, authorization, input validation failures) must be structurally different from application diagnostic logs. They must support classification-driven redaction (PII never appears in security logs) and log injection prevention. Wall has noted that conflating security events with `log.info()` makes incident response nearly impossible.

6. **Errors must never leak internal details to clients** — The error handling layer must map internal errors (SQL exception text, file paths, stack traces) to safe public error codes. This is a hard requirement, not a soft recommendation. Wall's position: if an error message contains a hostname, file path, or exception class name, the security library has failed.

7. **All security controls centralized, not scattered** — Security controls must be library-provided, not left to each developer to implement ad hoc. A centralized security library ensures consistent application of controls across all code paths. Wall: "If you have to write your own input validation regex, the security library hasn't done its job."

### Modernizing ESAPI Principles for Rust (Critical Adaptation Notes)

ESAPI was designed in 2007–2010 for Java — a language with runtime reflection, interface-based DI containers, checked exceptions, and heavyweight OOP patterns. Directly porting ESAPI's architecture to Rust produces Java-isms that fight the language instead of leveraging it. The principles above must be **adapted**, not copied:

| ESAPI Pattern | Why It Doesn't Fit Rust | Rust-Idiomatic Alternative |
|---|---|---|
| Stateless `Encoder` objects (`HtmlEncoder` struct with no fields) | Java needs objects for polymorphism. Rust has modules and free functions. A zero-field struct exists only to satisfy the trait — it adds indirection for no benefit. | **Free functions as primary API** (`secure_output::html::encode(s)`), with trait impl available for generic contexts. Both APIs coexist. |
| Factory/DI for swappable implementations | Java relies on IoC containers. Rust has generics, trait bounds, and feature flags — all resolved at compile time. | **Generics `<P: PolicyEngine>`** for compile-time dispatch. **Feature flags** for swappable backends. Trait objects (`dyn Trait`) only when runtime dispatch is genuinely needed (e.g., plugin architectures). |
| Sealed traits on "pluggable" abstractions | ESAPI controls the inheritance hierarchy. Sealing a `KeyProvider` trait defeats the purpose of extensibility. | **Open traits** for abstractions consumers must extend (`KeyProvider`, `SessionStore`, `AuditSink`). **Sealed traits** only for internal implementation details. |
| Stringly-typed identifiers (`String` for actor, tenant, role) | Java commonly uses `String` with conventions. Rust's newtype pattern provides compile-time safety. | **Newtypes** (`ActorId`, `TenantId`, `Role`) backed by `id_newtype!` macro — already established in `security_core`. Extend to authorization subjects. |
| Enterprise complexity (XACML obligations, full ABAC engines, HMAC chain linking) | ESAPI serves Java enterprise apps with thousands of developers. SunLit targets Rust teams who value simplicity and composability. | **Simple, composable building blocks**. Attribute predicates as closures/functions, not a policy language. Per-event HMAC, not chain linking. No obligation enforcement engine. |
| Monolithic `ESAPI.encoder()` facade | Java singleton pattern. Rust prefers explicit imports and zero-cost abstractions. | **Module-level functions** (`use secure_output::html;` then `html::encode(s)`). No global state. |

**Guiding principle**: Take ESAPI's *security coverage goals* (encode all contexts, hash all passwords, sign all audit events) but deliver them through **Rust-native APIs** — free functions, builders, newtypes, feature flags, and zero-cost abstractions. A Rust developer should be able to use these libraries without ever thinking about ESAPI.

### OWASP Proactive Controls 2024 (v4) — Gap Mapping

The 2024 release of the OWASP Top 10 Proactive Controls restructured and expanded the control set. SunLit was originally built against the 2018 numbering. Key changes affecting SunLit:

| 2024 Control | 2018 Equivalent | SunLit Crate | Gap Status |
|---|---|---|---|
| C1: Implement Access Control | C7: Enforce Access Controls | `secure_authz` | ABAC/JIT/JEA gaps |
| C2: Use Cryptography to Protect Data | C8: Protect Data Everywhere | `secure_data` | Password hashing missing; crypto agility partial |
| C3: Validate all Input & Handle Exceptions | C5+C10: Validate All Inputs + Handle Errors | `secure_boundary` + `secure_errors` | Limit enforcement gaps; HTML sanitization missing |
| C4: Address Security from the Start | C1: Define Security Requirements | (architecture) | Already strong (threat-model-first) |
| C5: Secure By Default Configurations | (new) | All crates | Mostly covered; CSP nonce gap |
| C6: Keep your Components Secure | C2: Leverage Security Frameworks | Supply chain | Already strong (cargo-audit/deny/vet) |
| C7: Secure Digital Identities | C6: Implement Digital Identity | `secure_identity` | Password hashing, MFA, OIDC discovery, session backends missing |
| C8: Leverage Browser Security Features | (new, expanded from C4) | `secure_boundary` headers | CORS, CSP nonces, Permissions-Policy, Fetch Metadata missing |
| C9: Implement Security Logging and Monitoring | C9: same | `security_events` | Audit signing, batch emission, sink extensibility gaps |
| C10: Stop Server Side Request Forgery | (new) | `secure_boundary` safe types | SafeUrl exists; Fetch Metadata validation missing |

---

## Milestone Tracker

Update this table as each milestone is completed. This is the single source of truth for progress.

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 18 | Enforce input limits & HTML sanitization | `done` | 2026-04-10 | 2026-04-10 | [sunlit-owasp-m18](../lessons/sunlit-owasp-m18.md) | [sunlit-owasp-m18](../completion/sunlit-owasp-m18.md) |
| 19 | Complete output encoder contexts (LDAP, OS, DN) | `done` | 2026-04-10 | 2026-04-10 | [sunlit-owasp-m19](../lessons/sunlit-owasp-m19.md) | [sunlit-owasp-m19](../completion/sunlit-owasp-m19.md) |
| 20 | Password hashing & secure credential storage | `done` | 2026-04-10 | 2026-04-10 | [sunlit-owasp-m20](../lessons/sunlit-owasp-m20.md) | [sunlit-owasp-m20](../completion/sunlit-owasp-m20.md) |
| 21 | Browser security headers & CORS | `done` | 2026-04-10 | 2026-04-10 | [sunlit-owasp-m21](../lessons/sunlit-owasp-m21.md) | [sunlit-owasp-m21](../completion/sunlit-owasp-m21.md) |
| 22 | Security events hardening | `done` | 2026-04-11 | 2026-04-11 | [sunlit-owasp-m22](../lessons/sunlit-owasp-m22.md) | [sunlit-owasp-m22](../completion/sunlit-owasp-m22.md) |
| 23 | Authorization enhancements (ABAC, time-bounded) | `done` | 2026-04-11 | 2026-04-12 | [sunlit-owasp-m23](../lessons/sunlit-owasp-m23.md) | [sunlit-owasp-m23](../completion/sunlit-owasp-m23.md) |
| 24 | Identity enhancements (OIDC, MFA, sessions) | `done` | 2026-04-12 | 2026-04-12 | [sunlit-owasp-m24](../lessons/sunlit-owasp-m24.md) | [sunlit-owasp-m24](../completion/sunlit-owasp-m24.md) |
| 25 | Crypto agility & key management | `done` | 2026-04-12 | 2026-04-12 | [sunlit-owasp-m25](../lessons/sunlit-owasp-m25.md) | [sunlit-owasp-m25](../completion/sunlit-owasp-m25.md) |
| 26 | Documentation & ergonomics retrofit | `done` | 2026-04-12 | 2026-04-12 | | |

<!-- Status values: not_started | in_progress | blocked | done -->
<!-- Lessons files go in docs/slo/lessons/sunlit-owasp-m<N>.md -->
<!-- Completion summaries go in docs/slo/completion/sunlit-owasp-m<N>.md -->

---

## End-to-End Architecture Diagram

The diagram below shows the target end state after all milestones. Dashed borders indicate new or modified components introduced by this runbook.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     SunLit Security Libraries — Target State                      │
│                                                                                 │
│  HTTP Request                                                                   │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐         │
│  │                   secure_boundary (C3/C5/C10)                       │         │
│  │  ┌──────────┐  ┌───────────────┐  ┌──────────────┐  ┌──────────┐  │         │
│  │  │SecureJson│  │ SecurityHdrs  │  │  FetchMeta   │  │  CORS    │  │         │
│  │  │ depth ✓  │  │ CSP+nonce ✓   │  │  Layer ✓     │  │  Layer ✓ │  │         │
│  │  │ fields ✓ │  │ PermPolicy ✓  │  │  (new)       │  │  (new)   │  │         │
│  │  │ size ✓   │  │ HSTS/XFO ✓   │  └──────────────┘  └──────────┘  │         │
│  │  └──────────┘  └───────────────┘                                   │         │
│  │  ┌──────────────────┐  ┌─────────────────────┐                    │         │
│  │  │  Safe Types       │  │  HTML Sanitizer      │                    │         │
│  │  │  SafeUrl ✓        │  │  (new: ammonia)      │                    │         │
│  │  │  SafePath ✓       │  └─────────────────────┘                    │         │
│  │  │  LdapFilter (new) │                                             │         │
│  │  └──────────────────┘                                              │         │
│  └─────────────────────────────────────────────────────────────────────┘         │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐         │
│  │                   secure_identity (C7)                              │         │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │         │
│  │  │JWT valid │  │ PwdHashing   │  │ OIDC Disc   │  │ MFA/TOTP   │  │         │
│  │  │HS/RS/ES  │  │ Argon2id     │  │ .well-known │  │ (new)      │  │         │
│  │  │kid ✓     │  │ (new)        │  │ (new)       │  └────────────┘  │         │
│  │  └──────────┘  └──────────────┘  └─────────────┘                   │         │
│  │  ┌──────────────────────────────────────────────────────────────┐  │         │
│  │  │ Session Management: InMemory ✓ | Redis (new) | DB (new)     │  │         │
│  │  └──────────────────────────────────────────────────────────────┘  │         │
│  └─────────────────────────────────────────────────────────────────────┘         │
│       │                                                                         │
│       ▼                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐         │
│  │                   secure_authz (C1)                                 │         │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────┐                  │         │
│  │  │RBAC eng  │  │ ABAC eval    │  │ Time-bounds │                  │         │
│  │  │ casbin ✓ │  │ (new)        │  │ (new)       │                  │         │
│  │  └──────────┘  └──────────────┘  └─────────────┘                  │         │
│  │  ┌──────────────────┐  ┌─────────────────────┐                    │         │
│  │  │ Cache + tenant ✓ │  │ Bulk authz (new)    │                    │         │
│  │  └──────────────────┘  └─────────────────────┘                    │         │
│  └─────────────────────────────────────────────────────────────────────┘         │
│       │                                                                         │
│       ▼                                                                         │
│  ┌──────────────┐  ┌───────────────────┐  ┌──────────────────────────┐          │
│  │secure_output │  │ secure_data (C2)  │  │ security_events (C9)     │          │
│  │ HTML ✓       │  │ AES-GCM ✓        │  │ HMAC audit signing (new) │          │
│  │ URL ✓        │  │ Vault ✓          │  │ Async batch emit (new)   │          │
│  │ JS ✓         │  │ AWS KMS ✓        │  │ File/HTTP sinks (new)    │          │
│  │ CSS ✓        │  │ Crypto agility   │  │ Event correlation (new)  │          │
│  │ XML ✓        │  │  (enhanced)      │  │ AppSensor expanded       │          │
│  │ LDAP (new)   │  │ PwdHash (new)    │  └──────────────────────────┘          │
│  │ OS cmd (new) │  │ Azure KV (new)   │                                        │
│  │ DN (new)     │  └───────────────────┘                                        │
│  └──────────────┘                                                               │
│                                                                                 │
│  ┌──────────────┐  ┌───────────────┐                                           │
│  │secure_errors │  │ security_core │                                           │
│  │ 3-layer ✓    │  │ types ✓       │                                           │
│  │ panic bdry ✓ │  │ traits ✓      │                                           │
│  └──────────────┘  └───────────────┘                                           │
│                                                                                 │
│  Legend:                                                                        │
│  ─── existing    - - - new    ✓ verified    (new) introduced by this runbook    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Milestone Introduced/Changed | Key Interfaces |
|---|---|---|---|
| `secure_boundary` limits enforcement | Enforce nesting depth and field count during deserialization | M18 | `SecureJson`, `RequestLimits` |
| `secure_boundary` HTML sanitizer | Sanitize user-provided HTML (ammonia integration) | M18 | `sanitize_html()` |
| `secure_output` LDAP encoder | Encode output for LDAP DN and filter contexts | M19 | `LdapDnEncoder`, `LdapFilterEncoder` |
| `secure_output` OS command encoder | Encode output for shell contexts | M19 | `ShellEncoder` |
| `secure_identity` password hashing | Argon2id password hashing and verification | M20 | `hash_password()`, `verify_password()` |
| `secure_boundary` CORS layer | Cross-Origin Resource Sharing enforcement | M21 | `CorsLayer` |
| `secure_boundary` CSP nonce | Per-request CSP nonce generation | M21 | `CspNonceLayer` |
| `secure_boundary` Fetch Metadata | Sec-Fetch-* header validation | M21 | `FetchMetadataLayer` |
| `security_events` HMAC signing | HMAC-SHA256 seal on audit entries | M22 | `HmacAuditSigner` |
| `security_events` async batching | Buffered async event emission | M22 | `BatchingSink` |
| `secure_authz` ABAC | Attribute-based access control evaluation | M23 | `AbacPolicy`, `AttributeContext` |
| `secure_authz` time-bounded perms | Temporal permission validity checks | M23 | `TemporalPermission` |
| `secure_identity` OIDC discovery | Thin wrapper around `openidconnect` crate with secure defaults | M24 | `OidcClient` |
| `secure_identity` MFA TOTP | Time-based one-time password implementation | M24 | `TotpProvider` |
| `secure_data` crypto agility | Configurable algorithm selection and negotiation | M25 | `CryptoAlgorithm`, `AlgorithmPolicy` |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Milestone |
|---|---|---|---|---|
| HTML sanitization | HTTP body | `sanitize_html()` | In-process function call | M18 |
| CSP nonce injection | `CspNonceLayer` | HTTP response headers | Tower middleware | M21 |
| Fetch Metadata validation | HTTP request | `FetchMetadataLayer` | Tower middleware | M21 |
| HMAC seal | `SecurityEvent` | `HmacAuditSigner` | In-process cryptographic operation | M22 |
| OIDC discovery | `OidcClient` | IdP `.well-known` | HTTPS GET (via `openidconnect` crate) | M24 |
| TOTP verification | `TotpProvider` | User-provided code | In-process HMAC-SHA1 | M24 |

---

## High-Level Design for Formal Verification (TLA+ Section)

**N/A** — This runbook adds defense-in-depth security controls to an existing system. No concurrent state machines, distributed consensus, or ordering guarantees are introduced. Each milestone adds local, stateless middleware or utility functions. The authorization cache (M23) and session backends (M24) have existing concurrency models that are not changed.

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

### 8) Documentation and API ergonomics are not optional

- Every new public API must have `# Examples` in its doc comment before the milestone is marked done.
- `cargo doc --no-deps --workspace` must complete with zero warnings.
- `cargo test --doc --workspace` must pass (doc examples must compile and run).
- Convenience free functions must exist for stateless operations (encoding, hashing, sanitization).
- New types must derive standard traits per the Rust API Design Standards section.
- Follow the Rust API Guidelines checklist for all new public surface area.

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
3. Verify the app builds and boots to a usable state.
   ```
   cargo build --workspace
   ```
4. Verify documentation builds with zero warnings and doc tests pass.
   ```
   cargo doc --no-deps --workspace 2>&1 | grep -c warning  # must be 0
   cargo test --doc --workspace
   ```
5. Run the smoke tests listed in the milestone. Check off each item in the runbook.
5. Verify backward compatibility for all items listed in the milestone Compatibility Checklist.
6. Complete the Self-Review Gate.
7. **Clean up test artifacts**: Verify no test output files, temporary fixtures, or generated data remain in the working tree. Run `git status` and confirm no untracked test artifacts exist.
8. **Review .gitignore**: Ensure any new build outputs, generated files, or tool caches introduced in this milestone have matching `.gitignore` patterns. Remove stale patterns that no longer apply.
9. Update ARCHITECTURE.md following the Documentation Update Table.
10. Update README.md if user-facing capabilities changed.
11. Write a lessons-learned file at `docs/slo/lessons/sunlit-owasp-m<N>.md`.
12. Write a completion summary at `docs/slo/completion/sunlit-owasp-m<N>.md`.
13. Update the Milestone Tracker in this file: set status to `done`, record Completed date, and fill in the lessons and completion summary paths.
14. Re-read the next milestone with fresh eyes and record any assumption changes in the lessons file.

---

## Background Context

### Current State

SunLit Security Libraries is a production-grade Cargo workspace of eight security crates (plus two service crates) implementing OWASP Proactive Controls for Rust web services. All original milestones (M0–M10) and improvement milestones (M11–M17) are complete. The workspace has:

- Full STRIDE threat model with 20 documented threats
- Eight security crates covering C1/C4–C10 (2018 numbering)
- Two service crates (reference service + 39-route smoke service)
- Adversarial testing (fuzz, property, CVE regression, timing)
- Supply-chain hardening (cargo-audit, cargo-deny, cargo-vet)
- DAST scanning (OWASP ZAP + Dastardly)

### Problem

Cross-referencing the codebase against the OWASP Proactive Controls 2024 revision and Kevin Wall's ESAPI security library design principles has revealed specific gaps:

1. **Input limit enforcement gap**: `max_nesting_depth` and `max_field_count` are defined in `secure_boundary/src/limits.rs` but never enforced during deserialization in `extract.rs` — JSON bomb DoS attacks bypass validation.
2. **No HTML sanitization**: Encoding exists but sanitization (allowing safe HTML subset) does not — cannot accept user HTML (WYSIWYG editors) safely.
3. **Incomplete output encoder set**: ESAPI requires encoders for all output contexts. SunLit is missing LDAP (filter + DN), OS command, and needs verification of JS/CSS completeness.
4. **No password hashing**: Neither `secure_identity` nor `secure_data` provides password hashing (Argon2id/bcrypt/scrypt) — the most fundamental credential storage control.
5. **Browser security header gaps**: No CORS middleware, no CSP nonce generation, no Permissions-Policy header, no Fetch Metadata validation (Sec-Fetch-*).
6. **Audit log integrity**: Hash-chained audit entries lack HMAC signing — attackers can forge new entries that chain correctly.
7. **Authorization lacks ABAC and temporal bounds**: Only RBAC policies supported; no attribute-based evaluation, no time-bounded permissions, no JIT/JEA patterns.
8. **Identity gaps**: No OIDC auto-discovery, no MFA implementation (trait exists but no TOTP provider), no persistent session backends, no authentication success auditing.
9. **Crypto agility partial**: Envelope encryption uses hardcoded AES-256-GCM; no algorithm selection/negotiation mechanism for future migration.

### Key Design Principles

These are system-wide rules the AI agent must follow when making implementation decisions.

1. **Idiomatic Rust API design** (replaces "trait-first, ESAPI-style"): Use the right Rust abstraction for each situation:
   - **Traits** when consumers need polymorphism or must provide their own implementation (e.g., `KeyProvider`, `SessionStore`, `AuditSink`, `IdentitySource`).
   - **Free functions** for stateless operations (e.g., encoding, hashing, sanitization). Provide convenience functions like `secure_output::html::encode(s)` as the primary API. Trait impls may coexist for generic contexts.
   - **Builder pattern** for types with more than 3 configuration options (e.g., CORS config, algorithm policy, event emitter).
   - **Newtypes** for all domain identifiers — continue the `id_newtype!` pattern. Never use raw `String` for actor, tenant, role, or resource IDs.
   - **`#[must_use]`** on all types where silently discarding the value is a bug (decisions, errors, secrets, hashes).
   - **`#[non_exhaustive]`** on all public enums and error types for forward compatibility.
2. **Secure by default**: All new defaults must be the most restrictive safe option. New features opt-in to permissiveness, never the reverse.
3. **Identity-agnostic authorization preserved**: `secure_authz` must never depend on `secure_identity`. Any identity source implementing `IdentitySource` must work.
4. **Classification-driven redaction**: All new event fields must declare a `DataClassification`. Only `Public` fields leave the process unredacted.
5. **Feature-flag gating for external deps**: New external integrations (ammonia, argon2, totp-rs) must be gated behind Cargo feature flags to keep default builds lean.
6. **Lightweight by default**: Minimize dependency weight. Prefer pure-Rust crates from the RustCrypto ecosystem. Avoid dependencies that pull in scripting engines, runtime codegen, or heavyweight frameworks. Every new dependency must justify its compile-time and binary-size cost.
7. **Documentation-as-API**: Every new public type, trait, and function must include:
   - A `///` doc comment explaining what it does and when to use it.
   - An `# Examples` section with a runnable code snippet (tested by `cargo test --doc`).
   - An `# Errors` section for fallible functions listing each error variant and when it occurs.
   - Hyperlinks to relevant types, traits, and modules (`[`TypeName`]` intra-doc links).
8. **Compose, don't wrap**: Prefer composing existing ecosystem crates (e.g., `tower-http::cors::CorsLayer` with secure-default helpers) over wrapping them in new types that hide functionality. Wrappers are justified only when adding security invariants the upstream crate does not enforce.

### What to Keep

- All existing public APIs and their signatures
- All existing test suites and their assertions
- The crate dependency graph (especially `secure_authz` → `security_core` only)
- The threat model structure and numbering
- Supply-chain configuration (deny.toml, supply-chain/)
- DAST pipeline (ZAP + Dastardly scripts)

### What to Change

- **`secure_boundary/src/extract.rs`** — Wire depth/field limit enforcement into deserializer
- **`secure_boundary/src/` (new files)** — HTML sanitizer, CORS layer, Fetch Metadata layer, CSP nonce
- **`secure_output/src/` (new files)** — LDAP, DN, OS command encoders
- **`secure_identity/src/` (new files)** — Password hashing, OIDC discovery, MFA TOTP, session backends
- **`secure_authz/src/`** — ABAC policy evaluation, time-bounded permissions, bulk authorization, cache key fix
- **`secure_data/src/`** — Crypto algorithm enum, password hashing module
- **`security_events/src/`** — HMAC signing, async batching, new sinks, event correlation

### Global Red Lines

These are forbidden unless explicitly overridden inside a milestone.

- No unrelated refactors
- No new dependencies (unless milestone declares them)
- No schema migrations
- No config key renames
- No public API/event/route renames
- No production placeholders
- No silent error swallowing
- No secrets in source control
- No test output data committed to source control

---

## Rust API Design Standards

Every milestone must comply with these standards, adapted from the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/). These are not optional — they are part of the Definition of Done.

### Naming (RFC 430)

- Types: `UpperCamelCase` (e.g., `LdapDnEncoder`, `PasswordHash`, `CspNonce`)
- Functions/methods: `snake_case` (e.g., `encode_for_dn()`, `hash_password()`, `verify()`)
- Constants: `SCREAMING_SNAKE_CASE`
- Feature flags: lowercase kebab-case with no placeholder words (e.g., `html-sanitize`, `session-redis`, `azure-kv`)
- Modules: `snake_case`, matching the primary type or capability (e.g., `ldap.rs`, `password.rs`, `cors.rs`)

### Documentation (C-CRATE-DOC, C-EXAMPLE, C-FAILURE)

Every milestone must produce documentation that meets these requirements:

1. **Crate-level `//!` docs** updated if a milestone adds a new top-level capability.
2. **`# Examples`** on every new public function, method, trait, and type. Examples must compile and pass under `cargo test --doc`. Use `?` for error handling, never `unwrap()`.
3. **`# Errors`** on every new public function that returns `Result`. List each error variant.
4. **`# Panics`** if a function can panic (should be rare — prefer `Result`).
5. **Intra-doc links** (`[`TypeName`]`) to related types, traits, and functions.
6. **`cargo doc --no-deps --workspace`** must complete with zero warnings. Add to smoke tests.

### Type Design

1. **Newtypes** for domain identifiers — never accept raw `String` where a typed ID exists.
2. **`From` / `TryFrom` / `AsRef`** conversions where natural (e.g., `impl From<&str> for Role`).
3. **Builder pattern** for types with >3 config fields. Builder must have a `build()` method that validates and returns `Result`.
4. **All public types**: derive or implement `Debug`, `Clone` where appropriate. For secret-bearing types, implement custom `Debug` that redacts.
5. **`Send + Sync`** for all new types that may be shared across async tasks. Compiler-verified by adding `assert_impl_all!` or equivalent in tests.
6. **`#[must_use]`** on security-critical return types (decisions, hashes, encoded strings, errors).
7. **`#[non_exhaustive]`** on all new public enums and struct error types.

### Error Design

1. Use `thiserror` version 2 consistently (do not introduce `thiserror` v1 — workspace already has both versions; new code must use v2).
2. Every error enum must implement `std::error::Error` via `thiserror`.
3. Error types must be meaningful — carry context, not just string messages.
4. Map all internal errors through `secure_errors::kind::AppError` before HTTP responses. New errors in `secure_boundary` must not bypass the `PublicError` system.

### API Ergonomics

1. **Convenience free functions** alongside trait-based APIs for stateless operations. Example: `secure_output::html::encode(s)` is the primary API; `HtmlEncoder.encode(s)` exists for generic trait-object contexts.
2. **Minimal boilerplate** for common operations. If a 3-line setup can be a 1-line function call, provide the 1-line version.
3. **Sensible defaults** via `Default` trait implementations. All configuration types should have secure defaults.
4. **Method chaining** for builder APIs: `.allow_origin("app.example.com").allow_methods([Method::GET, Method::POST])`.

### Dependency Discipline

1. **Prefer RustCrypto crates** for cryptographic operations (`argon2`, `hmac`, `sha2`, `aes-gcm`, `chacha20poly1305`). These are pure Rust, well-audited, and minimal.
2. **Feature-gate** all optional dependencies. The default feature set should compile with minimal transitive deps.
3. **Avoid vendoring ecosystems**: Use `tower-http::cors` directly, not a wrapper that hides it. Use the `openidconnect` crate for OIDC, not a hand-rolled client.
4. **Audit compile-time cost**: For each new dependency, run `cargo tree -p <dep> | wc -l` and record the transitive dep count in the Evidence Log. Flag anything over 20 transitive deps for review.

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
| Backend integration/BDD tests | `tests/sunlit_owasp_<feature>.rs` | `crates/<crate>/tests/` |
| E2E runtime validation | `tests/e2e_sunlit_owasp_m<N>.rs` | `crates/<crate>/tests/` |

### Test Artifact Cleanup Rules

Every test that creates files, directories, or temporary data on disk must follow these rules:

1. **Use temporary directories**: Prefer `tempdir()`, `tempfile::TempDir`, or OS-provided temp locations. Never write test output into the source tree.
2. **Clean up on completion and failure**: Use RAII patterns (Rust `Drop`) to ensure cleanup runs even when tests fail.
3. **No residual state**: After the full test suite runs, `git status` must show no untracked files from test execution.
4. **Dedicated output directories**: If a test must write to a project-relative path (e.g., `output/`), that directory must be in `.gitignore` and tests must clean it between runs.
5. **CI parity**: Test cleanup behavior must be identical locally and in CI.

### End-to-End Runtime Validation

Every milestone must include E2E tests that go beyond compilation and verify that the system works correctly at runtime.

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
| Build/boot | `cargo build --workspace` | boots cleanly | | | |
| Doc build | `cargo doc --no-deps --workspace` | zero warnings | | | |
| Doc tests | `cargo test --doc --workspace` | all pass | | | |
| Dependency audit | `cargo tree -p <new-dep> \\| wc -l` | <20 transitive deps | | | |
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
- Does every new public type/function/trait have `# Examples` in its doc comment?
- Does `cargo doc --no-deps --workspace` complete with zero warnings?
- Do `cargo test --doc --workspace` doc examples all pass?
- Did I provide convenience free functions for stateless operations (encoding, hashing, sanitization)?
- Is every assumption either verified or explicitly documented as unresolved?
- Do all tests clean up their output artifacts? Does `git status` show a clean working tree?
- Is `.gitignore` up to date with any new generated files or build outputs?
- Is the milestone truly done according to its Definition of Done?

If any answer is "no", the milestone is not complete.

---

## Lessons-Learned File Template

Path: `docs/slo/lessons/sunlit-owasp-m<N>.md`

```md
# Lessons Learned — sunlit-owasp Milestone <N>

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

Path: `docs/slo/completion/sunlit-owasp-m<N>.md`

```md
# Completion Summary — sunlit-owasp Milestone <N>

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

### Milestone 18 — Enforce Input Limits & HTML Sanitization (OWASP C3)

**Goal**: Wire the already-defined `max_nesting_depth` and `max_field_count` limits into the `SecureJson` deserialization pipeline so they are actually enforced at runtime, and add an HTML sanitization module for accepting user-provided HTML safely.

**Context**: `secure_boundary/src/limits.rs` defines `RequestLimits` with `max_nesting_depth` (default 10) and `max_field_count` (default 100), but `extract.rs` never checks these during deserialization. This means the documented nesting/field limits are aspirational, not enforced. JSON bomb attacks with 500-level nesting or 10,000 fields will succeed. Additionally, OWASP C3 and Kevin Wall's ESAPI principles require HTML sanitization (not just encoding) for accepting rich text input.

**Important design rule**: The depth/field counting must be done during deserialization, not after. Post-deserialization checking is too late — the memory has already been allocated. Use a custom serde `Deserializer` wrapper or streaming JSON cursor.

**Refactor budget**: `Minimal local refactor permitted in listed files only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | JSON request bodies with arbitrary nesting depth and field counts; HTML strings |
| Outputs | Rejection (422) for bodies exceeding limits; sanitized HTML strings |
| Interfaces touched | `SecureJson<T>` extractor, `RequestLimits`, new `sanitize_html()` function |
| Files allowed to change | `crates/secure_boundary/src/extract.rs`, `crates/secure_boundary/src/limits.rs`, `crates/secure_boundary/Cargo.toml` |
| Files to read before changing anything | `crates/secure_boundary/src/extract.rs`, `crates/secure_boundary/src/limits.rs`, `crates/secure_boundary/src/validate.rs` |
| New files allowed | `crates/secure_boundary/src/sanitize.rs`, `crates/secure_boundary/tests/sunlit_owasp_limits.rs`, `crates/secure_boundary/tests/sunlit_owasp_sanitize.rs`, `crates/secure_boundary/tests/e2e_sunlit_owasp_m18.rs` |
| New dependencies allowed | `ammonia` (HTML sanitization — well-maintained, Mozilla-backed, used by docs.rs); feature-gated as `html-sanitize` |
| Migration allowed | `no` |
| Compatibility commitments | All existing `SecureJson<T>` usage must continue to work with default limits; `sanitize_html()` is additive |
| Forbidden shortcuts | No post-deserialization-only depth checks; no disabling existing body size limits; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not change the `SecureValidate` trait signature
- Do not modify the XML extractor (`SecureXml`)
- Do not add new safe types in this milestone
- Do not change any other crate's code
- Do not add CSS/JS sanitization (encoding is the control for those contexts)

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-imp-m17.md` and apply relevant corrections.
3. Read the allowed files before editing.
4. Copy the Evidence Log template into this milestone section or working notes.
5. Re-state the milestone constraints before coding.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/src/extract.rs` | Add depth/field counting wrapper around serde deserialization |
| `crates/secure_boundary/src/limits.rs` | Add builder methods if needed for limit configuration |
| `crates/secure_boundary/Cargo.toml` | Add `ammonia` under `[dependencies]` with `optional = true`; add `html-sanitize` feature |
| `crates/secure_boundary/src/sanitize.rs` | NEW: HTML sanitization module wrapping `ammonia` |
| `crates/secure_boundary/src/lib.rs` | Add `pub mod sanitize;` under `html-sanitize` feature gate |
| `crates/secure_boundary/tests/sunlit_owasp_limits.rs` | NEW: BDD tests for depth/field enforcement |
| `crates/secure_boundary/tests/sunlit_owasp_sanitize.rs` | NEW: BDD tests for HTML sanitization |
| `crates/secure_boundary/tests/e2e_sunlit_owasp_m18.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review for new patterns |

#### Step-by-Step

1. Write BDD test stubs first for all scenarios below.
2. Write E2E runtime validation stubs first for all tests below.
3. Implement depth-counting `Deserializer` wrapper in `extract.rs`.
4. Implement field-counting logic in the same wrapper.
5. Wire limits from `RequestLimits` into the `SecureJson::from_request()` path.
6. Create `sanitize.rs` with `sanitize_html()` function wrapping `ammonia`.
7. Make all BDD tests pass.
8. Run the full test suite.
9. Run E2E runtime validation.
10. Verify test artifact cleanup.
11. Update .gitignore.
12. Run smoke tests.
13. Complete the Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: JSON depth limit enforcement**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Shallow JSON accepted | happy path | A JSON body with nesting depth 3 | Deserialized via `SecureJson<T>` | Succeeds, inner value available |
| Exact depth limit accepted | boundary | A JSON body with nesting depth exactly 10 (default) | Deserialized via `SecureJson<T>` | Succeeds |
| Depth exceeds limit rejected | invalid input | A JSON body with nesting depth 11 | Deserialized via `SecureJson<T>` | Returns 422 with error code `nesting_depth_exceeded` |
| Deeply nested bomb rejected | DoS | A JSON body with nesting depth 500 | Deserialized via `SecureJson<T>` | Returns 422; no OOM; constant-time rejection |
| Custom depth limit honoured | config | `RequestLimits` configured with `max_nesting_depth = 5`; JSON with depth 6 | Deserialized | Returns 422 |

**Feature: JSON field count limit enforcement**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Normal field count accepted | happy path | A JSON body with 5 fields | Deserialized via `SecureJson<T>` | Succeeds |
| Exact field limit accepted | boundary | A JSON body with exactly 100 fields (default) | Deserialized | Succeeds |
| Field count exceeds limit rejected | invalid input | A JSON body with 101 fields | Deserialized | Returns 422 with error code `field_count_exceeded` |
| Field flood attack rejected | DoS | A JSON body with 10,000 fields | Deserialized | Returns 422; no excessive memory use |

**Feature: HTML sanitization**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Clean HTML passes through | happy path | `<p>Hello <strong>world</strong></p>` | `sanitize_html()` | Returns same HTML |
| Script tags removed | XSS | `<p>Hello</p><script>alert(1)</script>` | `sanitize_html()` | Returns `<p>Hello</p>` (script removed) |
| Event handlers removed | XSS | `<img src=x onerror=alert(1)>` | `sanitize_html()` | Returns `<img src="x">` (onerror removed) |
| Style injection removed | CSS injection | `<div style="background:url(javascript:alert(1))">` | `sanitize_html()` | Attribute removed or sanitized |
| Empty input returns empty | empty state | `""` | `sanitize_html()` | Returns `""` |
| Allowed tags configurable | config | Custom allow list with only `<b>`, `<i>` | `sanitize_html()` with config | Only those tags preserved |

#### Regression Tests

- All existing `SecureJson` tests must still pass
- All existing `SecureXml` tests must still pass
- All existing safe type tests must still pass
- Smoke service routes that use `SecureJson` must still work

#### Compatibility Checklist

- [ ] `SecureJson<T>` with default limits works identically for payloads within limits
- [ ] `SecureValidate` trait is unchanged
- [ ] `SecurityHeadersLayer` is unchanged
- [ ] All existing integration tests pass

#### E2E Runtime Validation

**File**: `crates/secure_boundary/tests/e2e_sunlit_owasp_m18.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_depth_limit_enforced_at_runtime` | Depth counting works during real HTTP request processing | 422 response for depth > limit |
| `test_field_count_enforced_at_runtime` | Field counting works during real HTTP request processing | 422 response for fields > limit |
| `test_html_sanitization_removes_xss` | HTML sanitizer strips dangerous tags in real function call | Script tags absent from output |
| `test_existing_routes_still_work` | Backward compatibility for normal payloads | 200 response for valid payloads |

#### Smoke Tests

- [ ] `cargo test -p secure_boundary` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] App launches without errors (`cargo build --workspace`)
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --doc -p secure_boundary` passes
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` covers all new generated files and build outputs

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | | | |
| BDD tests created | `sunlit_owasp_limits.rs`, `sunlit_owasp_sanitize.rs` | fail for expected reason | | | |
| E2E stubs created | `e2e_sunlit_owasp_m18.rs` | fail for expected reason | | | |
| Implementation | Depth/field counter + sanitizer | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test -p secure_boundary --test 'e2e_*'` | green | | | |
| Build/boot | `cargo build --workspace` | boots cleanly | | | |
| Smoke tests | all items above | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current | | | |
| Compatibility checks | existing SecureJson tests | no regressions | | | |

#### Definition of Done

The milestone is done only when all of the following are true:

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests are checked off
- compatibility checklist is complete
- no forbidden shortcuts remain in production code
- all tests clean up their output artifacts — `git status` is clean
- `.gitignore` is up to date
- docs are updated to match implementation
- lessons file is written at `docs/slo/lessons/sunlit-owasp-m18.md`
- completion summary is written at `docs/slo/completion/sunlit-owasp-m18.md`
- Milestone Tracker is updated

#### Post-Flight

Complete the Global Exit Rules above. Key documentation updates:

- **ARCHITECTURE.md**: Add depth/field enforcement and HTML sanitizer to `secure_boundary` section
- **README.md**: Update `secure_boundary` usage examples with depth/field limit configuration and `sanitize_html()` example
- **docs/dev-guide/secure-boundary.md**: Add sections on limit enforcement and HTML sanitization

#### Notes

- Concurrency/race behavior does not apply — deserialization is per-request, single-threaded.
- Retry/rollback does not apply — validation is stateless.

---

### Milestone 19 — Complete Output Encoder Contexts (OWASP C4, ESAPI Alignment)

**Goal**: Add the missing output encoder contexts identified by Kevin Wall's ESAPI principles: LDAP DN encoding (RFC 4514), LDAP filter encoding (RFC 4515), and OS command/shell encoding. Verify completeness of existing JS and CSS encoders.

**Context**: ESAPI's `Encoder` interface provides encoding for 11 output contexts. SunLit's `secure_output` currently covers HTML, URL, JS, CSS, and XML. Missing are LDAP (DN + filter) and OS command contexts. Kevin Wall has emphasized that partial encoder coverage is worse than no library — developers assume they are safe when they use the library, so every context they might encounter must be covered.

**Important design rule — Rust-idiomatic API, not Java-style Encoder objects**: Each new encoder must implement the existing `OutputEncoder` trait for generic contexts, but the **primary API must be convenience free functions** following existing Rust ecosystem conventions. Developers should write `secure_output::ldap::encode_dn(s)` — not construct a `LdapDnEncoder` struct. The trait impl exists for code that needs `dyn OutputEncoder` or `impl OutputEncoder` polymorphism. Both APIs must coexist. Encoding must be context-specific (LDAP DN escaping ≠ LDAP filter escaping).

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Arbitrary UTF-8 strings to be encoded for LDAP DN, LDAP filter, or OS shell contexts |
| Outputs | Safely encoded strings that prevent injection in each context |
| Interfaces touched | `OutputEncoder` trait (implemented, not changed), new encoder structs, **new convenience free functions** |
| Files allowed to change | `crates/secure_output/src/lib.rs`, `crates/secure_output/Cargo.toml` |
| Files to read before changing anything | `crates/secure_output/src/lib.rs`, `crates/secure_output/src/html.rs`, `crates/secure_output/src/js.rs`, `crates/secure_output/src/css.rs` |
| New files allowed | `crates/secure_output/src/ldap.rs`, `crates/secure_output/src/shell.rs`, `crates/secure_output/tests/sunlit_owasp_ldap.rs`, `crates/secure_output/tests/sunlit_owasp_shell.rs`, `crates/secure_output/tests/e2e_sunlit_owasp_m19.rs` |
| New dependencies allowed | `none` (LDAP and shell encoding are pure string manipulation) |
| Migration allowed | `no` |
| Compatibility commitments | All existing encoders unchanged; `OutputEncoder` trait unchanged |
| Forbidden shortcuts | No partial encoding that misses RFC-defined special characters; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not modify existing encoder implementations (HTML, URL, JS, CSS, XML)
- Do not add SQL encoding (parameterized queries are the control, not encoding)
- Do not add encoding for contexts not in ESAPI's standard set
- Do not change the `OutputEncoder` trait signature

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_output/src/ldap.rs` | NEW: `LdapDnEncoder` (RFC 4514) and `LdapFilterEncoder` (RFC 4515), plus `encode_dn()` and `encode_filter()` free functions |
| `crates/secure_output/src/shell.rs` | NEW: `ShellEncoder` for POSIX shell metacharacter escaping, plus `encode()` free function |
| `crates/secure_output/src/lib.rs` | Add `pub mod ldap;` and `pub mod shell;`; re-export new types and free functions |
| `crates/secure_output/Cargo.toml` | No changes expected |
| `crates/secure_output/tests/sunlit_owasp_ldap.rs` | NEW: BDD tests for LDAP encoding |
| `crates/secure_output/tests/sunlit_owasp_shell.rs` | NEW: BDD tests for shell encoding |
| `crates/secure_output/tests/e2e_sunlit_owasp_m19.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review for new patterns |

#### BDD Acceptance Scenarios

**Feature: LDAP DN encoding (RFC 4514)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Plain CN passes through | happy path | `"John Smith"` | `LdapDnEncoder.encode()` | Returns `"John Smith"` |
| Special chars escaped | injection prevention | `"John+Smith,OU=Users"` | `LdapDnEncoder.encode()` | Returns `"John\+Smith\,OU\=Users"` — escapes `+,;\"<>#=` |
| Leading/trailing spaces escaped | RFC compliance | `" admin "` | `LdapDnEncoder.encode()` | Returns `"\ admin\ "` — leading/trailing space escaped |
| Null byte escaped | injection prevention | `"user\x00admin"` | `LdapDnEncoder.encode()` | Returns `"user\00admin"` |
| Empty input returns empty | empty state | `""` | `LdapDnEncoder.encode()` | Returns `""` |

**Feature: LDAP filter encoding (RFC 4515)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Plain value passes through | happy path | `"john"` | `LdapFilterEncoder.encode()` | Returns `"john"` |
| Wildcard escaped | injection prevention | `"user*admin"` | `LdapFilterEncoder.encode()` | Returns `"user\2aadmin"` |
| Parentheses escaped | injection prevention | `"(admin)"` | `LdapFilterEncoder.encode()` | Returns `"\28admin\29"` |
| Backslash escaped | injection prevention | `"a\\b"` | `LdapFilterEncoder.encode()` | Returns `"a\5cb"` |
| Null byte escaped | injection prevention | `"\x00"` | `LdapFilterEncoder.encode()` | Returns `"\00"` |

**Feature: OS shell encoding**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Alphanumeric passes through | happy path | `"backup-2024"` | `ShellEncoder.encode()` | Returns `"backup-2024"` |
| Semicolon escaped | command injection | `"file; rm -rf /"` | `ShellEncoder.encode()` | Metacharacters escaped or single-quoted |
| Pipe escaped | command injection | `"file | cat /etc/passwd"` | `ShellEncoder.encode()` | Pipe escaped |
| Backtick escaped | command injection | `` "file`id`" `` | `ShellEncoder.encode()` | Backtick escaped |
| Dollar sign escaped | variable injection | `"$HOME"` | `ShellEncoder.encode()` | Dollar escaped |
| Newline escaped | injection | `"file\nid"` | `ShellEncoder.encode()` | Newline escaped |
| Empty input returns empty | empty state | `""` | `ShellEncoder.encode()` | Returns `""` |

**Feature: Convenience free functions**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Free function matches trait | equivalence | Any input string | `secure_output::ldap::encode_dn(s)` vs `LdapDnEncoder.encode(s)` | Same output |
| Free function matches trait (filter) | equivalence | Any input string | `secure_output::ldap::encode_filter(s)` vs `LdapFilterEncoder.encode(s)` | Same output |
| Free function matches trait (shell) | equivalence | Any input string | `secure_output::shell::encode(s)` vs `ShellEncoder.encode(s)` | Same output |
| Doc examples compile | documentation | All new `# Examples` sections | `cargo test --doc -p secure_output` | Pass |

#### Regression Tests

- All existing encoder tests (HTML, URL, JS, CSS, XML) must still pass
- All existing `OutputEncoder` trait tests must still pass
- Smoke service output encoding routes must still work

#### Compatibility Checklist

- [ ] `HtmlEncoder`, `UrlEncoder`, `JsStringEncoder`, `CssEncoder`, `XmlEncoder` unchanged
- [ ] `OutputEncoder` trait unchanged
- [ ] `sanitize_uri_scheme()` unchanged
- [ ] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/secure_output/tests/e2e_sunlit_owasp_m19.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_ldap_dn_injection_prevented` | DN injection characters are escaped at runtime | No unescaped special chars |
| `test_ldap_filter_injection_prevented` | Filter injection characters are escaped at runtime | No unescaped `*()\\x00` |
| `test_shell_injection_prevented` | Shell metacharacters are escaped at runtime | No unescaped `;|&\`$` |
| `test_existing_encoders_still_work` | Backward compatibility | HTML/URL/JS/CSS/XML encoding unchanged |

#### Smoke Tests

- [ ] `cargo test -p secure_output` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --doc -p secure_output` passes
- [ ] All new public types/functions have `# Examples` in doc comments
- [ ] `git status` shows no untracked test artifacts

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | | | |
| BDD tests created | `sunlit_owasp_ldap.rs`, `sunlit_owasp_shell.rs` | fail for expected reason | | | |
| E2E stubs created | `e2e_sunlit_owasp_m19.rs` | fail for expected reason | | | |
| Implementation | LDAP DN, LDAP filter, shell encoders | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test -p secure_output --test 'e2e_*'` | green | | | |
| Build/boot | `cargo build --workspace` | boots cleanly | | | |
| Compatibility checks | existing encoder tests | no regressions | | | |

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file written at `docs/slo/lessons/sunlit-owasp-m19.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m19.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add LDAP and shell encoder to `secure_output` component description
- **README.md**: Add LDAP and shell encoding usage examples
- **docs/dev-guide/secure-output.md**: Add sections for new encoder contexts

---

### Milestone 20 — Password Hashing & Secure Credential Storage (OWASP C2/C7)

**Goal**: Add production-grade password hashing (Argon2id by default, with bcrypt and scrypt behind feature flags) to the SunLit workspace, satisfying the most critical gap identified by OWASP C2 (Cryptography) and C7 (Digital Identities). Kevin Wall's ESAPI principle: "If your security library doesn't handle password storage, developers will roll their own — and they will get it wrong."

**Context**: Neither `secure_identity` nor `secure_data` currently provides password hashing. This is the single most impactful gap in the workspace. Applications building on SunLit have no secure password storage guidance or tooling. The implementation will live in `secure_data` (which owns cryptographic operations) with integration helpers in `secure_identity`.

**Important design rule**: Password hashing must use constant-time comparison to prevent timing attacks. The API must make it impossible to accidentally store plaintext passwords. The `PasswordHash` type must implement `Zeroize` on drop.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Plaintext passwords (as `SecretString`), hash parameters (algorithm, memory, iterations) |
| Outputs | `PasswordHash` (PHC string format), verification result (`bool`) |
| Interfaces touched | New `PasswordHasher` trait, `SecretString` (existing), new `PasswordHash` type |
| Files allowed to change | `crates/secure_data/Cargo.toml`, `crates/secure_data/src/lib.rs` |
| Files to read before changing anything | `crates/secure_data/src/secret.rs`, `crates/secure_data/src/envelope.rs`, `crates/secure_identity/src/token.rs` |
| New files allowed | `crates/secure_data/src/password.rs`, `crates/secure_data/tests/sunlit_owasp_password.rs`, `crates/secure_data/tests/e2e_sunlit_owasp_m20.rs` |
| New dependencies allowed | `argon2` (Argon2id — RustCrypto, pure Rust, widely audited), `password-hash` (PHC string format — RustCrypto); `bcrypt` and `scrypt` behind feature flags `password-bcrypt` and `password-scrypt` |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_data` APIs unchanged; `SecretString` unchanged |
| Forbidden shortcuts | No plaintext storage anywhere; no MD5/SHA-1/SHA-256 for passwords; no hardcoded salt; no `unsafe` for timing |

#### Out of Scope / Must Not Do

- Do not implement user signup/login flows (that is application logic)
- Do not modify `secure_identity` in this milestone (integration comes in M24)
- Do not add session management here
- Do not change the `SecretString` API
- Do not add password policy enforcement (length, complexity) — that is input validation in `secure_boundary`

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_data/src/password.rs` | NEW: `PasswordHasher` trait, `Argon2Hasher` default impl, `PasswordHash` type, `hash_password()`, `verify_password()` |
| `crates/secure_data/src/lib.rs` | Add `pub mod password;` |
| `crates/secure_data/Cargo.toml` | Add `argon2`, `password-hash` deps; add feature flags |
| `crates/secure_data/tests/sunlit_owasp_password.rs` | NEW: BDD tests |
| `crates/secure_data/tests/e2e_sunlit_owasp_m20.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review |

#### BDD Acceptance Scenarios

**Feature: Password hashing with Argon2id**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Hash a password | happy path | A plaintext password `"correct-horse-battery"` | `hash_password()` | Returns `PasswordHash` in PHC format starting with `$argon2id$` |
| Verify correct password | happy path | A hashed password and the same plaintext | `verify_password()` | Returns `true` |
| Verify wrong password | invalid input | A hashed password and a different plaintext | `verify_password()` | Returns `false`; no error |
| Hash is unique per call | security | Same password hashed twice | Compare hashes | Different hashes (random salt) |
| Empty password rejected | invalid input | `""` empty password | `hash_password()` | Returns error `empty_password` |
| PasswordHash redacted in Debug | info disclosure | A `PasswordHash` value | `format!("{:?}", hash)` | Contains `[REDACTED]`, not the hash |
| PasswordHash redacted in JSON | info disclosure | A `PasswordHash` value | `serde_json::to_string()` | Contains `"[REDACTED]"` |
| Timing consistency | timing | Correct and incorrect passwords | `verify_password()` with both | Time difference < 1ms (constant-time comparison) |

#### Regression Tests

- All existing `secure_data` tests (envelope encryption, secret types, key providers) must still pass
- `SecretString` behavior unchanged

#### Compatibility Checklist

- [ ] `encrypt_for_storage()` / `decrypt_for_use()` unchanged
- [ ] `SecretString` API unchanged
- [ ] `SecretReference::parse()` unchanged
- [ ] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/secure_data/tests/e2e_sunlit_owasp_m20.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_argon2_hash_verify_roundtrip` | Full hash → verify cycle works at runtime | Verify returns true for correct password |
| `test_argon2_rejects_wrong_password` | Wrong password correctly rejected at runtime | Verify returns false |
| `test_password_hash_not_leaked` | Hash value never appears in Debug/Display/JSON | No raw hash in formatted output |
| `test_hash_uniqueness` | Salt randomization works | Two hashes of same password differ |

#### Smoke Tests

- [ ] `cargo test -p secure_data` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --doc -p secure_data` passes
- [ ] All new public types/functions have `# Examples` in doc comments
- [ ] `git status` shows no untracked test artifacts

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m20.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m20.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add password hashing to `secure_data` component description
- **README.md**: Add password hashing usage example
- **docs/dev-guide/secure-data.md**: Add password hashing section

---

### Milestone 21 — Browser Security Headers & CORS (OWASP C8)

**Goal**: Add CORS middleware, CSP nonce generation, Fetch Metadata request validation, and Permissions-Policy header support to `secure_boundary`. This addresses OWASP C8 (Leverage Browser Security Features), a control that is new in the 2024 Proactive Controls and entirely absent from SunLit.

**Context**: `secure_boundary/src/headers.rs` already sets some security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`), but lacks CORS configuration, CSP nonce generation, Fetch Metadata validation (`Sec-Fetch-*`), and `Permissions-Policy`. Kevin Wall has consistently argued that security libraries should make CORS safe-by-default: deny all cross-origin requests unless explicitly configured.

**Important design rule**: CORS must default to denying all origins. The developer must explicitly opt in to allowed origins, methods, and headers. CSP nonces must be cryptographically random per-request and injected into responses via tower middleware or extensions. **Compose, don't wrap**: Use `tower-http::cors::CorsLayer` directly — provide a `secure_cors_defaults()` helper function that returns a pre-configured `CorsLayer` with deny-all defaults, not a wrapper struct that hides the underlying API. Developers familiar with `tower-http` should recognize the types.

**Refactor budget**: `Minimal local refactor permitted in listed files only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | HTTP requests with `Origin`, `Sec-Fetch-*` headers; configuration for allowed origins/methods |
| Outputs | CORS preflight responses; CSP headers with nonces; 403 for invalid Sec-Fetch-* |
| Interfaces touched | `SecurityHeadersLayer` (extended), new `secure_cors_defaults()` helper, new `FetchMetadataLayer` |
| Files allowed to change | `crates/secure_boundary/src/headers.rs`, `crates/secure_boundary/Cargo.toml`, `crates/secure_boundary/src/lib.rs` |
| Files to read before changing anything | `crates/secure_boundary/src/headers.rs`, `crates/secure_boundary/src/lib.rs` |
| New files allowed | `crates/secure_boundary/src/cors.rs`, `crates/secure_boundary/src/fetch_metadata.rs`, `crates/secure_boundary/tests/sunlit_owasp_cors.rs`, `crates/secure_boundary/tests/sunlit_owasp_fetch_meta.rs`, `crates/secure_boundary/tests/e2e_sunlit_owasp_m21.rs` |
| New dependencies allowed | `tower-http` (CORS support — already widely used in tower ecosystem; use only the `cors` feature); `base64` if not already present (for nonce encoding); `rand` or `getrandom` if not already present (for nonce generation) |
| Migration allowed | `no` |
| Compatibility commitments | `SecurityHeadersLayer` must continue to work with existing configuration; new layers are additive |
| Forbidden shortcuts | No wildcard CORS origin by default; no disabling preflight; no static CSP nonces; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not implement cookie management (SameSite is set via `Set-Cookie` which is application-level)
- Do not implement Subresource Integrity (SRI) — that is a build-tool concern
- Do not modify `SecureJson` or `SecureXml` extractors
- Do not add rate limiting middleware (separate concern)
- Do not add WebSocket-specific security

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/src/cors.rs` | NEW: `secure_cors_defaults()` returning a pre-configured `tower_http::cors::CorsLayer` with deny-all; `SecureCorsBuilder` for customization |
| `crates/secure_boundary/src/fetch_metadata.rs` | NEW: `FetchMetadataLayer` validating `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest` |
| `crates/secure_boundary/src/headers.rs` | Add CSP nonce generation; add `Permissions-Policy` header |
| `crates/secure_boundary/src/lib.rs` | Add `pub mod cors;`, `pub mod fetch_metadata;`; re-export types |
| `crates/secure_boundary/Cargo.toml` | Add `tower-http` with `cors` feature |
| `crates/secure_boundary/tests/sunlit_owasp_cors.rs` | NEW: BDD tests for CORS |
| `crates/secure_boundary/tests/sunlit_owasp_fetch_meta.rs` | NEW: BDD tests for Fetch Metadata |
| `crates/secure_boundary/tests/e2e_sunlit_owasp_m21.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review |

#### BDD Acceptance Scenarios

**Feature: CORS deny-all default**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| No CORS config rejects cross-origin | secure default | `secure_cors_defaults()` with no modifications | Cross-origin request from `evil.com` | 403 or no CORS headers |
| Allowed origin accepted | happy path | `SecureCorsBuilder::new().allow_origin("app.example.com").build()` | Request from `app.example.com` | `Access-Control-Allow-Origin: app.example.com` |
| Disallowed origin rejected | invalid input | Allowed origin is `app.example.com` | Request from `evil.com` | No CORS headers / 403 on preflight |
| Preflight with valid method | happy path | Allowed methods: `GET, POST` | OPTIONS preflight with `Access-Control-Request-Method: POST` | 200 with correct CORS headers |
| Returns tower-http CorsLayer type | composability | `secure_cors_defaults()` | Check return type | Returns `tower_http::cors::CorsLayer` — no wrapper type |

**Feature: CSP nonce generation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Nonce in CSP header | happy path | `SecurityHeadersLayer` with CSP nonce enabled | Any response | `Content-Security-Policy` header contains `'nonce-<base64>'` |
| Nonce is unique per request | security | Two sequential requests | Compare CSP headers | Different nonces |
| Nonce is at least 128 bits | security | Any response with nonce | Decode nonce | At least 16 bytes of randomness |
| Nonce available via request extension | usability | Request processed through middleware | Access `CspNonce` extension | Nonce value matches header |

**Feature: Fetch Metadata validation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Same-origin request accepted | happy path | `Sec-Fetch-Site: same-origin` | Any API request | Request passes through |
| Cross-site request rejected | injection prevention | `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: cors` | API request (not CORS-configured endpoint) | 403 |
| No Sec-Fetch headers (old browser) | backward compat | No `Sec-Fetch-*` headers | API request | Configurable: default allow (log warning) |
| Navigation request allowed | happy path | `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document` | GET request to page | Allowed (top-level navigation) |

**Feature: Permissions-Policy header**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Default restrictive policy | secure default | `SecurityHeadersLayer::new()` | Any response | `Permissions-Policy: camera=(), microphone=(), geolocation=()` |
| Custom policy configurable | config | Custom permissions policy string | Response | Header matches configured value |

#### Regression Tests

- All existing `SecurityHeadersLayer` tests must still pass
- All existing security headers must still be present in responses
- Smoke service header checks must still work

#### Compatibility Checklist

- [x] `SecurityHeadersLayer` existing behavior unchanged
- [x] All existing security headers still present
- [x] `SecureJson` and `SecureXml` extractors unchanged
- [x] Existing integration tests pass

#### E2E Runtime Validation

**File**: `crates/secure_boundary/tests/e2e_sunlit_owasp_m21.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_cors_deny_all_default` | Cross-origin requests rejected by default | 403 or no CORS headers for cross-origin |
| `test_cors_allowed_origin_works` | Configured origins are accepted | Correct CORS headers in response |
| `test_csp_nonce_unique_per_request` | Nonce changes each request | Different nonces across requests |
| `test_fetch_metadata_blocks_cross_site` | Fetch Metadata validation works | 403 for `cross-site` requests |
| `test_permissions_policy_present` | Permissions-Policy header set | Header present with restrictive defaults |
| `test_existing_headers_preserved` | Backward compatibility | X-Content-Type-Options etc. still present |

#### Smoke Tests

- [x] `cargo test -p secure_boundary` passes
- [x] `cargo test --workspace` passes
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [x] `cargo build --workspace` succeeds
- [x] `cargo doc --no-deps --workspace` completes with zero warnings
- [x] `cargo test --doc -p secure_boundary` passes
- [x] All new public types/functions have `# Examples` in doc comments
- [x] `git status` shows no untracked test artifacts

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m21.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m21.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add CORS, Fetch Metadata, CSP nonce, Permissions-Policy to `secure_boundary` components
- **README.md**: Add CORS and CSP nonce usage examples
- **docs/dev-guide/secure-boundary.md**: Add browser security features section

---

### Milestone 22 — Security Events Hardening (OWASP C9, ESAPI Alignment)

**Goal**: Harden the `security_events` crate with HMAC signing of audit log entries (tamper evidence), async batch emission, additional sinks (file, HTTP webhook), event correlation (parent_event_id), and alert threshold configuration. This addresses OWASP C9 (Implement Security Logging and Monitoring) and Kevin Wall's ESAPI principle that security events must be separated from diagnostic logs and must be tamper-evident.

**Context**: `security_events` already has a well-designed `SecurityEvent` struct, `AuditEmitter`, `InMemorySink`, and tracing integration. However it lacks: (1) tamper evidence — nothing prevents log modification after emission, (2) high-throughput emission — batch support, (3) production sinks — only stdout/tracing/in-memory, (4) correlation — no way to link related events, (5) alerting — no threshold-based alert triggers.

**Important design rule**: Each event gets an independent HMAC-SHA256 signature over its serialized fields. This provides tamper evidence — if an event is modified after emission, verification fails. **Do not use chain linking** (where each HMAC includes the previous event's HMAC). Chain linking creates operational complexity: events processed out-of-order, distributed systems with multiple emitters, and log rotation all break the chain. Per-event HMAC is simpler, composable, and sufficient for tamper detection. Key management for the HMAC key should use `SecretString` from `secure_data`.

**Refactor budget**: `Minimal local refactor permitted in listed files only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `SecurityEvent`s to emit; HMAC key; sink configuration; correlation IDs |
| Outputs | HMAC-signed audit entries; batch delivery to sinks; correlated event groups |
| Interfaces touched | `AuditEmitter`, `AuditSink` trait, `SecurityEvent` (extended with `parent_event_id`) |
| Files allowed to change | `crates/security_events/src/audit.rs` or equivalent, `crates/security_events/Cargo.toml`, `crates/security_events/src/lib.rs` |
| Files to read before changing anything | `crates/security_events/src/audit.rs`, `crates/security_events/src/event.rs`, `crates/security_events/src/sink.rs` (if exists), `crates/security_events/src/lib.rs` |
| New files allowed | `crates/security_events/src/hmac.rs`, `crates/security_events/src/sink_file.rs`, `crates/security_events/src/sink_http.rs`, `crates/security_events/src/correlation.rs`, `crates/security_events/tests/sunlit_owasp_hmac.rs`, `crates/security_events/tests/sunlit_owasp_sinks.rs`, `crates/security_events/tests/e2e_sunlit_owasp_m22.rs` |
| New dependencies allowed | `hmac`, `sha2` (RustCrypto — for HMAC-SHA256); `tokio` features if needed for async batch; `reqwest` behind `http-sink` feature flag (for HTTP webhook sink) |
| Migration allowed | `no` |
| Compatibility commitments | Existing `AuditEmitter` API must not break; `SecurityEvent` extension is additive (new optional field) |
| Forbidden shortcuts | No MD5/SHA-1 for HMAC; no plaintext HMAC keys; no blocking I/O in the hot path; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not add a database sink (application-specific)
- Do not implement log aggregation or SIEM integration
- Do not modify the `SecurityEvent` core fields (only add `parent_event_id`)
- Do not implement distributed tracing middleware (separate middleware concern)
- Do not add retention policy enforcement (operational concern)

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/security_events/src/hmac.rs` | NEW: `HmacEventSigner` with per-event HMAC-SHA256 signing and verification |
| `crates/security_events/src/sink_file.rs` | NEW: `FileSink` implementing `AuditSink` |
| `crates/security_events/src/sink_http.rs` | NEW: `HttpWebhookSink` implementing `AuditSink` (behind feature flag) |
| `crates/security_events/src/correlation.rs` | NEW: Event correlation with `parent_event_id` |
| Event struct file | Add `parent_event_id: Option<EventId>` field |
| `crates/security_events/src/lib.rs` | Add new module declarations, re-exports |
| `crates/security_events/Cargo.toml` | Add `hmac`, `sha2`; add `http-sink` feature with `reqwest` |
| `crates/security_events/tests/sunlit_owasp_hmac.rs` | NEW: BDD tests for HMAC signing |
| `crates/security_events/tests/sunlit_owasp_sinks.rs` | NEW: BDD tests for file and HTTP sinks |
| `crates/security_events/tests/e2e_sunlit_owasp_m22.rs` | NEW: E2E runtime validation |
| `.gitignore` | Add patterns for test audit log files |

#### BDD Acceptance Scenarios

**Feature: HMAC audit signing**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Event signed on emit | happy path | HMAC key configured | Emit an event | Event has `hmac` field containing HMAC-SHA256 of serialized event fields |
| Tampered event detected | integrity | A signed event | Modify any field | `verify_hmac()` returns `false` |
| Unsigned event detected | integrity | An event without `hmac` field | `verify_hmac()` | Returns error `missing_hmac` |
| Empty HMAC key rejected | config | No HMAC key configured | Create signer | Returns error `missing_hmac_key` |
| HMAC computed over all fields | security | Event with all fields populated | Sign, then verify | HMAC covers `event_id`, `timestamp`, `kind`, `severity`, `outcome`, `actor`, `tenant`, `description` |
| Different events produce different HMACs | security | Two distinct events | Compare HMACs | Different values |

**Feature: File sink**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Events written to file | happy path | `FileSink` configured with path | Emit 3 events | File contains 3 JSON lines |
| File rotated on size | config | `FileSink` with max size 1KB | Emit events exceeding 1KB | New file created, old file preserved |
| Directory created if missing | first-run | Path to non-existent directory | Create `FileSink` | Directory created; no error |
| Write failure emits warning | dependency failure | Read-only directory | Emit event | Error returned; event not lost (returned to caller) |

**Feature: Event correlation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Parent event linked | happy path | Parent event with ID `A` | Create child event referencing `A` | Child `parent_event_id == Some("A")` |
| Root event has no parent | happy path | First event in chain | Inspect `parent_event_id` | `None` |
| Query by correlation | usability | 5 events, 3 sharing parent `A` | Filter by parent | Returns 3 events |

#### Regression Tests

- All existing `SecurityEvent` tests must still pass
- All existing `AuditEmitter` tests must still pass
- `InMemorySink` behavior unchanged
- Tracing integration unchanged

#### Compatibility Checklist

- [x] `SecurityEvent` serialization backward compatible (new fields are `Option` and omitted when absent)
- [x] `AuditEmitter` existing API unchanged
- [x] `InMemorySink` behavior preserved and still usable in tests/runtime validation
- [x] Tracing subscriber integration unchanged
- [x] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/security_events/tests/e2e_sunlit_owasp_m22.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_hmac_tamper_detected` | Tamper detection works at runtime | Modified event fails HMAC verification |
| `test_file_sink_writes_events` | File sink works end-to-end | Events appear in file on disk |
| `test_event_correlation_roundtrip` | Parent-child linking works | Child events reference parent correctly |
| `test_existing_sinks_still_work` | Backward compatibility | InMemorySink and tracing still function |

#### Smoke Tests

- [x] `cargo test -p security_events` passes
- [x] `cargo test --workspace` passes
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [x] `cargo build --workspace` succeeds
- [x] `cargo doc --no-deps --workspace` completes with zero warnings
- [x] `cargo test --doc -p security_events` passes
- [x] All new public types/functions have `# Examples` in doc comments
- [x] `git status` shows no untracked test artifacts (especially no leftover audit log files)

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | Green baseline confirmed before M22 edits | Pass | Verified on 2026-04-11 |
| BDD tests created | `sunlit_owasp_hmac.rs`, `sunlit_owasp_sinks.rs` | fail for expected reason | Initial `cargo test -p security_events` failed with unresolved imports for `hmac`, `correlation`, `FileSink`, `BatchingSink`, and `InMemorySink` | Pass | Confirmed TDD red phase |
| E2E stubs created | `e2e_sunlit_owasp_m22.rs` | fail for expected reason | Initial red run also failed because the new E2E types/modules were not implemented yet | Pass | Runtime validation added before production changes |
| Implementation | HMAC signing, sinks, correlation | contract satisfied | Added `HmacEventSigner`, optional `parent_event_id`/`hmac` fields, `FileSink`, `BatchingSink`, `InMemorySink`, feature-gated `HttpWebhookSink`, and correlation helpers | Pass | Kept `SecuritySink` backward compatible with additive `try_write_event()` |
| Full tests | `cargo test --workspace` | green | Green after M22 changes; the new `sunlit_owasp_hmac`, `sunlit_owasp_sinks`, and `e2e_sunlit_owasp_m22` coverage all passes | Pass | Final workspace regression run re-verified on 2026-04-11 |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | Green, including `e2e_sunlit_owasp_m22` (4 passed, 0 failed) | Pass | Confirms runtime tamper detection, file sink, correlation, and sink compatibility |
| Build/boot | `cargo build --workspace` | boots cleanly | Finished `dev` profile successfully | Pass | Verified on 2026-04-11 |
| Doc build | `cargo doc --no-deps --workspace` | zero warnings | Documentation completed with no warnings in output | Pass | New public APIs documented with examples |
| Doc tests | `cargo test --doc --workspace` | all pass | Green; `security_events` doc tests passed 10/10 | Pass | Includes HMAC, correlation, and sink examples |
| Dependency audit | `cargo tree -p hmac \| wc -l`; `cargo tree -p security_events --features http-sink \| wc -l` | review cost | `hmac`: 15 lines; `security_events --features http-sink`: 357 lines | Pass | `reqwest` path is intentionally feature-gated because of its heavier footprint |
| Smoke tests | listed above | all checked | All smoke items verified green | Pass | No skipped checks |
| Test artifact cleanup | `git status --short --untracked-files=all` | no untracked test artifacts | Only intended source/doc edits shown; no temp audit files left in repo | Pass | Tests now clean up their temp directories |
| .gitignore review | review `.gitignore` | patterns current | Existing patterns already cover build outputs/logs; no new repo-local artifact pattern needed | Pass | Temp audit files use OS temp dirs, not the workspace |
| Compatibility checks | existing `security_events` and workspace tests | no regressions | Existing schema/redaction/CVE/E2E coverage and full workspace checks remain green | Pass | Also updated `secure_authz` struct literal to include new optional fields |

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m22.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m22.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add per-event HMAC, file sink, HTTP sink, correlation to `security_events` description
- **README.md**: Add audit chain and file sink usage examples
- **docs/dev-guide/security-events.md**: Add tamper evidence, sinks, and correlation sections

---

### Milestone 23 — Authorization Enhancements (OWASP C1, ESAPI Alignment)

**Goal**: Enhance `secure_authz` with lightweight attribute-based access control (ABAC) predicates, time-bounded permissions, tenant-aware cache keys, and bulk authorization. This addresses OWASP C1 (Implement Access Control) with a Rust-idiomatic approach — simple, composable building blocks rather than a full enterprise XACML engine.

**Context**: `secure_authz` currently uses Casbin for RBAC policy evaluation. The architecture supports a `PolicyEngine` trait, but the current implementation is limited to role-based checks. Gaps: (1) no ability to authorize based on resource attributes or request context, (2) cache key does not include `tenant_id` — risk of cross-tenant authorization bypass in multi-tenant deployments, (3) no time-bounded permissions — cannot express "access expires at 5pm", (4) no bulk authorization for batch operations.

**Important design rule**: ABAC predicates should be implemented as **simple Rust closures/functions** — `Fn(&Subject, &ResourceRef, &Action) -> Decision` — not a policy language or rule engine. This keeps the library lightweight and Rust-native. Developers compose predicates using standard Rust combinators. The `PolicyEngine` trait should be extended (not replaced) with default-implemented methods. Time-bounded permissions must be checked at enforcement time, not just at grant time. Cache keys must include all context that could affect the authorization decision (subject, resource, action, tenant).

**Refactor budget**: `Targeted refactor permitted for cache key computation only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Subject attributes, resource attributes, action, environment context (time, tenant) |
| Outputs | Authorization decision (`Allow`/`Deny`) |
| Interfaces touched | `PolicyEngine` trait (extended with default impls), `AuthzDecision`, cache key logic |
| Files allowed to change | `crates/secure_authz/src/` (all files in this crate) |
| Files to read before changing anything | `crates/secure_authz/src/lib.rs`, `crates/secure_authz/src/engine.rs`, `crates/secure_authz/src/decision.rs`, `crates/secure_authz/src/cache.rs` (if exists) |
| New files allowed | `crates/secure_authz/src/abac.rs`, `crates/secure_authz/src/temporal.rs`, `crates/secure_authz/tests/sunlit_owasp_abac.rs`, `crates/secure_authz/tests/sunlit_owasp_temporal.rs`, `crates/secure_authz/tests/e2e_sunlit_owasp_m23.rs` |
| New dependencies allowed | `chrono` or `time` (for temporal permission evaluation — use `time` if already in dependency tree); no other new deps |
| Migration allowed | `no` |
| Compatibility commitments | Existing RBAC policy evaluations must continue to work; `PolicyEngine` trait additions must have default implementations |
| Forbidden shortcuts | No skipping tenant_id in cache keys; no caching time-bounded decisions without TTL; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not replace Casbin — extend via the `PolicyEngine` trait
- Do not implement a policy management UI
- Do not add policy hot-reload (separate operational concern)
- Do not implement JIT/JEA (complex workflow, separate milestone if needed)
- Do not change `security_core::IdentitySource`
- Do not implement obligation enforcement (enterprise XACML pattern — too complex for a lightweight library; consumers can implement this at the application layer)
- Do not build a policy language or rule engine — use Rust closures and functions

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_authz/src/abac.rs` | NEW: ABAC predicate type `AttributePredicate = Box<dyn Fn(&Subject, &ResourceRef, &Action) -> bool>`, `AttributeGuard` for composing predicates |
| Engine file | Extend `PolicyEngine` trait with ABAC and bulk authorization methods (with default impls) |
| Cache file | Fix cache key to include `tenant_id` and relevant context |
| Decision file | No changes needed — decision remains `Allow`/`Deny` |
| `crates/secure_authz/src/temporal.rs` | NEW: Time-bounded permission checks |
| Engine file | Extend `PolicyEngine` trait with ABAC and bulk authorization methods (with default impls) |
| Cache file | Fix cache key to include `tenant_id` and relevant context |
| `crates/secure_authz/Cargo.toml` | Add `time` or `chrono` if needed |
| `crates/secure_authz/tests/sunlit_owasp_abac.rs` | NEW: BDD tests |
| `crates/secure_authz/tests/sunlit_owasp_temporal.rs` | NEW: BDD tests |
| `crates/secure_authz/tests/e2e_sunlit_owasp_m23.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review |

#### BDD Acceptance Scenarios

**Feature: ABAC evaluation (attribute predicates as closures)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Attribute match allows access | happy path | Predicate: `\|s, _, _\| s.attr("role") == "admin" && s.attr("dept") == "eng"` | Subject has both attributes | `Allow` |
| Missing attribute denies access | invalid input | Predicate checks `s.attr("dept")` | Subject has no `department` attr | `Deny` |
| Multiple predicates AND | security | Two predicates: role check AND IP range check | Subject has role but wrong IP | `Deny` |
| Composed predicates OR | happy path | `predicate_a.or(predicate_b)` — admin OR superuser | Subject has `role==superuser` | `Allow` |
| Unknown attribute yields Deny | secure default | Predicate checks `s.attr("clearance_level")` | Attribute not in subject context | `Deny` (fail-closed) |
| Predicate is `Send + Sync` | type safety | `Box<dyn Fn(&Subject, &ResourceRef, &Action) -> bool + Send + Sync>` | Compile check | Compiles; usable across threads |

**Feature: Time-bounded permissions**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Active permission allowed | happy path | Permission valid `09:00–17:00`; current time `12:00` | Authorize | `Allow` |
| Expired permission denied | temporal | Permission valid until `2024-01-01`; current date later | Authorize | `Deny` |
| Not-yet-active permission denied | temporal | Permission valid from `2025-06-01`; current date earlier | Authorize | `Deny` |
| No temporal constraint | happy path | Permission with no time bounds | Authorize | Normal RBAC evaluation |

**Feature: Tenant-aware cache key**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Same user different tenant | cross-tenant | User `alice`, tenant `A` → Allow; tenant `B` → Deny | Query for tenant `B` | `Deny` (not cached `Allow` from tenant `A`) |
| Cache hit for same tenant | performance | Same user, same tenant, same resource | Second query | Cache hit; no policy engine call |

**Feature: Bulk authorization**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Batch of 100 checks | happy path | 100 (subject, resource, action) tuples | `authorize_bulk()` | Returns 100 decisions |
| Partial allow/deny in batch | mixed | 50 allowed, 50 denied | `authorize_bulk()` | Correct per-item decisions |

#### Regression Tests

- All existing RBAC policy tests must still pass
- All existing `PolicyEngine` implementations must compile
- Casbin integration unchanged
- Middleware integration unchanged

#### Compatibility Checklist

- [x] Existing RBAC evaluations produce same results
- [x] `PolicyEngine` trait additions have default implementations
- [x] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/secure_authz/tests/e2e_sunlit_owasp_m23.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_abac_attribute_evaluation` | ABAC works at runtime | Correct allow/deny based on attributes |
| `test_temporal_permission_expiry` | Time-bounded checks work at runtime | Expired permission denied |
| `test_tenant_isolation_in_cache` | Cache keys include tenant | No cross-tenant cache leakage |
| `test_bulk_authorization_correctness` | Batch authorization works | Correct per-item decisions |
| `test_existing_rbac_still_works` | Backward compatibility | RBAC decisions unchanged |

#### Smoke Tests

- [x] `cargo test -p secure_authz` passes
- [x] `cargo test --workspace` passes
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [x] `cargo build --workspace` succeeds
- [x] `cargo doc --no-deps --workspace` completes with zero warnings
- [x] `cargo test --doc -p secure_authz` passes
- [x] All new public types/functions have `# Examples` in doc comments
- [x] `git status` shows no untracked test artifacts

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | all green | Initial run failed only in pre-created M23 ABAC/temporal/e2e tests due unresolved symbols (`abac`, `temporal`, `with_abac_guard`, `with_time_source`, `authorize_bulk`) | Pass | Valid red phase for test-first M23 work in progress |
| BDD tests created | `sunlit_owasp_abac.rs`, `sunlit_owasp_temporal.rs` | fail for expected reason | Existing files already present and failing for missing M23 APIs | Pass | Reused existing red-phase tests |
| E2E stubs created | `e2e_sunlit_owasp_m23.rs` | fail for expected reason | Existing file present and failing for missing M23 APIs | Pass | Reused existing red-phase E2E |
| Implementation | ABAC + temporal + cache key + bulk auth | contract satisfied | Implemented ABAC guard integration, temporal checks, `CacheKey::for_request`, `DefaultAuthorizer::authorize_bulk`, and default `PolicyEngine::evaluate_bulk` | Pass | Kept trait/API compatibility additive |
| Full tests | `cargo test --workspace` | green | Green after implementation and final rerun | Pass | Includes regression coverage across all crates |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | Green, including `e2e_sunlit_owasp_m23` | Pass | Confirms runtime ABAC/temporal/cache/bulk behavior |
| Build/boot | `cargo build --workspace` | boots cleanly | Build completed successfully | Pass | Verified in final validation batch |
| Doc build | `cargo doc --no-deps --workspace` | zero warnings | Completed successfully with no warnings | Pass | Also validated by warning-count run |
| Doc tests | `cargo test --doc --workspace` | all pass | All workspace doctests passed | Pass | `secure_authz` doctests 11/11 |
| Smoke tests | all items above | all checked | All listed smoke checks passed | Pass | No skipped checks |
| Test artifact cleanup | `git status --short --untracked-files=all` | no untracked test artifacts | Only intended source/doc files are modified; no test artifact files | Pass | Cleanup validated |
| .gitignore review | review `.gitignore` | patterns current | No new generated patterns required for M23 | Pass | M23 changes do not emit new repo-local artifacts |
| Compatibility checks | existing RBAC + middleware tests | no regressions | Existing RBAC/tenant/middleware tests remain green | Pass | Backward behavior preserved |

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m23.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m23.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add ABAC and temporal permissions to `secure_authz` description
- **README.md**: Add ABAC and temporal permission usage examples
- **docs/dev-guide/secure-authz.md**: Add ABAC and temporal permissions sections

---

### Milestone 24 — Identity Enhancements: OIDC, MFA, Sessions (OWASP C7)

**Goal**: Enhance `secure_identity` with OIDC discovery client support (via the `openidconnect` crate, not hand-rolled), TOTP-based MFA implementation, persistent session backends (Redis/database behind feature flags), and authentication success event auditing. This addresses OWASP C7 (Implement Digital Identity Controls) and the principle that security libraries should compose existing well-audited crates rather than reimplement protocol-level logic.

**Context**: `secure_identity` currently has JWT-based `TokenProvider`, an `MfaProvider` trait (with no implementations), `InMemorySessionStore` (not production-ready), and no OIDC support. Applications building on SunLit have no path to federated identity, no concrete MFA, and no persistent sessions. The `MfaProvider` trait exists but provides zero implementations — developers cannot use it without writing their own TOTP logic.

**Important design rule**: OIDC integration must use the `openidconnect` crate (a well-maintained, widely-used Rust OIDC client library) behind an `oidc` feature flag. SunLit's role is to provide a thin ergonomic wrapper that applies secure defaults and integrates with `security_events` — not to reimplement OIDC discovery, token validation, or PKCE from scratch. TOTP must follow RFC 6238 exactly. Session backends must implement the existing `SessionStore` trait. Authentication success events (not just failures) must be emitted for anomaly detection.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | OIDC issuer URL; TOTP secret + code; session data; authentication results |
| Outputs | OIDC token validation; TOTP verification result; persistent session lifecycle; audit events |
| Interfaces touched | `MfaProvider` trait (implemented), `SessionStore` trait (new impl), new `OidcClient` wrapper around `openidconnect` crate |
| Files allowed to change | `crates/secure_identity/src/`, `crates/secure_identity/Cargo.toml` |
| Files to read before changing anything | `crates/secure_identity/src/lib.rs`, `crates/secure_identity/src/token.rs`, `crates/secure_identity/src/mfa.rs`, `crates/secure_identity/src/session.rs` |
| New files allowed | `crates/secure_identity/src/oidc.rs`, `crates/secure_identity/src/totp.rs`, `crates/secure_identity/src/session_redis.rs`, `crates/secure_identity/src/auth_events.rs`, `crates/secure_identity/tests/sunlit_owasp_oidc.rs`, `crates/secure_identity/tests/sunlit_owasp_totp.rs`, `crates/secure_identity/tests/sunlit_owasp_sessions.rs`, `crates/secure_identity/tests/e2e_sunlit_owasp_m24.rs` |
| New dependencies allowed | `totp-rs` (RFC 6238 TOTP — widely used, pure Rust); `openidconnect` behind `oidc` feature flag (handles OIDC discovery, token validation, PKCE — do not hand-roll); `redis` behind `session-redis` feature flag; `serde_json` if not already present |
| Migration allowed | `no` |
| Compatibility commitments | `TokenProvider` unchanged; `SessionStore` trait unchanged; `MfaProvider` trait unchanged |
| Forbidden shortcuts | No hardcoded TOTP secrets; no skipping OIDC issuer validation; no plaintext session storage; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not implement a full OAuth2 authorization server
- Do not implement SAML
- Do not implement WebAuthn/FIDO2 (separate milestone if needed)
- Do not modify `TokenProvider` JWT logic
- Do not implement rate limiting on authentication (operational concern in middleware)
- Do not implement password reset flows (application logic)

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_identity/src/oidc.rs` | NEW: Thin wrapper around `openidconnect` crate — `OidcClient` with secure defaults (HTTPS-only issuers, PKCE enforcement), caching, and `security_events` integration. Do NOT reimplement discovery/validation logic. |
| `crates/secure_identity/src/totp.rs` | NEW: `TotpProvider` implementing `MfaProvider` trait — RFC 6238 TOTP generation and validation |
| `crates/secure_identity/src/session_redis.rs` | NEW: `RedisSessionStore` implementing `SessionStore` trait (behind `session-redis` feature) |
| `crates/secure_identity/src/auth_events.rs` | NEW: Emit `AuthenticationSuccess` and `AuthenticationFailure` events via `security_events` |
| `crates/secure_identity/src/lib.rs` | Add new module declarations with feature gates |
| `crates/secure_identity/Cargo.toml` | Add `totp-rs`, `reqwest` (oidc feature), `redis` (session-redis feature) |
| `crates/secure_identity/tests/sunlit_owasp_oidc.rs` | NEW: BDD tests |
| `crates/secure_identity/tests/sunlit_owasp_totp.rs` | NEW: BDD tests |
| `crates/secure_identity/tests/sunlit_owasp_sessions.rs` | NEW: BDD tests |
| `crates/secure_identity/tests/e2e_sunlit_owasp_m24.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review |

#### BDD Acceptance Scenarios

**Feature: OIDC client (via `openidconnect` crate)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Discovery document fetched | happy path | Valid OIDC issuer URL | `OidcClient::discover()` | Returns configured client via `openidconnect` with `jwks_uri`, `token_endpoint`, etc. |
| Issuer URL mismatch rejected | security | Discovery doc `issuer` field differs from request URL | `OidcClient::discover()` | Returns error `issuer_mismatch` (delegated to `openidconnect` validation) |
| Discovery cached with TTL | performance | Same issuer fetched twice within TTL | Second `discover()` | Cache hit; no HTTP request |
| Cache expired refetches | staleness | TTL expired | `discover()` | New HTTP request; cache updated |
| Non-HTTPS issuer rejected | security | `http://` issuer URL | `OidcClient::discover()` | Returns error `insecure_issuer` (SunLit layer enforces before delegating) |
| Network failure handled | dependency failure | Issuer URL unreachable | `OidcClient::discover()` | Returns error `discovery_unreachable`; no panic |
| PKCE enforced by default | security | Client initiates auth code flow | `OidcClient::auth_url()` | PKCE challenge included automatically |

**Feature: TOTP MFA**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid TOTP accepted | happy path | Correct TOTP code for current time window | `TotpProvider.verify()` | Returns `true` |
| Expired TOTP rejected | temporal | TOTP from previous time window beyond skew | `TotpProvider.verify()` | Returns `false` |
| One-step skew accepted | usability | TOTP from adjacent time window (within configured skew) | `TotpProvider.verify()` | Returns `true` (with skew=1) |
| Wrong code rejected | invalid input | Random 6-digit code | `TotpProvider.verify()` | Returns `false` |
| Secret generation | setup | New user enrollment | `TotpProvider.generate_secret()` | Returns base32-encoded secret and provisioning URI |
| Secret is SecretString | info disclosure | Generated secret | `format!("{:?}", secret)` | Contains `[REDACTED]` |

**Feature: Persistent session store**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Create session | happy path | Valid session data | `store.create()` | Returns session ID; data persisted |
| Retrieve session | happy path | Existing session ID | `store.get()` | Returns session data |
| Expired session returns None | temporal | Session with TTL expired | `store.get()` | Returns `None` |
| Delete session | happy path | Existing session ID | `store.delete()` | Subsequent `get()` returns `None` |
| Backend unavailable | dependency failure | Redis down | `store.create()` | Returns error; no panic |

**Feature: Authentication event auditing**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Success event emitted | happy path | Successful authentication | After auth | `AuthenticationSuccess` event emitted with user ID, timestamp, method |
| Failure event emitted | happy path | Failed authentication | After auth failure | `AuthenticationFailure` event emitted with reason |
| Events include IP and user-agent | forensics | Auth attempt with request context | Event emitted | Contains source IP and user-agent |

#### Regression Tests

- All existing `TokenProvider` tests must still pass
- All existing `SessionStore` tests must still pass
- `MfaProvider` trait unchanged
- `InMemorySessionStore` unchanged

#### Compatibility Checklist

- [ ] `TokenProvider` API unchanged
- [ ] `SessionStore` trait unchanged
- [ ] `MfaProvider` trait unchanged
- [ ] `InMemorySessionStore` still works
- [ ] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/secure_identity/tests/e2e_sunlit_owasp_m24.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_totp_generate_and_verify` | Full TOTP lifecycle works at runtime | Generate secret → generate code → verify succeeds |
| `test_totp_wrong_code_rejected` | Wrong codes rejected at runtime | Random code → verify returns false |
| `test_auth_success_event_emitted` | Auth events flow to security_events | Event captured by InMemorySink |
| `test_session_create_retrieve_delete` | Session lifecycle works | Create → get → delete → get returns None |
| `test_existing_token_provider_works` | Backward compatibility | JWT token operations unchanged |

#### Smoke Tests

- [ ] `cargo test -p secure_identity` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --doc -p secure_identity` passes
- [ ] All new public types/functions have `# Examples` in doc comments
- [ ] `git status` shows no untracked test artifacts

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m24.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m24.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add OIDC, TOTP, persistent sessions, auth events to `secure_identity` description
- **README.md**: Add TOTP and OIDC usage examples
- **docs/dev-guide/secure-identity.md**: Add OIDC discovery, TOTP MFA, persistent sessions, and auth event sections

---

### Milestone 25 — Crypto Agility & Key Management (OWASP C2, ESAPI Alignment)

**Goal**: Implement crypto agility in `secure_data` — support for multiple encryption algorithms (currently hardcoded to AES-256-GCM), algorithm negotiation via policy, key version metadata persistence, and an Azure Key Vault provider behind a feature flag. This addresses OWASP C2 (Leverage Cryptography) and Kevin Wall's ESAPI principle: "Cryptographic agility — you must be able to switch algorithms without changing application code."

**Context**: `secure_data/src/envelope.rs` currently hardcodes AES-256-GCM. There is a `KeyProvider` trait and in-memory ring, but no persistent key storage and no way to roll forward to a new algorithm. When AES-256-GCM eventually shows weakness (or a compliance mandate requires a different algorithm), every adopter must patch application code. Kevin Wall has written extensively about this problem in the ESAPI context — crypto agility must be built in from the start.

**Important design rule**: The `CryptoAlgorithm` enum must be stored in the encrypted envelope alongside the ciphertext, so decryption can select the correct algorithm even when the system default has changed. Key version metadata must support both "encrypt with latest, decrypt with any known version" semantics. The Azure Key Vault provider must never expose key material to the application — wrap/unwrap only.

**Refactor budget**: `Targeted refactor permitted for envelope format extension only`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Plaintext data, algorithm preference, key provider configuration |
| Outputs | Encrypted envelope with algorithm tag and key version; decrypted data |
| Interfaces touched | `EncryptedEnvelope` (extended), `KeyProvider` trait (extended), new `AlgorithmPolicy` |
| Files allowed to change | `crates/secure_data/src/envelope.rs`, `crates/secure_data/src/key.rs` or equivalent, `crates/secure_data/src/lib.rs`, `crates/secure_data/Cargo.toml` |
| Files to read before changing anything | `crates/secure_data/src/envelope.rs`, `crates/secure_data/src/key.rs`, `crates/secure_data/src/lib.rs`, `crates/secure_data/src/secret.rs` |
| New files allowed | `crates/secure_data/src/algorithm.rs`, `crates/secure_data/src/key_vault.rs`, `crates/secure_data/tests/sunlit_owasp_agility.rs`, `crates/secure_data/tests/sunlit_owasp_keyvault.rs`, `crates/secure_data/tests/e2e_sunlit_owasp_m25.rs` |
| New dependencies allowed | `chacha20poly1305` (RustCrypto — for XChaCha20-Poly1305 as alt algorithm); `azure_security_keyvault` behind `azure-kv` feature flag; `aes-gcm` version bump if needed |
| Migration allowed | `Envelope format extension only — old envelopes must still decrypt` |
| Compatibility commitments | Existing envelopes created with AES-256-GCM must still decrypt; `KeyProvider` trait additions have default implementations |
| Forbidden shortcuts | No removing AES-256-GCM support; no exposing key material from Key Vault; no `unsafe`; no algorithm downgrade without explicit policy |

#### Out of Scope / Must Not Do

- Do not implement HSM integration beyond Azure Key Vault
- Do not implement key ceremony workflows
- Do not modify password hashing (M20) or HMAC signing (M22)
- Do not add post-quantum cryptography (separate research milestone)
- Do not implement certificate management

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_data/src/algorithm.rs` | NEW: `CryptoAlgorithm` enum (`Aes256Gcm`, `XChaCha20Poly1305`), `AlgorithmPolicy` |
| `crates/secure_data/src/envelope.rs` | Extend `EncryptedEnvelope` to include `algorithm` and `key_version` fields |
| `crates/secure_data/src/key.rs` or equivalent | Extend `KeyProvider` with version-aware methods (with defaults) |
| `crates/secure_data/src/key_vault.rs` | NEW: Azure Key Vault `KeyProvider` impl (behind `azure-kv` feature) |
| `crates/secure_data/src/lib.rs` | Add new module declarations |
| `crates/secure_data/Cargo.toml` | Add `chacha20poly1305`, `azure_security_keyvault` behind feature flag |
| `crates/secure_data/tests/sunlit_owasp_agility.rs` | NEW: BDD tests |
| `crates/secure_data/tests/sunlit_owasp_keyvault.rs` | NEW: BDD tests (mockable, no real Azure) |
| `crates/secure_data/tests/e2e_sunlit_owasp_m25.rs` | NEW: E2E runtime validation |
| `.gitignore` | Review |

#### BDD Acceptance Scenarios

**Feature: Crypto algorithm selection**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Default algorithm is AES-256-GCM | backward compat | No algorithm configured | `encrypt_for_storage()` | Envelope contains `algorithm: Aes256Gcm` |
| XChaCha20 selected via policy | happy path | `AlgorithmPolicy::prefer(XChaCha20Poly1305)` | `encrypt_for_storage()` | Envelope contains `algorithm: XChaCha20Poly1305` |
| Decrypt old AES envelope | backward compat | Envelope created before agility feature | `decrypt_for_use()` | Decrypts successfully (assumes AES-256-GCM) |
| Decrypt XChaCha envelope | happy path | Envelope with `algorithm: XChaCha20Poly1305` | `decrypt_for_use()` | Decrypts successfully with correct algorithm |
| Unknown algorithm rejected | invalid input | Envelope with `algorithm: "unknown"` | `decrypt_for_use()` | Returns error `unsupported_algorithm` |
| Algorithm downgrade prevented | security | Policy: `min_algorithm: XChaCha20Poly1305` | Attempt encrypt with AES-256-GCM | Returns error `algorithm_below_policy_minimum` |

**Feature: Key versioning**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Encrypt with latest key version | happy path | Key ring with versions 1, 2, 3 | `encrypt_for_storage()` | Envelope contains `key_version: 3` |
| Decrypt with old key version | backward compat | Envelope with `key_version: 1` | `decrypt_for_use()` | Decrypts using key version 1 |
| Unknown key version rejected | invalid input | Envelope with `key_version: 99` | `decrypt_for_use()` | Returns error `key_version_not_found` |
| Key rotation transparent | happy path | Rotate key from v2 to v3 | Encrypt new data | New envelopes use v3; old envelopes still decrypt with v2 |

**Feature: Azure Key Vault provider**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Wrap key via vault | happy path | Mock Key Vault provider | `wrap_key()` | Returns wrapped key blob |
| Unwrap key via vault | happy path | Mock Key Vault provider, wrapped blob | `unwrap_key()` | Returns plaintext key (never leaves vault in real impl) |
| Vault unavailable | dependency failure | Mock vault returns error | `wrap_key()` | Returns error `vault_unavailable`; no panic |
| Key material never in memory | security | Real Key Vault pattern | Inspect API surface | No method returns raw key bytes from vault |

#### Regression Tests

- All existing envelope encryption tests must still pass
- All existing `KeyProvider` implementations must compile
- `SecretString` and `SecretReference` unchanged
- Password hashing (M20) unaffected

#### Compatibility Checklist

- [ ] Existing `EncryptedEnvelope` deserialization backward compatible (new fields have defaults)
- [ ] `encrypt_for_storage()` / `decrypt_for_use()` API unchanged for callers not using new features
- [ ] `KeyProvider` trait additions have default implementations
- [ ] `InMemoryKeyRing` unchanged
- [ ] All existing tests pass

#### E2E Runtime Validation

**File**: `crates/secure_data/tests/e2e_sunlit_owasp_m25.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_aes_encrypt_decrypt_roundtrip` | Existing AES-256-GCM still works | Encrypt → decrypt → original data |
| `test_xchacha_encrypt_decrypt_roundtrip` | New algorithm works end-to-end | Encrypt with XChaCha → decrypt → original data |
| `test_old_envelope_still_decrypts` | Backward compatibility for pre-agility envelopes | Old-format envelope decrypts correctly |
| `test_key_version_rotation` | Key rotation is transparent | Old data decrypts with old key; new data uses new key |
| `test_algorithm_downgrade_prevented` | Policy enforcement works | Attempt to use below-minimum algorithm fails |

#### Smoke Tests

- [ ] `cargo test -p secure_data` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --doc -p secure_data` passes
- [ ] All new public types/functions have `# Examples` in doc comments
- [ ] `git status` shows no untracked test artifacts

#### Definition of Done

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green
- smoke tests checked off
- compatibility checklist complete
- lessons file at `docs/slo/lessons/sunlit-owasp-m25.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m25.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add crypto agility, key versioning, Azure Key Vault to `secure_data` description
- **README.md**: Add crypto agility and key rotation usage examples
- **docs/dev-guide/secure-data.md**: Add crypto agility, algorithm policy, key versioning, and Key Vault sections

---

### Milestone 26 — Documentation & Ergonomics Retrofit (Rust API Guidelines)

**Goal**: Retrofit `# Examples` doc sections, convenience free functions, and standard trait derives across ALL existing public APIs in the workspace. The sub-agent codebase analysis found only 1 `# Examples` section in the entire workspace (in `audit_chain.rs`). This milestone brings the entire codebase up to Rust API Guidelines C-EXAMPLE, C-FAILURE, and C-CRATE-DOC standards, and adds the convenience free functions mandated by the Rust API Design Standards section of this runbook.

**Context**: The codebase has strong type safety (A-grade newtypes, `TryFrom`, `Cow<str>`) but extremely poor documentation ergonomics (C+ grade). New milestones M18–M25 require `# Examples` on all new public APIs, but the existing codebase has nearly zero documentation examples. Without this milestone, there will be a severe inconsistency between new and existing code, and developers adopting the library will have no usage examples for core types like `SecureString`, `HtmlSafe`, `ResourceRef`, `CorrelationContext`, `PolicyEngine`, `TokenProvider`, etc.

**Important design rule**: Every public type, trait, and function must have at least one `# Examples` doc section that compiles under `cargo test --doc`. Every fallible function must have an `# Errors` section listing error variants. Every crate must have a crate-level doc comment (`//!`) with a usage overview. Convenience free functions must be added for stateless encoder operations (e.g., `secure_output::html::encode(s)` alongside `HtmlEncoder::encode(s)`).

**Refactor budget**: `Documentation additions and convenience free functions only — no logic changes`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Existing public API surface across all crates |
| Outputs | Doc examples on all public items; convenience free functions for stateless operations; crate-level docs; `# Errors` sections on fallible functions |
| Interfaces touched | All crates — documentation only (plus convenience free functions that delegate to existing implementations) |
| Files allowed to change | All `src/lib.rs` and public module files across all crates |
| Files to read before changing anything | `cargo doc --no-deps --workspace 2>&1` to identify missing doc warnings; all `src/lib.rs` files |
| New files allowed | None — all changes are to existing files |
| New dependencies allowed | None |
| Migration allowed | `no` |
| Compatibility commitments | Zero API changes — only additive (new functions, documentation) |
| Forbidden shortcuts | No `# Examples` that use `ignore` or `no_run` without justification; no stub examples that don't demonstrate real usage; no `unsafe` |

#### Out of Scope / Must Not Do

- Do not change any existing function signatures or behavior
- Do not add new types, traits, or error variants
- Do not refactor existing code
- Do not add dependencies
- Do not modify tests (doc tests are new tests, not modifications)

#### Checklist by Crate

| Crate | `//!` crate doc | `# Examples` on public items | `# Errors` on fallible fns | Convenience free fns | Standard derives |
|---|---|---|---|---|---|
| `security_core` | ☐ | ☐ | ☐ | N/A | ☐ |
| `secure_boundary` | ☐ | ☐ | ☐ | N/A | ☐ |
| `secure_output` | ☐ | ☐ | ☐ | ☐ `html::encode()`, `url::encode()`, etc. | ☐ |
| `secure_data` | ☐ | ☐ | ☐ | N/A | ☐ |
| `secure_errors` | ☐ | ☐ | ☐ | N/A | ☐ |
| `secure_identity` | ☐ | ☐ | ☐ | N/A | ☐ |
| `secure_authz` | ☐ | ☐ | ☐ | N/A | ☐ |
| `security_events` | ☐ | ☐ | ☐ | N/A | ☐ |

#### BDD Acceptance Scenarios

**Feature: Doc examples compile and pass**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All doc examples compile | documentation | All `# Examples` sections | `cargo test --doc --workspace` | Zero failures |
| No doc warnings | documentation | All crates | `cargo doc --no-deps --workspace 2>&1` | Zero warnings about missing docs |
| Convenience free functions equivalent | API ergonomics | `secure_output::html::encode(s)` | Compare with `HtmlEncoder::encode(s)` | Identical output |
| Crate-level docs present | documentation | Each crate | `//!` comment at top of `lib.rs` | Non-empty crate description |

#### Smoke Tests

- [ ] `cargo test --doc --workspace` passes
- [ ] `cargo doc --no-deps --workspace` completes with zero warnings
- [ ] `cargo test --workspace` passes (no regressions)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] Every public type/trait/function has `# Examples`
- [ ] Every fallible public function has `# Errors`
- [ ] Every `lib.rs` has a `//!` crate-level doc comment
- [ ] Convenience free functions exist for all stateless encoder operations

#### Definition of Done

- all listed BDD scenarios pass
- full existing test suite remains green
- smoke tests checked off
- `cargo doc` output reviewed manually for quality
- lessons file at `docs/slo/lessons/sunlit-owasp-m26.md`
- completion summary at `docs/slo/completion/sunlit-owasp-m26.md`
- Milestone Tracker updated

#### Post-Flight

- **README.md**: Update usage examples to use convenience free functions where applicable
- **docs/dev-guide/*.md**: Verify all code examples in dev guides still compile

---

## Documentation Update Table

Track all documentation changes required across the 9 milestones.

| File | M18 | M19 | M20 | M21 | M22 | M23 | M24 | M25 | M26 | Description |
|---|---|---|---|---|---|---|---|---|---|---|
| `ARCHITECTURE.md` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | Component descriptions updated |
| `README.md` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Usage examples updated |
| `docs/dev-guide/secure-boundary.md` | ✓ | | | ✓ | | | | | ✓ | Limits + sanitize; browser security; doc examples |
| `docs/dev-guide/secure-output.md` | | ✓ | | | | | | | ✓ | LDAP + shell encoders; doc examples |
| `docs/dev-guide/secure-data.md` | | | ✓ | | | | | ✓ | ✓ | Password hashing; crypto agility; doc examples |
| `docs/dev-guide/security-events.md` | | | | | ✓ | | | | ✓ | HMAC, sinks, correlation; doc examples |
| `docs/dev-guide/secure-authz.md` | | | | | | ✓ | | | ✓ | ABAC, temporal permissions; doc examples |
| `docs/dev-guide/secure-identity.md` | | | | | | | ✓ | | ✓ | OIDC, TOTP, sessions; doc examples |
| `docs/dev-guide/integration-guide.md` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Cross-crate integration updated |
| `THREAT_MODEL.md` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | New controls and mitigations |
| `docs/attack-trees/input-output.md` | ✓ | ✓ | | ✓ | | | | | | JSON bomb, LDAP/shell inject, browser |
| `docs/attack-trees/data-protection.md` | | | ✓ | | ✓ | | | ✓ | | Password, audit tamper, crypto agility |
| `docs/attack-trees/authorization.md` | | | | | | ✓ | | | | ABAC, temporal bypass |
| `docs/attack-trees/identity.md` | | | | | | | ✓ | | | OIDC, MFA bypass, session fixation |

---

## Final Notes

This runbook covers all gaps identified through the OWASP Proactive Controls 2024 alignment review, adapted from ESAPI principles into idiomatic Rust patterns. The original ESAPI research informed the *what* (which security controls are needed) while the Rust API Guidelines and modern Rust ecosystem informed the *how* (lightweight, composable, well-documented crates — not Java-style enterprise wrappers).

The 9 milestones (M18–M26) are sequenced by impact: input validation and output encoding first (most exploitable), then browser security, then hardening of existing subsystems, then new capabilities, and finally a cross-cutting documentation and ergonomics pass.

Each milestone is self-contained and can be executed independently. However, the recommended order minimizes cross-milestone dependencies:

1. **M18** (input limits) — no dependencies on other milestones
2. **M19** (output encoders) — no dependencies
3. **M20** (password hashing) — no dependencies
4. **M21** (browser security) — no dependencies
5. **M22** (security events) — no dependencies
6. **M23** (authz enhancements) — independent
7. **M24** (identity enhancements) — depends on `security_events` for auth auditing
8. **M25** (crypto agility) — independent but benefits from M20 password infrastructure context
9. **M26** (documentation & ergonomics) — should be done last, after all new APIs from M18–M25 are in place, so all public surfaces get doc examples in one pass

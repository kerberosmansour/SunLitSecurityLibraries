# SunLit Security Libraries — OWASP Proactive Controls for Rust (AI-First Runbook v3)

> **Purpose**: Build a production-grade Cargo workspace of eight security crates (`security_core`, `secure_errors`, `security_events`, `secure_boundary`, `secure_identity`, `secure_authz`, `secure_data`, `secure_output`) implementing OWASP Proactive Controls C1/C4/C5/C6/C7/C8/C9/C10 for Rust web services targeting critical infrastructure, with first-class axum/tower adapters, supply-chain scanning via cargo-audit/cargo-deny/cargo-vet/cargo-audit-build, adversarial testing via cargo-fuzz/proptest/miri, and a reference service proving end-to-end integration.  
> **Audience**: AI coding agents first, humans second. This document is written to reduce ambiguity, prevent scope drift, and improve code quality with the same model capability.  
> **How to use**: Work through milestones sequentially. Before starting any milestone, read its full section and the Global Execution Rules. After completing it, follow the Global Exit Rules. Never skip ahead. Never silently widen scope.  
> **Prerequisite reading**: [ARCHITECTURE.md](../../../ARCHITECTURE.md), [README.md](../../../README.md)

---

## Runbook Metadata

- **Runbook ID**: `sunlit-sec`
- **Prefix for test files and lessons files**: `sunlit`
- **Primary stack**: `Rust 1.85+ (2024 edition)`
- **Target platforms**: Linux (x86_64, aarch64), macOS (x86_64, aarch64/Apple Silicon), Windows (x86_64). All code, tests, scripts, and CI must work on all three OSes unless a deviation is explicitly documented.
- **Primary package/app names**: `security_core`, `secure_errors`, `security_events`, `secure_boundary`, `secure_identity`, `secure_authz`, `secure_data`, `secure_output`, `secure_reference_service`
- **Default test commands** (platform-independent — Cargo commands work identically on Linux, macOS, and Windows):
  - Backend: `cargo test --workspace`
  - Supply-chain audit: `cargo audit && cargo deny check && cargo vet`
  - E2E backend: `cargo test --workspace --test 'e2e_*'`
  - Build/boot: `cargo build --workspace && cargo run -p secure_reference_service`
  - Clippy: `cargo clippy --workspace --all-targets -- -D warnings`
  - Doc build: `cargo doc --workspace --no-deps`
- **Allowed new dependencies by default**: `none` — each milestone explicitly lists permitted crates
- **Schema/config migration allowed by default**: `no`
- **Public interfaces that must remain stable unless explicitly listed otherwise**:
  - `security_core::types::*` (shared ID types, classifications, severity)
  - `security_core::identity::*` (shared identity traits: `IdentitySource`, `AuthenticatedIdentity`)
  - `secure_errors::public::PublicError` response shape
  - `security_events::event::SecurityEvent` schema
  - `secure_boundary::extract::SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>` extractor APIs
  - `secure_identity::authenticator::Authenticator` trait
  - `secure_identity::session::SessionManager` trait
  - `secure_authz::enforcer::Authorizer` trait
  - `secure_authz::resolver::SubjectResolver` trait (accepts any `IdentitySource` implementor)
  - `secure_data::kms::KeyProvider` trait
  - `secure_output::encode::OutputEncoder` trait

---

## Milestone Tracker

Update this table as each milestone is completed. This is the single source of truth for progress.

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 0 | Threat model & security requirements (OWASP C1) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m0.md` | `docs/slo/completion/sunlit-m0.md` |
| 1 | Workspace scaffold + `security_core` | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m1.md` | `docs/slo/completion/sunlit-m1.md` |
| 2 | `secure_errors` — Centralized error handling (OWASP C10) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m2.md` | `docs/slo/completion/sunlit-m2.md` |
| 3 | `security_events` — Security logging, monitoring & tamper-evident audit (OWASP C9) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m3.md` | `docs/slo/completion/sunlit-m3.md` |
| 4 | `secure_boundary` + `secure_output` — Input validation, output encoding & security headers (OWASP C5, C4) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m4.md` | `docs/slo/completion/sunlit-m4.md` |
| 5 | `secure_identity` — Digital identity abstraction (OWASP C6) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m5.md` | `docs/slo/completion/sunlit-m5.md` |
| 6 | `secure_authz` — Access control enforcement (OWASP C7) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m6.md` | `docs/slo/completion/sunlit-m6.md` |
| 7 | `secure_data` — Data protection, secrets management & FIPS readiness (OWASP C8) | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m7.md` | `docs/slo/completion/sunlit-m7.md` |
| 8 | Reference service + axum integration + resilience | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m8.md` | `docs/slo/completion/sunlit-m8.md` |
| 9 | Adversarial testing — fuzzing, property tests & miri | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m9.md` | `docs/slo/completion/sunlit-m9.md` |
| 10 | Supply-chain hardening + CI security gate | `done` | 2026-04-06 | 2026-04-06 | `docs/slo/lessons/sunlit-m10.md` | `docs/slo/completion/sunlit-m10.md` |

<!-- Status values: not_started | in_progress | blocked | done -->
<!-- Lessons files go in docs/slo/lessons/sunlit-m<N>.md -->
<!-- Completion summaries go in docs/slo/completion/sunlit-m<N>.md -->

---

## End-to-End Architecture Diagram

### Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                           SunLit Security Libraries Workspace                                   │
│                        (Critical Infrastructure Security Platform)                            │
│                                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                          Trust Boundary (HTTP Edge)                                      │  │
│  │                                                                                          │  │
│  │  ┌──────────┐    ┌──────────────────┐    ┌───────────────────┐    ┌──────────────────┐   │  │
│  │  │  Client   │───▶│  axum Router +   │───▶│  secure_boundary  │───▶│  secure_output   │   │  │
│  │  │ (HTTP)    │    │  tower Middleware │    │  (extractors,     │    │  (output encoding │   │  │
│  │  └──────────┘    │  + SecurityHeaders│    │   validators,     │    │   context-aware   │   │  │
│  │                  └──────────────────┘    │   normalizers,    │    │   escaping, HSTS  │   │  │
│  │                         │                 │   size limits)    │    │   CSP, headers)   │   │  │
│  │                         │                 └────────┬──────────┘    └────────┬─────────┘   │  │
│  └─────────────────────────┼──────────────────────────┼───────────────────────┼──────────────┘  │
│                            │                          │                       │                  │
│                            ▼                          ▼                       │                  │
│  ┌──────────────────┐   ┌──────────────────┐   ┌───────────────────┐         │                  │
│  │  secure_identity  │   │                  │   │  secure_data      │         │                  │
│  │  (Authenticator   │   │  Handler Logic   │──▶│  (envelope crypto,│         │                  │
│  │   trait, session  │──▶│  (app domain)    │   │   KMS/Vault/FIPS, │◀────────┘                  │
│  │   mgmt, token     │   └──────┬───────────┘   │   secret wrappers)│                           │
│  │   validation,     │          │               └────────┬──────────┘                           │
│  │   pluggable IdP)  │          │                         │                                     │
│  └────────┬─────────┘          │                         │                                     │
│           │                    │                         │                                     │
│           ▼                    │                         │                                     │
│  ┌──────────────────┐          │                         │                                     │
│  │  secure_authz    │◀─────────┘                         │                                     │
│  │  (policy engine, │   Subject from any IdentitySource  │                                     │
│  │   enforcer,      │   (secure_identity, Keycloak,      │                                     │
│  │   middleware,     │    custom IdP, etc.)               │                                     │
│  │   tenant isoln)  │                                    │                                     │
│  └────────┬─────────┘                                    │                                     │
│           │                                              │                                     │
│           │         ┌──────────────────────┐             │                                     │
│           │         │  secure_errors       │◀────────────┘                                     │
│           │         │  (error taxonomy,    │                                                    │
│           └────────▶│   public mapping,    │                                                    │
│                     │   panic catcher)     │                                                    │
│                     └──────────┬───────────┘                                                    │
│                                │                                                               │
│                     ┌──────────▼───────────┐                                                    │
│                     │  security_events     │                                                    │
│                     │  (canonical events,  │                                                    │
│                     │   redaction engine,  │──────▶  OTLP / SIEM / stdout JSON                  │
│                     │   detection points,  │                                                    │
│                     │   tamper-evident     │                                                    │
│                     │   audit trail)       │                                                    │
│                     └──────────┬───────────┘                                                    │
│                                │                                                               │
│                     ┌──────────▼───────────┐                                                    │
│                     │  security_core       │                                                    │
│                     │  (ActorId, TenantId, │                                                    │
│                     │   RequestId, TraceId,│                                                    │
│                     │   DataClassification,│                                                    │
│                     │   SecuritySeverity,  │                                                    │
│                     │   IdentitySource     │                                                    │
│                     │   trait, shared)     │                                                    │
│                     └──────────────────────┘                                                    │
│                                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Supply-Chain & Adversarial Testing Gate (CI)                                          │   │
│  │  cargo-audit │ cargo-deny │ cargo-vet │ cargo-fuzz │ proptest │ miri │ clippy │ forbid  │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │  secure_reference_service (example axum app proving full integration + resilience)      │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                               │
│  Identity integration note:                                                                   │
│  secure_authz accepts Subject from ANY IdentitySource (trait in security_core).               │
│  secure_identity is one implementation. Keycloak, Auth0, custom OIDC — any crate that         │
│  implements IdentitySource can feed into secure_authz. They are decoupled by design.          │
│                                                                                               │
│  Legend:                                                                                      │
│  ─── existing (none — greenfield)    - - - new (all components)                               │
│  ═══ external (KMS, Vault, OTLP, IdP)  ▶ data flow                                           │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Milestone Introduced | Key Interfaces |
|---|---|---|---|
| `security_core` | Shared ID types, data classification, severity levels, redaction traits, time source, correlation context, **`IdentitySource` trait** (the universal bridge between any identity provider and the authorization layer) | M1 | `ActorId`, `TenantId`, `RequestId`, `TraceId`, `ResourceId`, `DataClassification`, `SecuritySeverity`, `SecretRef`, `PolicyVersion`, `IdentitySource`, `AuthenticatedIdentity`, `IdentityResolutionError` |
| `secure_errors` | Internal error taxonomy, public error mapping, panic catching, HTTP/gRPC response rendering, security-signal escalation | M2 | `AppError`, `PublicError`, `IntoResponse`, `ErrorClassification`, `incident_fingerprint()` |
| `security_events` | Canonical security event schema, redaction engine, detection points, tracing subscriber, OTLP/SIEM sink adapters, **tamper-evident audit trail** with hash-chain event integrity | M3 | `SecurityEvent`, `EventKind`, `Severity`, `RedactionPolicy`, `DetectionPoint`, `SecurityLayer`, `AuditChain` |
| `secure_boundary` | Axum extractors (`SecureJson`, `SecureQuery`, `SecurePath`), DTO validation, normalization, content-type enforcement, size limits, attack-signal emission, **`SecurityHeadersLayer`** for response hardening (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Cache-Control) | M4 | `SecureValidate`, `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>`, `ValidationContext`, `BoundaryViolation`, `SecurityHeadersLayer`, `SecurityHeadersConfig` |
| `secure_output` | Context-aware output encoding (HTML, JSON, URL, SQL contexts), XSS prevention, injection-safe response rendering, stored-XSS defense | M4 | `OutputEncoder`, `HtmlEncoder`, `JsonEncoder`, `UrlEncoder`, `EncodingContext` |
| `secure_identity` | **Pluggable identity abstraction** — `Authenticator` trait, `SessionManager` trait, token validation (JWT/PASETO), credential verification patterns, MFA hooks. Ships with `DevAuthenticator` for testing. Designed so consumers can swap in Keycloak, Auth0, custom OIDC, or any identity provider without changing authorization or business code. Does NOT own `Subject` — it produces an `AuthenticatedIdentity` that any `IdentitySource` implementor (including third-party crates) can convert into a `Subject` for `secure_authz`. | M5 | `Authenticator`, `AuthenticatedIdentity`, `SessionManager`, `TokenValidator`, `MfaChallenge`, `DevAuthenticator` |
| `secure_authz` | Policy-engine abstraction, deny-by-default enforcer, middleware guards, decision logging, tenant/ownership isolation. **Identity-agnostic**: accepts `Subject` built from any `IdentitySource` implementor — `secure_identity`, Keycloak adapter, custom IdP, or direct construction. No compile-time dependency on `secure_identity`. | M6 | `Authorizer`, `Subject`, `Decision`, `Resource`, `SubjectResolver` |
| `secure_data` | Secret wrappers, envelope encryption, KMS/Vault key providers, key rotation, secret-reference config, zeroization, **FIPS readiness** via feature-gated `aws-lc-rs` backend, HSM provider trait | M7 | `KeyProvider`, `SecretString`, `SecretBytes`, `encrypt_for_storage()`, `decrypt_for_use()`, `KeyAlias`, `FipsKeyProvider` |
| `secure_reference_service` | Example axum service integrating all crates, proving the platform works end-to-end, **resilience patterns** (circuit breaker, timeouts, bulkhead, graceful degradation), **security config validation at startup** | M8 | HTTP routes, middleware stack, integration tests, `SecurityConfig::validate()` |
| Adversarial testing | Fuzz targets for all parsers, property tests for validators/normalizers, `cargo miri` for memory safety, timing side-channel tests, CVE regression tests | M9 | Fuzz targets, property test suites |
| Supply-chain gate | `cargo-audit`, `cargo-deny`, `cargo-vet`, `cargo-audit-build`, CI pipeline, deterministic builds | M10 | `deny.toml`, `supply-chain/`, CI config |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Milestone |
|---|---|---|---|---|
| HTTP request ingress | Client | `secure_boundary` extractors | HTTP via axum | M4 |
| Response output encoding | Handler / `secure_output` | Client | Encoded HTTP response | M4 |
| Security headers injection | `SecurityHeadersLayer` | HTTP response | tower middleware | M4 |
| Validated DTO | `secure_boundary` | Handler logic | Rust function call | M4 |
| Identity resolution | `secure_identity` / external IdP | `Subject` (via `IdentitySource` trait in `security_core`) | Rust async trait call | M5 |
| Authorization check | Handler / middleware | `secure_authz` enforcer | Rust async trait call (receives `Subject` from any `IdentitySource`) | M6 |
| Secret retrieval | Handler / `secure_data` | KMS / Vault / HSM | HTTPS / gRPC | M7 |
| Envelope encrypt/decrypt | Handler | `secure_data` | Rust function call | M7 |
| Error mapping | Any crate | `secure_errors` mapper | `Into<AppError>` | M2 |
| Security event emission | All crates | `security_events` layer | `tracing` spans/events | M3 |
| Tamper-evident audit | `security_events` | Persistent audit log | Hash-chain append | M3 |
| Event export | `security_events` | OTLP collector / SIEM | OTLP gRPC or JSON stdout | M3 |
| Boundary violation signal | `secure_boundary` | `security_events` | Typed `AttackSignal` event | M4 |
| Authn failure signal | `secure_identity` / external IdP | `security_events` | Typed `AuthnFailure` event | M5 |
| Authz deny signal | `secure_authz` | `security_events` | Typed `Decision::Deny` event | M6 |
| Supply-chain scan | CI | `cargo-audit`/`cargo-deny`/`cargo-vet` | CLI in CI pipeline | M10 |
| Adversarial testing | CI | `cargo-fuzz`/`proptest`/`miri` | CLI in CI pipeline | M9 |

### Crate Dependency Graph

```
secure_reference_service
  ├── secure_boundary
  │     ├── security_events
  │     │     ├── secure_errors
  │     │     │     └── security_core
  │     │     └── security_core
  │     ├── secure_errors
  │     └── security_core
  ├── secure_output
  │     ├── secure_errors
  │     └── security_core
  ├── secure_identity              ← optional; one of many IdentitySource implementors
  │     ├── security_events
  │     ├── secure_errors
  │     └── security_core
  ├── secure_authz                 ← depends on security_core::IdentitySource, NOT on secure_identity
  │     ├── security_events
  │     ├── secure_errors
  │     └── security_core          (IdentitySource trait lives here)
  ├── secure_data
  │     ├── security_events
  │     ├── secure_errors
  │     └── security_core
  ├── secure_errors
  └── security_core

  Note: secure_authz has NO dependency on secure_identity.
  The IdentitySource trait in security_core is the contract.
  Any crate (secure_identity, a Keycloak adapter, a custom IdP)
  can implement IdentitySource to produce a Subject for secure_authz.
```

---

## High-Level Design for Formal Verification (TLA+ Section)

This section captures correctness-critical concurrency and state-machine behavior suitable for TLA+ modeling.

### 1. System Goal

The system must guarantee that: (a) every inbound request passes through input validation before reaching business logic, (b) every request to a protected resource passes through authentication (identity resolution via any `IdentitySource` implementor) and authorization, denied by default if no policy matches, (c) secrets are never exposed in logs, debug output, public error responses, or serialized payloads, (d) encryption key rotation preserves the ability to read data encrypted under previous key versions (dual-read), (e) security events are emitted for all authorization denials, authentication failures, boundary violations, and error escalations without losing events under backpressure, (f) the audit trail is tamper-evident — any modification to the event chain is detectable, and (g) output encoding prevents injection in all response contexts (HTML, JSON, URL).

### 2. Main Components

| Component | Responsibility | Key State (durable / volatile) | Visible Actions |
|---|---|---|---|
| `RequestPipeline` | Sequences extraction → validation → authentication → authorization → handler → output encoding → response mapping | Volatile: current request phase (`raw` → `extracted` → `validated` → `authenticated` → `authorized` → `handled` → `encoded` → `responded`) | `extract`, `validate`, `authenticate`, `authorize`, `handle`, `encode_output`, `map_error`, `emit_event` |
| `IdentityResolver` | Resolves authenticated identity from any `IdentitySource` (secure_identity, Keycloak, custom) into a `Subject` for authorization | Volatile: session state, token cache | `resolve_identity`, `validate_token`, `refresh_session`, `revoke_session` |
| `AuthzEnforcer` | Evaluates policies against (subject, action, resource) — identity-agnostic, accepts Subject from any source | Durable: policy set, policy version. Volatile: decision cache | `evaluate`, `deny_default`, `cache_hit`, `cache_miss`, `invalidate_cache` |
| `KeyRotation` | Manages encryption key lifecycle and dual-read windows | Durable: key versions, activation windows, wrapped data keys. Volatile: active key alias | `rotate_key`, `activate_version`, `deactivate_version`, `encrypt`, `decrypt_with_version` |
| `EventPipeline` | Accepts security events, redacts, serializes, chains (hash-chain for tamper evidence), exports | Volatile: event buffer, backpressure state. Durable: audit chain hashes | `emit`, `redact`, `chain_hash`, `export`, `drop_under_pressure`, `verify_chain` |

### 3. Abstract State

| Variable | Type (abstract) | Why Necessary | Explosion Risk |
|---|---|---|---|
| `request_phase` | function Request → {raw, extracted, validated, authenticated, authorized, handled, encoded, responded, rejected} | Safety: no request reaches `handled` without passing `validated`, `authenticated`, and `authorized` | low |
| `identity_state` | function Session → {anonymous, pending_mfa, authenticated, expired, revoked} | Safety: no anonymous or expired identity passes authorization | low |
| `policy_set` | set of (subject_pattern, action, resource_pattern) → {allow, deny} | Safety: deny-by-default when no policy matches | medium — bounded by policy count |
| `key_versions` | function KeyAlias → sequence of {version, status ∈ {active, decrypt_only, deactivated}} | Safety: dual-read, no data loss during rotation | low |
| `event_buffer` | bounded sequence of SecurityEvent | Liveness: events eventually exported or explicitly dropped | medium — bounded by buffer size |
| `audit_chain` | sequence of (event_hash, prev_hash) | Safety: tamper-evidence — any gap or mutation is detectable | low |

### 4. Key Actions / Transitions

| Action | Preconditions | State Updates | Failure / Interleaving Notes |
|---|---|---|---|
| `extract(req)` | `request_phase[req] = raw` | `request_phase[req] := extracted` or `rejected` | Extraction failure → reject, emit boundary violation event |
| `validate(req)` | `request_phase[req] = extracted` | `request_phase[req] := validated` or `rejected` | Validation failure → reject, classify as client_mistake or attack_signal |
| `authenticate(req)` | `request_phase[req] = validated` | `request_phase[req] := authenticated` or `rejected` | Identity resolution failure → reject. Expired token → reject. MFA pending → reject. Any `IdentitySource` may perform this step. |
| `authorize(req)` | `request_phase[req] = authenticated` | `request_phase[req] := authorized` or `rejected` | Policy miss → deny. Engine error → deny. Cache stale → re-evaluate. Subject comes from any IdentitySource — secure_identity, Keycloak, custom. |
| `encode_output(resp)` | `request_phase[req] = handled` | `request_phase[req] := encoded` | Output encoding failure → reject with safe error. Context mismatch → reject. |
| `rotate_key(alias)` | `key_versions[alias]` has at least one `active` version | New version `active`, previous version `decrypt_only` | Must be atomic: no window where zero versions are active |
| `emit_event(e)` | true | Append `e` to `event_buffer`, extend `audit_chain` | Under backpressure: drop oldest non-critical events, never drop security-critical events. Hash chain must remain contiguous. |

### 5. Safety Properties

- **No bypass**: For every request `r`, if `request_phase[r] = handled` then there exists a prior state where `request_phase[r] = validated` AND `request_phase[r] = authenticated` AND `request_phase[r] = authorized`.
- **Authentication before authorization**: For every request `r`, if `request_phase[r] = authorized` then `request_phase[r]` was previously `authenticated`. Authorization never evaluates an unauthenticated subject.
- **Identity-source agnostic**: The `authenticate` action accepts any `IdentitySource` implementor. The safety properties hold regardless of which identity provider produced the `Subject`.
- **Deny by default**: For any `(subject, action, resource)` not matched by any policy in `policy_set`, the decision is `Deny`.
- **No secret leakage**: No `SecurityEvent` in `event_buffer` contains a field with `DataClassification ∈ {secret, credentials}` in cleartext.
- **Key rotation safety**: At every state, for every `alias` in `key_versions`, at least one version has status `active` OR `decrypt_only`.
- **Consistent public errors**: Every `rejected` request produces a `PublicError` containing only the fields: `status`, `code`, `message`, `request_id`. No internal details, stack traces, or SQL text.
- **Audit chain integrity**: For every pair of consecutive events `(e_i, e_{i+1})` in `audit_chain`, `e_{i+1}.prev_hash = hash(e_i)`. Any gap or mutation is detectable by chain verification.
- **Output encoding completeness**: Every response containing user-supplied content passes through context-appropriate encoding before serialization.

### 6. Liveness Assumptions

- **Request completion**: Every submitted request is eventually `responded` or `rejected` — Fairness: weak fairness on `extract`, `validate`, `authenticate`, `authorize`, `handle`, `encode_output`, `map_error`.
- **Event export**: Every event in `event_buffer` is eventually exported or explicitly dropped under backpressure policy — Fairness: weak fairness on `export`.
- **Audit chain continuity**: Every security-critical event is eventually appended to the audit chain — strong fairness on `chain_hash`.
- **Key activation**: After `rotate_key`, the new version eventually reaches `active` status — Fairness: strong fairness on `activate_version`.
- **Session expiry**: Every authenticated session eventually transitions to `expired` or `revoked` — Fairness: weak fairness on session lifecycle.

### 7. Simplifications Made for TLA+

| What Was Simplified | Why It Still Covers the Bugs We Care About |
|---|---|
| Requests modeled as opaque IDs, not full HTTP payloads | Phase-ordering bugs are independent of payload content |
| Identity sources modeled as a single `authenticate` action | Safety properties hold regardless of which IdP backs the action |
| Policy set is static per evaluation (no concurrent mutation during request) | Real mutations are guarded by version+cache invalidation; modeled as atomic swap |
| Event buffer bounded at small N (e.g., 5) | Sufficient to detect backpressure drop vs. block behaviors |
| Audit chain bounded at small N (e.g., 10) | Sufficient to verify chain integrity and gap detection |
| Key versions bounded to 3 per alias | Sufficient to verify dual-read and deactivation transitions |
| Session states bounded to {anonymous, authenticated, expired, revoked} | MFA pending collapsed into anonymous for model simplicity |

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

### 8) Rust-specific engineering rules (all milestones)

These apply to every crate in the workspace:

**Crate-level attributes (mandatory in every `lib.rs`)**:
- `#![forbid(unsafe_code)]` unless a documented exception exists in this runbook.
- `#![deny(missing_docs)]`.
- `#![deny(clippy::all, clippy::pedantic)]` — fix all warnings before completing a milestone.
- Every crate must have a crate-level doc comment explaining its OWASP control mapping.

**Type system — leverage the compiler as a security gate**:
- All public enums must be annotated `#[non_exhaustive]` to preserve semver-safe extensibility. This ensures downstream code uses `_ =>` arms and additions are non-breaking.
- Types whose return values must not be silently discarded (e.g., `Decision`, `EnvelopeEncrypted`, `PublicError`) must be annotated `#[must_use]`.
- All public types must derive or implement `Clone`, `Send`, `Sync` where semantically appropriate. Verify `Send + Sync` bounds with static assertions: `const _: () = { fn assert_send_sync<T: Send + Sync>() {} assert_send_sync::<MyType>(); };`.
- Use **newtype wrappers** (not type aliases) for all domain IDs. Derive `From` for the inner type but do not implement `Deref` to prevent transparent access.
- Use **sealed traits** (`mod sealed { pub trait Sealed {} }`) for traits that must not be implemented outside the crate (e.g., `KeyProvider`, `SecuritySink`, `PolicyEngine`). Expose a public supertrait that requires `sealed::Sealed`.
- Use **type-state patterns** where the compiler can enforce correct sequencing at compile time (e.g., the validation pipeline stages: `Raw → Extracted → Validated → Authorized`).
- Use `PhantomData<T>` for zero-size markers when a type needs to carry a generic parameter without storing it.

**Ownership, borrowing, and lifetimes**:
- Prefer `&str` over `String` in function parameters. Accept `impl Into<String>` when ownership is needed.
- Use `Cow<'static, str>` for strings that are usually static but occasionally dynamic (e.g., error messages).
- Prefer `impl Trait` in argument position over `dyn Trait` for monomorphized zero-cost abstraction. Use `dyn Trait` only when type erasure is required (e.g., storing heterogeneous collections, object-safe requirements).
- Use `Box<dyn Error + Send + Sync + 'static>` for opaque error sources. This is the standard error chain pattern.

**Async and concurrency**:
- Use native `async fn` in trait definitions (stabilized in Rust 1.75). Do **not** use the `async-trait` crate — it boxes futures unnecessarily. If object safety is needed, use `trait Foo { fn bar(&self) -> impl Future<Output = R> + Send; }` or `-> Pin<Box<dyn Future<...> + Send>>` explicitly.
- All tower `Layer` and `Service` implementations must satisfy `Clone + Send + Sync + 'static` bounds.
- Use `tower::ServiceBuilder` for composing middleware stacks idiomatically.

**Error handling**:
- Use `thiserror` v2 for error enums. Prefer `#[error(transparent)]` for wrapping source errors.
- Never use `unwrap()` or `expect()` in production code paths. Use `unwrap()` only in tests, and prefer `expect("reason")` there.
- Propagate errors with `?`. A function that can fail must return `Result<T, E>`.

**Const, static, and compile-time**:
- Mark functions `const fn` where the body permits. Const evaluation catches bugs earlier and enables compile-time initialization.
- Use `const` assertions for invariant checking: `const _: () = assert!(std::mem::size_of::<MyType>() <= 64);`.

**Secrets and data safety**:
- No secret-bearing types may implement `Debug` or `Display`. Use `secrecy::SecretBox` or a custom opaque wrapper.
- Feature flags for optional integrations: `axum`, `tower`, `grpc`, `vault`, `kms`, `otel`.

**Platform independence**:
- Do not use platform-specific APIs (e.g., `/dev/urandom` directly). Use `rand::rngs::OsRng` or `getrandom` for randomness.
- Do not hard-code path separators. Use `std::path::Path` and `std::path::PathBuf` for filesystem paths.
- Do not assume a Unix shell. Scripts and CI must work on Linux, macOS, and Windows.
- Prefer `tempfile::TempDir` for test temporaries — it is cross-platform and RAII-based.

**Rust 2024 edition features**:
- Use `unsafe_op_in_unsafe_fn` lint (default in 2024 edition) — not relevant since we `forbid(unsafe_code)`.
- Leverage improved lifetime capture rules in 2024 edition (opaque types capture all in-scope lifetimes by default).

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
3. Verify the workspace builds cleanly.
   ```
   cargo build --workspace
   cargo doc --workspace --no-deps
   ```
4. Run the smoke tests listed in the milestone. Check off each item in the runbook.
5. Verify backward compatibility for all items listed in the milestone Compatibility Checklist.
6. Complete the Self-Review Gate.
7. **Clean up test artifacts**: Verify no test output files, temporary fixtures, or generated data remain in the working tree. Run `git status` and confirm no untracked test artifacts exist.
8. **Review .gitignore**: Ensure any new build outputs, generated files, or tool caches introduced in this milestone have matching `.gitignore` patterns. Remove stale patterns that no longer apply.
9. Update ARCHITECTURE.md following the Documentation Update Table.
10. Update README.md if user-facing capabilities changed.
11. Write a lessons-learned file at `docs/slo/lessons/sunlit-m<N>.md`.
12. Write a completion summary at `docs/slo/completion/sunlit-m<N>.md`.
13. Update the Milestone Tracker in this file: set status to `done`, record Completed date, and fill in the lessons and completion summary paths.
14. Re-read the next milestone with fresh eyes and record any assumption changes in the lessons file.

---

## Background Context

### Current State

This is a greenfield project. No code exists yet. The workspace will be created from scratch as a Cargo workspace containing eight library crates and one binary crate (reference service), targeting critical infrastructure environments (energy, finance, healthcare, government).

### Problem

Rust web services built with axum/tower lack a unified, OWASP-aligned security platform suitable for critical infrastructure. Teams currently must:

1. **No threat model**: No STRIDE analysis, no abuse cases, no formal verification of security invariants. Teams build controls without knowing what adversary they are defending against. This violates OWASP C1 (Define Security Requirements).
2. **Scattered input validation**: No standard "secure extractor" exists. Teams use bare `Json<T>` which accepts unknown fields by default (Serde ignores them), has no semantic validation hooks, and no automatic security event emission. This violates OWASP C5 (Validate All Inputs).
3. **No output encoding**: No context-aware escaping for HTML, JSON, URL, or SQL contexts. Responses reflect user input without encoding, enabling stored XSS and injection on the response path. This violates OWASP C4 (Encode and Escape Data).
4. **Ad hoc error handling**: Error responses leak stack traces, SQL text, internal hostnames, and differential authn information (`"invalid user"` vs `"invalid password"`). No centralized mapper exists. This violates OWASP C10 (Handle All Errors and Exceptions).
5. **No security telemetry**: `tracing`'s `#[instrument]` macro records all function arguments by default, risking secret/PII leakage. No canonical security event schema, redaction engine, or detection-point system exists. No tamper-evident audit trail for regulatory compliance. This violates OWASP C9 (Security Logging and Monitoring).
6. **No identity abstraction**: Authentication is either missing or tightly coupled to a single provider. No pluggable identity trait exists — teams cannot swap between Keycloak, Auth0, custom OIDC, or a local provider without rewriting authorization and middleware code. This violates OWASP C6 (Implement Digital Identity).
7. **Weak authorization patterns**: Role checks are scattered as `if user.role == "ADMIN"` strings. No deny-by-default enforcer, no typed policy engine, no tenant isolation. Authorization is tightly coupled to a specific identity provider rather than working with any `IdentitySource`. This violates OWASP C7 (Enforce Access Controls).
8. **Raw secret handling**: Secrets stored as plain `String`, logged via `Debug`, serialized via Serde, never zeroed. No envelope encryption, no key rotation, no Vault/KMS abstraction, no FIPS readiness. This violates OWASP C8 (Protect Data Everywhere).
9. **No supply-chain security**: No `cargo-audit`, `cargo-deny`, `cargo-vet`, or `cargo-audit-build` integration. Dependencies are unaudited.
10. **No adversarial testing**: No fuzz targets, no property tests for validators, no `cargo miri` for memory safety, no timing side-channel tests for crypto operations.

### Target Architecture

See the End-to-End Architecture Diagram above. The target is a single Cargo workspace where:

- A formal threat model (STRIDE, TLA+ verification) defines security requirements before implementation (OWASP C1).
- `security_core` provides shared types used by all crates, including the `IdentitySource` trait that decouples identity providers from authorization.
- `secure_errors` centralizes error handling (OWASP C10).
- `security_events` provides security telemetry with redaction and tamper-evident audit trails (OWASP C9).
- `secure_boundary` provides secure axum extractors with validation and security response headers (OWASP C5).
- `secure_output` provides context-aware output encoding (OWASP C4).
- `secure_identity` provides a pluggable authentication abstraction — one of many possible `IdentitySource` implementations (OWASP C6). Consumers may use Keycloak, Auth0, custom OIDC, or any crate implementing `IdentitySource` instead.
- `secure_authz` provides deny-by-default authorization, **identity-agnostic** — it accepts `Subject` from any `IdentitySource` implementor, not just `secure_identity` (OWASP C7).
- `secure_data` provides secret management, envelope encryption, and FIPS-readiness path (OWASP C8).
- `secure_reference_service` demonstrates full integration with resilience patterns.
- Adversarial testing gate via `cargo-fuzz`, `proptest`, `cargo miri`.
- CI pipeline enforces supply-chain security via `cargo-audit`, `cargo-deny`, `cargo-vet`, `cargo-audit-build`.

### Key Design Principles

1. **Wrap, don't replace**: Build on `serde`, `axum`, `tower`, `tracing`, `thiserror`, `secrecy`, `validator`, `casbin`. Do not reimplement their functionality. Add security policy and composition on top.
2. **Default deny everywhere**: Unknown JSON fields rejected. Authorization denies by default. Secrets hidden from Debug/Display/Serde by default. Errors reveal nothing by default.
3. **DTO-only writes**: Never deserialize directly into domain/persistence models. Always go through a validated DTO boundary. This prevents mass-assignment per OWASP C5.
4. **Schema-based redaction**: Every event field classified by `DataClassification`. Only `Public` and explicit `Internal` fields leave the process. Others are redacted, hashed, or dropped.
5. **Envelope encryption, not ad hoc crypto**: Application code calls `encrypt_for_storage()` / `decrypt_for_use()`. The crate handles key IDs, versioning, AEAD, and associated data.
6. **Identity-agnostic authorization**: `secure_authz` depends ONLY on `security_core::IdentitySource`, never on `secure_identity`. Any identity provider — Keycloak, Auth0, custom OIDC, or `secure_identity` — can feed `Subject` into the policy engine by implementing `IdentitySource`. Consumers can replace or omit `secure_identity` entirely.
7. **Encode output, not just validate input**: Every response path runs through context-aware encoding (HTML, JSON, URL). Input validation (OWASP C5) and output encoding (OWASP C4) are complementary, not interchangeable.
8. **Threat model before code**: No implementation begins until the threat model is complete. STRIDE analysis, abuse cases, and attack trees define what controls to build and what to prioritize.
9. **One platform, not five libraries**: Ship as one workspace with one integration example. Teams adopt the whole platform.

### What to Keep

Nothing — this is a greenfield project.

### What to Change

Everything is new:

- **`Cargo.toml` (workspace root)** — workspace definition, shared dependencies
- **`crates/security_core/`** — shared types crate (includes `IdentitySource` trait)
- **`crates/secure_errors/`** — error handling crate
- **`crates/security_events/`** — security events crate (+ tamper-evident audit trail)
- **`crates/secure_boundary/`** — input validation crate (+ security response headers)
- **`crates/secure_output/`** — context-aware output encoding crate
- **`crates/secure_identity/`** — pluggable authentication crate (one of many possible `IdentitySource` implementations)
- **`crates/secure_authz/`** — authorization crate (identity-agnostic, depends on `security_core` not `secure_identity`)
- **`crates/secure_data/`** — data protection crate (+ FIPS readiness path)
- **`crates/secure_reference_service/`** — reference axum service (+ resilience patterns)
- **`deny.toml`** — cargo-deny configuration
- **`supply-chain/`** — cargo-vet audit data
- **`.github/workflows/`** — CI pipeline

### Global Red Lines

These are forbidden unless explicitly overridden inside a milestone.

- No unrelated refactors
- No new dependencies beyond what each milestone explicitly permits
- No schema migrations (not applicable — greenfield)
- No public API renames after initial stabilization in the introducing milestone
- No production placeholders
- No silent error swallowing
- No secrets in source control
- No test output data committed to source control
- No `unsafe` code without documented exception
- No `Debug` or `Display` on secret-bearing types
- No raw `String` for secrets in production code
- No timing side-channels in security-sensitive comparisons — use constant-time comparison (`subtle` crate or `ring::constant_time`)
- No compile-time dependency from `secure_authz` on `secure_identity` — authorization must remain identity-agnostic
- No security control without a corresponding threat model entry (after M0)

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
| Unit tests | `#[cfg(test)] mod tests` inside the source file | Same file as production code |
| Integration/BDD tests | `tests/sunlit_<crate>_<feature>.rs` | `crates/<crate>/tests/` |
| E2E runtime validation | `tests/e2e_sunlit_m<N>.rs` | `crates/<crate>/tests/` or workspace root `tests/` |
| Property tests | `tests/prop_<feature>.rs` | `crates/<crate>/tests/` |
| Fuzz targets | `fuzz/fuzz_targets/<target>.rs` | `crates/<crate>/fuzz/` |

### Test Artifact Cleanup Rules

Every test that creates files, directories, or temporary data on disk must follow these rules:

1. **Use temporary directories**: Use `tempfile::TempDir` (cross-platform, RAII). Never write test output into the source tree. Do not use platform-specific temp paths (e.g., `/tmp`) — `tempfile` handles this portably.
2. **Clean up on completion and failure**: Use RAII patterns (Rust `Drop`) to ensure cleanup runs even when tests fail. `TempDir` deletes its contents on drop.
3. **No residual state**: After the full test suite runs, `git status` must show no untracked files from test execution.
4. **Dedicated output directories**: If a test must write to a project-relative path, that directory must be in `.gitignore` and tests must clean it between runs.
5. **CI parity**: Test cleanup behavior must be identical on Linux, macOS, and Windows CI runners.

### End-to-End Runtime Validation

Every milestone must include E2E tests that go beyond compilation and verify that the system works correctly at runtime. These tests prove:

1. the crate initializes without panics
2. runtime contracts are met across trait boundaries
3. BDD scenarios work at runtime, not just in isolation
4. there are no runtime panics, unhandled errors, or silent failures
5. degraded states behave safely and visibly

### E2E Test Design Rules

1. Test runtime behavior, not just types.
2. Test the full stack where possible.
3. Test degraded and failure states, not just the happy path.
4. Assert against observable behavior.
5. For milestones touching multiple crates, include at least one cross-crate integration test.

---

## Dependency, Migration, and Refactor Policy

### Dependency policy

A new dependency is allowed only if the milestone explicitly includes:

- package/crate name and version constraint
- why existing dependencies are insufficient
- security and maintenance rationale (check advisories via `cargo audit`)
- build/runtime cost rationale
- tests covering the new integration

### Supply-chain verification for new dependencies

Every new dependency added in any milestone must pass:

1. `cargo audit` — no known vulnerabilities in the dependency or its transitive deps
2. `cargo deny check` — passes advisory, license, ban, duplicate, and source checks
3. `cargo vet` — audited or exempted with documented rationale

If a dependency fails any check, it must not be added. Find an alternative or document an exemption in the milestone with explicit justification.

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
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| BDD tests created | `[files]` | compile or fail for expected reason | | | |
| E2E stubs created | `[files]` | compile or fail for expected reason | | | |
| Implementation | `[summary]` | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | `cargo build --workspace && cargo doc --workspace --no-deps` | builds cleanly | | | |
| Smoke tests | `[steps]` | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current, no stale entries | | | |
| Compatibility checks | `[checks]` | no regressions | | | |
| Supply-chain | `cargo audit && cargo deny check` | no advisories, no policy violations | | | |

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
- Does `cargo clippy --workspace --all-targets -- -D warnings` pass with zero warnings?
- Does `cargo doc --workspace --no-deps` build without warnings?
- Do all crates have `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`?
- Are all secret-bearing types free of `Debug` and `Display` implementations?
- Are all public enums annotated `#[non_exhaustive]`?
- Are types whose values must not be silently discarded annotated `#[must_use]`?
- Are there any uses of `async-trait` crate? Replace with native `async fn in trait`.
- Is any platform-specific code used without `#[cfg(target_os = ...)]` gating?
- Is the milestone truly done according to its Definition of Done?

If any answer is "no", the milestone is not complete.

---

## Lessons-Learned File Template

Path: `docs/slo/lessons/sunlit-m<N>.md`

```md
# Lessons Learned — sunlit Milestone <N>

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

Path: `docs/slo/completion/sunlit-m<N>.md`

```md
# Completion Summary — sunlit Milestone <N>

## Goal completed
- [what capability now exists]

## Files changed
- [file]
- [file]

## Tests added
- [test file]
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

## Supply-chain verification
- [cargo audit result]
- [cargo deny result]

## Deferred follow-ups
- [follow-up]

## Known non-blocking limitations
- [limitation]
```

---

## Milestone Plan

### Milestone 0 — Threat Model & Security Requirements (OWASP C1)

**Goal**: Produce a formal threat model that defines what adversaries, attack vectors, and security invariants every subsequent milestone must address. No implementation begins until this milestone is complete.

**Context**: OWASP Proactive Control C1 (Define Security Requirements) mandates that security requirements are explicit, traceable, and derived from threat analysis — not assumed. Critical infrastructure environments (energy, finance, healthcare, government) require documented threat models for compliance with NIST 800-53, IEC 62443, and SOC 2. Without a threat model, teams build controls reactively — patching vulnerabilities instead of preventing entire attack classes.

**Important design rule**: Every threat must map to at least one control in a subsequent milestone. Every control in M1–M10 must trace back to at least one threat entry. Threats without controls are gaps. Controls without threats are waste.

**Refactor budget**: `No refactor permitted — this is a document-only milestone`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Initial design spec, OWASP Proactive Controls C1–C10, STRIDE methodology |
| Outputs | `THREAT_MODEL.md` with STRIDE analysis, abuse cases, attack trees, control-to-threat traceability matrix |
| Interfaces touched | None (document-only) |
| Files allowed to change | None (all new) |
| Files to read before changing anything | This runbook |
| New files allowed | `THREAT_MODEL.md`, `docs/attack-trees/` |
| New dependencies allowed | None |
| Migration allowed | `no` |
| Compatibility commitments | None (first milestone) |
| Forbidden shortcuts | Skipping STRIDE categories, generic threats without specific attack scenarios, threats without mapped controls, controls without mapped threats |

#### Out of Scope / Must Not Do

- Do not write any Rust code in this milestone.
- Do not create Cargo.toml or any crate directories.
- Do not prescribe specific algorithms or implementations — focus on *what* must be defended, not *how*.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read the architecture and this runbook in full to understand all crate responsibilities.
3. Read this runbook's architecture diagram, component table, and TLA+ model.
4. Copy the Evidence Log template into this milestone section.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `THREAT_MODEL.md` | NEW: Complete threat model document |
| `docs/attack-trees/identity.md` | NEW: Attack tree for authentication/identity bypass |
| `docs/attack-trees/authorization.md` | NEW: Attack tree for privilege escalation and tenant escape |
| `docs/attack-trees/data-protection.md` | NEW: Attack tree for secret exfiltration and crypto failures |
| `docs/attack-trees/input-output.md` | NEW: Attack tree for injection via input and output paths |

#### Step-by-Step

1. Perform STRIDE analysis on each component in the architecture diagram (security_core, secure_errors, security_events, secure_boundary, secure_output, secure_identity, secure_authz, secure_data, secure_reference_service).
2. Document threat categories: Spoofing (identity), Tampering (data integrity), Repudiation (audit), Information Disclosure (secrets, errors), Denial of Service (resource exhaustion), Elevation of Privilege (authz bypass, tenant escape).
3. For each threat, write at least one concrete abuse case with attacker motivation, preconditions, attack steps, and impact.
4. Create attack trees for the four critical attack surfaces: identity, authorization, data protection, input/output.
5. Build a control-to-threat traceability matrix mapping every threat to the milestone and crate that mitigates it.
6. Map threats to compliance frameworks: NIST 800-53 control families (AC, AU, IA, SC, SI), IEC 62443 zones/conduits (if applicable), SOC 2 trust service criteria.
7. Identify residual risks — threats that the library cannot fully mitigate (e.g., physical access, insider threat) — and document recommended compensating controls for consumers.
8. Peer-review checklist: every STRIDE category has at least 2 threats, every milestone M1–M10 traces to at least one threat, no threat is unmitigated.
9. Complete the Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: Threat model completeness**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All STRIDE categories covered | happy path | The THREAT_MODEL.md document | Reviewed for STRIDE coverage | Every category (S, T, R, I, D, E) has at least 2 documented threats |
| Every threat has a mapped control | happy path | The traceability matrix | Cross-referenced with milestones M1–M10 | Every threat maps to at least one milestone/crate |
| Every control has a mapped threat | happy path | The traceability matrix | Cross-referenced with THREAT_MODEL.md | Every milestone/crate maps back to at least one threat |
| Abuse cases are concrete | happy path | Each abuse case entry | Reviewed for specificity | Contains attacker motivation, preconditions, steps, and impact |
| Residual risks documented | happy path | The residual risks section | Reviewed | At least 3 residual risks with compensating control recommendations |

#### Regression Tests

- Not applicable — document-only milestone, no code.

#### Compatibility Checklist

- Not applicable — first milestone.

#### E2E Runtime Validation

- Not applicable — document-only milestone.

#### Smoke Tests

- [ ] `THREAT_MODEL.md` exists and is non-empty
- [ ] Every STRIDE category has at least 2 threats
- [ ] Traceability matrix covers all milestones M1–M10
- [ ] Every threat has at least one mapped control
- [ ] Every control has at least one mapped threat
- [ ] At least 4 attack trees exist in `docs/attack-trees/`
- [ ] Residual risks section exists with at least 3 entries
- [ ] Document reviewed against NIST 800-53 control families

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| 1 | Review STRIDE coverage | All 6 categories with ≥2 threats each | | | |
| 2 | Review traceability matrix | All M1–M10 milestones mapped | | | |
| 3 | Review abuse cases | Concrete with motivation/steps/impact | | | |
| 4 | Review attack trees | ≥4 trees covering critical surfaces | | | |
| 5 | Review residual risks | ≥3 risks with compensating controls | | | |

#### Self-Review Gate

```
## Self-Review Gate — Milestone 0

- [ ] All STRIDE categories covered with ≥2 threats each
- [ ] Control-to-threat traceability matrix complete (no orphan threats, no orphan controls)
- [ ] At least 4 attack trees with concrete attack paths
- [ ] Compliance mapping includes NIST 800-53 control families
- [ ] Residual risks documented with compensating controls
- [ ] Document peer-reviewed (or self-reviewed against checklist)
- [ ] No Rust code written in this milestone

## Known non-blocking limitations
- Threat model is a living document — will be updated as implementation reveals new attack surfaces
- Compliance mapping covers control families, not individual controls (detailed mapping deferred to implementation milestones)
```

---

### Milestone 1 — Workspace Scaffold + `security_core`

**Goal**: Establish the Cargo workspace structure with all nine crate stubs and implement `security_core` with shared ID types, data classification, severity levels, redaction traits, correlation context, time-source abstraction, and the `IdentitySource` trait used by all downstream crates.

**Context**: Nothing exists yet. Every subsequent crate depends on `security_core` for `ActorId`, `TenantId`, `RequestId`, `TraceId`, `ResourceId`, `DataClassification`, `SecuritySeverity`, `ReasonCode`, `PolicyVersion`, `SecretRef`, and `IdentitySource`. The `IdentitySource` trait is critical: it lives in `security_core` so that `secure_authz` can accept identity from ANY provider (Keycloak, Auth0, `secure_identity`, custom OIDC) without depending on any specific identity crate. Getting these types right now prevents breaking changes later. The workspace `Cargo.toml` must establish shared dependency versions, `forbid(unsafe_code)`, and `deny(missing_docs)` policies workspace-wide.

**Important design rule**: Every ID type must be a newtype wrapper (not a type alias) to prevent accidental mixing. Implement `From<Uuid>` but do not implement `Deref<Target = Uuid>` — consumers must explicitly call `.as_uuid()` or `.into_inner()`. `DataClassification` must be an `#[non_exhaustive]` enum with ordered variants so redaction logic can compare levels. All public enums (`DataClassification`, `SecuritySeverity`) must use `#[non_exhaustive]`. The `IdentitySource` trait must be defined in `security_core` (not `secure_identity`) — this is the integration point that keeps `secure_authz` identity-agnostic.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | None (greenfield) |
| Outputs | Compilable workspace with `security_core` crate exporting all shared types |
| Interfaces touched | `security_core::types::*`, `security_core::classification::*`, `security_core::context::*`, `security_core::time::*`, `security_core::identity::*` |
| Files allowed to change | All new files listed below |
| Files to read before changing anything | Architecture and README shared types sections |
| New files allowed | All workspace scaffolding and `security_core` source files |
| New dependencies allowed | `uuid` (v1), `time` (v0.3), `serde` (v1, with `derive`), `smallvec` (v1), `derive_more` (v1) |
| Migration allowed | `no` |
| Compatibility commitments | None (first milestone) |
| Forbidden shortcuts | Type aliases instead of newtypes, `String` for IDs, missing `#![forbid(unsafe_code)]`, missing `#![deny(missing_docs)]`, `Deref` on newtype IDs, missing `#[non_exhaustive]` on public enums, placing `IdentitySource` in `secure_identity` instead of `security_core` |

#### Out of Scope / Must Not Do

- Do not implement any business logic in `security_core` — it is types and traits only.
- Do not add axum, tower, tracing, or any framework dependency to `security_core`.
- Do not implement `Debug` or `Display` for `SecretRef` — it must be opaque.
- Do not create production code in any crate other than `security_core`.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. This is the first milestone — no previous lessons file exists.
3. No existing tests to baseline (greenfield).
4. Copy the Evidence Log template into this milestone section or working notes.
5. Re-state the milestone constraints before coding.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `Cargo.toml` (workspace root) | NEW: workspace definition with members, shared dependency versions via `[workspace.dependencies]` |
| `crates/security_core/Cargo.toml` | NEW: crate manifest with dependencies |
| `crates/security_core/src/lib.rs` | NEW: crate root with `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, module declarations |
| `crates/security_core/src/types.rs` | NEW: `ActorId`, `TenantId`, `RequestId`, `TraceId`, `ResourceId`, `PolicyVersion` newtypes |
| `crates/security_core/src/classification.rs` | NEW: `DataClassification` enum (Public, Internal, Confidential, Secret, Credentials, PII, Regulated) |
| `crates/security_core/src/severity.rs` | NEW: `SecuritySeverity` enum (Info, Low, Medium, High, Critical) |
| `crates/security_core/src/context.rs` | NEW: `CorrelationContext` struct, `ReasonCode`, `SecretRef` |
| `crates/security_core/src/time.rs` | NEW: `TimeSource` trait with `SystemTimeSource` and `MockTimeSource` implementations |
| `crates/security_core/src/redact.rs` | NEW: `Redact` trait, `RedactedDisplay` wrapper |
| `crates/security_core/src/identity.rs` | NEW: `IdentitySource` trait (open — NOT sealed), `AuthenticatedIdentity` struct, `IdentityResolutionError` enum (`#[non_exhaustive]`: `InvalidToken`, `Expired`, `ProviderUnavailable`, `Other(Box<dyn Error>)`) — the integration point for identity-agnostic authorization |
| `crates/secure_errors/Cargo.toml` | NEW: stub crate manifest (lib.rs with doc comment only) |
| `crates/secure_errors/src/lib.rs` | NEW: stub with `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, doc comment |
| `crates/security_events/Cargo.toml` | NEW: stub crate manifest |
| `crates/security_events/src/lib.rs` | NEW: stub |
| `crates/secure_boundary/Cargo.toml` | NEW: stub crate manifest |
| `crates/secure_boundary/src/lib.rs` | NEW: stub |
| `crates/secure_authz/Cargo.toml` | NEW: stub crate manifest |
| `crates/secure_authz/src/lib.rs` | NEW: stub |
| `crates/secure_data/Cargo.toml` | NEW: stub crate manifest |
| `crates/secure_data/src/lib.rs` | NEW: stub |
| `crates/secure_output/Cargo.toml` | NEW: stub crate manifest |
| `crates/secure_output/src/lib.rs` | NEW: stub |
| `crates/secure_identity/Cargo.toml` | NEW: stub crate manifest |
| `crates/secure_identity/src/lib.rs` | NEW: stub |
| `crates/secure_reference_service/Cargo.toml` | NEW: stub binary manifest |
| `crates/secure_reference_service/src/main.rs` | NEW: stub with `fn main() {}` |
| `.gitignore` | NEW: Rust/Cargo patterns (`target/`, `*.swp`, `*.pdb`, editor/IDE configs) — must cover Linux, macOS, and Windows artifacts |
| `ARCHITECTURE.md` | NEW: initial architecture document |
| `README.md` | NEW: project overview |

#### Step-by-Step

1. Create workspace `Cargo.toml` with all member crates (including `secure_identity` and `secure_output`) and shared dependency versions.
2. Create `.gitignore` with Rust/Cargo patterns.
3. Create stub `Cargo.toml` and `lib.rs` for all eight library crates and the reference service binary.
4. Write BDD test stubs first for `security_core` types.
5. Write E2E runtime validation stubs.
6. Implement `security_core` types module: all ID newtypes with `Serialize`, `Deserialize`, `Clone`, `PartialEq`, `Eq`, `Hash`, `From` (inner type), and `Display` (except `SecretRef`). Do not implement `Deref` on any newtype. Provide an explicit `as_inner()` or `into_inner()` method instead.
7. Implement `DataClassification` with `Ord` for level comparison. Annotate `#[non_exhaustive]`.
8. Implement `SecuritySeverity` with `Ord`. Annotate `#[non_exhaustive]`.
9. Implement `CorrelationContext`, `ReasonCode`, `SecretRef`. Mark `CorrelationContext` `#[must_use]`.
10. Implement `TimeSource` trait with system and mock implementations. Define `TimeSource` as a **sealed trait** — only crate-internal implementations are permitted. Use `mod sealed { pub trait Sealed {} }` with `pub trait TimeSource: sealed::Sealed { ... }`.
11. Implement `Redact` trait and `RedactedDisplay`. `Redact` should be a sealed trait.
12. Implement `IdentitySource` trait and `IdentityResolutionError` in `security_core::identity`. `IdentityResolutionError` is a `#[non_exhaustive]` error enum with variants `InvalidToken`, `Expired`, `ProviderUnavailable`, `Other(Box<dyn std::error::Error + Send + Sync + 'static>)` — it lives in `security_core` so that any `IdentitySource` implementor can use it without depending on `secure_identity`. This is an **open trait** (NOT sealed) — external crates (Keycloak adapters, Auth0 adapters, `secure_identity`, custom OIDC) must be able to implement it. Define `AuthenticatedIdentity` struct with `actor_id: ActorId`, `tenant_id: Option<TenantId>`, `roles: Vec<String>`, `attributes: HashMap<String, String>`, `authenticated_at: OffsetDateTime`. `IdentitySource` has one method: `async fn resolve(&self, token: &str) -> Result<AuthenticatedIdentity, IdentityResolutionError>`.
13. Make all BDD tests pass.
14. Run full workspace build and clippy.
15. **Verify test artifact cleanup**: Run `git status` and confirm no untracked test output remains.
16. **Update .gitignore**: Add patterns for any new generated files or build outputs.
17. Run smoke tests.
18. Complete the Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: Shared ID types**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| ActorId round-trip serialization | happy path | An `ActorId` wrapping a UUID | Serialized to JSON and deserialized back | The round-trip produces an equal value |
| TenantId display | happy path | A `TenantId` wrapping a UUID | Formatted via `Display` | The output is the UUID string, not a debug repr |
| SecretRef no Debug leak | security invariant | A `SecretRef` containing `"vault://kv/db-pass"` | Formatted via `Debug` | The output is `SecretRef(REDACTED)`, not the URI |
| Different ID types not mixable | invalid input | An `ActorId` and a `TenantId` with the same inner UUID | Compared for equality | Compilation fails — different types |
| RequestId generates unique | happy path | Two calls to `RequestId::generate()` | Compared | They are not equal |

**Feature: Data classification ordering**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Classification ordering | happy path | `DataClassification::Public` and `DataClassification::Secret` | Compared with `<` | `Public < Secret` is true |
| All variants ordered | happy path | All seven variants | Sorted | Order is Public < Internal < Confidential < PII < Regulated < Secret < Credentials |

**Feature: Correlation context**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Context construction | happy path | A `CorrelationContext` with request_id, trace_id, actor_id | Accessed | All fields return the set values |
| Context with optional fields | empty state | A `CorrelationContext` with only request_id | Accessed for actor_id | Returns `None` |

**Feature: TimeSource**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| SystemTimeSource returns current time | happy path | A `SystemTimeSource` | `now()` called | Returns a time within 1 second of `OffsetDateTime::now_utc()` |
| MockTimeSource returns fixed time | happy path | A `MockTimeSource` set to `2025-01-01T00:00:00Z` | `now()` called | Returns exactly `2025-01-01T00:00:00Z` |

**Feature: Redact trait**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Redacted display masks value | happy path | A `RedactedDisplay` wrapping `"secret123"` | Formatted via `Display` | Output is `[REDACTED]` |

**Feature: IdentitySource trait**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| IdentitySource is an open trait | happy path | A custom struct implementing `IdentitySource` | Compiled | Compilation succeeds — trait is not sealed |
| AuthenticatedIdentity carries actor and tenant | happy path | An `AuthenticatedIdentity` with actor_id, tenant_id, roles | Fields accessed | All values match what was set |
| AuthenticatedIdentity optional tenant | empty state | An `AuthenticatedIdentity` with `tenant_id: None` | `tenant_id` accessed | Returns `None` |
| AuthenticatedIdentity roles are typed | happy path | An `AuthenticatedIdentity` with roles `["ADMIN", "READER"]` | `roles` accessed | Returns the exact role list |

#### Regression Tests

- Not applicable — first milestone, no pre-existing tests.

#### Compatibility Checklist

- Not applicable — first milestone.

#### E2E Runtime Validation

**File**: `crates/security_core/tests/e2e_sunlit_m1.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_all_id_types_constructible` | All ID newtypes can be instantiated and cloned at runtime | No panics, values preserved |
| `test_classification_ordering_at_runtime` | `DataClassification` variants maintain correct ordering at runtime | `Public < Internal < ... < Credentials` |
| `test_correlation_context_propagation` | `CorrelationContext` can be built, cloned, and all fields accessed | No panics, correct values |
| `test_secret_ref_does_not_leak` | `SecretRef` debug output does not contain the inner value | `format!("{:?}", secret_ref)` does not contain the original string |
| `test_workspace_compiles` | All workspace members compile together | `cargo build --workspace` succeeds |
| `test_identity_source_implementable` | External crates can implement `IdentitySource` | A test struct implementing the trait compiles and resolves identity |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds with zero errors
- [ ] `cargo test --workspace` passes all tests
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings
- [ ] `cargo doc --workspace --no-deps` builds without warnings
- [ ] Every `lib.rs` has `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- [ ] `SecretRef` debug output verified manually to not leak
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` covers `target/` and build outputs

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | N/A (greenfield) | N/A | | | |
| BDD tests created | `crates/security_core/tests/sunlit_core_types.rs` | fail for expected reason | | | |
| E2E stubs created | `crates/security_core/tests/e2e_sunlit_m1.rs` | fail for expected reason | | | |
| Implementation | `security_core` types + traits | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | `cargo build --workspace && cargo doc --workspace --no-deps` | builds cleanly | | | |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| Smoke tests | all items above | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current | | | |

#### Definition of Done

The milestone is done only when all of the following are true:

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- `cargo build --workspace` succeeds (all stubs compile)
- `cargo test --workspace` green
- `cargo clippy --workspace --all-targets -- -D warnings` zero warnings
- `cargo doc --workspace --no-deps` builds
- all crate roots have `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`
- all public enums have `#[non_exhaustive]`
- no newtype ID implements `Deref`
- `TimeSource` and `Redact` are sealed traits
- `SecretRef` does not implement `Debug` that leaks its contents
- smoke tests are checked off
- no forbidden shortcuts remain
- all tests clean up their output artifacts — `git status` is clean
- `.gitignore` is up to date
- ARCHITECTURE.md created
- README.md created
- lessons file written at `docs/slo/lessons/sunlit-m1.md`
- completion summary written at `docs/slo/completion/sunlit-m1.md`
- Milestone Tracker updated

#### Post-Flight

Complete the Global Exit Rules above. Key documentation updates:

- **ARCHITECTURE.md**: Document workspace layout, crate dependency graph, shared types inventory
- **README.md**: Project overview, build instructions, crate purposes
- **Other docs**: None yet

#### Notes

- Concurrency and persistence categories do not apply to this milestone — it is pure types and traits with no I/O.
- The stub crates for M2-M8 must compile (empty `lib.rs` with doc comment and `forbid`/`deny` attributes) but contain no logic.

---

### Milestone 2 — `secure_errors` — Centralized Error Handling (OWASP C10)

**Goal**: Implement `secure_errors` providing a three-layer error model (internal cause → public class → operational classification), centralized error-to-HTTP mapping via axum's `IntoResponse`, panic catching at the service boundary, request-ID propagation in public error responses, and security-signal escalation hooks — all without leaking internal details per OWASP C10.

**Context**: OWASP C10 states that error handling should be centralized, should not leak internal details to clients, should still log enough for forensics, and should help detect attacks in progress. The `secure_errors` crate is second in the build order because `secure_boundary`, `secure_authz`, and `secure_data` all need to produce errors that flow through this centralized mapper. The crate depends only on `security_core` for shared types.

**Important design rule**: The `PublicError` struct is the *only* type that may be serialized to HTTP responses. Internal error variants must never appear in the response body. The mapper is the *only* place that chooses the public payload.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Internal `AppError` variants from handler code and downstream crates |
| Outputs | `PublicError` HTTP responses, internal `ErrorReport` for logging, security signal flags |
| Interfaces touched | `secure_errors::kind::*`, `secure_errors::public::*`, `secure_errors::report::*`, `secure_errors::http::*`, `secure_errors::classify::*`, `secure_errors::capture::*`, `secure_errors::incident::*`, `secure_errors::panic::*` |
| Files allowed to change | All new files listed below, plus `crates/secure_errors/Cargo.toml` (was stub) |
| Files to read before changing anything | `crates/security_core/src/types.rs`, `crates/security_core/src/severity.rs`, `crates/security_core/src/classification.rs`, architecture error-handling notes |
| New files allowed | All source files under `crates/secure_errors/src/`, test files |
| New dependencies allowed | `thiserror` (v2), `axum-core` (v0.5), `http` (v1), `serde_json` (v1), `tracing` (v0.1, for internal error logging only) |
| Migration allowed | `no` |
| Compatibility commitments | `security_core` public types must not change |
| Forbidden shortcuts | Exposing internal error text in `PublicError`, implementing `Display` on `AppError` in a way that leaks SQL/hostnames, using `unwrap()` in production paths, ad hoc JSON construction for error responses, missing `#[non_exhaustive]` on `AppError` or `ErrorClassification` enums |

#### Out of Scope / Must Not Do

- Do not implement gRPC status mapping yet — defer to a later milestone or feature flag.
- Do not implement the `security_events` integration hooks yet — leave `incident_fingerprint()` and `security_signal()` as trait methods that downstream can implement. The actual event emission comes in M3.
- Do not add axum router, handlers, or server code — this crate provides `IntoResponse` impl only.
- Do not add any dependency injection framework.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m1.md` and apply relevant corrections.
3. Run `cargo test --workspace` and confirm green baseline.
4. Read `crates/security_core/src/types.rs` and `crates/security_core/src/severity.rs`.
5. Copy the Evidence Log template.
6. Re-state constraints before coding.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_errors/Cargo.toml` | UPDATE: add dependencies (`thiserror`, `axum-core`, `http`, `serde`, `serde_json`, `tracing`, `security_core` path dep) |
| `crates/secure_errors/src/lib.rs` | UPDATE: add module declarations, crate doc comment |
| `crates/secure_errors/src/kind.rs` | NEW: internal error taxonomy — `AppError` enum with `thiserror` derives |
| `crates/secure_errors/src/public.rs` | NEW: `PublicError` struct with `status`, `code`, `message`, `request_id` fields; `Serialize` impl |
| `crates/secure_errors/src/report.rs` | NEW: `ErrorReport` struct for internal forensic logging — root cause chain, backtrace, component, tenant/actor context |
| `crates/secure_errors/src/http.rs` | NEW: `IntoResponse` impl for `AppError`, centralized mapper from internal errors to `PublicError` |
| `crates/secure_errors/src/classify.rs` | NEW: `ErrorClassification` — retryable/not, alert/no-alert, security-signal/normal |
| `crates/secure_errors/src/capture.rs` | NEW: backtrace/context attachment helpers |
| `crates/secure_errors/src/incident.rs` | NEW: `SecurityIncident` trait — `security_signal()`, `alert_severity()`, `incident_fingerprint()` |
| `crates/secure_errors/src/panic.rs` | NEW: panic-to-safe-response handler — catches panics at service boundary, returns 500 with request ID only |
| `crates/secure_errors/tests/sunlit_errors_mapping.rs` | NEW: BDD tests for error-to-HTTP mapping |
| `crates/secure_errors/tests/sunlit_errors_leakage.rs` | NEW: BDD tests proving no internal leakage |
| `crates/secure_errors/tests/sunlit_errors_panic.rs` | NEW: BDD tests for panic boundary |
| `crates/secure_errors/tests/e2e_sunlit_m2.rs` | NEW: E2E runtime validation |
| `.gitignore` | Add patterns for any new generated files |

#### Step-by-Step

1. Write BDD test stubs first for all scenarios below.
2. Write E2E runtime validation stubs.
3. Implement `kind.rs`: `AppError` enum with variants for Validation, Forbidden, NotFound, Conflict, Dependency, Crypto, Internal, RateLimit. Annotate `#[non_exhaustive]`. Use `thiserror` v2 `#[error(...)]` for each variant. Use `#[error(transparent)]` for wrapped source errors.
4. Implement `public.rs`: `PublicError` struct — only `status: u16`, `code: &'static str`, `message: Cow<'static, str>`, `request_id: Option<RequestId>`. Annotate `#[must_use]`. Derive `Serialize` but not `Deserialize` (responses only).
5. Implement `classify.rs`: `ErrorClassification` with `is_retryable()`, `is_alertable()`, `is_security_signal()`, `is_user_fixable()`. Annotate `#[non_exhaustive]`. Use `const fn` for classification methods where the body permits.
6. Implement `report.rs`: `ErrorReport` with causal chain, backtrace capture, component name, tenant/actor, secrecy-aware context attachments.
7. Implement `http.rs`: centralized `IntoResponse` for `AppError` — maps each variant to exactly one `PublicError` response with correct HTTP status.
8. Implement `incident.rs`: `SecurityIncident` trait methods. `SecurityIncident` should be a **sealed trait** — only types from within the security crates should implement it.
9. Implement `panic.rs`: `PanicSafeLayer` that catches panics and returns a safe 500 response. The layer must satisfy `Clone + Send + Sync + 'static` tower bounds. Use `std::panic::catch_unwind` (cross-platform) — do not rely on Unix signals.
10. Implement `capture.rs`: backtrace capture and context attachment.
11. Make all BDD tests pass.
12. Run the full test suite.
13. Run E2E runtime validation.
14. **Verify test artifact cleanup**: Run `git status`.
15. **Update .gitignore**.
16. Run smoke tests.
17. Complete Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: Error-to-HTTP mapping**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Validation error maps to 400 | happy path | An `AppError::Validation { code: "invalid_email" }` | Converted via `IntoResponse` | HTTP 400, body contains `{"code": "invalid_request", "message": "..."}`, no internal details |
| Forbidden error maps to 403 | happy path | An `AppError::Forbidden { policy: "delete_account" }` | Converted via `IntoResponse` | HTTP 403, body code is `"forbidden"`, policy name not in body |
| Not found maps to 404 | happy path | An `AppError::NotFound` | Converted via `IntoResponse` | HTTP 404, body code is `"not_found"` |
| Dependency error maps to 503 | happy path | An `AppError::Dependency { dep: "postgres" }` | Converted via `IntoResponse` | HTTP 503, body code is `"temporarily_unavailable"`, dep name not in body |
| Internal error maps to 500 | happy path | An `AppError::Internal` | Converted via `IntoResponse` | HTTP 500, body code is `"internal_error"`, no stack trace |
| Rate limit maps to 429 | happy path | An `AppError::RateLimit` | Converted via `IntoResponse` | HTTP 429, body code is `"rate_limited"` |
| Request ID propagated | happy path | An `AppError` with a `RequestId` in context | Converted | `PublicError.request_id` matches the input |

**Feature: No internal leakage**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| No SQL in response | security invariant | An `AppError::Dependency` created from a SQL error string | Serialized to JSON response | Response body does not contain `SELECT`, `INSERT`, `WHERE`, or the SQL text |
| No hostname in response | security invariant | An `AppError::Dependency` with hostname `"db-prod-03.internal"` | Serialized | Response body does not contain `db-prod-03` |
| No stack trace in response | security invariant | An `AppError::Internal` with captured backtrace | Serialized | Response body does not contain `at src/`, `frame`, or function names |
| No authn differential | security invariant | Two errors: "user not found" and "wrong password" | Both converted | Both produce identical response shape and status code (401) with identical `code` field |
| Internal report retains details | forensics | An `AppError::Dependency` with SQL text | Converted to `ErrorReport` | Report contains the SQL text, hostname, backtrace |

**Feature: Panic boundary**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Panic caught at boundary | partial failure | A handler that panics with `"unexpected state"` | Request processed through `PanicSafeLayer` | HTTP 500 response with `code: "internal_error"`, no panic message in body |
| Panic does not crash service | partial failure | A handler that panics | Next request processed | Service still responds normally |

**Feature: Error classification**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Dependency error is retryable | happy path | An `AppError::Dependency` | Classified | `is_retryable()` returns true |
| Validation error not retryable | happy path | An `AppError::Validation` | Classified | `is_retryable()` returns false |
| Forbidden is security signal | happy path | An `AppError::Forbidden` | Classified | `is_security_signal()` returns true |

#### Regression Tests

- All `security_core` tests from M1 must still pass.
- All other workspace crate stubs must still compile.

#### Compatibility Checklist

- [ ] `security_core` public types unchanged
- [ ] All workspace crate stubs still compile
- [ ] M1 tests still pass

#### E2E Runtime Validation

**File**: `crates/secure_errors/tests/e2e_sunlit_m2.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_error_to_response_roundtrip` | `AppError` converts to a valid HTTP response at runtime | Response has correct status code, valid JSON body, `Content-Type: application/json` |
| `test_public_error_serialization` | `PublicError` serializes to valid JSON with exactly the expected fields | JSON has only `code`, `message`, `request_id` — no extra fields |
| `test_no_internal_leak_runtime` | Multiple error variants converted and response bodies scanned for forbidden strings | No response body contains SQL keywords, internal hostnames, or stack trace fragments |
| `test_panic_safe_layer` | `PanicSafeLayer` catches a panic and returns a safe 500 | No crash, correct response, panic message not in body |
| `test_error_classification_consistency` | Every `AppError` variant has a consistent classification | No variant returns contradictory flags |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: `PublicError` JSON output for three error variants — no internal text leaks
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` covers all generated files

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1 tests green | | | |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| BDD tests created | `tests/sunlit_errors_*.rs` | fail for expected reason | | | |
| E2E stubs created | `tests/e2e_sunlit_m2.rs` | fail for expected reason | | | |
| Implementation | `secure_errors` modules | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | `cargo build --workspace && cargo doc --workspace --no-deps` | builds cleanly | | | |
| Smoke tests | all items above | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current | | | |
| Compatibility checks | M1 tests, stub compilation | no regressions | | | |

#### Definition of Done

The milestone is done only when all of the following are true:

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green (M1 tests)
- `PublicError` responses contain only `code`, `message`, `request_id` — no internal details
- no response body contains SQL, hostnames, stack traces, or differential authn information
- `PanicSafeLayer` catches panics without crashing the process
- every `AppError` variant has a consistent `ErrorClassification`
- `IntoResponse` is implemented centrally — no ad hoc JSON response construction
- smoke tests checked off
- compatibility checklist complete
- no forbidden shortcuts remain
- `git status` clean
- `.gitignore` up to date
- ARCHITECTURE.md updated with error-handling architecture
- lessons file written at `docs/slo/lessons/sunlit-m2.md`
- completion summary written at `docs/slo/completion/sunlit-m2.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add error-handling section — three-layer model, mapping rules, panic boundary
- **README.md**: Add `secure_errors` crate description and usage example
- **Other docs**: None

#### Notes

- Concurrency category: panic boundary is concurrent (multiple requests). Tests verify service survives a panic on one request.
- Persistence category: not applicable — no I/O.
- The `SecurityIncident` trait is defined here but wired to `security_events` in M3.

---

### Milestone 3 — `security_events` — Security Logging & Monitoring (OWASP C9)

**Goal**: Implement `security_events` providing a canonical `SecurityEvent` schema, schema-based redaction engine, security-aware `tracing` subscriber layer, detection points (AppSensor-style), OTLP/JSON/stdout sink adapters, injection-safe log formatting, and integration hooks for `secure_errors` — all following OWASP C9's requirements to log security information without leaking sensitive data.

**Context**: OWASP C9 states that security logging should use a common format, capture identifying information (timestamp, source IP, user ID), avoid sensitive data, protect against log injection, and support intrusion detection. The `tracing` crate's `#[instrument]` macro records all function arguments by default, which can leak secrets/PII. This crate wraps `tracing` with security-first defaults: sensitive fields skip/redacted unless explicitly allowed, control characters sanitized, and event fields classified by `DataClassification`. This crate depends on `security_core` and `secure_errors`.

**Important design rule**: Redaction is driven by `DataClassification` on each event field, not by ad hoc string replacement. Only fields classified as `Public` or explicitly `Internal` leave the process. All others are hashed, masked, dropped, or pseudonymized.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `SecurityEvent` structs from all crates, `tracing` spans/events |
| Outputs | Redacted, structured security events to stdout JSON, OTLP, or custom sinks |
| Interfaces touched | `security_events::event::*`, `security_events::redact::*`, `security_events::context::*`, `security_events::emit::*`, `security_events::detect::*`, `security_events::sink::*`, `security_events::layer::*` |
| Files allowed to change | All new files listed below, plus `crates/security_events/Cargo.toml`, `crates/secure_errors/src/incident.rs` (wire up event emission) |
| Files to read before changing anything | `crates/security_core/src/classification.rs`, `crates/security_core/src/context.rs`, `crates/secure_errors/src/incident.rs`, architecture security-events notes |
| New files allowed | All source files under `crates/security_events/src/`, test files |
| New dependencies allowed | `tracing` (v0.1), `tracing-subscriber` (v0.3), `tracing-opentelemetry` (v0.27, feature-gated behind `otel`), `opentelemetry` (v0.27, feature-gated), `serde_json` (v1), `uuid` (v1, re-export from workspace) |
| Migration allowed | `no` |
| Compatibility commitments | `security_core` and `secure_errors` public types must not change |
| Forbidden shortcuts | Logging secrets by default, missing control-character sanitization, un-classified event fields, raw `tracing::info!()` for security events without redaction, missing `#[non_exhaustive]` on `EventKind` or `DetectionPoint`, using `async-trait` crate |

#### Out of Scope / Must Not Do

- Do not build a full SIEM integration — provide the schema and sink trait, not connector implementations.
- Do not implement per-event persistence (writing to disk/DB) — events go to subscribers/sinks.
- Do not implement hash-chain audit log integrity yet — this is a stretch goal for this milestone. If time permits, implement `AuditChain` with SHA-256 hash linking. If deferred, document in the lessons file and ensure it is completed by M9 (Adversarial Testing) at the latest.
- Do not add axum routes or handlers.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m2.md` and apply relevant corrections.
3. Run `cargo test --workspace` and confirm green baseline.
4. Read `crates/security_core/src/classification.rs` and `crates/secure_errors/src/incident.rs`.
5. Copy Evidence Log template.
6. Re-state constraints.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/security_events/Cargo.toml` | UPDATE: add dependencies |
| `crates/security_events/src/lib.rs` | UPDATE: module declarations, crate doc comment |
| `crates/security_events/src/event.rs` | NEW: `SecurityEvent` struct with canonical fields (timestamp, event_id, kind, severity, outcome, actor, tenant, source_ip, request_id, trace_id, session_id, resource, reason_code, labels) |
| `crates/security_events/src/kind.rs` | NEW: `EventKind` enum — BoundaryViolation, AuthnFailure, MfaEvent, AuthzDeny, CrossTenantAttempt, SecretAccess, KeyRotation, AdminAction, FileUploadAnomaly, DeserializationAnomaly, ErrorEscalation, RateLimitBlock, AntiAutomation |
| `crates/security_events/src/redact.rs` | NEW: `RedactionPolicy`, `RedactionEngine` — field-level redaction based on `DataClassification`, hash/mask/drop/pseudonymize strategies |
| `crates/security_events/src/context.rs` | NEW: `SecurityContext` — correlation IDs, request IDs, trace IDs extracted from `tracing` span context |
| `crates/security_events/src/emit.rs` | NEW: `emit_security_event()` function, `SecurityEventEmitter` trait |
| `crates/security_events/src/detect.rs` | NEW: `DetectionPoint` enum — InputOutOfRange, AuthzDenied, RepeatedDeserializerFailure, CrossTenantProbe, BruteForceAttempt; threshold-based escalation |
| `crates/security_events/src/sink.rs` | NEW: `SecuritySink` trait, `StdoutJsonSink`, `TracingSink` implementations |
| `crates/security_events/src/layer.rs` | NEW: `SecurityLayer` — a `tracing_subscriber::Layer` that intercepts security-tagged spans/events, applies redaction, and routes to sinks |
| `crates/security_events/src/sanitize.rs` | NEW: control-character sanitization, newline normalization for text sinks (prevents log injection per OWASP C9) |
| `crates/security_events/src/rate_limit.rs` | NEW: per-event-kind throttling and deduplication to prevent log floods |
| `crates/secure_errors/src/incident.rs` | UPDATE: wire `SecurityIncident` implementations to emit events via `security_events::emit` |
| `crates/security_events/tests/sunlit_events_redaction.rs` | NEW: BDD tests for redaction |
| `crates/security_events/tests/sunlit_events_sanitize.rs` | NEW: BDD tests for injection safety |
| `crates/security_events/tests/sunlit_events_detection.rs` | NEW: BDD tests for detection points |
| `crates/security_events/tests/sunlit_events_schema.rs` | NEW: BDD tests for event schema stability |
| `crates/security_events/tests/e2e_sunlit_m3.rs` | NEW: E2E runtime validation |
| `.gitignore` | Update if needed |

#### Step-by-Step

1. Write BDD test stubs for all scenarios below.
2. Write E2E runtime validation stubs.
3. Implement `event.rs`: `SecurityEvent` struct with all canonical fields, `Serialize` impl.
4. Implement `kind.rs`: `EventKind` enum covering all must-have event families.
5. Implement `sanitize.rs`: control-character stripping, newline normalization.
6. Implement `redact.rs`: `RedactionPolicy` linking `DataClassification` to redaction strategy; `RedactionEngine` that processes `SecurityEvent` labels.
7. Implement `context.rs`: `SecurityContext` with correlation propagation.
8. Implement `emit.rs`: `emit_security_event()` and `SecurityEventEmitter` trait. `SecurityEventEmitter` should be a **sealed trait**.
9. Implement `detect.rs`: `DetectionPoint` enum and threshold-based escalation logic. Annotate `#[non_exhaustive]`. Use `std::sync::atomic` or `tokio::sync::Mutex` for thread-safe threshold counters.
10. Implement `sink.rs`: `SecuritySink` trait (sealed), `StdoutJsonSink` implementation. Use `std::io::stdout()` lock for atomic line writes (cross-platform).
11. Implement `layer.rs`: `SecurityLayer` wrapping `tracing_subscriber::Layer`. The layer must satisfy `Clone + Send + Sync + 'static`.
12. Implement `rate_limit.rs`: per-event throttling.
13. Update `secure_errors/src/incident.rs` to emit events via `security_events`.
14. Make all BDD tests pass.
15. Run full test suite and E2E.
16. Verify test artifact cleanup, .gitignore, smoke tests, self-review gate.

#### BDD Acceptance Scenarios

**Feature: Redaction engine**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Public field passes through | happy path | A `SecurityEvent` label classified as `Public` with value `"login_page"` | Processed by `RedactionEngine` | Value unchanged in output |
| Secret field is redacted | security invariant | A label classified as `Secret` with value `"sk-abc123"` | Processed | Value replaced with `[REDACTED]` |
| PII field is hashed | security invariant | A label classified as `PII` with value `"user@example.com"` | Processed | Value replaced with a stable hash (e.g., `SHA256:<hex>`) |
| Credentials field is dropped | security invariant | A label classified as `Credentials` with value `"Bearer eyJ..."` | Processed | Label entirely removed from output |
| Internal field allowed with explicit opt-in | happy path | A label classified as `Internal` with value `"handler_name"` | Processed with default policy | Value remains (Internal is allowed by default) |

**Feature: Log injection prevention**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Newline in field sanitized | security invariant | A label value containing `"value\nINJECTED_LOG_LINE"` | Sanitized for text sink | Newline replaced with `\n` literal or escaped; no new log line created |
| Control characters stripped | security invariant | A label value containing ASCII control chars (0x00-0x1F except 0x0A/0x0D) | Sanitized | Control characters replaced with Unicode replacement character or removed |
| Carriage return normalized | security invariant | A label value `"start\r\nend"` | Sanitized | Normalized to `"start\\r\\nend"` or equivalent safe representation |

**Feature: Detection points**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Detection point fires on threshold | happy path | 5 `AuthzDenied` events from the same actor within 60 seconds with a threshold of 3 | Detection engine evaluates | `DetectionPoint::BruteForceAttempt` escalation emitted with `High` severity |
| Below threshold no escalation | happy path | 2 `AuthzDenied` events from same actor with threshold of 3 | Detection engine evaluates | No escalation event emitted |
| Cross-tenant probe detected | security invariant | Actor from tenant A accesses resource in tenant B | Event emitted | `EventKind::CrossTenantAttempt` with `Critical` severity |

**Feature: Event schema stability**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Event serializes to expected JSON shape | happy path | A fully populated `SecurityEvent` | Serialized to JSON | JSON contains all expected top-level keys, no unexpected keys |
| Event with optional fields null | happy path | A `SecurityEvent` with `actor: None`, `source_ip: None` | Serialized | Null/absent fields handled correctly (not serialized or serialized as `null`) |

**Feature: Rate limiting**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Duplicate events deduplicated | happy path | 100 identical `BoundaryViolation` events in 1 second | Processed through rate limiter | Only N events emitted (configurable) plus a summary count |
| Different event kinds not affected | happy path | 100 `BoundaryViolation` + 100 `AuthzDeny` | Processed | Both kinds independently rate-limited |

**Feature: Error integration**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Forbidden error emits authz deny event | happy path | An `AppError::Forbidden` escalated via `SecurityIncident` | Event captured | `SecurityEvent` with `EventKind::AuthzDeny` emitted |
| Dependency error emits escalation event | happy path | An `AppError::Dependency` classified as security signal | Event captured | `SecurityEvent` with `EventKind::ErrorEscalation` emitted |

#### Regression Tests

- All `security_core` tests from M1 must still pass.
- All `secure_errors` tests from M2 must still pass.
- All workspace crate stubs must still compile.

#### Compatibility Checklist

- [ ] `security_core` public types unchanged
- [ ] `secure_errors` public types unchanged (except `incident.rs` update)
- [ ] `secure_errors` `IntoResponse` behavior unchanged
- [ ] All M1 and M2 tests still pass
- [ ] Workspace stubs still compile

#### E2E Runtime Validation

**File**: `crates/security_events/tests/e2e_sunlit_m3.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_security_event_roundtrip` | `SecurityEvent` constructs, serializes, and redacts at runtime | Valid JSON output, redacted fields do not contain original values |
| `test_redaction_engine_runtime` | Redaction engine correctly applies all classification-based rules | Secret fields absent, PII hashed, Public unchanged |
| `test_stdout_json_sink` | `StdoutJsonSink` produces valid NDJSON output | Each line is valid JSON matching `SecurityEvent` schema |
| `test_detection_threshold_integration` | Detection points fire correctly at runtime with real events | Escalation event produced after threshold |
| `test_log_injection_prevention` | Injected control characters do not create additional log lines | Output line count matches expected count, no injected lines |
| `test_rate_limiter_under_load` | Rate limiter correctly deduplicates under simulated burst | Output event count within configured limits |
| `test_error_event_integration` | `secure_errors` incidents produce security events | Event captured with correct kind and severity |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: a `SecurityEvent` with a `Secret`-classified label serializes without the secret value
- [ ] Manually verify: a string containing `\n` in a label does not produce a new log line in JSON output
- [ ] `git status` shows no untracked test artifacts
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1+M2 tests green | | | |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| BDD tests created | `tests/sunlit_events_*.rs` | fail for expected reason | | | |
| E2E stubs created | `tests/e2e_sunlit_m3.rs` | fail for expected reason | | | |
| Implementation | `security_events` modules | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | `cargo build --workspace && cargo doc --workspace --no-deps` | builds cleanly | | | |
| Smoke tests | all items above | all checked | | | |
| Test artifact cleanup | `git status` | no untracked test artifacts | | | |
| .gitignore review | review `.gitignore` | patterns current | | | |
| Compatibility checks | M1+M2 tests, stub compilation | no regressions | | | |

#### Definition of Done

The milestone is done only when all of the following are true:

- all listed BDD scenarios pass
- all listed E2E runtime validations pass
- full existing test suite remains green (M1 + M2 tests)
- redaction engine correctly handles all seven `DataClassification` levels
- no security event output contains `Secret` or `Credentials` classified field values in cleartext
- log injection payloads do not create extra log lines
- detection points fire at configured thresholds
- rate limiter prevents log floods
- `secure_errors` integration wired — `SecurityIncident` produces events
- smoke tests checked off
- compatibility checklist complete
- no forbidden shortcuts remain
- `git status` clean, `.gitignore` up to date
- ARCHITECTURE.md updated with security events architecture
- lessons file at `docs/slo/lessons/sunlit-m3.md`
- completion summary at `docs/slo/completion/sunlit-m3.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add security events section — event schema, redaction model, detection points, sink architecture
- **README.md**: Add `security_events` crate description
- **Other docs**: None

#### Notes

- Concurrency category: rate limiter and detection threshold tracking involve concurrent state. Tests verify correctness under simulated concurrent access.
- The OTLP exporter is feature-gated behind `otel` and tested only when the feature is enabled. A basic test should verify the feature compiles.
- `hash-chain` integrity is a stretch goal for this milestone. If not completed here, it MUST be addressed by M9.

---

### Milestone 4 — `secure_boundary` + `secure_output` — Input Validation, Output Encoding & Security Headers (OWASP C5 + C4)

**Goal**: Implement `secure_boundary` providing secure axum extractors (`SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>`), two-stage validation (syntax then semantics per OWASP C5), strict DTO deserialization that rejects unknown fields, body/multipart size limits, content-type enforcement, Unicode normalization, canonical ID types, automatic security event emission for boundary violations, and a `SecurityHeadersLayer` tower middleware that applies defense-in-depth response headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Cache-Control, CORS). Also implement `secure_output` providing context-aware output encoding for HTML, JSON, URL, and SQL contexts (OWASP C4) — making unsafe input impossible to consume accidentally and ensuring no response path reflects unencoded user input.

**Context**: OWASP C5 requires server-side validation checking syntax then semantics, preferring allowlists over denylists, using DTOs to prevent mass-assignment, and rejecting untrusted deserialization of complex formats. OWASP C4 requires encoding output data based on the context where it will be rendered — HTML body, HTML attribute, JavaScript, URL, CSS, SQL. Input validation alone is insufficient: stored XSS and injection attacks succeed when output is not encoded for its target context. Security response headers provide defense-in-depth against XSS, clickjacking, MIME sniffing, and transport downgrade. Serde defaults to ignoring unknown fields for JSON unless `deny_unknown_fields` is used, and `deny_unknown_fields` is incompatible with `flatten`. Axum's `DefaultBodyLimit` provides a 2 MB baseline. This milestone covers both crates because input validation and output encoding are complementary halves of the same trust boundary.

**Important design rule**: Every extractor enforces a four-stage pipeline — transport validity (content type, body size, charset) → syntactic validity (parse, format) → semantic validity (ranges, relationships, business invariants) → authorization-adjacent invariants (resource owner IDs match auth context). Unknown JSON fields are rejected by default. Use a **type-state pattern** to enforce the pipeline at compile time: define zero-sized marker types (`TransportVerified`, `SyntaxValid`, `SemanticsValid`) and parameterize the extraction state machine so that skipping a stage is a compilation error, not a runtime bug.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Raw HTTP requests (body, query, path, headers, multipart) |
| Outputs | Validated, normalized DTOs or structured rejections; boundary violation security events; encoded output; security response headers |
| Interfaces touched | `secure_boundary::extract::*`, `secure_boundary::validate::*`, `secure_boundary::normalize::*`, `secure_boundary::content_type::*`, `secure_boundary::limits::*`, `secure_boundary::serde::*`, `secure_boundary::dto::*`, `secure_boundary::attack_signal::*`, `secure_boundary::error::*`, `secure_boundary::headers::*`, `secure_output::encode::*`, `secure_output::html::*`, `secure_output::json::*`, `secure_output::url::*` |
| Files allowed to change | All new files under `crates/secure_boundary/` and `crates/secure_output/`, plus their `Cargo.toml` files |
| Files to read before changing anything | `crates/security_core/src/types.rs`, `crates/secure_errors/src/kind.rs`, `crates/security_events/src/emit.rs`, architecture boundary notes |
| New files allowed | All source and test files under `crates/secure_boundary/` and `crates/secure_output/` |
| New dependencies allowed | `axum` (v0.8), `axum-core` (v0.5), `tower` (v0.5), `tower-http` (v0.6), `validator` (v0.20), `serde` (v1), `serde_json` (v1), `serde_urlencoded` (v0.7), `unicode-normalization` (v0.1), `mime` (v0.3), `bytes` (v1), `http` (v1), `http-body-util` (v0.1) |
| Migration allowed | `no` |
| Compatibility commitments | `security_core`, `secure_errors`, `security_events` public types must not change |
| Forbidden shortcuts | Using plain `Json<T>` in any path, deserializing directly into domain models, accepting unknown fields, skipping body size checks, logging raw input, echoing payloads in rejections, missing `#[non_exhaustive]` on `BoundaryRejection` or `ViolationKind` enums, implementing `Deref<Target = T>` on extractors (use explicit `.into_inner()`) |

#### Out of Scope / Must Not Do

- Do not implement HTML sanitization boundary yet — add the `html` module as a future feature flag.
- Do not implement multipart file upload extraction — add `SecureMultipart<T>` module structure but defer implementation.
- Do not implement `#[derive(SecureRequest)]` procedural macro — hand-impl `SecureValidate` for now.
- Do not build domain model types — only DTOs and validation.
- Do not implement database/ORM interaction.

#### Pre-Flight

1. Complete the Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m3.md`.
3. Run `cargo test --workspace` green baseline.
4. Read files listed above.
5. Copy Evidence Log template.
6. Re-state constraints.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/Cargo.toml` | UPDATE: add dependencies |
| `crates/secure_boundary/src/lib.rs` | UPDATE: module declarations, crate doc comment |
| `crates/secure_boundary/src/validate.rs` | NEW: `SecureValidate` trait with `validate_syntax()` and `validate_semantics()`, `ValidationContext`, composable validators. `SecureValidate` must be an **open trait** — application DTOs in consumer crates (e.g., `secure_reference_service`) must implement it for the extractors to work. Use associated types for validated output to enforce type-level progression. |
| `crates/secure_boundary/src/extract.rs` | NEW: `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>` axum extractors |
| `crates/secure_boundary/src/dto.rs` | NEW: DTO marker trait, safe request/response patterns |
| `crates/secure_boundary/src/normalize.rs` | NEW: trimming, Unicode NFC normalization, case normalization, separator normalization |
| `crates/secure_boundary/src/content_type.rs` | NEW: allowlist-based content-type and charset enforcement |
| `crates/secure_boundary/src/limits.rs` | NEW: body size limits, field count limits, nesting depth limits, configurable per-route |
| `crates/secure_boundary/src/serde.rs` | NEW: strict deserialization helpers — `StrictDeserialize<T>` that rejects unknown fields, macro/helper for `deny_unknown_fields` enforcement |
| `crates/secure_boundary/src/attack_signal.rs` | NEW: `BoundaryViolation` event type flowing into `security_events`; classification as client_mistake, attack_signal, or parser_fault |
| `crates/secure_boundary/src/error.rs` | NEW: `BoundaryRejection` error type implementing `IntoResponse` via `secure_errors` |
| `crates/secure_boundary/src/id.rs` | NEW: canonical ID types — `UserId`, `TenantId`, `OrderId`, `OpaquePublicId` with validation |
| `crates/secure_boundary/src/headers.rs` | NEW: `SecurityHeadersLayer` — tower middleware applying HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, Cache-Control for authenticated responses, configurable CORS |
| `crates/secure_output/Cargo.toml` | UPDATE: add dependencies (`security_core`, `v_htmlescape` or manual impl) |
| `crates/secure_output/src/lib.rs` | UPDATE: module declarations, crate doc comment |
| `crates/secure_output/src/encode.rs` | NEW: `OutputEncoder` trait — context-aware encoding dispatch |
| `crates/secure_output/src/html.rs` | NEW: `HtmlEncoder` — entity-encode `<>&"'/` for HTML body and attribute contexts |
| `crates/secure_output/src/json.rs` | NEW: `JsonEncoder` — ensure JSON strings are properly escaped, no raw interpolation |
| `crates/secure_output/src/url.rs` | NEW: `UrlEncoder` — percent-encode user data for URL path and query contexts |
| `crates/secure_output/tests/sunlit_output_encoding.rs` | NEW: BDD tests for output encoding |
| `crates/secure_output/tests/e2e_sunlit_m4_output.rs` | NEW: E2E runtime validation for output encoding |
| `crates/secure_boundary/tests/sunlit_boundary_headers.rs` | NEW: BDD tests for security headers |
| `crates/secure_boundary/tests/sunlit_boundary_extractors.rs` | NEW: BDD tests for extractors |
| `crates/secure_boundary/tests/sunlit_boundary_validation.rs` | NEW: BDD tests for validation pipeline |
| `crates/secure_boundary/tests/sunlit_boundary_strict_serde.rs` | NEW: BDD tests for strict deserialization |
| `crates/secure_boundary/tests/sunlit_boundary_normalization.rs` | NEW: BDD tests for normalization |
| `crates/secure_boundary/tests/sunlit_boundary_mass_assignment.rs` | NEW: BDD tests for mass-assignment prevention |
| `crates/secure_boundary/tests/e2e_sunlit_m4.rs` | NEW: E2E runtime validation |
| `.gitignore` | Update if needed |

#### Step-by-Step

1. Write BDD test stubs for all scenarios.
2. Write E2E runtime validation stubs.
3. Implement `validate.rs`: `SecureValidate` trait (open — must be implementable by consumer DTOs), `ValidationContext`, composable validator combinators. Use associated types: `type SyntaxChecked; type SemanticsChecked;` to encode pipeline progression in the type system.
4. Implement `serde.rs`: `StrictDeserialize<T>` wrapper that forces `deny_unknown_fields` behavior. Use `serde::de::DeserializeSeed` or a wrapper `Deserializer` to inject `deny_unknown_fields` without requiring the attribute on every DTO.
5. Implement `normalize.rs`: Unicode NFC via `unicode-normalization` crate, trimming, case, separator normalizers. Normalization must produce identical results on Linux, macOS, and Windows.
6. Implement `content_type.rs`: content-type allowlist checking.
7. Implement `limits.rs`: configurable body size, field count, nesting depth limits.
8. Implement `attack_signal.rs`: `BoundaryViolation` with classification and `security_events` integration. Annotate `#[non_exhaustive]` on all violation kind enums.
9. Implement `error.rs`: `BoundaryRejection` with `IntoResponse` via `secure_errors`. Annotate `#[non_exhaustive]` and `#[must_use]`.
10. Implement `dto.rs`: DTO marker trait.
11. Implement `id.rs`: canonical ID types with syntax validation.
12. Implement `extract.rs`: `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>` — each runs the four-stage pipeline. Do **not** implement `Deref<Target = T>` — provide `.into_inner()` to consume the validated value. This forces callers to acknowledge the security boundary.
13. Implement `headers.rs`: `SecurityHeadersLayer` tower middleware. Default headers: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cache-Control: no-store` for authenticated responses. Allow per-route overrides via builder pattern. Must satisfy `Clone + Send + Sync + 'static`.
14. Implement `secure_output` crate: `OutputEncoder` trait (open, not sealed — consumers may add custom contexts), `HtmlEncoder`, `JsonEncoder`, `UrlEncoder`. Each encoder must be zero-allocation for common cases (use `Cow<str>` return). `HtmlEncoder` must encode at minimum: `<`, `>`, `&`, `"`, `'`, `/`. `UrlEncoder` must percent-encode per RFC 3986.
15. Make all BDD tests pass.
16. Run full test suite and E2E.
17. Verify cleanup, .gitignore, smoke tests, self-review gate.

#### BDD Acceptance Scenarios

**Feature: SecureJson extractor**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid JSON accepted | happy path | A JSON body `{"name": "Alice", "age": 30}` with matching DTO | Extracted via `SecureJson<CreateUserDto>` | DTO fields contain `"Alice"` and `30` |
| Unknown field rejected | security invariant | A JSON body `{"name": "Alice", "admin": true}` where DTO has no `admin` field | Extracted | HTTP 400 with `code: "invalid_request"`, no echoing of payload |
| Body too large rejected | security invariant | A JSON body exceeding configured limit (e.g., 1MB) | Extracted | HTTP 400 with `code: "body_too_large"`, boundary violation event emitted |
| Wrong content type rejected | security invariant | Body sent as `text/plain` instead of `application/json` | Extracted | HTTP 400 with `code: "invalid_content_type"` |
| Syntax validation failure | invalid input | A JSON body where `age` is `"not_a_number"` (string instead of u32) | Extracted | HTTP 400 with `code: "invalid_format"`, no raw parse error in response |
| Semantic validation failure | invalid input | A JSON body where `age` is `250` (out of range) | DTO `validate_semantics` rejects | HTTP 400 with `code: "invalid_range"` |
| Empty body rejected | empty state | No body sent with `Content-Type: application/json` | Extracted | HTTP 400 with `code: "invalid_request"` |
| Deeply nested JSON rejected | security invariant | JSON with 100 levels of nesting, limit set to 20 | Extracted | HTTP 400 with `code: "invalid_request"`, boundary violation event |

**Feature: SecureQuery and SecurePath extractors**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid query params | happy path | Query string `?page=1&limit=20` | Extracted via `SecureQuery<PaginationDto>` | DTO contains page=1, limit=20 |
| Valid path param | happy path | Path `/users/550e8400-e29b-41d4-a716-446655440000` | Extracted via `SecurePath<UserIdParam>` | UUID parsed correctly |
| Invalid UUID in path | invalid input | Path `/users/not-a-uuid` | Extracted | HTTP 400, no raw value echoed |
| Duplicate query param | security invariant | Query `?page=1&page=2` for a single-value field | Extracted | HTTP 400 with `code: "invalid_request"` or last-wins with documentation |

**Feature: Strict deserialization**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Unknown fields rejected | security invariant | JSON `{"username": "alice", "role": "admin"}` where DTO only has `username` | Deserialized | Error: unknown field `role` |
| Flatten not used in strict DTOs | security invariant | A DTO that uses `#[serde(flatten)]` passed to strict deserializer | Compile-time or runtime check | Fails with clear error (compile-time lint preferred, runtime check acceptable) |
| Null for required field rejected | invalid input | JSON `{"username": null}` where `username: String` | Deserialized | Error: null not allowed for required field |

**Feature: Mass-assignment prevention**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| DTO does not bind to model | security invariant | A request DTO `CreateUserDto` and a domain model `User` with `is_admin` field | DTO deserialized | DTO has no `is_admin` field; domain model constructed explicitly from DTO fields |
| Extra fields in request ignored or rejected | security invariant | JSON with `{"name": "Alice", "is_admin": true}` for `CreateUserDto` without `is_admin` | Processed | Field rejected (strict mode), never bound to domain model |

**Feature: Normalization**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Unicode NFC normalization | happy path | Input string with decomposed `é` (e + combining accent) | Normalized | Composed `é` (single codepoint) |
| Whitespace trimming | happy path | Input `"  Alice  "` | Normalized | `"Alice"` |
| Case normalization | happy path | Email `"Alice@Example.COM"` | Normalized as email (local part preserved, domain lowered) | `"Alice@example.com"` |

**Feature: Boundary violation events**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Unknown field emits attack signal | security invariant | Unknown field detected | Event captured | `SecurityEvent` with `EventKind::BoundaryViolation` and severity based on classification |
| Body too large emits event | security invariant | Oversized body rejected | Event captured | `BoundaryViolation` event with `SuspiciousPayload` kind |
| Repeated violations escalate | security invariant | 10 boundary violations from same actor in 60s | Detection point evaluates | Escalated event emitted |

**Feature: Security response headers**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Default headers applied | happy path | A response passing through `SecurityHeadersLayer` with default config | Headers inspected | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Permissions-Policy all present with secure defaults |
| HSTS includes preload | security invariant | Default `SecurityHeadersLayer` | `Strict-Transport-Security` header inspected | Contains `max-age=63072000; includeSubDomains; preload` |
| CSP restricts all sources | security invariant | Default `SecurityHeadersLayer` | `Content-Security-Policy` inspected | Contains `default-src 'none'; frame-ancestors 'none'` |
| Cache-Control for authenticated | security invariant | Authenticated response (has Authorization context) | `Cache-Control` header inspected | Contains `no-store` |
| Per-route override | happy path | `SecurityHeadersLayer` with custom CSP for a specific route | Headers inspected | Custom CSP applied, other defaults preserved |
| CORS configured | happy path | `SecurityHeadersLayer` with allowed origins `["https://app.example.com"]` | `Access-Control-Allow-Origin` inspected | Only configured origin reflected |

**Feature: Output encoding (secure_output)**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| HTML entity encoding | happy path | Input `<script>alert('xss')</script>` | Encoded via `HtmlEncoder` | Output is `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;` |
| HTML attribute encoding | happy path | Input `" onmouseover="alert(1)` | Encoded for HTML attribute | Double quotes and event handler escaped |
| JSON string encoding | happy path | Input containing `</script>` | Encoded via `JsonEncoder` | Forward slash escaped: `<\/script>` |
| URL percent encoding | happy path | Input `hello world&foo=bar` | Encoded via `UrlEncoder` | `hello%20world%26foo%3Dbar` |
| Already-safe string passthrough | happy path | Input `"hello"` (no special chars) | Encoded via `HtmlEncoder` | Returns `Cow::Borrowed` (zero-allocation) |
| Null bytes stripped | security invariant | Input containing `\x00` | Encoded via any encoder | Null bytes removed or replaced |

#### Regression Tests

- All M1 (`security_core`), M2 (`secure_errors`), M3 (`security_events`) tests must still pass.
- Workspace stubs for `secure_authz` and `secure_data` must still compile.

#### Compatibility Checklist

- [ ] `security_core` public types unchanged
- [ ] `secure_errors` public types and IntoResponse unchanged
- [ ] `security_events` SecurityEvent schema unchanged
- [ ] All M1-M3 tests still pass
- [ ] Remaining stubs compile

#### E2E Runtime Validation

**File**: `crates/secure_boundary/tests/e2e_sunlit_m4.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_secure_json_happy_path` | `SecureJson<T>` extracts and validates a correct payload at runtime | DTO fields match input, no errors |
| `test_secure_json_unknown_field_rejection` | Unknown fields produce correct rejection | HTTP 400, no echoed payload, boundary event emitted |
| `test_secure_json_body_limit` | Oversized body rejected at runtime | HTTP 400 before parsing occurs |
| `test_validation_pipeline_order` | Transport → syntax → semantics → authz-adjacent checks run in order | Transport failure short-circuits before syntax check runs |
| `test_normalization_applied` | Normalization runs before validation | Trimmed and NFC-normalized values validated |
| `test_mass_assignment_blocked` | DTO with extra fields does not bind to domain model | Extra field not present in extracted DTO |
| `test_boundary_violation_event_emitted` | Rejection produces a SecurityEvent | Event captured in test subscriber with correct kind |
| `test_security_headers_applied` | `SecurityHeadersLayer` adds all default headers | Response contains HSTS, CSP, X-Content-Type-Options, X-Frame-Options |
| `test_html_encoding_prevents_xss` | `HtmlEncoder` encodes XSS payloads | Encoded output does not contain raw `<script>` |
| `test_url_encoding_roundtrip` | `UrlEncoder` produces valid percent-encoded output | Encoded output decodes back to original |
| `test_json_encoding_prevents_injection` | `JsonEncoder` escapes `</script>` in JSON strings | No raw `</script>` in output |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: `SecureJson` with unknown field returns 400 with no payload echo
- [ ] `git status` clean
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M3 green | | | |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| BDD tests created | `tests/sunlit_boundary_*.rs` | fail for expected reason | | | |
| E2E stubs created | `tests/e2e_sunlit_m4.rs` | fail for expected reason | | | |
| Implementation | `secure_boundary` modules | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | `cargo build --workspace && cargo doc --workspace --no-deps` | builds cleanly | | | |
| Smoke tests | all items | all checked | | | |
| Test artifact cleanup | `git status` | clean | | | |
| .gitignore review | review | current | | | |
| Compatibility checks | M1-M3 tests, stubs | no regressions | | | |

#### Definition of Done

- all BDD scenarios pass
- all E2E runtime validations pass
- full M1-M3 test suite remains green
- `SecureJson<T>` rejects unknown fields by default
- body size limits enforced before parsing
- validation pipeline runs transport → syntax → semantics in order
- DTO pattern prevents mass-assignment
- boundary violations emit `SecurityEvent`s
- no rejection response echoes raw input
- smoke tests checked, compatibility complete
- `git status` clean, `.gitignore` up to date
- ARCHITECTURE.md updated
- lessons at `docs/slo/lessons/sunlit-m4.md`, completion at `docs/slo/completion/sunlit-m4.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add input validation section — extractor pipeline, DTO pattern, normalization, attack signals
- **README.md**: Add `secure_boundary` usage examples: replacing `Json<T>` with `SecureJson<T>`
- **Other docs**: None

#### Notes

- HTML sanitization (`html` module) deferred — document in lessons.
- `SecureMultipart<T>` module stub only — no implementation yet.
- `#[derive(SecureRequest)]` proc macro deferred — document in lessons.
- Property tests for normalizers and fuzz tests for JSON parsing are stretch goals for this milestone; include at least one property test for Unicode normalization idempotency.

---

### Milestone 5 — `secure_identity` — Digital Identity (OWASP C6)

**Goal**: Implement `secure_identity` providing a pluggable authentication abstraction with `Authenticator` trait, `SessionManager` trait, `TokenValidator`, MFA challenge support, and a `DevAuthenticator` for development/testing — per OWASP C6. This crate is ONE of many possible `IdentitySource` implementations. Consumers may use Keycloak, Auth0, custom OIDC, or any other crate implementing `security_core::IdentitySource` instead of or alongside `secure_identity`.

**Context**: OWASP C6 (Implement Digital Identity) requires authentication based on risk level, support for multi-factor authentication, secure session management, and pluggable identity providers. Critical infrastructure environments may mandate specific identity providers (Keycloak for on-prem, Auth0 for cloud, custom OIDC for air-gapped). The `IdentitySource` trait in `security_core` (defined in M1) is the integration contract — `secure_identity` implements it, but so can any external adapter. `secure_authz` (M6) accepts `Subject` from ANY `IdentitySource`, not just this crate. This means consumers can adopt `secure_authz` without `secure_identity` in their dependency tree.

**Important design rule**: `secure_identity` must NEVER be a required dependency of `secure_authz`. The integration point is `security_core::IdentitySource`, which `secure_identity` implements. The `Authenticator` trait is sealed — third-party identity providers implement `IdentitySource` instead. `DevAuthenticator` is behind a `dev` feature flag and produces `AuthenticatedIdentity` with configurable roles for testing.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Authentication tokens (Bearer JWT, API keys, session cookies), MFA challenge responses |
| Outputs | `AuthenticatedIdentity` (from `security_core`), session tokens, MFA challenge objects |
| Interfaces touched | `secure_identity::authenticator::*`, `secure_identity::session::*`, `secure_identity::token::*`, `secure_identity::mfa::*`, `secure_identity::dev::*` |
| Files allowed to change | All new files under `crates/secure_identity/`, plus `crates/secure_identity/Cargo.toml` |
| Files to read before changing anything | `crates/security_core/src/identity.rs`, `crates/security_core/src/types.rs`, architecture identity notes |
| New files allowed | All source and test files under `crates/secure_identity/` |
| New dependencies allowed | `jsonwebtoken` (v9), `tokio` (v1, `sync` + `time`), `ring` (v0.17, for token signature verification), `base64` (v0.22) |
| Migration allowed | `no` |
| Compatibility commitments | All M1-M4 public types unchanged. `security_core::IdentitySource` trait unchanged. |
| Forbidden shortcuts | Making `secure_authz` depend on `secure_identity`, placing `IdentitySource` in this crate instead of `security_core`, exposing `DevAuthenticator` without feature gate, storing plaintext passwords, using timing-vulnerable comparisons for tokens, using `async-trait` crate |

#### Out of Scope / Must Not Do

- Do not implement specific OIDC/OAuth2 protocol flows — provide the trait abstractions and one reference implementation.
- Do not implement user registration, password reset, or account management.
- Do not implement persistent session storage — provide the `SessionManager` trait, not a database backend.
- Do not modify `secure_authz` — it will consume `IdentitySource` in M6.
- Do not make `secure_authz` depend on this crate at compile time.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m4.md`.
3. Run `cargo test --workspace` green baseline.
4. Read `crates/security_core/src/identity.rs` to understand the `IdentitySource` trait.
5. Copy Evidence Log.
6. Re-state constraints.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_identity/Cargo.toml` | UPDATE: add dependencies |
| `crates/secure_identity/src/lib.rs` | UPDATE: module declarations, crate doc comment, `IdentitySource` implementation |
| `crates/secure_identity/src/authenticator.rs` | NEW: `Authenticator` trait (sealed), `AuthenticationRequest`, `AuthenticationResult` |
| `crates/secure_identity/src/session.rs` | NEW: `SessionManager` trait, `Session` struct, session lifecycle (create, validate, refresh, revoke) |
| `crates/secure_identity/src/token.rs` | NEW: `TokenValidator` — JWT validation with configurable claims, issuer, audience, expiration |
| `crates/secure_identity/src/mfa.rs` | NEW: `MfaChallenge`, `MfaResponse`, `MfaProvider` trait — TOTP support stub |
| `crates/secure_identity/src/dev.rs` | NEW: `DevAuthenticator` — feature-gated (`dev`) authenticator producing configurable `AuthenticatedIdentity` for tests |
| `crates/secure_identity/src/error.rs` | NEW: `IdentityError` enum — `InvalidCredentials`, `TokenExpired`, `TokenMalformed`, `MfaRequired`, `SessionExpired`, `ProviderUnavailable` |
| `crates/secure_identity/tests/sunlit_identity_authenticator.rs` | NEW: BDD tests for Authenticator |
| `crates/secure_identity/tests/sunlit_identity_token.rs` | NEW: BDD tests for TokenValidator |
| `crates/secure_identity/tests/sunlit_identity_session.rs` | NEW: BDD tests for SessionManager |
| `crates/secure_identity/tests/sunlit_identity_dev.rs` | NEW: BDD tests for DevAuthenticator |
| `crates/secure_identity/tests/e2e_sunlit_m5.rs` | NEW: E2E runtime validation |
| `.gitignore` | Update if needed |

#### Step-by-Step

1. Write BDD test stubs for all scenarios.
2. Write E2E runtime validation stubs.
3. Implement `error.rs`: `IdentityError` enum with `#[non_exhaustive]`. Map to `secure_errors` via `From` impl.
4. Implement `authenticator.rs`: `Authenticator` trait (sealed). Defines `authenticate(request: &AuthenticationRequest) -> Result<AuthenticatedIdentity, IdentityError>`. Sealed because third-party providers implement `IdentitySource` (in `security_core`), not `Authenticator`.
5. Implement `token.rs`: `TokenValidator` for JWT. Validate signature, expiration, issuer, audience. Use `ring` for crypto, `jsonwebtoken` for JWT structure. Use **constant-time comparison** (`subtle` crate or `ring::constant_time`) for signature verification.
6. Implement `session.rs`: `SessionManager` trait. `Session` struct with ID, actor_id, created_at, expires_at, last_accessed. Session creation, validation, refresh (sliding window), revocation. Sessions must have bounded lifetime. Session IDs must be cryptographically random (128+ bits entropy).
7. Implement `mfa.rs`: `MfaChallenge`, `MfaResponse`, `MfaProvider` trait stub. TOTP validation stub. Full MFA implementation is a stretch goal.
8. Implement `dev.rs` (feature-gated behind `dev`): `DevAuthenticator` accepting any credentials, producing `AuthenticatedIdentity` with configurable actor_id, tenant_id, roles. Emit warning log when initialized. Mark with `#[cfg(feature = "dev")]`.
9. Implement `IdentitySource` for the crate's authenticator — bridge from `Authenticator` to `security_core::IdentitySource`.
10. Make all BDD tests pass.
11. Run full test suite and E2E.
12. Verify that `secure_authz` does NOT have a dependency on this crate (check `Cargo.toml`).
13. Verify cleanup, .gitignore, smoke tests, self-review gate.

#### BDD Acceptance Scenarios

**Feature: Authentication**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Valid JWT produces identity | happy path | A valid JWT with claims `{sub: "user-1", tenant: "t-1", roles: ["READER"]}` | Authenticated via `TokenValidator` | `AuthenticatedIdentity` with matching actor_id, tenant_id, roles |
| Expired JWT rejected | security invariant | A JWT with `exp` in the past | Authenticated | `IdentityError::TokenExpired` |
| Malformed JWT rejected | invalid input | A string that is not a valid JWT | Authenticated | `IdentityError::TokenMalformed` |
| Wrong issuer rejected | security invariant | A valid JWT with issuer `"evil.com"`, expected `"auth.example.com"` | Authenticated | `IdentityError::InvalidCredentials` |
| Missing required claims rejected | invalid input | A JWT without `sub` claim | Authenticated | `IdentityError::TokenMalformed` |
| Authentication failure emits event | security invariant | Any authentication failure | Event captured | `SecurityEvent` with `EventKind::AuthnFailure` |

**Feature: Session management**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Session created with bounded lifetime | happy path | A successful authentication | Session created | Session has `expires_at` within configured max lifetime |
| Session validated before expiry | happy path | A valid, non-expired session | Validated | Returns associated `AuthenticatedIdentity` |
| Expired session rejected | security invariant | A session past `expires_at` | Validated | `IdentityError::SessionExpired` |
| Session revoked | happy path | A valid session | Revoked, then validated | `IdentityError::SessionExpired` (or equivalent) |
| Session ID is cryptographically random | security invariant | 1000 sessions created | Session IDs inspected | All unique, 128+ bits entropy |

**Feature: DevAuthenticator**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| DevAuthenticator accepts any credentials | happy path | `DevAuthenticator` configured with roles `["ADMIN"]` | Any token provided | `AuthenticatedIdentity` with `roles: ["ADMIN"]` |
| DevAuthenticator only available with feature | security invariant | Crate compiled without `dev` feature | `DevAuthenticator` referenced | Compilation fails |
| DevAuthenticator emits warning | security invariant | `DevAuthenticator` initialized | Logs inspected | Warning log: "DevAuthenticator in use — not for production" |

**Feature: IdentitySource implementation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| secure_identity implements IdentitySource | happy path | The crate's authenticator | Called via `IdentitySource::resolve()` | Returns `AuthenticatedIdentity` |
| secure_authz has no dependency on secure_identity | security invariant | `crates/secure_authz/Cargo.toml` | Inspected for dependencies | `secure_identity` is NOT listed |

#### Regression Tests

- All M1-M4 tests must still pass.
- `security_core::IdentitySource` trait must not have changed.

#### Compatibility Checklist

- [ ] `security_core` public types unchanged (especially `IdentitySource`)
- [ ] All M1-M4 tests still pass
- [ ] `secure_authz` has NO dependency on `secure_identity`
- [ ] `secure_authz` stub still compiles

#### E2E Runtime Validation

**File**: `crates/secure_identity/tests/e2e_sunlit_m5.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_jwt_authentication_roundtrip` | JWT creation → validation → identity extraction works at runtime | Valid identity returned with correct claims |
| `test_session_lifecycle` | Create → validate → refresh → revoke works | Each step produces expected state |
| `test_dev_authenticator_produces_identity` | `DevAuthenticator` produces valid `AuthenticatedIdentity` | Identity has configured roles and actor_id |
| `test_identity_source_integration` | `IdentitySource::resolve()` produces `AuthenticatedIdentity` | Same result as direct authenticator call |
| `test_authz_independence` | `secure_authz` compiles and tests pass without `secure_identity` in its dep tree | `cargo test -p secure_authz` succeeds |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] `cargo test -p secure_authz` passes without `secure_identity` dependency
- [ ] `DevAuthenticator` not accessible without `dev` feature
- [ ] `git status` clean
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M4 green | | | |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | zero warnings | | | |
| BDD tests created | `tests/sunlit_identity_*.rs` | fail for expected reason | | | |
| E2E stubs created | `tests/e2e_sunlit_m5.rs` | fail for expected reason | | | |
| Implementation | `secure_identity` modules | contract satisfied | | | |
| Independence check | `cargo tree -p secure_authz` | no `secure_identity` | | | |
| Full tests | `cargo test --workspace` | green | | | |
| Smoke tests | all items | all checked | | | |

#### Definition of Done

- all BDD scenarios pass
- all E2E runtime validations pass
- full M1-M4 test suite remains green
- `secure_identity` implements `security_core::IdentitySource`
- `secure_authz` has ZERO compile-time dependency on `secure_identity`
- `DevAuthenticator` feature-gated behind `dev`
- JWT validation uses constant-time comparison
- session IDs are cryptographically random (128+ bits)
- authentication failures emit security events
- smoke tests checked, compatibility complete
- `git status` clean, `.gitignore` up to date
- ARCHITECTURE.md updated
- lessons at `docs/slo/lessons/sunlit-m5.md`, completion at `docs/slo/completion/sunlit-m5.md`
- Milestone Tracker updated

#### Self-Review Gate

```
## Self-Review Gate — Milestone 5

- [ ] All BDD scenarios pass
- [ ] E2E runtime validation passes
- [ ] `cargo test -p secure_authz` passes without secure_identity dependency
- [ ] `cargo tree -p secure_authz | grep secure_identity` returns nothing
- [ ] DevAuthenticator is behind `dev` feature gate
- [ ] JWT validation uses constant-time comparison
- [ ] Session IDs use 128+ bits of cryptographic entropy
- [ ] Authentication failures emit SecurityEvent with EventKind::AuthnFailure
- [ ] M1-M4 tests still pass (no regressions)
- [ ] cargo clippy clean
- [ ] cargo doc builds

## Known non-blocking limitations
- TOTP MFA is a stub — full implementation deferred
- No persistent session storage — SessionManager is trait-only
- No OIDC/OAuth2 protocol flow implementation
```

#### Post-Flight

- **ARCHITECTURE.md**: Add identity section — IdentitySource trait, secure_identity as one implementation, how to bring your own identity provider
- **README.md**: Add `secure_identity` usage examples, document how to implement `IdentitySource` for custom providers
- **Other docs**: Add `docs/identity-integration.md` showing Keycloak/Auth0/custom adapter patterns

#### Notes

- The key architectural invariant: `secure_authz` depends on `security_core::IdentitySource`, NOT on `secure_identity`. Verify with `cargo tree -p secure_authz`.
- Consumers who use Keycloak would create a `keycloak-identity` crate implementing `IdentitySource`, and `secure_authz` works with it directly — no `secure_identity` needed.
- TOTP MFA is a stub. Full TOTP + backup codes is a stretch goal.

---

### Milestone 6 — `secure_authz` — Access Control Enforcement (OWASP C7)

**Goal**: Implement `secure_authz` providing a deny-by-default authorization enforcer, pluggable policy engine (defaulting to casbin), typed subjects/actions/resources (no role strings in business code), axum middleware and extractor-based guards, tenant/ownership isolation, decision logging to `security_events`, and bounded decision caching — per OWASP C7. Authorization is **identity-agnostic**: `Subject` is built from `AuthenticatedIdentity` provided by ANY `IdentitySource` implementor (Keycloak, Auth0, `secure_identity`, or custom adapters), not from a specific identity crate.

**Context**: OWASP C7 requires access control designed up front, forcing all requests through a verification layer, denying by default, supporting multi-tenancy, and not hard-coding roles. The `casbin` crate provides the policy engine under the hood, but application code depends on the `Authorizer` trait, not casbin directly. Every deny and engine fault emits a security event. This crate depends on `security_core`, `secure_errors`, and `security_events`. It does NOT depend on `secure_identity` — the `IdentitySource` trait in `security_core` is the only integration point.

**Important design rule**: Service code must express authorization as `Authorize<Action>` or `authorize(action, resource)` — never as `if user.role == "ADMIN"`. Missing policy, engine failure, cache miss with backend failure, malformed resource, or partial context must all result in `Deny`. The `Authorizer` trait uses native `async fn` (no `async-trait` crate). `Decision` must be annotated `#[must_use]` so callers cannot silently ignore an authorization result. `Subject` must be constructible from any `security_core::AuthenticatedIdentity` — which can come from ANY `IdentitySource` implementor. The `SubjectResolver` trait accepts `AuthenticatedIdentity` and produces `Subject`.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `Subject` (from any `IdentitySource` via `SubjectResolver`), `Action`, `Resource` descriptor, policy definitions |
| Outputs | `Decision` (Allow with obligations / Deny with reason), decision audit events, security events for denials |
| Interfaces touched | `secure_authz::subject::*`, `secure_authz::resolver::*`, `secure_authz::resource::*`, `secure_authz::action::*`, `secure_authz::policy::*`, `secure_authz::enforcer::*`, `secure_authz::middleware::*`, `secure_authz::ownership::*`, `secure_authz::decision_log::*`, `secure_authz::cache::*`, `secure_authz::testkit::*` |
| Files allowed to change | All new files under `crates/secure_authz/`, plus `crates/secure_authz/Cargo.toml` |
| Files to read before changing anything | `crates/security_core/src/types.rs`, `crates/secure_errors/src/kind.rs`, `crates/security_events/src/emit.rs`, architecture authorization notes |
| New files allowed | All source and test files under `crates/secure_authz/` |
| New dependencies allowed | `casbin` (v2), `smallvec` (v1), `lru` (v0.12 or latest, for bounded cache), `tokio` (v1, `sync` + `time` features) |
| Migration allowed | `no` |
| Compatibility commitments | All M1-M5 public types unchanged |
| Forbidden shortcuts | Hard-coded role strings, `unwrap()` on policy evaluation, allow-by-default fallback, unbounded decision cache, skipping policy version in cache keys, using `async-trait` crate (use native `async fn in trait`), missing `#[non_exhaustive]` on `Decision`, `DenyReason`, or `Action` enums, depending on `secure_identity` at compile time, constructing `Subject` from anything other than `AuthenticatedIdentity` |

#### Out of Scope / Must Not Do

- Do not implement `#[protect()]` procedural macro — hand-write middleware/extractor guards.
- Do not implement hierarchical resource inheritance — defer to future work.
- Do not implement field-level authorization — defer.
- Do not implement SQL/data-layer row-filter helpers — defer.
- Do not build policy management UI or admin API.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m5.md`.
3. Run `cargo test --workspace` green baseline.
4. Read listed files.
5. Verify `crates/secure_authz/Cargo.toml` does NOT list `secure_identity` as a dependency.
6. Copy Evidence Log.
7. Re-state constraints — especially: NO dependency on `secure_identity`.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_authz/Cargo.toml` | UPDATE: add dependencies |
| `crates/secure_authz/src/lib.rs` | UPDATE: module declarations |
| `crates/secure_authz/src/subject.rs` | NEW: `Subject` struct — actor_id, tenant_id, roles (SmallVec), attributes (BTreeMap). Constructed from `security_core::AuthenticatedIdentity` via `SubjectResolver`. |
| `crates/secure_authz/src/resolver.rs` | NEW: `SubjectResolver` trait — converts `AuthenticatedIdentity` (from any `IdentitySource`) into `Subject`. Default impl `DefaultSubjectResolver` maps fields directly. |
| `crates/secure_authz/src/resource.rs` | NEW: `Resource` trait — kind, resource_id, tenant_id, owner_id, attributes; `ResourceRef` struct |
| `crates/secure_authz/src/action.rs` | NEW: `Action` enum framework — typed actions per domain, not strings. Annotate `#[non_exhaustive]`. |
| `crates/secure_authz/src/policy.rs` | NEW: `PolicyEngine` trait (sealed) abstracting casbin; policy loading, registration. Use native `async fn` — no `async-trait`. |
| `crates/secure_authz/src/enforcer.rs` | NEW: `Authorizer` trait with `authorize()` native async method (no `async-trait`); `DefaultAuthorizer` wrapping casbin `Enforcer` |
| `crates/secure_authz/src/decision.rs` | NEW: `Decision` enum — `Allow { obligations }`, `Deny { reason: DenyReason }`; `DenyReason` enum. Both annotated `#[non_exhaustive]` and `#[must_use]`. |
| `crates/secure_authz/src/middleware.rs` | NEW: axum middleware layer that injects authorization checks; `AuthzLayer`, `AuthzService`. Both must satisfy `Clone + Send + Sync + 'static` tower bounds. Use `tower::ServiceBuilder` for composition. |
| `crates/secure_authz/src/ownership.rs` | NEW: `OwnedResource` trait, tenant-scoping helpers |
| `crates/secure_authz/src/decision_log.rs` | NEW: structured decision event emission to `security_events` |
| `crates/secure_authz/src/cache.rs` | NEW: bounded LRU decision cache with TTL, policy-version keying, invalidation |
| `crates/secure_authz/src/testkit.rs` | NEW: `MockAuthorizer`, policy fixtures, golden-test helpers |
| `crates/secure_authz/tests/sunlit_authz_deny_default.rs` | NEW: BDD tests for deny-by-default |
| `crates/secure_authz/tests/sunlit_authz_policies.rs` | NEW: BDD tests for policy evaluation |
| `crates/secure_authz/tests/sunlit_authz_tenant.rs` | NEW: BDD tests for tenant isolation |
| `crates/secure_authz/tests/sunlit_authz_ownership.rs` | NEW: BDD tests for resource ownership |
| `crates/secure_authz/tests/sunlit_authz_cache.rs` | NEW: BDD tests for decision cache |
| `crates/secure_authz/tests/e2e_sunlit_m6.rs` | NEW: E2E runtime validation |
| `.gitignore` | Update if needed |

#### BDD Acceptance Scenarios

**Feature: Deny by default**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| No policy matches → deny | security invariant | A subject/action/resource with no matching policy | Authorized | `Decision::Deny { reason: NoPolicyMatch }` |
| Engine error → deny | partial failure | Policy engine returns an error | Authorized | `Decision::Deny { reason: EngineError }`, security event emitted |
| Empty subject → deny | empty state | An authorization request with no actor_id | Authorized | `Decision::Deny { reason: IncompleteContext }` |
| Missing resource → deny | invalid input | Authorization for a resource with no kind | Authorized | `Decision::Deny` |

**Feature: Policy evaluation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| RBAC allow | happy path | Subject with role `"editor"`, policy says editors can `Read` articles | Authorized | `Decision::Allow` |
| RBAC deny | happy path | Subject with role `"viewer"`, policy says only editors can `Write` | Authorized | `Decision::Deny { reason: InsufficientRole }` |
| ABAC condition met | happy path | Subject with attribute `department=engineering`, policy allows engineering to access code repos | Authorized | `Decision::Allow` |
| No role strings in code | security invariant | Business code uses `Action::Delete` and typed resource, not `"ADMIN"` string | Compilation | Compiles without string role checks |

**Feature: Tenant isolation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Same-tenant access | happy path | Subject tenant_id=A, resource tenant_id=A | Authorized | Allowed (if policy permits) |
| Cross-tenant blocked | security invariant | Subject tenant_id=A, resource tenant_id=B | Authorized | `Decision::Deny { reason: TenantMismatch }`, `CrossTenantAttempt` security event emitted |
| No tenant on subject → deny for tenanted resource | security invariant | Subject tenant_id=None, resource tenant_id=B | Authorized | Deny |

**Feature: Resource ownership**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Owner can access own resource | happy path | Subject actor_id=X, resource owner_id=X, policy allows owner access | Authorized | Allow |
| Non-owner denied | security invariant | Subject actor_id=X, resource owner_id=Y, no admin policy | Authorized | Deny |

**Feature: Decision cache**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Cache hit returns same decision | happy path | Same (subject, action, resource, policy_version) evaluated twice | Second call | Returns cached decision, engine not called again |
| Policy version change invalidates | happy path | Policy version changes between evaluations | Second call with new version | Cache miss, engine re-evaluated |
| Cache bounded by size | happy path | Cache max_size=100, 200 decisions cached | 201st evaluation | Oldest entries evicted, no OOM |
| Stale cache entry expires | happy path | TTL=60s, entry cached, 61 seconds pass | Accessed | Cache miss, re-evaluated |

**Feature: Decision logging**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Every deny emits event | security invariant | A `Decision::Deny` returned | Event captured | `SecurityEvent` with `EventKind::AuthzDeny` |
| Engine fault emits event | partial failure | Engine error causes deny | Event captured | `SecurityEvent` with `EventKind::ErrorEscalation` and `Critical` severity |
| Allow does not emit high-severity event | happy path | A `Decision::Allow` | Events checked | No `High`/`Critical` severity event for successful allow |

**Feature: Identity-agnostic subject resolution**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Subject from secure_identity | happy path | `AuthenticatedIdentity` produced by `secure_identity`'s `IdentitySource` | Resolved via `SubjectResolver` | `Subject` with matching actor_id, tenant_id, roles |
| Subject from custom IdentitySource | happy path | `AuthenticatedIdentity` produced by a test `MockIdentitySource` (simulating Keycloak) | Resolved via `SubjectResolver` | `Subject` with matching actor_id, tenant_id, roles — no `secure_identity` involved |
| No compile-time dep on secure_identity | security invariant | `crates/secure_authz/Cargo.toml` and `cargo tree -p secure_authz` | Inspected | `secure_identity` does not appear |
| SubjectResolver extensible | happy path | Custom `SubjectResolver` that maps extra attributes | Used with `DefaultAuthorizer` | Extra attributes available in policy evaluation |

#### Regression Tests

- All M1-M5 tests must still pass.
- `secure_data` stub must still compile.
- `cargo tree -p secure_authz` must NOT show `secure_identity`.

#### Compatibility Checklist

- [ ] All M1-M5 public types unchanged
- [ ] `secure_errors` `IntoResponse` unchanged
- [ ] `security_events` `SecurityEvent` schema unchanged
- [ ] `secure_boundary` extractors unchanged
- [ ] All M1-M5 tests pass

#### E2E Runtime Validation

**File**: `crates/secure_authz/tests/e2e_sunlit_m6.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_deny_by_default_runtime` | No-policy scenario denies at runtime | `Decision::Deny` returned, no panic |
| `test_rbac_policy_evaluation` | RBAC policies evaluate correctly at runtime with casbin | Allow for permitted role, Deny for unpermitted |
| `test_cross_tenant_denied` | Cross-tenant authorization denied with security event | Deny returned, `CrossTenantAttempt` event emitted |
| `test_decision_cache_lifecycle` | Cache stores, hits, expires, and invalidates correctly | Cache hit avoids engine, TTL expiry re-evaluates |
| `test_middleware_integration` | `AuthzLayer` denies unauthorized requests in an axum test router | Unauthorized request gets 403, authorized gets 200 |
| `test_engine_failure_denies` | When policy engine errors, result is Deny | No panic, Deny returned, event emitted |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: middleware returns 403 for unprotected request
- [ ] `git status` clean
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M5 green | | | |
| BDD tests created | `tests/sunlit_authz_*.rs` | fail expected | | | |
| E2E stubs | `tests/e2e_sunlit_m6.rs` | fail expected | | | |
| Implementation | `secure_authz` modules | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | builds cleanly | | | | |
| Smoke/compat | all checked | | | | |
| Cleanup | `git status` clean | | | | |

#### Definition of Done

- all BDD scenarios pass, all E2E pass
- full M1-M5 test suite green
- deny-by-default verified for all failure modes
- no role strings in production code
- no compile-time dependency on `secure_identity` (verified via `cargo tree`)
- `SubjectResolver` accepts `AuthenticatedIdentity` from any `IdentitySource`
- tenant isolation enforced
- decision cache bounded with TTL and version-key
- every deny emits security event
- middleware integration works with axum
- smoke/compat complete, `git status` clean, .gitignore current
- ARCHITECTURE.md updated, lessons at `docs/slo/lessons/sunlit-m6.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add authorization section — policy engine, enforcer trait, middleware, cache, tenant isolation
- **README.md**: Add `secure_authz` description and middleware usage example

#### Notes

- `#[protect()]` proc macro deferred — document in lessons.
- Hierarchical resources and field-level authz deferred.
- Bulk authorization for list filtering deferred.
- Property tests: "no policy → never allow" is a required property test.

---

### Milestone 7 — `secure_data` — Data Protection & Secrets Management (OWASP C8)

**Goal**: Implement `secure_data` providing typed secret wrappers (no raw `String` for secrets), pluggable key backends (KMS, Vault, static-dev), envelope encryption/decryption, key lifecycle with rotation and dual-read, secret-reference config resolution, zeroization on drop, `Debug`/`Display`/`Serde` suppression for secrets, and a FIPS-readiness path via feature-gated `aws-lc-rs` backend — per OWASP C8.

**Context**: OWASP C8 requires encrypting data in transit and at rest, a secret lifecycle with key rotation, secret data types that minimize memory exposure, and using secrets vaults rather than storing secrets in code/config. The `secrecy` crate provides in-memory secret wrapping with `SecretBox`, and `zeroize` guarantees clearing is not optimized away. This crate composes these with envelope encryption (AEAD under a KMS/Vault-wrapped data key), secret-reference resolution, and audit metadata. It depends on `security_core`, `secure_errors`, and `security_events`. For critical infrastructure deployments requiring FIPS 140-2/3 compliance, a `fips` feature flag swaps `aes-gcm` (RustCrypto) for `aws-lc-rs` (FIPS-validated module).

**Important design rule**: Application code never calls AEAD primitives directly. It calls `encrypt_for_storage()` and `decrypt_for_use()`. The crate manages data key generation, wrapping, versioning, nonce generation, authenticated encryption, and AAD binding internally. Both functions return `#[must_use]` results. The `KeyProvider` trait is **sealed** and uses native `async fn`. Crypto algorithm selection is abstracted behind an `AeadBackend` trait so the FIPS backend can be swapped without changing application code.

**Refactor budget**: `No refactor permitted beyond direct implementation`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Plaintext data, `KeyAlias`, `SecretRef` config references, wrapped data keys |
| Outputs | `EnvelopeEncrypted` ciphertext blobs, decrypted plaintext, resolved secrets, audit events |
| Interfaces touched | `secure_data::secret::*`, `secure_data::kms::*`, `secure_data::vault::*`, `secure_data::envelope::*`, `secure_data::keyring::*`, `secure_data::rotation::*`, `secure_data::config::*`, `secure_data::serde::*`, `secure_data::memory::*` |
| Files allowed to change | All new files under `crates/secure_data/`, plus `crates/secure_data/Cargo.toml` |
| Files to read before changing anything | `crates/security_core/src/types.rs`, `crates/security_core/src/classification.rs`, architecture data-protection notes |
| New files allowed | All source and test files under `crates/secure_data/` |
| New dependencies allowed | `secrecy` (v0.10), `zeroize` (v1), `aes-gcm` (v0.10), `rand` (v0.8), `base64` (v0.22), `tokio` (v1, `sync` feature), `aws-lc-rs` (v1, feature-gated behind `fips`) |
| Migration allowed | `no` |
| Compatibility commitments | All M1-M6 public types unchanged |
| Forbidden shortcuts | Raw `String` for secrets, `Debug`/`Display` on secret types, serializing secrets via default Serde, homebrew AEAD construction, unbounded key version list, skipping zeroization, using `async-trait` crate, missing `#[must_use]` on `EnvelopeEncrypted` |

#### Out of Scope / Must Not Do

- Do not implement actual Vault or KMS client integration — provide the `KeyProvider` trait and a `StaticDevKeyProvider` for tests. Real backend adapters are feature-gated stubs.
- Do not implement field-level ORM encryption helpers — defer.
- Do not implement TLS profile helpers — defer.
- Do not implement JWT/PASETO token signing — defer to a `token_signing` module stub.
- Do not write custom AEAD constructions — use `aes-gcm` directly.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m6.md`.
3. Run `cargo test --workspace` green baseline.
4. Read listed files.
5. Copy Evidence Log.
6. Re-state constraints.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_data/Cargo.toml` | UPDATE: add dependencies, add `fips` feature flag for `aws-lc-rs` |
| `crates/secure_data/src/lib.rs` | UPDATE: module declarations |
| `crates/secure_data/src/secret.rs` | NEW: `SecretString`, `SecretBytes`, `ApiToken`, `DbPassword`, `SigningKeyRef` wrappers using `secrecy::SecretBox`; no `Debug`/`Display`/default `Serialize` |
| `crates/secure_data/src/kms.rs` | NEW: `KeyProvider` trait (sealed, native `async fn`) — `resolve_key()`, `generate_data_key()`, `unwrap_data_key()`; `StaticDevKeyProvider` for tests |
| `crates/secure_data/src/envelope.rs` | NEW: `encrypt_for_storage()`, `decrypt_for_use()`, `EnvelopeEncrypted` struct (version, algorithm, key_alias, key_version, wrapped_data_key, nonce, ciphertext, aad). Annotate `#[must_use]` on `EnvelopeEncrypted`. Use `rand::rngs::OsRng` for nonce generation (cross-platform). |
| `crates/secure_data/src/keyring.rs` | NEW: `KeyRing` — logical key registry with aliases, versions, activation windows; `KeyVersion` status enum (Active, DecryptOnly, Deactivated). Annotate `#[non_exhaustive]` on status enum. |
| `crates/secure_data/src/rotation.rs` | NEW: `RotationPlan`, `re_encrypt()` — re-encrypts data from old key version to new; dual-read support during rotation window |
| `crates/secure_data/src/config.rs` | NEW: `SecretReference` parsing — `vault://kv/path#field`, `kms://alias/name`, `env://VAR`; `resolve_secret()` |
| `crates/secure_data/src/serde.rs` | NEW: `#[serde(skip)]` and custom serializer that always redacts; `Serialize` impl for secret-bearing structs that emits `[REDACTED]` |
| `crates/secure_data/src/memory.rs` | NEW: `ReadOnce<T>` wrapper — value accessible once then zeroed; `Zeroizing<T>` re-export. `ReadOnce` must be `!Clone`, `!Copy`, not `Sync` (enforced via `PhantomData<*mut ()>` or similar). |
| `crates/secure_data/tests/sunlit_data_secrets.rs` | NEW: BDD tests for secret wrappers |
| `crates/secure_data/tests/sunlit_data_envelope.rs` | NEW: BDD tests for envelope encryption |
| `crates/secure_data/tests/sunlit_data_rotation.rs` | NEW: BDD tests for key rotation |
| `crates/secure_data/tests/sunlit_data_leakage.rs` | NEW: BDD tests proving secrets don't leak |
| `crates/secure_data/tests/e2e_sunlit_m7.rs` | NEW: E2E runtime validation |
| `.gitignore` | Update if needed |

#### BDD Acceptance Scenarios

**Feature: Secret wrappers**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| SecretString no Debug leak | security invariant | A `SecretString` containing `"my-db-password"` | `format!("{:?}", secret)` | Output does not contain `"my-db-password"` |
| SecretString no Display | security invariant | A `SecretString` | Attempt `format!("{}", secret)` | Compilation error (no Display impl) |
| SecretBytes zeroized on drop | security invariant | A `SecretBytes` held in a scope | Scope exits | Memory is zeroed (verified via `zeroize` guarantees; test checks the wrapper uses `Zeroizing`) |
| SecretString not serializable by default | security invariant | A `SecretString` | Passed to `serde_json::to_string()` | Either compilation failure or output is `"[REDACTED]"`, never the plaintext |

**Feature: Envelope encryption**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Encrypt and decrypt roundtrip | happy path | Plaintext `b"Hello, world!"` with `StaticDevKeyProvider` | `encrypt_for_storage()` then `decrypt_for_use()` | Decrypted plaintext equals original |
| Envelope format contains metadata | happy path | After encryption | Inspect `EnvelopeEncrypted` | Has `version`, `algorithm`, `key_alias`, `key_version`, `wrapped_data_key`, `nonce`, `ciphertext`, `aad` |
| Different plaintexts produce different ciphertext | happy path | Two encryptions of same plaintext | Compared | Ciphertexts differ (unique nonces) |
| Tampered ciphertext fails decryption | security invariant | `EnvelopeEncrypted` with flipped byte in ciphertext | `decrypt_for_use()` | Error returned, no plaintext |
| Tampered AAD fails decryption | security invariant | `EnvelopeEncrypted` with modified AAD | Decrypted | Error — authentication failure |

**Feature: Key rotation**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Rotate adds new version | happy path | KeyRing with key alias "app-key" at version 1 | `rotate()` called | Version 2 is `Active`, version 1 is `DecryptOnly` |
| Decrypt with old version during rotation | happy path | Data encrypted under version 1, key rotated to version 2 | `decrypt_for_use()` called | Decryption succeeds using version 1 key |
| Re-encrypt to new version | happy path | Data encrypted under version 1 | `re_encrypt()` called targeting version 2 | New envelope uses version 2, old envelope obsolete |
| Deactivated key cannot decrypt | security invariant | Version 1 deactivated (not just DecryptOnly) | `decrypt_for_use()` for version 1 data | Error — key deactivated |
| At least one active or decrypt-only version | safety invariant | Attempt to deactivate the only remaining key version | Operation | Error — cannot deactivate last version |

**Feature: Secret references in config**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Vault reference parsed | happy path | String `"vault://kv/db-credentials#password"` | Parsed as `SecretReference` | `provider: Vault`, `path: "kv/db-credentials"`, `field: "password"` |
| KMS reference parsed | happy path | String `"kms://alias/app-prod-key"` | Parsed | `provider: Kms`, `alias: "app-prod-key"` |
| Invalid reference rejected | invalid input | String `"plaintext-password"` | Parsed | Error — not a valid secret reference scheme |

**Feature: No leakage**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Secret absent from JSON output | security invariant | A struct with `SecretString` field serialized | JSON output inspected | Field is `"[REDACTED]"` or absent, never plaintext |
| Secret absent from panic payload | security invariant | A function holding `SecretString` panics | Panic message captured | Does not contain the secret value |
| Secret absent from tracing output | security invariant | A `SecretString` passed to `tracing::info!()` attempt | Logged output | Does not contain secret (compilation prevented or redacted) |

#### Regression Tests

- All M1-M6 tests pass.

#### Compatibility Checklist

- [ ] All M1-M6 public types unchanged
- [ ] `secure_boundary` extractors unchanged
- [ ] `secure_authz` Authorizer trait unchanged
- [ ] All M1-M6 tests pass

#### E2E Runtime Validation

**File**: `crates/secure_data/tests/e2e_sunlit_m7.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_encrypt_decrypt_roundtrip` | Envelope encryption works end-to-end at runtime | Plaintext recovered matches original |
| `test_key_rotation_dual_read` | Rotation and dual-read work at runtime | Old data decryptable after rotation |
| `test_secret_no_debug_leak` | Secret wrappers don't leak via Debug at runtime | `format!("{:?}")` output scanned, no secrets found |
| `test_secret_no_serde_leak` | Secrets don't leak via serde at runtime | JSON output scanned, no secrets found |
| `test_tampered_data_rejected` | Tampered ciphertext rejected at runtime | Error returned, no corrupted plaintext |
| `test_secret_reference_resolution` | SecretReference parsing works at runtime | Correct provider and path extracted |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: `SecretString` debug output does not contain plaintext
- [ ] `git status` clean
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M6 green | | | |
| BDD tests created | `tests/sunlit_data_*.rs` | fail expected | | | |
| E2E stubs | `tests/e2e_sunlit_m7.rs` | fail expected | | | |
| Implementation | `secure_data` modules | contract satisfied | | | |
| Full tests | `cargo test --workspace` | green | | | |
| E2E runtime | `cargo test --workspace --test 'e2e_*'` | green | | | |
| Build/doc | builds cleanly | | | | |
| Smoke/compat | all checked | | | | |
| Cleanup | `git status` clean | | | | |

#### Definition of Done

- all BDD scenarios pass, all E2E pass
- full M1-M6 test suite green
- `SecretString` / `SecretBytes` never leak via Debug, Display, Serde, or panic
- envelope encryption round-trips correctly
- key rotation with dual-read proven
- tampered ciphertext rejected
- secret references parseable
- `StaticDevKeyProvider` works for all test scenarios
- `KeyProvider` trait ready for real backend adapters
- smoke/compat complete, `git status` clean
- ARCHITECTURE.md updated, lessons at `docs/slo/lessons/sunlit-m7.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add data protection section — secret types, envelope encryption, key lifecycle, rotation protocol
- **README.md**: Add `secure_data` description, encryption usage example

#### Notes

- Real Vault/KMS client adapters are feature-gated stubs — document in lessons.
- Field-level ORM helpers deferred.
- TLS profile helpers deferred.
- JWT/PASETO signing deferred.
- KAT (Known Answer Test) tests for encryption format stability are required — use fixed key + nonce + plaintext → expected ciphertext.

---

### Milestone 8 — `secure_reference_service` — Reference Axum Integration + Resilience

**Goal**: Build a single-binary axum web service (`secure_reference_service`) that composes all eight library crates into a working application, proving that the abstractions compose correctly, demonstrating canonical middleware ordering, providing example routes with full security coverage, applying resilience patterns (circuit breaker, timeouts, bulkhead), validating security configuration at startup, and serving as a living integration test and documentation artifact. The service demonstrates how `secure_identity` (or any `IdentitySource` implementor) feeds into `secure_authz` via `SubjectResolver`.

**Context**: This milestone is the integration proof. Each library crate was tested in isolation — this binary proves they compose. The middleware stack must follow a strict ordering: panic recovery → request ID → tracing span → security headers → body limits → content-type enforcement → security event layer → rate limiting → identity resolution (via `IdentitySource`) → error mapping → authorization (via `SubjectResolver` + `Authorizer`) → output encoding → route handler with `SecureJson<T>` extraction. The binary is not production-grade infrastructure — it is a reference implementation that shows the right patterns. Resilience patterns prevent cascading failures in critical infrastructure deployments.

**Important design rule**: The reference service must not introduce new security logic — it only composes what the library crates provide. If integration reveals a gap, the fix goes into the library crate, not the binary. `SecurityConfig::validate()` must run at startup and fail fast if any security invariant is violated (missing policies, invalid key references, misconfigured headers).

**Refactor budget**: `Library crates may receive bug-fix-only patches; no API changes`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | HTTP requests via axum router |
| Outputs | JSON responses demonstrating all security layers active |
| Interfaces touched | All eight library crates' public APIs composed in `secure_reference_service` |
| Files allowed to change | All files under `crates/secure_reference_service/`, plus small bug-fix patches in library crates if integration reveals a genuine bug (logged in evidence) |
| Files to read before changing anything | `crates/*/src/lib.rs`, reference-service docs, all milestone lessons |
| New files allowed | All source and test files under `crates/secure_reference_service/` |
| New dependencies allowed | `axum` (v0.8), `tower` (v0.5), `tower-http` (v0.6), `tokio` (v1, full), `hyper` (v1), `serde_json` (v1) |
| Migration allowed | `no` |
| Compatibility commitments | All library crate public APIs unchanged (bug-fix patches only) |
| Forbidden shortcuts | Implementing security logic in the binary, bypassing middleware, hard-coding responses, skipping correlation context, `unwrap()` in production code paths |

#### Out of Scope / Must Not Do

- Do not implement a real database layer — use in-memory state or mocks.
- Do not implement real authentication (OAuth/JWT/OIDC) — use a `DevAuthLayer` that extracts a fixed test subject from headers.
- Do not implement real KMS/Vault calls — use `StaticDevKeyProvider`.
- Do not implement health checks, metrics endpoints, or observability infrastructure beyond tracing.
- Do not write Dockerfile or deployment manifests.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m7.md`.
3. Run `cargo test --workspace` green baseline.
4. Read all library crate `lib.rs` files.
5. Copy Evidence Log.
6. Re-state constraints.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_reference_service/Cargo.toml` | UPDATE: add all library crate dependencies + axum + tower + tokio |
| `crates/secure_reference_service/src/main.rs` | NEW/UPDATE: application entry point with middleware stack |
| `crates/secure_reference_service/src/middleware.rs` | NEW: middleware composition — `SecurityStack` builder |
| `crates/secure_reference_service/src/routes/mod.rs` | NEW: route declarations |
| `crates/secure_reference_service/src/routes/items.rs` | NEW: example CRUD routes for items — demonstrates `SecureJson`, validation, authz |
| `crates/secure_reference_service/src/routes/health.rs` | NEW: basic health route (no security middleware) |
| `crates/secure_reference_service/src/dto.rs` | NEW: example DTOs with `SecureValidate`, `deny_unknown_fields` |
| `crates/secure_reference_service/src/state.rs` | NEW: shared app state — in-memory store, authorizer, key ring |
| `crates/secure_reference_service/src/auth_dev.rs` | NEW: Integration with `secure_identity::DevAuthenticator` (feature-gated) — resolves `AuthenticatedIdentity` from `IdentitySource`, converts to `Subject` via `SubjectResolver` |
| `crates/secure_reference_service/src/config.rs` | NEW: `SecurityConfig` — startup configuration validation. Validates: policies loaded, key provider reachable, required security headers configured, identity source configured. Fails fast on misconfiguration. |
| `crates/secure_reference_service/src/resilience.rs` | NEW: resilience patterns — request timeouts (tower-http `Timeout`), circuit breaker for downstream calls, bulkhead (bounded concurrency via `tower::limit::ConcurrencyLimit`) |
| `crates/secure_reference_service/src/error.rs` | NEW: application-level error mapping composing `secure_errors` |
| `crates/secure_reference_service/tests/e2e_sunlit_m8.rs` | NEW: integration tests using `axum::test` or `hyper::test` |
| `.gitignore` | Update if needed |

#### Step-by-Step

1. Define example DTOs: `CreateItemRequest`, `UpdateItemRequest`, `ItemResponse`.
2. Implement `DevAuthLayer` for test authentication.
3. Build `SecurityStack` middleware composition in the correct order. Use `tower::ServiceBuilder` for idiomatic layer composition — do not manually nest `.layer().layer().layer()` calls. Every layer must satisfy `Clone + Send + Sync + 'static`.
4. Implement example CRUD routes using `SecureJson`, `SecurePath`, `secure_authz` guards.
5. Wire up `state.rs` with in-memory store, `DefaultAuthorizer`, `StaticDevKeyProvider`, `SecurityLayer`.
6. Build `main.rs` with `#[tokio::main]`, router, middleware, and graceful shutdown. Bind to `127.0.0.1:3000` (loopback only — cross-platform safe). Use `tokio::signal::ctrl_c()` for graceful shutdown on all platforms (do not use `SIGTERM` handler directly — it is Unix-only; `ctrl_c()` works on Linux, macOS, and Windows).
7. Write integration tests proving middleware ordering and all layers active.
8. Run full workspace tests.

#### Middleware Stack Order (Mandatory)

```
Request →
  1. PanicSafeLayer           (secure_errors)     — catch panics, emit 500
  2. RequestIdLayer           (tower-http)         — assign X-Request-Id
  3. SecurityTracingLayer     (security_events)    — open tracing span with request_id + actor_id
  4. SecurityHeadersLayer     (secure_boundary)    — apply HSTS, CSP, X-Content-Type-Options, etc.
  5. TimeoutLayer             (tower-http)         — request-level timeout (resilience)
  6. ConcurrencyLimitLayer    (tower)              — bulkhead pattern (resilience)
  7. DefaultBodyLimit         (tower-http / secure_boundary) — enforce global body limit
  8. ContentTypeEnforcement   (secure_boundary)    — reject wrong content types
  9. SecurityEventLayer       (security_events)    — subscribe to security events within span
  10. ErrorMappingLayer       (secure_errors)      — map internal errors to public responses
  11. IdentityResolutionLayer (secure_identity/custom) — resolve AuthenticatedIdentity from IdentitySource
  12. SubjectResolutionLayer  (secure_authz)       — convert AuthenticatedIdentity to Subject via SubjectResolver
  13. AuthzLayer              (secure_authz)       — check authorization
  14. Route handler           — SecureJson<T> extraction → business logic → OutputEncoder encoding
← Response
```

#### BDD Acceptance Scenarios

**Feature: Middleware composition**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All layers active | integration | Server started with full stack | `GET /items` with valid subject | 200 response with correlation ID header |
| Panic caught | integration | Route handler panics | `/panic-test` route called | 500 returned, no crash, security event emitted |
| Unknown content type rejected | integration | `POST /items` with `text/xml` | Request processed | 400 returned before route handler runs |
| Body too large rejected | integration | `POST /items` with 5MB body (limit 2MB) | Request processed | 400 before deserialization |
| Unauthorized rejected | integration | `POST /items` without subject | Request processed | 403 returned by AuthzLayer |
| Unknown JSON field rejected | integration | `POST /items` with `{"name":"x","admin":true}` | Request processed | 400, no echo of payload |

**Feature: End-to-end CRUD**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Create item | happy path | Valid `CreateItemRequest` with authorized subject | `POST /items` | 201 with `ItemResponse` |
| Get item | happy path | Item exists | `GET /items/{id}` with authorized subject | 200 with `ItemResponse` |
| Get item unauthorized | security invariant | Item exists, subject not authorized | `GET /items/{id}` | 403 |
| Create item with invalid data | validation | `CreateItemRequest` with empty name | `POST /items` | 400 with structured error |

**Feature: Security event flow**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Boundary violation logged | integration | Unknown field sent | Events captured | `BoundaryViolation` event in output |
| Authz denial logged | integration | Unauthorized request | Events captured | `AuthzDeny` event with subject and resource |
| All events have correlation | integration | Any request | Events captured | Every event has `request_id`, `actor_id`, `tenant_id` |

**Feature: Resilience patterns**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Request timeout enforced | resilience | Route handler sleeps 10s, timeout set to 5s | Request sent | 408 or 504 returned before 10s |
| Concurrency limit enforced | resilience | Concurrency limit set to 10, 15 concurrent requests | All sent | 5 requests receive 503 Service Unavailable |
| Startup config validation | resilience | Missing authorization policy file | Server started | Fails fast with clear error message, does not bind port |
| Invalid key provider | resilience | Non-existent key alias in config | Server started | Fails fast with key provider error |

**Feature: Identity integration**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Identity resolved from token | integration | Valid JWT in Authorization header | IdentitySource resolves | AuthenticatedIdentity available in request extensions |
| Subject resolved from identity | integration | AuthenticatedIdentity in extensions | SubjectResolver runs | Subject with correct roles available for AuthzLayer |
| Invalid token rejected | integration | Malformed JWT in Authorization header | IdentitySource rejects | 401 returned, AuthnFailure event emitted |
| Custom IdentitySource works | integration | Test with MockIdentitySource (simulating Keycloak) | Request processed | Same authz flow works without secure_identity |

**Feature: Security headers in responses**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All responses have security headers | integration | Any response from the service | Headers inspected | HSTS, CSP, X-Content-Type-Options, X-Frame-Options present |
| Error responses have security headers | integration | 400/403/500 error response | Headers inspected | Security headers still present |

#### Regression Tests

- All M1-M7 library crate tests must pass.

#### Compatibility Checklist

- [ ] All library crate public APIs unchanged
- [ ] All M1-M7 tests pass
- [ ] No new security logic in the binary

#### E2E Runtime Validation

**File**: `crates/secure_reference_service/tests/e2e_sunlit_m8.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `test_full_crud_lifecycle` | Create, read, update, delete with all security layers | All operations succeed for authorized user, all produce correlation IDs |
| `test_middleware_ordering` | Middleware runs in correct order (panic → tracing → headers → limits → auth → handler) | Panic caught before auth, limits before extraction, security headers on all responses |
| `test_cross_tenant_blocked` | Tenant A cannot access Tenant B items | 403 returned, security event emitted |
| `test_unknown_field_blocked` | Extra JSON fields rejected at boundary | 400 returned, no payload echo |
| `test_security_events_emitted` | All security-relevant actions produce events | Events captured with correct kinds and severity |
| `test_error_no_internal_leak` | Internal errors produce generic public errors | No stack trace, no internal message in response |

#### Smoke Tests

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo doc --workspace --no-deps` builds
- [ ] Manually verify: send HTTP requests using either `curl` (Linux/macOS) or `Invoke-WebRequest`/`curl.exe` (Windows): `POST localhost:3000/items` with `Content-Type: application/json` body `{"name":"test"}` with and without `X-Dev-Subject` header. Alternatively, use the integration test suite which exercises these paths programmatically and portably.
- [ ] `git status` clean
- [ ] `.gitignore` up to date

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M7 green | | | |
| Middleware impl | `secure_reference_service` | compiles | | | |
| Integration tests | `tests/e2e_sunlit_m8.rs` | green | | | |
| Full tests | `cargo test --workspace` | green | | | |
| CRUD smoke | curl commands | expected status codes | | | |
| Build/doc | builds cleanly | | | | |
| Cleanup | `git status` clean | | | | |

#### Definition of Done

- reference service compiles and runs
- all eight library crates integrated with correct middleware ordering
- integration tests prove all layers are active
- CRUD routes demonstrate full security coverage
- identity resolution from IdentitySource demonstrated
- Subject resolution via SubjectResolver demonstrated
- resilience patterns active (timeout, concurrency limit)
- startup config validation fails fast on misconfiguration
- security headers present on all responses including errors
- no security logic in the binary — only composition
- all M1-M7 test suites green
- smoke/compat complete
- ARCHITECTURE.md updated with middleware ordering diagram
- lessons at `docs/slo/lessons/sunlit-m8.md`
- Milestone Tracker updated

#### Post-Flight

- **ARCHITECTURE.md**: Add middleware ordering diagram, reference service section
- **README.md**: Add quickstart for running the reference service

#### Notes

- `DevAuthLayer` is for development only — document this prominently.
- If integration reveals a library crate bug, fix it in the library crate, log it in the evidence log, and add a regression test.
- The reference service is the primary artifact for onboarding new developers to the security crate patterns.

---

### Milestone 9 — Adversarial Testing & Fuzzing

**Goal**: Establish a comprehensive adversarial testing gate across all library crates — `cargo-fuzz` targets for all parser/deserializer entry points, `proptest` property tests for all validators and encoders, `cargo miri` for memory safety verification, timing side-channel tests for cryptographic operations, and CVE regression tests — ensuring the security libraries withstand real-world attack patterns.

**Context**: Critical infrastructure deployments require evidence that security controls resist adversarial input, not just well-formed test cases. BDD scenarios (M1–M8) test expected behavior; this milestone tests *unexpected* behavior — what happens when an attacker sends malformed JWTs, pathological Unicode, huge payloads, bit-flipped ciphertext, or timing-based probes. If hash-chain audit trail was deferred from M3, it MUST be completed in this milestone.

**Important design rule**: Every public-facing parser, deserializer, or validator must have at least one fuzz target. Every encoder must have at least one property test proving encode/decode roundtrip safety. `cargo miri` must pass for all `unsafe`-free crates (which should be all of them given `#![forbid(unsafe_code)]`). Timing tests for crypto comparisons must use statistical methods (e.g., Welch's t-test) to detect timing leaks.

**Refactor budget**: `Bug fixes only — no API changes to library crates`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | All library crate public APIs, adversarial input corpuses |
| Outputs | Fuzz targets, property tests, miri results, timing test results, CVE regression tests |
| Interfaces touched | Test infrastructure only — no production code changes unless a bug is found |
| Files allowed to change | Test and fuzz directories in all crates, `Cargo.toml` (dev-dependencies only) |
| Files to read before changing anything | All `crates/*/src/lib.rs`, `THREAT_MODEL.md`, all milestone lessons |
| New files allowed | `crates/*/fuzz/`, `crates/*/tests/prop_*.rs`, `crates/*/tests/timing_*.rs`, `crates/*/tests/cve_*.rs` |
| New dependencies allowed (dev only) | `cargo-fuzz` / `libfuzzer-sys` (fuzz), `proptest` (v1), `arbtest` (optional), `criterion` (v0.5, for timing benchmarks) |
| Migration allowed | `no` |
| Compatibility commitments | All M1-M8 public APIs unchanged |
| Forbidden shortcuts | Skipping fuzz targets for parsers, using `#[ignore]` on timing tests without justification, suppressing miri errors, marking property tests as `#[ignore]` |

#### Out of Scope / Must Not Do

- Do not modify production APIs — only add tests.
- Do not implement automated exploit generation.
- Do not build a fuzzing-as-a-service infrastructure.
- Do not add runtime overhead to production code for testing purposes.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m8.md` and all previous lessons.
3. Run `cargo test --workspace` green baseline.
4. Read `THREAT_MODEL.md` to identify high-risk attack surfaces.
5. Check if hash-chain audit trail was deferred from M3 — if so, implement it now.
6. Copy Evidence Log.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_boundary/fuzz/fuzz_targets/fuzz_json_parse.rs` | NEW: Fuzz target for `SecureJson` deserialization with arbitrary bytes |
| `crates/secure_boundary/fuzz/fuzz_targets/fuzz_query_parse.rs` | NEW: Fuzz target for `SecureQuery` deserialization |
| `crates/secure_boundary/fuzz/fuzz_targets/fuzz_normalize.rs` | NEW: Fuzz target for Unicode normalization |
| `crates/secure_boundary/tests/prop_validation.rs` | NEW: Property tests — validated input always satisfies invariants, invalid input always rejected |
| `crates/secure_output/fuzz/fuzz_targets/fuzz_html_encode.rs` | NEW: Fuzz target for HTML encoding |
| `crates/secure_output/tests/prop_encoding.rs` | NEW: Property tests — encode(decode(x)) roundtrip, no raw `<script>` in HTML-encoded output |
| `crates/secure_identity/fuzz/fuzz_targets/fuzz_jwt_parse.rs` | NEW: Fuzz target for JWT parsing with arbitrary bytes |
| `crates/secure_identity/tests/prop_session.rs` | NEW: Property tests — session IDs always unique, expired sessions always rejected |
| `crates/secure_identity/tests/timing_token_compare.rs` | NEW: Timing test — token comparison is constant-time |
| `crates/secure_data/fuzz/fuzz_targets/fuzz_envelope.rs` | NEW: Fuzz target for envelope decryption with corrupted input |
| `crates/secure_data/tests/prop_encryption.rs` | NEW: Property tests — encrypt/decrypt roundtrip, tampered ciphertext always rejected |
| `crates/secure_data/tests/timing_crypto.rs` | NEW: Timing test — AEAD tag verification is constant-time |
| `crates/security_events/fuzz/fuzz_targets/fuzz_sanitize.rs` | NEW: Fuzz target for log sanitization |
| `crates/security_events/tests/prop_redaction.rs` | NEW: Property tests — Secret fields never appear in redacted output |
| `crates/secure_authz/tests/prop_deny_default.rs` | NEW: Property test — no policy → always deny (universal property) |
| `crates/*/tests/cve_regression.rs` | NEW: Regression tests for known CVE patterns relevant to each crate's domain |
| `security_events/src/audit_chain.rs` | NEW (if deferred from M3): `AuditChain` — SHA-256 hash-linked event chain for tamper-evident audit |

#### Step-by-Step

1. Check if hash-chain audit trail was deferred from M3. If yes, implement `AuditChain` in `security_events` now.
2. Create fuzz targets for all parser entry points (SecureJson, SecureQuery, JWT, envelope decrypt, HTML encode, log sanitize).
3. Run each fuzz target for at least 60 seconds (configurable). Document any findings.
4. Create property tests for validators, encoders, and crypto operations.
5. Run `cargo miri test --workspace` (or `cargo +nightly miri test --workspace`). Fix any findings.
6. Create timing tests for crypto-sensitive comparisons (token verification, AEAD tag check).
7. Create CVE regression tests — at minimum: log injection (CVE-2019-10081 pattern), JWT algorithm confusion (CVE-2015-9235 pattern), Unicode normalization bypass, CRLF injection in headers.
8. Run full test suite including property tests.
9. Document all findings in evidence log.
10. Complete self-review gate.

#### BDD Acceptance Scenarios

**Feature: Fuzz target coverage**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| JSON parser fuzz | adversarial | Arbitrary bytes fed to `SecureJson` deserializer | 60s of fuzzing | No panics, no undefined behavior, all rejections are clean errors |
| JWT parser fuzz | adversarial | Arbitrary bytes fed to `TokenValidator` | 60s of fuzzing | No panics, all malformed tokens rejected cleanly |
| HTML encoder fuzz | adversarial | Arbitrary strings fed to `HtmlEncoder` | 60s of fuzzing | No panics, output never contains unescaped `<script>` |
| Envelope decrypt fuzz | adversarial | Corrupted ciphertext + random keys | 60s of fuzzing | No panics, all tampered data rejected |
| Log sanitizer fuzz | adversarial | Arbitrary strings with control characters | 60s of fuzzing | No panics, no log injection |

**Feature: Property tests**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Validation idempotency | property | Any valid input | Validated twice | Same result both times |
| HTML encode safety | property | Any string | HTML-encoded | Output does not contain raw `<`, `>`, `&`, `"`, `'` in unescaped positions |
| Encrypt/decrypt roundtrip | property | Any plaintext | Encrypted then decrypted | Original plaintext recovered |
| Tampered ciphertext rejected | property | Any valid ciphertext with 1 bit flipped | Decrypted | Error returned, no corrupted plaintext |
| No policy → always deny | property | Any (subject, action, resource) with empty policy set | Authorized | Always `Decision::Deny` |
| Secret never in redacted output | property | Any `SecurityEvent` with `Secret`-classified labels | Redacted | No label value contains original secret |

**Feature: Memory safety**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Miri clean | memory safety | Full workspace test suite | `cargo miri test --workspace` | Exit 0 — no undefined behavior detected |

**Feature: Timing side-channels**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Token comparison constant-time | timing | Valid token vs 1000 random tokens of same length | Timing measured | No statistically significant timing difference (Welch's t-test p > 0.05) |
| AEAD tag verification constant-time | timing | Valid ciphertext vs 1000 tampered ciphertexts | Timing measured | No statistically significant timing difference |

**Feature: CVE regression**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Log injection blocked | CVE regression | Input `"user\nINJECTED"` in actor field | Event logged | No new log line created |
| JWT algorithm confusion blocked | CVE regression | JWT with `alg: "none"` | Validated | Rejected — algorithm "none" not allowed |
| Unicode normalization bypass blocked | CVE regression | Username with mixed Unicode forms | Normalized then compared | Equal after normalization |
| CRLF header injection blocked | CVE regression | Header value with `\r\n` | Processed by SecurityHeadersLayer | Rejected or sanitized |

#### Regression Tests

- All M1-M8 tests must still pass.
- No production API changes.

#### Compatibility Checklist

- [ ] All M1-M8 public APIs unchanged
- [ ] All M1-M8 tests pass
- [ ] No new production dependencies (only dev-dependencies)

#### E2E Runtime Validation

- Fuzz targets run for configured duration without crashes.
- Property tests pass for all configured iterations (default: 256 cases per test).
- `cargo miri test --workspace` exits 0.
- Timing tests show no statistically significant leaks.

#### Smoke Tests

- [ ] `cargo test --workspace` passes (including property tests)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] All fuzz targets compile: `cargo fuzz list` (per crate)
- [ ] `cargo miri test --workspace` passes (requires nightly)
- [ ] No production code modified
- [ ] `git status` clean
- [ ] `.gitignore` up to date (includes fuzz corpus/artifact directories)

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M8 green | | | |
| Hash-chain check | M3 lessons file | Deferred or completed | | | |
| Fuzz: JSON parser | `cargo fuzz run fuzz_json_parse -- -max_total_time=60` | no crashes | | | |
| Fuzz: JWT parser | `cargo fuzz run fuzz_jwt_parse -- -max_total_time=60` | no crashes | | | |
| Fuzz: HTML encoder | `cargo fuzz run fuzz_html_encode -- -max_total_time=60` | no crashes | | | |
| Fuzz: envelope | `cargo fuzz run fuzz_envelope -- -max_total_time=60` | no crashes | | | |
| Fuzz: sanitizer | `cargo fuzz run fuzz_sanitize -- -max_total_time=60` | no crashes | | | |
| Property tests | `cargo test --workspace -- prop_` | all pass | | | |
| Miri | `cargo +nightly miri test --workspace` | exit 0 | | | |
| Timing tests | `cargo test -- timing_` | no leaks detected | | | |
| CVE regression | `cargo test -- cve_` | all pass | | | |
| Full tests | `cargo test --workspace` | green | | | |

#### Definition of Done

- all fuzz targets run without crashes for configured duration
- all property tests pass
- `cargo miri test` exits 0
- timing tests show no statistically significant leaks
- CVE regression tests pass
- hash-chain audit trail implemented (if deferred from M3)
- no production API changes
- all M1-M8 tests green
- evidence log complete with fuzz/miri/timing results
- ARCHITECTURE.md updated with adversarial testing section
- lessons at `docs/slo/lessons/sunlit-m9.md`
- Milestone Tracker updated

#### Self-Review Gate

```
## Self-Review Gate — Milestone 9

- [ ] All fuzz targets compile and run
- [ ] No crashes in 60s fuzz runs
- [ ] All property tests pass (≥256 cases each)
- [ ] cargo miri clean
- [ ] Timing tests show no leaks
- [ ] CVE regression tests pass
- [ ] Hash-chain audit trail complete (or was completed in M3)
- [ ] No production API changes
- [ ] All M1-M8 tests still pass
- [ ] Evidence log filled with actual results

## Known non-blocking limitations
- Fuzz duration is configurable — 60s is a minimum; CI may use shorter runs
- Timing tests are statistical — may need re-running on noisy CI environments
- cargo miri requires nightly — CI should use nightly toolchain for this step only
```

#### Post-Flight

- **ARCHITECTURE.md**: Add adversarial testing section — fuzz targets, property tests, miri, timing tests
- **README.md**: Add section on running adversarial tests

#### Notes

- Fuzz corpuses should be committed to `crates/*/fuzz/corpus/` for regression.
- Property test failures are bugs — fix the library crate and add regression test.
- Timing tests may be flaky on shared CI runners — use dedicated runners or mark as `#[ignore]` with justification for CI, but require local verification.
- `cargo miri` may not support all dependencies — document any unsupported crates.

---

### Milestone 10 — Supply-Chain Hardening & CI Pipeline

**Goal**: Configure supply-chain security scanning and enforcement across the workspace — `cargo-audit` for known vulnerabilities, `cargo-deny` for license/advisory/source policy, `cargo-vet` for third-party audit trails, `cargo-audit-build` for build-time dependency audit — and create a CI pipeline definition (GitHub Actions) that runs all checks on every PR, ensuring the security libraries are themselves verified.

**Context**: The user explicitly requested: "libraries which themselves have been scanned and tested." This milestone fulfills that requirement. Every dependency of every crate must be auditable, license-compliant, and free of known advisories. The workspace must fail CI if any check fails. This is the capstone milestone that provides supply-chain confidence.

**Important design rule**: All supply-chain tools must run in CI and be runnable locally with the same commands. `deny.toml` must be restrictive by default — deny all unlicensed, deny copy-left in library context, deny unmaintained advisories. `cargo-vet` must have at least a self-audit for all first-party crates and imports for well-known auditors.

**Refactor budget**: `No refactor permitted`

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `Cargo.toml` workspace, `Cargo.lock`, third-party dependency tree |
| Outputs | `deny.toml`, `supply-chain/` directory (cargo-vet), `.github/workflows/ci.yml`, audit scripts |
| Files allowed to change | Root-level config files, `.github/` directory |
| Files to read before changing anything | All `Cargo.toml` files, `Cargo.lock`, supply-chain docs |
| New files allowed | `deny.toml`, `supply-chain/**`, `.github/workflows/ci.yml`, `scripts/audit.sh` |
| New dependencies allowed | None (tools installed via `cargo install` or GitHub Actions) |
| Migration allowed | `no` |
| Compatibility commitments | No source code changes to any crate |
| Forbidden shortcuts | `[allow]`-listing advisories without justification, setting `cargo-deny` to warn instead of deny, skipping `cargo-vet` initialization, allow-all license policy |

#### Out of Scope / Must Not Do

- Do not implement SBOM generation — defer to future work.
- Do not implement container image scanning — defer.
- Do not implement code signing or binary attestation — defer.
- Do not modify any library crate source code.

#### Pre-Flight

1. Complete Global Entry Rules.
2. Read `docs/slo/lessons/sunlit-m9.md`.
3. Run `cargo test --workspace` green baseline.
4. Read `Cargo.lock` to understand the full dependency tree.
5. Copy Evidence Log.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `deny.toml` | NEW: cargo-deny configuration — advisories (deny), licenses (allowlist), bans (deny duplicates of security-relevant crates), sources (deny unknown registries) |
| `supply-chain/config.toml` | NEW: cargo-vet configuration |
| `supply-chain/imports.lock` | NEW: imported audits from well-known auditors (Mozilla, Google, etc.) |
| `supply-chain/audits.toml` | NEW: self-audits for first-party crates, any required manual audits |
| `.github/workflows/ci.yml` | NEW: CI workflow — test, clippy, doc, cargo-audit, cargo-deny, cargo-vet, cargo-audit-build |
| `scripts/audit.sh` | NEW: local audit runner (Linux/macOS) — runs all supply-chain checks with same commands as CI |
| `scripts/audit.ps1` | NEW: local audit runner (Windows/PowerShell) — identical checks as `audit.sh` for Windows developers |
| `.gitignore` | Update if needed |
| `Cargo.lock` | Committed to version control (if not already) — required for reproducible audit |
| `README.md` | UPDATE: add supply-chain security section |

#### Step-by-Step

1. Ensure `Cargo.lock` is committed.
2. Run `cargo install cargo-audit cargo-deny cargo-vet` (document versions).
3. Initialize `cargo-vet`: `cargo vet init`.
4. Create self-audits for all first-party crates.
5. Import audits from well-known auditors.
6. Run `cargo vet` and resolve any unvetted dependencies.
7. Create `deny.toml` with strict policy.
8. Run `cargo deny check` and resolve all findings.
9. Run `cargo audit` and resolve any advisories.
10. Create `scripts/audit.sh` (Linux/macOS, bash) and `scripts/audit.ps1` (Windows, PowerShell) with all checks. Both scripts must run identical cargo commands.
11. Create `.github/workflows/ci.yml`.
12. Run full CI pipeline locally to verify.

#### `deny.toml` Structure

```toml
[advisories]
vulnerability = "deny"
unmaintained = "deny"
yanked = "deny"
notice = "warn"
ignore = []  # Each entry must have a justification comment

[licenses]
unlicensed = "deny"
copyleft = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "Zlib",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"      # Deny for security-critical crates
wildcards = "deny"
highlight = "all"
# Ban known-problematic crates
deny = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

#### CI Pipeline Structure (`.github/workflows/ci.yml`)

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test
        run: cargo test --workspace
      - name: Doc
        run: cargo doc --workspace --no-deps

  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Install audit tools
        run: cargo install cargo-audit cargo-deny cargo-vet
      - name: Cargo audit
        run: cargo audit
      - name: Cargo deny
        run: cargo deny check
      - name: Cargo vet
        run: cargo vet
```

#### BDD Acceptance Scenarios

**Feature: Dependency auditing**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| No known vulnerabilities | security invariant | Current `Cargo.lock` | `cargo audit` | Exit 0 — no known advisories |
| Advisory added triggers failure | security invariant | A hypothetical advisory for a dependency | `cargo audit` | Exit non-zero — CI fails |

**Feature: License compliance**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All licenses allowed | happy path | Current dependency tree | `cargo deny check licenses` | Exit 0 — all licenses in allowlist |
| Copyleft dependency blocked | security invariant | A hypothetical GPL dependency added | `cargo deny check licenses` | Exit non-zero — copyleft denied |

**Feature: Source verification**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All sources from crates.io | happy path | Current dependency tree | `cargo deny check sources` | Exit 0 |
| Unknown registry blocked | security invariant | Dependency from unknown registry | `cargo deny check` | Exit non-zero |

**Feature: Cargo vet**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| All dependencies vetted | happy path | Current tree with audits | `cargo vet` | Exit 0 |
| Unvetted dependency blocked | security invariant | New dependency without audit | `cargo vet` | Exit non-zero — requires audit or import |

**Feature: Local audit script**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Local matches CI | parity | Developer runs `scripts/audit.sh` (Linux/macOS) or `scripts/audit.ps1` (Windows) | Script completes | Same checks as CI, same results |

#### Regression Tests

- All M1-M9 tests must pass.
- No source code changes to any crate.

#### Compatibility Checklist

- [ ] No crate source code changed
- [ ] All M1-M9 tests pass
- [ ] `Cargo.lock` committed and consistent
- [ ] `deny.toml` in sync with actual dependencies
- [ ] `cargo vet` in sync with actual dependencies

#### Evidence Log

| Step | Command / Check | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test --workspace` | M1-M9 green | | | |
| cargo-audit | `cargo audit` | exit 0 | | | |
| cargo-deny | `cargo deny check` | exit 0 | | | |
| cargo-vet init | `cargo vet init` | initialized | | | |
| cargo-vet | `cargo vet` | exit 0 | | | |
| CI workflow | syntax valid | | | | |
| Local audit | `bash scripts/audit.sh` (Linux/macOS) or `pwsh scripts/audit.ps1` (Windows) | exit 0 | | | |
| Full tests | `cargo test --workspace` | green | | | |
| No source changes | `git diff --stat crates/` | no changes | | | |

#### Definition of Done

- `cargo audit` exits 0
- `cargo deny check` exits 0 on advisories, licenses, bans, and sources
- `cargo vet` exits 0 with all dependencies vetted or imported
- `deny.toml` has strict policy (deny copyleft, deny unknown registry, deny vulnerabilities)
- `supply-chain/` directory committed with audits
- `.github/workflows/ci.yml` runs all checks
- `scripts/audit.sh` and `scripts/audit.ps1` run all checks locally
- `Cargo.lock` committed
- all M1-M9 tests green, no source code changes
- README.md updated with supply-chain section
- ARCHITECTURE.md updated with dependency policy
- lessons at `docs/slo/lessons/sunlit-m10.md`
- Milestone Tracker updated
- Completion summary filled

#### Post-Flight

- **ARCHITECTURE.md**: Add supply-chain security section — tools, policy, CI enforcement
- **README.md**: Add badge for CI, supply-chain security section with commands

#### Notes

- `cargo-audit-build` for build-time auditing is a stretch goal — include if the tool is mature enough for the dependency set.
- SBOM generation deferred — document in lessons.
- Consider pinning cargo-audit/cargo-deny/cargo-vet versions in CI for reproducibility.
- CI runs tests on all three target platforms (Linux, macOS, Windows) via matrix strategy. Supply-chain checks run on Linux only (tools output is platform-independent).
- If any dependency has an unresolvable advisory, add to `deny.toml` ignore list with justification comment.

---

## Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | Other |
|---|---|---|---|
| M0 — Threat Model | Threat model reference, STRIDE summary | Security requirements overview | `THREAT_MODEL.md`, `docs/attack-trees/` |
| M1 — Workspace + `security_core` | Crate dependency graph, shared types, DataClassification, IdentitySource trait | Workspace overview, crate descriptions, build commands | `.gitignore`, `Cargo.toml` workspace |
| M2 — `secure_errors` | Three-layer error model, error flow diagram, PanicSafeLayer | Error handling usage examples | — |
| M3 — `security_events` | Security event schema, redaction engine, event flow, tamper-evident audit | Event emission examples | — |
| M4 — `secure_boundary` + `secure_output` | Input validation pipeline, DTO pattern, extractor reference, output encoding, security headers | Extractor migration guide (Json → SecureJson), output encoding examples | — |
| M5 — `secure_identity` | IdentitySource trait, secure_identity as one implementation, bring-your-own identity | Identity provider usage, IdentitySource implementation guide | `docs/identity-integration.md` |
| M6 — `secure_authz` | Authorizer trait, policy engine, decision flow, cache, SubjectResolver, identity-agnostic design | Authorization middleware usage, identity integration examples | Policy file examples |
| M7 — `secure_data` | Secret types, envelope encryption, key lifecycle, rotation, FIPS readiness | Encryption usage examples, FIPS feature flag | — |
| M8 — Reference Service | Middleware ordering diagram, integration architecture, resilience patterns | Quickstart, curl examples, SecurityConfig validation | — |
| M9 — Adversarial Testing | Adversarial testing section, fuzz targets, property tests, miri, timing | Running adversarial tests | — |
| M10 — Supply-Chain + CI | Dependency policy, scan tools | CI badge, supply-chain commands, audit instructions | `deny.toml`, `supply-chain/`, `.github/workflows/ci.yml`, `scripts/audit.sh`, `scripts/audit.ps1` |

---

## Final Completion Summary

> Fill this section after all milestones are complete.

| Item | Status |
|---|---|
| All milestones complete | ☐ |
| All tests green (`cargo test --workspace`) | ☐ |
| All clippy clean (`cargo clippy --workspace --all-targets -- -D warnings`) | ☐ |
| All docs build (`cargo doc --workspace --no-deps`) | ☐ |
| Supply-chain clean (`cargo audit && cargo deny check && cargo vet`) | ☐ |
| Adversarial testing passed (fuzz, proptest, miri, timing) | ☐ |
| ARCHITECTURE.md current | ☐ |
| README.md current | ☐ |
| THREAT_MODEL.md current | ☐ |
| All lessons written (`docs/slo/lessons/sunlit-m[0-10].md`) | ☐ |
| All completion summaries (`docs/slo/completion/sunlit-m[0-10].md`) | ☐ |
| `git status` clean | ☐ |
| `.gitignore` comprehensive | ☐ |
| No TODO/FIXME/HACK in codebase (except documented deferrals) | ☐ |
| Self-review gate passed for every milestone | ☐ |
| `secure_authz` has ZERO dependency on `secure_identity` | ☐ |

**Total Milestones**: 11 (M0–M10)  
**Total BDD Scenarios**: ~130+  
**Total E2E Tests**: ~50+  
**Crates Delivered**: 9 (8 libraries + 1 binary)  
**OWASP Controls Covered**: C1, C4, C5, C6, C7, C8, C9, C10  
**Supply-Chain Tools**: cargo-audit, cargo-deny, cargo-vet  
**Adversarial Testing**: cargo-fuzz, proptest, cargo miri, timing tests

# Lessons Learned — Milestone 3: `security_events` — Security Logging & Monitoring (OWASP C9)

**Date**: 2026-04-06
**Milestone**: 3 — `security_events` — Security Logging & Monitoring
**Status**: done

---

## What We Built

The `security_events` crate providing structured, redacted, injection-safe security telemetry:

| Module | Contents |
|---|---|
| `event` | `SecurityEvent` struct with canonical fields (timestamp, event_id, kind, severity, outcome, actor, tenant, source_ip, request_id, trace_id, session_id, resource, reason_code, labels). `EventValue` carries a `DataClassification` tag. `EventOutcome` enum. |
| `kind` | `EventKind` enum — 13 variants covering all must-have event families. `#[non_exhaustive]`. |
| `sanitize` | `sanitize_for_text_sink()` — newline escaping, carriage return escaping, ASCII control char → U+FFFD. Prevents log injection (OWASP C9). |
| `redact` | `RedactionPolicy` mapping `DataClassification` to `RedactionStrategy`. `RedactionEngine::process_event()` applies per-label redaction using SHA-256 hashing for PII/Regulated, `[REDACTED]` for Secret/Confidential, Drop for Credentials. |
| `context` | `SecurityContext` — builder for request-scoped metadata (request_id, trace_id, actor_id, tenant_id, session_id). |
| `emit` | `emit_security_event()` free function. Sealed `SecurityEventEmitter` trait. |
| `detect` | `DetectionEngine` with `#[non_exhaustive]` `DetectionPoint` enum. Per-actor threshold tracking via `Mutex<HashMap>`. Fires `BruteForceAttempt` at threshold; always fires `CrossTenantAttempt` at Critical. |
| `sink` | Sealed `SecuritySink` trait (`Send + Sync`). `StdoutJsonSink` uses `stdout().lock()` for atomic NDJSON. `TracingSink` routes via `tracing::info!`. |
| `layer` | `SecurityLayer<S>` implementing `tracing_subscriber::Layer<S>`. `Clone + Send + Sync + 'static`. |
| `rate_limit` | `RateLimiter` per-`EventKind` sliding-window throttling. Independent limits per kind. |

Updated `secure_errors::incident` with `emit_event_for_incident()` wiring `AppError::Forbidden` → `AuthzDeny` and `AppError::Dependency` → `ErrorEscalation`.

**22 tests** across 5 test files: BDD redaction (6), BDD sanitize (3), BDD detection (3), BDD schema (2), E2E runtime (8).

---

## Key Design Decisions

### 1. `EventValue` carries `DataClassification` inline

Rather than storing classification in a separate registry, each `EventValue::Classified` variant contains the value and its classification. This makes the redaction engine a simple map — no external lookup needed.

### 2. Circular dependency avoided: `security_events` does NOT depend on `secure_errors`

`secure_errors` depends on `security_events` (to emit events), not the other way around. The E2E integration test for `error_event_integration` calls `emit_event_for_incident` from within `security_events/tests/` by importing `secure_errors` as a dev-dependency. This cleanly avoids a cycle.

### 3. Sealed traits for `SecuritySink` and `SecurityEventEmitter`

Both use the `mod private { pub trait Sealed {} }` pattern so downstream crates cannot add unauthorized sink implementations. Only types in the defining crate can implement these traits.

### 4. `DetectionEngine` uses `Mutex<HashMap<String, (u32, Instant)>>`

Per-actor counts are stored in a `Mutex<HashMap>` keyed by actor string. Each entry holds a count and the window start `Instant`. When the window expires, the count resets. This is correct under concurrent access and avoids `AtomicU32` + separate timestamp complexity.

### 5. `StdoutJsonSink` uses `stdout().lock()` for atomic line writes

On Unix and Windows, `stdout().lock()` holds the lock for the duration of the write, ensuring each JSON line is written atomically. This prevents interleaved NDJSON lines under concurrent event emission.

### 6. SHA-256 for PII hashing is stable and deterministic

The same PII input always produces the same hash, enabling correlation across events (e.g., "same email address across two events") without storing the raw PII. This is the `SHA256:<hex>` format visible in redacted output.

---

## Gotchas

1. **`#[non_exhaustive]` on `EventKind` means test match arms need `_` wildcards** — within the crate this is not required, but integration test files outside the crate will need wildcard arms.
2. **`tracing-subscriber` features must include `"fmt"` and `"json"`** — without these, `SecurityLayer` cannot compile.
3. **`sha2` requires explicit `use sha2::Digest`** — the `.finalize()` method comes from the `Digest` trait, not the struct.
4. **`serde_json::to_string` panics on non-serializable types** — `SecurityEvent` must `#[derive(Serialize)]` with all fields either `Serialize` or `#[serde(skip)]`.
5. **`time::OffsetDateTime::now_utc()` requires `time` crate with `macros` feature** — already in workspace deps, no extra config needed.

---

## Test Coverage

- **6 BDD redaction tests**: Public pass-through, Secret → [REDACTED], PII → SHA256 hash, Credentials dropped, Internal allowed, custom policy
- **3 BDD sanitize tests**: newline escaped, control chars stripped, carriage return normalized
- **3 BDD detection tests**: fires on threshold, below threshold no escalation, cross-tenant always fires Critical
- **2 BDD schema tests**: JSON shape correct, optional fields handled
- **8 E2E tests**: roundtrip, redaction runtime, stdout sink, detection integration, injection prevention, rate limiter, error integration, emit no-panic

---

## Hash-Chain Audit Log (Deferred)

Per the out-of-scope section, `AuditChain` with SHA-256 hash linking is a stretch goal. **This MUST be completed by M9 (Adversarial Testing) at the latest.** Document in the M9 pre-flight checklist.

---

## What the Next Milestone Needs From This One

- `secure_boundary` (M4) will produce `AppError::Validation` errors and `BoundaryViolation` events — use `security_events::emit::emit_security_event` with `EventKind::BoundaryViolation`.
- `secure_output` (M4) can use `SecurityContext` for correlation propagation.
- `secure_authz` (M6) will emit `EventKind::AuthzDeny` and `EventKind::CrossTenantAttempt` events.
- All downstream crates should add `security_events = { path = "../security_events" }` and call `emit_security_event` at security decision points.

---

## Rules for the Next Milestone

1. Always classify event labels with `DataClassification` — never add raw string labels.
2. Always run events through `RedactionEngine` before passing to any sink.
3. `EventKind` is `#[non_exhaustive]` — use wildcard arms in external crate matches.
4. `SecuritySink` is sealed — do not implement it outside `security_events`.
5. `DetectionEngine` is not `Clone` (Mutex) — pass by `Arc<DetectionEngine>` across threads.

# Lessons Learned — Milestone 2: `secure_errors` — Centralized Error Handling (OWASP C10)

**Date**: 2026-04-06
**Milestone**: 2 — `secure_errors` — Centralized Error Handling
**Status**: done

---

## What We Built

The `secure_errors` crate providing a complete three-layer error model:

| Module | Contents |
|---|---|
| `kind` | `AppError` enum with 8 variants (`Validation`, `Forbidden`, `NotFound`, `Conflict`, `Dependency`, `Crypto`, `Internal`, `RateLimit`). `#[non_exhaustive]`, `thiserror`-derived. |
| `public` | `PublicError` struct — the only type serialized to HTTP responses. Fields: `code`, `message`, `request_id`. `Serialize` only (not `Deserialize`). |
| `classify` | `ErrorClassification` — per-variant flags for `is_retryable()`, `is_alertable()`, `is_security_signal()`, `is_user_fixable()`. |
| `report` | `ErrorReport` — forensic context with cause chain, component, actor/tenant IDs, backtrace. Internal use only. |
| `http` | `into_response_parts(&AppError) -> (u16, PublicError)` — single source of truth for error-to-HTTP mapping. |
| `incident` | `SecurityIncident` sealed trait — `incident_fingerprint()`, `alert_severity()`, `security_signal()`. Implemented on `AppError`. Wired to `security_events` in M3. |
| `panic` | `catch_panic_to_safe_response()` using `std::panic::catch_unwind`. `PanicSafeLayer` marker type (Clone + Send + Sync). |
| `capture` | `capture_backtrace()` and `attach_context()` helpers for `ErrorReport`. |

**23 tests** across 4 test files: BDD mapping, BDD leakage, BDD panic, and E2E runtime validation.

---

## Key Design Decisions

### 1. `into_response_parts` takes `&AppError` not `AppError`

The clippy pedantic lint `needless_pass_by_value` correctly flagged passing `AppError` by value since we only pattern-match on it. Taking a reference is idiomatic and avoids unnecessary moves.

### 2. Struct excessive bools — `#[allow(clippy::struct_excessive_bools)]`

`ErrorClassification` has 4 boolean flags. `clippy::pedantic` flags this as `struct_excessive_bools`. The flags are semantically distinct (retryable ≠ user-fixable ≠ security-signal ≠ alertable) and converting to enums would add indirection without clarity. We allow this lint locally on the struct with a comment.

### 3. `#[non_exhaustive]` on `AppError` — match wildcard is unreachable within the crate

`#[non_exhaustive]` only forces downstream crates (outside the defining crate) to add wildcard arms. Within the `secure_errors` crate itself, the compiler knows all variants and the wildcard arm is unreachable — clippy will flag it. **Do not add wildcard arms to crate-internal matches on `AppError`.**

### 4. Match same-arms must be merged

When two `AppError` variants map to identical `ErrorClassification` (e.g. `Forbidden` and `Crypto` are both security signals), merge them with `|` syntax. This is required by `clippy::match_same_arms`.

### 5. `double_must_use` — don't annotate `#[must_use]` on functions returning `#[must_use]` types

`PublicError` is annotated `#[must_use]`. Functions returning `PublicError` (or tuples containing it) should not also be annotated `#[must_use]` — clippy will flag this as `double_must_use`.

### 6. Sealed trait for `SecurityIncident`

The `private::Sealed` marker trait limits who can implement `SecurityIncident`. The module is private, so only crates that have access to `crate::incident::private::Sealed` (i.e., code in the same crate or explicitly re-exported) can implement the trait.

---

## Gotchas

1. **Wildcard arm in crate-internal `AppError` match causes `unreachable_patterns`** — Don't add it; the compiler is exhaustive.
2. **`#[deny(clippy::pedantic)]` at crate level catches many patterns** — specifically `struct_excessive_bools`, `match_same_arms`, `needless_pass_by_value`. Fix these before running smoke tests.
3. **`serde_json` must be in both `[dependencies]` and `[dev-dependencies]` if used in both production and test code** — or move it to dev only if production code doesn't use it directly.

---

## Test Coverage

- **10 BDD mapping tests**: all 7 HTTP status mappings + request ID propagation + 3 classification scenarios
- **5 BDD leakage tests**: SQL, hostname, stack trace, authn differential, report retention
- **3 BDD panic tests**: catch, survive, trait bounds
- **5 E2E tests**: round-trip, serialization fields, leakage scan, panic layer, classification consistency

---

## What the Next Milestone Needs From This One

- `security_events` (M3) will wire the `SecurityIncident` trait — `AppError::security_signal()` and `AppError::alert_severity()` will emit audit events.
- `security_events` will depend on `security_core::severity::SecuritySeverity` (same as this crate) and `security_core::types::RequestId`.
- `secure_boundary` (M4) will produce `AppError::Validation` errors that flow through `into_response_parts`.
- `secure_authz` (M6) will produce `AppError::Forbidden` errors.
- All downstream crates should add `secure_errors` as a path dependency and use `AppError` as their error type.

---

## Rules for the Next Milestone

1. When adding new `AppError` variants, add them to `classify.rs`, `http.rs`, and `incident.rs` simultaneously.
2. Never add a wildcard arm to crate-internal `AppError` matches.
3. `PublicError` must not gain new fields that could carry internal data (no `detail`, no `trace`).
4. `SecurityIncident` implementations must be in `incident.rs` — do not scatter them across downstream crates.

# Lessons Learned — Milestone 1: Workspace Scaffold + `security_core`

**Date**: 2026-04-06
**Milestone**: 1 — Workspace scaffold + `security_core`
**Status**: done

---

## What We Built

A Cargo workspace with 9 member crates:

- **`security_core`** — Fully implemented shared types, traits, and abstractions
- **`secure_errors`, `security_events`, `secure_boundary`, `secure_authz`, `secure_data`, `secure_output`, `secure_identity`** — Stub library crates
- **`secure_reference_service`** — Stub binary crate

`security_core` implements all foundational primitives:

| Module | Contents |
|---|---|
| `types` | `ActorId`, `TenantId`, `RequestId`, `TraceId`, `ResourceId`, `PolicyVersion` newtypes over `Uuid` |
| `classification` | `DataClassification` enum with `PartialOrd`/`Ord` for threshold comparisons |
| `severity` | `SecuritySeverity` enum ordered Info → Critical |
| `context` | `CorrelationContext`, `SecretRef` (no-leak Debug), `ReasonCode` |
| `time` | `TimeSource` (sealed trait), `SystemTimeSource`, `MockTimeSource` |
| `redact` | `Redact` (sealed trait), `RedactedDisplay<T>` wrapper |
| `identity` | `IdentitySource` (open async trait), `AuthenticatedIdentity`, `IdentityResolutionError` |

---

## Key Design Decisions

### 1. Macro-generated newtype IDs

Used a `macro_rules! id_newtype!` macro to generate 6 UUID newtypes without boilerplate. `Deref` was intentionally NOT implemented — callers must use `.as_inner()` or `.into_inner()`, preventing accidental mixing of `ActorId` and `TenantId` at the type level.

### 2. Sealed vs. open traits

| Trait | Sealed? | Reason |
|---|---|---|
| `TimeSource` | ✅ Sealed | Only `SystemTimeSource` and `MockTimeSource` should exist; prevents untestable implementations |
| `Redact` | ✅ Sealed | Prevents bypassing the `[REDACTED]` contract |
| `IdentitySource` | ❌ Open | External identity providers (Keycloak, Auth0) must implement it |

### 3. `SecretRef` no-leak Debug

`SecretRef` wraps a URI string but implements `Debug` to output `SecretRef(REDACTED)` rather than the URI. This prevents credential URIs from appearing in logs, panic messages, or test output. Mitigates THREAT-I-02.

### 4. `async fn` in trait (Rust 1.75+ RPITIT)

Used `async fn resolve(...)` directly in `IdentitySource`. Suppressed the `async_fn_in_trait` lint with `#[allow(async_fn_in_trait)]` on the trait, with a doc comment explaining the deliberate API choice. This is the idiomatic approach on Rust 1.75+.

### 5. `DataClassification` discriminant values

Assigned explicit integer discriminants (`Public = 0` through `Credentials = 6`) to make the ordering declaration-site-obvious and to ensure stability if discriminants are ever serialized.

---

## Gotchas

1. **`assert!(true)` triggers `clippy::assertions_on_constants`** — Remove trivial true assertions; replace with a comment or a real no-op variable binding.

2. **`async fn` in public trait triggers `async_fn_in_trait` lint** — Must be suppressed with `#[allow]` on the trait definition to pass `cargo clippy -- -D warnings`.

3. **`#[non_exhaustive]` on enums** — Both `DataClassification` and `SecuritySeverity` are `#[non_exhaustive]`. This means external match expressions must use a wildcard arm. Intentional for forward-compatibility.

---

## Test Coverage

- **23 tests** across BDD acceptance (`sunlit_core_types.rs`) and E2E runtime (`e2e_sunlit_m1.rs`)
- All types tested for: construction, cloning, Display, Debug (no-leak for `SecretRef`), ordering, and trait implementability
- `IdentitySource` tested via `#[tokio::test]` async test with a local mock struct

---

## What the Next Milestone Needs From This One

- `secure_errors` will depend on `security_core::classification::DataClassification` and `security_core::context::CorrelationContext`
- `security_events` will depend on `security_core::severity::SecuritySeverity` and `security_core::types::*`
- All downstream crates should add `security_core` as a workspace dependency

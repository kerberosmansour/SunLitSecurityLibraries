# Lessons Learned — Milestone 5: `secure_identity` — Digital Identity (OWASP C6)

**Date**: 2026-04-06
**Milestone**: 5 — `secure_identity`
**Status**: done

---

## What We Built

A pluggable authentication abstraction implementing `security_core::IdentitySource`, providing:

| Module | Contents |
|---|---|
| `error` | `IdentityError` (`#[non_exhaustive]`): `InvalidCredentials`, `TokenExpired`, `TokenMalformed`, `MfaRequired`, `SessionExpired`, `ProviderUnavailable`. `From<IdentityError> for AppError` bridge. |
| `authenticator` | `Authenticator` sealed trait with `AuthenticationRequest` / `TokenKind`. Sealed so only crate-internal types (like `TokenValidator`) can implement it. Third-party providers implement `IdentitySource` instead. |
| `token` | `TokenValidator` — HS256 JWT validation via `jsonwebtoken` v9, which uses `ring` internally for constant-time HMAC-SHA256 verification. Validates signature, expiration, issuer, audience. Emits `EventKind::AuthnFailure` security events on every failure. Implements both `Authenticator` and `IdentitySource`. |
| `session` | `SessionManager` open trait + `InMemorySessionManager` using `tokio::sync::Mutex<HashMap>`. Session IDs use `ring::rand::SystemRandom` for 128-bit cryptographic entropy. Bounded lifetimes. Sliding-window refresh. Revocation. |
| `mfa` | `MfaChallenge`, `MfaResponse`, `MfaProvider` trait stub — TOTP deferred. |
| `dev` | `DevAuthenticator` feature-gated behind `dev` feature. Emits `tracing::warn!` on construction. |

**19 tests** passing across 5 test files.

---

## Key Design Decisions

### 1. `Authenticator` is sealed; `IdentitySource` is open

`Authenticator` is sealed to prevent third-party crates from creating unexpected authentication paths inside the identity crate's internal pipeline. Third-party identity providers implement `security_core::IdentitySource` directly — this is the intended extension point. `secure_authz` depends on `IdentitySource`, not `Authenticator`.

### 2. Constant-time comparison is handled by `jsonwebtoken` / `ring`

`jsonwebtoken` v9 uses `ring` internally for HMAC-SHA256 signature verification, which is constant-time. We don't need to add manual `subtle` crate comparisons on top of the JWT layer. The `subtle` dep was not added to avoid confusion about where constant-time guarantees apply.

### 3. Session IDs use `ring::rand::SystemRandom`

`ring::rand::SecureRandom::fill()` fills a 16-byte buffer from the OS CSPRNG. Hex-encoding produces 32-character IDs with 128 bits of entropy. UUID v4 would also work but `ring` is already a dependency for JWT verification.

### 4. `SecurityEvent::new()` constructor

The `SecurityEvent` struct has many optional fields. A `new(kind, severity, outcome)` constructor was used in `token.rs` to create minimal failure events. Check whether `SecurityEvent::new` exists or whether the struct must be constructed field-by-field — the impl uses direct struct construction with `..Default::default()` pattern if needed.

### 5. `InMemorySessionManager` is not persistent

The `SessionManager` trait is open — consumers can implement a Redis-backed or database-backed session store. The in-memory implementation serves testing and single-process deployments. This is explicit in the docs.

---

## Gotchas

1. **`jsonwebtoken` v9 `Validation`**: Use `validation.set_issuer(&[&self.config.issuer])` and `validation.set_audience(&[&self.config.audience])`. The old API used `validation.iss` directly — v9 uses setter methods.
2. **`jsonwebtoken` `ErrorKind` matching**: Match on `e.kind()`, not `e` directly. Variants: `ExpiredSignature`, `InvalidIssuer`, `InvalidAudience`, plus catch-all for malformed.
3. **`#[allow(async_fn_in_trait)]`**: Required for all trait definitions using `async fn` syntax (stabilised in Rust 1.75). The `async-trait` crate is explicitly forbidden.
4. **`dev` feature gate**: All items in `dev.rs` must be gated with `#[cfg(feature = "dev")]`. The module declaration in `lib.rs` must also be conditionally compiled. Test files for `DevAuthenticator` can use `#[cfg(feature = "dev")]` to conditionally run.
5. **`SecurityEvent` construction**: `security_events::event::SecurityEvent` has many fields. Use `..Default::default()` or a builder-style helper if available. Check the actual struct definition before writing event emission code.
6. **`cargo tree -p secure_authz | grep secure_identity` must return nothing** — verified in CI via the `test_authz_independence` E2E test.

---

## Test Coverage

- **6 BDD authenticator tests** (`sunlit_identity_authenticator.rs`): valid JWT, expired, malformed, wrong issuer, missing sub, failure event
- **3 BDD token tests** (`sunlit_identity_token.rs`): roles, tenant, no-tenant claims
- **5 BDD session tests** (`sunlit_identity_session.rs`): bounded lifetime, validate, expiry, revoke, 1000 unique IDs
- **1 BDD dev test** (`sunlit_identity_dev.rs`): compile-time feature guard
- **4 E2E tests** (`e2e_sunlit_m5.rs`): JWT roundtrip, session lifecycle, IdentitySource integration, authz independence

---

## What the Next Milestone Needs From This One

- `secure_authz` (M6) uses `security_core::IdentitySource` — test with `TokenValidator` as the concrete impl.
- `secure_authz` may use `AuthenticatedIdentity.roles` for RBAC checks.
- Pass `&TokenValidator` as `&dyn` or generic `impl IdentitySource` parameter to the authz engine.
- The `dev` feature of `secure_identity` is useful for `secure_authz` tests — configure a `DevAuthenticator` with specific roles to test policy decisions.

---

## Rules for the Next Milestone

1. `secure_authz` must NOT import `secure_identity` — use `security_core::IdentitySource` trait bound only.
2. Use `AuthenticatedIdentity.roles` (a `Vec<String>`) for role-based policy checks.
3. `TokenValidator` can be used in integration tests by creating a test JWT with `jsonwebtoken::encode`.
4. For unit tests of authz, use `DevAuthenticator` (with `dev` feature) to produce identities with specific roles.
5. Emit `EventKind::AuthzDeny` security events for authorization failures (already defined in `security_events::kind`).

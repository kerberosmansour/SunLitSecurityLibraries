# Lessons Learned — Milestone 4: `secure_boundary` + `secure_output` — Input Validation, Output Encoding & Security Headers (OWASP C5 + C4)

**Date**: 2026-04-06
**Milestone**: 4 — `secure_boundary` + `secure_output`
**Status**: done

---

## What We Built

Two crates implementing complementary halves of the HTTP trust boundary:

### `secure_boundary`

| Module | Contents |
|---|---|
| `validate` | `SecureValidate` open trait with `validate_syntax()` + `validate_semantics()` + `ValidationContext`. Associated `type SyntaxChecked` and `type SemanticsChecked` for type-state progression. |
| `serde` | `StrictDeserialize<T>` — a newtype wrapper using a custom `Deserializer` that injects `deny_unknown_fields` behavior without requiring it on every DTO struct. |
| `normalize` | `normalize_nfc()` (Unicode NFC via `unicode-normalization`), `trim_whitespace()`, `normalize_email_domain()` (local part preserved, domain lowercased). |
| `content_type` | `ContentTypeGuard` — allowlist checking accepting `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data` by default. |
| `limits` | `RequestLimits` — configurable max body bytes, max field count, max nesting depth. Builder pattern. Defaults: 1 MB body, 64 fields, 20 depth. |
| `attack_signal` | `ViolationKind` (#[non_exhaustive]), `BoundaryViolation`, `ViolationClassification` (ClientMistake / AttackSignal / ParserFault). Emits `SecurityEvent` via `security_events::emit::emit_security_event`. |
| `error` | `BoundaryRejection` (#[non_exhaustive]) implementing `IntoResponse`. Never echoes raw input — maps to stable public codes only. |
| `dto` | `SecureDto` marker trait for DTO structs. |
| `id` | `UserId`, `OrderId`, `OpaquePublicId` canonical ID newtypes over `Uuid` with `into_inner()` / `as_inner()`. (No `Deref`.) |
| `extract` | `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>` axum extractors. Four-stage pipeline: transport → syntax → semantics → (authz extension point). No `Deref<Target=T>`. |
| `headers` | `SecurityHeadersLayer` Tower middleware. Default headers: HSTS, CSP, XCTO, XFO, Permissions-Policy, Cache-Control. Builder overrides for CSP and allowed CORS origins. `Clone + Send + Sync + 'static`. |

### `secure_output`

| Module | Contents |
|---|---|
| `encode` | `OutputEncoder` open trait returning `Cow<'a, str>`. Not sealed — consumers can add custom contexts. |
| `html` | `HtmlEncoder` — encodes `<>'"&/`, strips null bytes, returns `Cow::Borrowed` for safe strings (zero-allocation fast path). |
| `json` | `JsonEncoder` — escapes `</script>` → `<\/script>` to prevent script injection in JSON-in-HTML contexts. |
| `url` | `UrlEncoder` — percent-encodes unreserved characters per RFC 3986. |

**129 tests** passing across 9 new test files plus all pre-existing M1-M3 tests.

---

## Key Design Decisions

### 1. `SecureValidate` is open (not sealed)

Consumer DTOs in other crates (e.g., `secure_reference_service`) need to implement `SecureValidate` for the extractors to work. Using a sealed trait here would prevent that. By contrast, `SecuritySink` (M3) is sealed because we don't want unauthorized sink implementations.

### 2. No `Deref<Target=T>` on extractors

Forces callers to call `.into_inner()` and explicitly acknowledge they've crossed the security boundary. A `Deref` implementation would make it too easy to accidentally use an extractor value without going through the validated type.

### 3. `StrictDeserialize<T>` uses a custom `Deserializer` wrapper

`serde`'s `deny_unknown_fields` attribute is a compile-time annotation that must be on the struct. Since we cannot control consumer DTOs, `StrictDeserialize<T>` wraps the deserializer to intercept map deserialization and enforce the policy at runtime. This is compatible with any `T: DeserializeOwned`.

### 4. `BoundaryRejection` never echoes raw input

All rejection variants map to static codes (`invalid_request`, `body_too_large`, `invalid_content_type`, `invalid_format`, `invalid_range`). The response body contains only the stable code — no raw field names, values, or parse error messages from serde.

### 5. `SecurityHeadersLayer` uses Tower's `Layer` + `Service` pattern

The layer wraps any inner service and post-processes responses to inject headers. This integrates cleanly with axum's `.layer()` call chain without requiring axum-specific APIs.

### 6. `HtmlEncoder` returns `Cow::Borrowed` for zero-allocation fast path

When the input string contains no characters that need encoding, the encoder returns `Cow::Borrowed` pointing into the original string slice. This avoids allocation on the hot path.

---

## Gotchas

1. **axum 0.8 `FromRequest` no longer has `async_trait`** — implement the trait directly with `async fn` syntax; no `#[async_trait]` needed.
2. **`http_body_util::BodyExt::collect()`** is needed to collect the request body into bytes in the extractor — add `http-body-util` as a dependency.
3. **`X_CONTENT_TYPE_OPTIONS` and `X_FRAME_OPTIONS` are not in `http::header` constants in all versions** — may need to construct via `HeaderName::from_static("x-content-type-options")`.
4. **`unicode-normalization` returns an iterator** — use `.nfc().collect::<String>()`.
5. **`ViolationKind` is `#[non_exhaustive]`** — test match arms outside the crate need a `_` wildcard.
6. **`security_core` already defines `TenantId`** — `secure_boundary::id` defines only `UserId`, `OrderId`, `OpaquePublicId`; re-use `security_core::types::TenantId` where needed.

---

## Test Coverage

- **10 BDD extractor tests** (`sunlit_boundary_extractors.rs`)
- **8 BDD validation tests** (`sunlit_boundary_validation.rs`)
- **8 BDD strict serde tests** (`sunlit_boundary_strict_serde.rs`)
- **4 BDD normalization tests** (`sunlit_boundary_normalization.rs`)
- **4 BDD mass-assignment tests** (`sunlit_boundary_mass_assignment.rs`)
- **6 BDD security headers tests** (`sunlit_boundary_headers.rs`)
- **10 E2E tests** (`e2e_sunlit_m4.rs`)
- **5 BDD output encoding tests** (`sunlit_output_encoding.rs`)
- **3 E2E output tests** (`e2e_sunlit_m4_output.rs`)

---

## What the Next Milestone Needs From This One

- `secure_identity` (M5) should use `UserId` and `TenantId` from `security_core::types`.
- `secure_authz` (M6) handlers will wrap axum routes with `SecureJson<T>` extractors — the DTO pattern is established.
- `secure_reference_service` (M8) will use `SecurityHeadersLayer` on all routes.
- All downstream handlers must call `.into_inner()` on extractors — never bypass the boundary.

---

## Rules for the Next Milestone

1. All request DTOs must implement `SecureValidate` — never use `axum::Json` directly.
2. Use `security_events::emit::emit_security_event` with `EventKind::BoundaryViolation` for any boundary rejection.
3. `OutputEncoder` is open — add domain-specific encoders as needed.
4. `SecurityHeadersLayer` should wrap the entire router, not individual routes, to ensure no response bypasses headers.
5. `BoundaryRejection` is `#[non_exhaustive]` — use wildcard arms in external crate matches.

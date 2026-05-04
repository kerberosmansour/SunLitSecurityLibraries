# SunLit Security Libraries — Architecture

> **Last updated**: Milestone 21 (`secure_boundary` — Browser Security Headers & CORS, OWASP C8)

## Overview

SunLit Security Libraries is a production-grade Cargo workspace of eight security crates, one reference service, and one security smoke-test service, implementing OWASP Proactive Controls C1/C4/C5/C6/C7/C8/C9/C10 for Rust web services targeting critical infrastructure (energy, finance, healthcare, government).

The workspace provides first-class adapters for `axum`/`tower`, adversarial testing via `cargo-fuzz`/`proptest`/`miri`, and supply-chain security via `cargo-audit`/`cargo-deny`/`cargo-vet`.

---

## Threat Model Reference

A formal STRIDE threat model governs all design and implementation decisions. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for:

- Full STRIDE analysis (20 threats across S, T, R, I, D, E categories)
- Abuse cases with attacker motivation, preconditions, steps, and impact
- Control-to-threat traceability matrix (M1–M10)
- Attack trees for identity, authorization, data protection, and input/output paths
- Residual risks and compensating controls
- Compliance mapping (NIST 800-53, IEC 62443, SOC 2)

**STRIDE Summary**:

| Category | Count | Primary Mitigating Crates |
|---|---|---|
| Spoofing | 3 | `secure_identity` (M5), `security_core` (M1) |
| Tampering | 3 | `security_events` (M3), `secure_data` (M7) |
| Repudiation | 3 | `security_events` (M3) |
| Information Disclosure | 4 | `secure_errors` (M2), `secure_data` (M7), `security_events` (M3) |
| Denial of Service | 3 | `secure_boundary` (M4), `security_events` (M3) |
| Elevation of Privilege | 4 | `secure_authz` (M6), `secure_boundary` (M4) |

---

## Crate Dependency Graph

```
secure_reference_service
├── secure_boundary   (OWASP C5)
├── secure_output     (OWASP C4)
├── secure_identity   (OWASP C6)
├── secure_authz      (OWASP C7)
├── secure_data       (OWASP C8)
├── security_events   (OWASP C9)
├── secure_errors     (OWASP C10)
└── security_core     (shared types, IdentitySource trait)

secure_smoke_service  (smoke-test service, M16)
├── secure_boundary
├── secure_output
├── secure_identity
├── secure_authz
├── secure_data
├── security_events
├── secure_errors
└── security_core

secure_network  (MASVS-NETWORK)
├── security_core
├── security_events
├── sha2
└── x509-parser

secure_resilience  (MASVS-RESILIENCE)
├── security_core
├── security_events
├── sha2
└── time

secure_boundary → security_core, secure_errors, security_events
secure_output   → security_core
secure_identity → security_core, secure_errors, security_events
secure_authz    → security_core  [NO dependency on secure_identity — identity-agnostic]
secure_data     → security_core, secure_errors
secure_network  → security_core, security_events
secure_resilience → security_core, security_events
security_events → security_core
secure_errors   → security_core
```

> **Key invariant**: `secure_authz` depends ONLY on `security_core::IdentitySource`. It never imports `secure_identity`. Any identity provider implementing `IdentitySource` works transparently with the authorization engine.

---

## Component Descriptions

### `security_core` (M1)
Shared types used by every crate: `ActorId`, `TenantId`, `RequestId`, `TraceId`, `ResourceId`, `DataClassification`, `SecuritySeverity`, `ReasonCode`, `PolicyVersion`, `SecretRef`. Defines the `IdentitySource` trait. All ID types are newtype wrappers (not aliases) to prevent accidental mixing.

### `secure_errors` (M2 — OWASP C10)
Centralized error handling. Three-layer model: internal errors (rich context, never sent externally), mapped errors (sanitized for logs), public errors (minimal, safe for HTTP responses). `PanicSafeLayer` tower middleware ensures no panics escape as 500s with stack traces.

**Three-layer error model (implemented M2):**
- **Internal layer** (`kind::AppError`): Full internal details — SQL text, hostnames, policy names. Variants: `Validation`, `Forbidden`, `NotFound`, `Conflict`, `Dependency`, `Crypto`, `Internal`, `RateLimit { retry_after_seconds }`. Never serialized to HTTP.
- **Public layer** (`public::PublicError`): The only struct serialized to HTTP responses. Fields: `code` (stable machine-readable), `message` (user-safe), `request_id` (correlation only). No internal details.
- **Operational layer** (`classify::ErrorClassification`): Flags for retryability, alerting, security signals, user-fixability.

**Mapping rules**: `http::into_response_parts` is the single source of truth. Each `AppError` variant maps to exactly one HTTP status and one `PublicError` shape. `http::retry_after_seconds` extracts the `Retry-After` value from `RateLimit` errors.

**ErrorMappingLayer (added M15)**: Opt-in Tower `Layer` that enables automatic `AppError` → HTTP response conversion via `IntoResponse` implementation. Handlers returning `Result<impl IntoResponse, AppError>` get automatic status code mapping, `Retry-After` header insertion for 429 responses, and JSON `PublicError` body serialisation — eliminating manual `into_response_parts()` calls.

**Context propagation (added M15)**: `context_propagation::ErrorContext` stores request-scoped metadata (`request_id`, `actor_id`, `tenant_id`) in task-local storage, enabling error handling code to access contextual information without explicit parameter passing.

**Panic boundary**: `panic::catch_panic_to_safe_response` uses `std::panic::catch_unwind` (cross-platform) to catch panics, discards the panic payload, and returns a safe 500 response.

**Security incident trait**: `incident::SecurityIncident` is a sealed trait — only types from within the security crate family may implement it. Wired to `security_events` in M3.

### `security_events` (M3 / M22 / MASVS-M7 — OWASP C9)

Security telemetry with classification-driven redaction, per-event HMAC sealing, event correlation, injection-safe formatting, AppSensor-style detection points, pluggable sinks, and mobile-specific log sanitization.

#### Event Schema

```rust
pub struct SecurityEvent {
    pub timestamp: time::OffsetDateTime,   // UTC, always present
    pub event_id: uuid::Uuid,              // unique per event
    pub parent_event_id: Option<uuid::Uuid>, // optional correlation link to a parent event
    pub kind: EventKind,                   // semantic event category
    pub severity: SecuritySeverity,        // Info / Low / Medium / High / Critical
    pub outcome: EventOutcome,             // Success / Failure / Blocked / Unknown
    pub actor: Option<String>,             // actor ID (user/service)
    pub tenant: Option<TenantId>,          // multi-tenant context
    pub source_ip: Option<IpAddr>,         // originating IP
    pub request_id: Option<RequestId>,     // correlation ID
    pub trace_id: Option<TraceId>,         // distributed trace ID
    pub session_id: Option<String>,        // session reference
    pub resource: Option<String>,          // resource being accessed
    pub reason_code: Option<&'static str>, // policy decision reason
    pub hmac: Option<String>,              // per-event HMAC-SHA256 tamper-evidence seal
    pub labels: BTreeMap<String, EventValue>, // classified key-value metadata
}
```

#### Integrity & Correlation

- `HmacEventSigner` computes an HMAC-SHA256 over the canonical serialized event fields and stores the hex signature in `event.hmac`.
- `with_parent()` / `attach_parent()` link follow-up events to a root event via `parent_event_id`.
- `filter_by_parent()` groups related events during forensic review without changing the base event schema.

Each `EventValue` carries a `DataClassification` tag that drives the redaction engine.

#### Redaction Model

Redaction is policy-driven, not ad hoc. The `RedactionEngine` applies a `RedactionPolicy` to every label in an event before emission:

| Classification | Default Strategy |
|---|---|
| `Public` | Allow (pass through unchanged) |
| `Internal` | Allow |
| `Confidential` | Redact → `[REDACTED]` |
| `PII` | Hash → `SHA256:<hex>` |
| `Regulated` | Hash → `SHA256:<hex>` |
| `Secret` | Redact → `[REDACTED]` |
| `Credentials` | Drop (label removed entirely) |

#### Mobile Log Sanitization (MASVS-M7)

`MobileRedactionEngine` scrubs mobile-specific device identifiers and location data from event labels before classification-driven redaction. Runs as a pre-processing step in the redaction pipeline.

| Pattern | Replacement | Detection Method |
|---|---|---|
| IMEI (15 digits) | `[DEVICE_ID_REDACTED]` | Exact 15-digit match |
| MAC address (`XX:XX:XX:XX:XX:XX`) | `[DEVICE_ID_REDACTED]` | Colon/dash-separated hex octets |
| GPS coordinates (`lat, lon`) | `[LOCATION_REDACTED]` | Decimal coordinate pair |
| IDFV / device UUID | `[DEVICE_ID_REDACTED]` | UUID format + device-related key name |
| GAID / IDFA (advertising ID) | `[AD_ID_REDACTED]` | UUID format + advertising-related key name |

`LogLevelEnforcer` provides compile-time log level enforcement:
- `LogLevelEnforcer::release()` — suppresses `Trace` and `Debug` events
- `LogLevelEnforcer::debug()` — allows all log levels

#### Event Kinds (`EventKind`)

`BoundaryViolation`, `AuthnFailure`, `MfaEvent`, `AuthzDeny`, `CrossTenantAttempt`, `SecretAccess`, `KeyRotation`, `AdminAction`, `FileUploadAnomaly`, `DeserializationAnomaly`, `ErrorEscalation`, `RateLimitBlock`, `AntiAutomation`.

All `#[non_exhaustive]` — downstream crates must use wildcard arms.

#### Detection Points

`DetectionEngine` provides AppSensor-style threshold escalation:

- `record_authz_denied(actor)` → fires `BruteForceAttempt` escalation at Critical severity when per-actor count exceeds threshold
- `record_cross_tenant_probe(actor, actor_tenant, resource_tenant)` → always fires `CrossTenantAttempt` at Critical severity

Detection counters use `std::sync::Mutex<HashMap>` for thread-safe per-actor tracking.

#### Sink Architecture

`SecuritySink` is a **sealed trait** (`Send + Sync`) with a fallible `try_write_event()` helper for sinks that need to surface I/O or serialization errors:

| Sink | Description |
|---|---|
| `StdoutJsonSink` | NDJSON to stdout — one JSON object per line. Uses `stdout().lock()` for atomic writes. |
| `TracingSink` | Emits events via `tracing::info!` for integration with existing subscribers. |
| `InMemorySink` | Stores cloned events in memory for tests, local inspection, and runtime validation. |
| `FileSink` | Appends NDJSON audit records to disk and rotates the active file when a configured size threshold is reached. |
| `BatchingSink<S>` | Buffers events and flushes them to an inner sink in the background to reduce hot-path overhead during event bursts. |
| `HttpWebhookSink` (`http-sink`) | Optional HTTPS webhook delivery for forwarding structured events to a SIEM or alerting pipeline. |

#### Log Injection Prevention

`sanitize_for_text_sink(input)` runs before every text-sink write:
- Newlines (`\n`) → literal `\n`
- Carriage returns (`\r`) → literal `\r`
- ASCII control characters 0x00–0x1F (except 0x0A/0x0D) → U+FFFD replacement character

#### Rate Limiting

`RateLimiter` provides per-`EventKind` sliding-window throttling to prevent log floods. Each kind is independently counted; exceeding `max_per_window` within `window_seconds` suppresses subsequent events.

#### Integration with `secure_errors`

`emit_event_for_incident(error)` in `secure_errors::incident` maps `AppError` variants to `SecurityEvent` kinds:
- `AppError::Forbidden` → `EventKind::AuthzDeny` at High severity
- `AppError::Dependency` → `EventKind::ErrorEscalation` at Medium severity

### `secure_boundary` (M4 — OWASP C5/C8; extended M11/M18/M21; MASVS-PLATFORM M4-mobile)

**Extractor pipeline**: Every request flows through a four-stage pipeline enforced at compile time via the `SecureValidate` trait:
1. **Transport validity** — `Content-Type` allowlist check, body size limits (`RequestLimits`, default 1 MB), field count / nesting depth limits
2. **Syntactic validity** — JSON/form parsing via `StrictDeserialize<T>` which rejects unknown fields at runtime without requiring `#[serde(deny_unknown_fields)]` on every DTO
3. **Semantic validity** — `SecureValidate::validate_semantics()` checks ranges, relationships, and business invariants
4. **Authz-adjacent invariants** — future extension point for resource-owner checks

**Extractors**: `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>`, `SecureXml<T>` implement `axum::extract::FromRequest`/`FromRequestParts`. No `Deref<Target=T>` — callers must call `.into_inner()` to acknowledge the boundary.

**`SecureXml<T>`** (M11): XML extractor with XXE prevention. Scans raw bytes for `<!DOCTYPE` and `<!ENTITY` declarations before parsing — any match is immediately rejected with `BoundaryRejection::XxeBlocked`. Accepts `application/xml` and `text/xml` content types. Uses `quick-xml` for deserialization.

**DTO pattern**: `SecureDto` marker trait; DTOs never share fields with domain models. Mass-assignment prevention is structural, not runtime-checked.

**Attack signal emission**: Every rejection produces a `BoundaryViolation` event via `security_events::emit::emit_security_event` with `EventKind::BoundaryViolation`. Violations are classified as `ClientMistake`, `AttackSignal`, or `ParserFault`.

**Depth and field limits** (M11): `SecureJson` enforces `RequestLimits::max_nesting_depth` (default 10) and `max_field_count` (default 100) via a single-pass byte scanner that runs before serde deserialization. Violations emit `NestingTooDeep` / `TooManyFields` boundary events and return 422. Custom limits can be injected per-route via `Extension<RequestLimits>` (M18).

**HTML sanitization** (M18, feature `html-sanitize`): `sanitize_html()` strips dangerous elements (scripts, event handlers, `javascript:` URIs) while preserving a safe HTML subset — suitable for WYSIWYG editor output. Backed by the `ammonia` crate. `SanitizeConfig` allows customising the allowed tag set.

**Safe types** (M11): Zero-cost newtypes with `into_inner()` / `as_inner()` — no `Deref`. Every type validates in both `TryFrom<&str>` and serde `Deserialize`. Invalid input emits a `BoundaryViolation` event before rejection.

| Safe Type | Attack Prevented | Key Rules |
|---|---|---|
| `SafePath` | Directory traversal | Rejects `../`, `..\`, absolute paths, null bytes, `%2e%2e` encoded traversal |
| `SafeFilename` | Path traversal + command injection | Rejects `/`, `\`, `..`, null bytes, shell metacharacters (`;|\`$><`) |
| `SafeCommandArg` | OS command injection | Rejects `;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `\r`, `\n` |
| `SafeUrl` | SSRF | Only `http`/`https`; rejects private IPs (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7) |
| `SafeRedirectUrl` | Open redirect | Relative paths only (`/path`); rejects `//` and scheme colons |
| `SqlIdentifier` | SQL injection | `[A-Za-z_][A-Za-z0-9_]*`, max 128 chars |
| `LdapSafeString` | LDAP injection | Escapes `*`, `(`, `)`, `\`, NUL per RFC 4515; always succeeds, emits violation event if escaping was needed |

**`sanitize_header_value()`** (M11): Rejects header values containing `\r` or `\n` to prevent HTTP response splitting / CRLF injection. Returns `Err(BoundaryRejection::InvalidHeaderValue)` on violation.

**Canonical ID types**: `UserId`, `OrderId`, `OpaquePublicId` — newtypes over `Uuid` with `into_inner()` / `as_inner()`. No `Deref`.

**Security headers**: `SecurityHeadersLayer` — Tower `Layer` that injects HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, and Cache-Control into every response. Also injects cross-origin isolation headers added in M12: `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-DNS-Prefetch-Control: off`, `X-Permitted-Cross-Domain-Policies: none`. Builder overrides for CSP, HSTS, and Permissions-Policy.

**Browser security controls** (M21): `secure_cors_defaults()` returns a deny-all `tower_http::cors::CorsLayer`; `SecureCorsBuilder` opt-in allowlists trusted origins, methods, and headers. `FetchMetadataLayer` rejects unsafe `Sec-Fetch-Site: cross-site` API requests while allowing same-origin traffic, safe top-level navigations, and older browsers with missing headers. `SecurityHeadersLayer::with_csp_nonce()` generates a fresh base64 CSP nonce per request, exposes it as `CspNonce` in request extensions, and appends nonce-based `script-src` / `style-src` directives to the response policy.

**Normalization**: Unicode NFC (`unicode-normalization`), whitespace trimming, email domain lowercasing — applied before validation to prevent normalization bypasses.

**Rejection responses**: `BoundaryRejection` (#[non_exhaustive]) maps to stable public codes only — never echoes raw field names, values, or serde error messages.

**Mobile platform safety** (MASVS-PLATFORM, feature `mobile-platform`): Pure Rust validation types for mobile platform interactions. No platform SDK dependencies — platform enforcement (e.g., `FLAG_SECURE`, clipboard APIs) happens in the consuming app.

| Platform Type | Attack Prevented | Key Rules |
|---|---|---|
| `SafeDeepLink` | Deep link hijacking, XSS via custom schemes | Configurable allowed schemes + optional host allowlist; blocks `javascript:`, `data:`, `blob:`, `vbscript:` unconditionally; rejects path traversal |
| `SafeWebViewUrl` | WebView code injection, local file access | Only `http`/`https`; blocks `file://`, `javascript:`, `data:`, `blob:`; optional domain allowlist |
| `ClipboardPolicy` | Clipboard data leakage | Classification-based: `Confidential`+ restricts to local device; `Secret`/`Credentials` auto-expire after 60s |
| `ScreenshotPolicy` | Screen capture of sensitive data | `Confidential`+ defaults to prevent; explicit `prevent()` / `allow()` overrides |

- `DeepLinkValidator` and `WebViewUrlValidator` provide `validate()` and `validate_with_events()` methods. Violations emit `EventKind::PlatformSafetyViolation` security events.
- `PlatformRejection` enum covers `InvalidScheme`, `DangerousScheme`, `PathTraversal`, `UntrustedHost`, `FileAccessBlocked`, `MalformedUrl`.

### `secure_output` (M4/M12 — OWASP C4)

**`OutputEncoder` trait** (open — consumers may add custom contexts): `fn encode<'a>(&self, input: &'a str) -> Cow<'a, str>`. Returns `Cow::Borrowed` for safe strings (zero-allocation fast path).

**`HtmlEncoder`**: Encodes `<`, `>`, `&`, `"`, `'`, `/` to HTML entities. Strips null bytes. Safe strings return `Cow::Borrowed`.

**`JsonEncoder`**: Escapes `</script>` → `<\/script>` to prevent JSON-in-HTML script injection.

**`UrlEncoder`**: Percent-encodes per RFC 3986 unreserved character set. Handles spaces, `&`, `=`, and special characters.

**`JsStringEncoder`** (M12): Escapes `\`, `'`, `"`, `\n`, `\r`, U+2028, U+2029 for safe embedding inside JavaScript string literals. Strips null bytes. Zero-copy fast path for safe strings.

**`CssEncoder`** (M12): CSS unicode-escape notation (`\XXXXXX`) for all non-alphanumeric, non-hyphen, non-underscore characters. Strips null bytes. Prevents CSS injection (`expression()`, `url()`, etc.).

**`XmlEncoder`** (M12): Encodes `<`, `>`, `&`, `"`, `'` to XML named entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`). Strips null bytes. Safe for both XML text content and attribute values.

**`sanitize_uri_scheme()`** (M12): Validates URI scheme safety. Blocks `javascript:`, `data:`, `vbscript:`, `file:`, `blob:` (case-insensitive). Allows `https:`, `http:`, `mailto:`, and relative URIs. Returns `Err(DangerousUriScheme)` on rejection.

**`LdapDnEncoder`** (M19): Escapes characters special in LDAP Distinguished Name attribute values per RFC 4514: `,`, `+`, `"`, `\`, `<`, `>`, `;`, `=`. Leading `#` and leading/trailing spaces are escaped. Null bytes are hex-escaped. Convenience free function: `ldap::encode_dn()`.

**`LdapFilterEncoder`** (M19): Hex-escapes characters special in LDAP search filter assertions per RFC 4515: `*`, `(`, `)`, `\`, NUL. Uses `\XX` notation. Convenience free function: `ldap::encode_filter()`.

**`ShellEncoder`** (M19): Single-quotes input for safe use as POSIX shell arguments. Inside single quotes, no metacharacters (`;`, `|`, `&`, `$`, `` ` ``, etc.) are interpreted. Embedded single quotes are escaped as `'\''`. Null bytes are stripped. Convenience free function: `shell::encode()`.

**Integration pattern**: Output encoding is applied at the rendering layer before any response is written. Handlers produce typed values; encoders are called explicitly on any user-derived string data going into HTML, URL, JS, CSS, XML, LDAP, or shell contexts.

### `secure_identity` (M5 — OWASP C6)

Pluggable authentication abstraction — **one of many possible `IdentitySource` implementations**. Consumers may replace or omit this crate by implementing `security_core::IdentitySource` directly (e.g., a `keycloak-identity` crate, an Auth0 adapter, or a custom OIDC client).

#### Key architectural invariant

`secure_authz` depends on `security_core::IdentitySource`, **never** on `secure_identity`. Any crate implementing `IdentitySource` works with `secure_authz` without adding `secure_identity` to the dependency tree.

#### Modules

| Module | Contents |
|---|---|
| `authenticator` | `Authenticator` sealed trait, `AuthenticationRequest`, `TokenKind` enum |
| `token` | `TokenValidator` — HS256 JWT validation via `jsonwebtoken` (constant-time via `ring`). `AsymmetricTokenValidator` — RS256/ES256 JWT validation with configurable `AlgorithmConfig`. Both validate signature, expiration, issuer, audience. Map JWT error kinds to `IdentityError`. Emit `EventKind::AuthnFailure` security event on every failure. Both implement `IdentitySource`. |
| `api_key` | `ApiKeyAuthenticator` — API key authentication with constant-time comparison via `subtle::ConstantTimeEq`. Handles length-mismatch timing leaks. Implements sealed `Authenticator` trait. |
| `jwks` | `JwksKeyStore` — fetch, parse, and cache JWKS public keys from identity provider endpoints. Configurable TTL cache with `Arc<RwLock>` for thread-safe concurrent access. Supports RSA and EC key types. |
| `session` | `SessionManager` open trait + `InMemorySessionManager`. `Session` struct with bounded lifetime. Session IDs generated via `ring::rand::SystemRandom` (128 bits, hex-encoded). Supports create / validate / refresh (sliding window) / revoke. |
| `session_redis` | `RedisSessionManager` (feature `session-redis`) — Redis-backed `SessionManager` implementation with TTL persistence and revocation support. |
| `mfa` | `MfaChallenge`, `MfaResponse`, `MfaProvider` trait. Implemented by `totp::TotpProvider`. |
| `totp` | `TotpProvider` — RFC 6238 TOTP using `totp-rs` (SHA-1, 6 digits, configurable skew) plus provisioning URI generation and redacted `SecretString`. |
| `oidc` | `OidcClient` (feature `oidc`) — thin OIDC discovery wrapper over `openidconnect` with HTTPS enforcement by default, redirect-disabled HTTP client, metadata caching, and PKCE-first auth URL generation. |
| `auth_events` | `AuthEventEmitter` + builders for authentication success/failure telemetry with source IP and user-agent labels for forensics. |
| `biometric` | (feature `biometric`) `BiometricPolicy`, `BiometricAuthResult`, `BiometricValidation`, `BiometricClass`, `CryptoBinding` — validates platform biometric authentication results against configurable policy (minimum class, crypto binding, enrollment change detection). Satisfies MASVS-AUTH-2. |
| `device_binding` | (feature `biometric`) `DeviceCredentialClaim`, `DeviceBindingType` — types for representing device-bound credential claims (hardware/software keystore, platform attestation). |
| `step_up` | (feature `biometric`) `StepUpPolicy`, `StepUpDecision` — time-based step-up authentication policy enforcement for sensitive operations. Satisfies MASVS-AUTH-3/MASWE-0029. |
| `dev` | `DevAuthenticator` — feature-gated behind `dev`. Accepts any token, returns configurable `AuthenticatedIdentity`. Emits `tracing::warn!` on construction. **NOT FOR PRODUCTION**. |
| `error` | `IdentityError` (`#[non_exhaustive]`): `InvalidCredentials`, `TokenExpired`, `TokenMalformed`, `MfaRequired`, `SessionExpired`, `ProviderUnavailable`. Implements `From<IdentityError> for secure_errors::AppError`. |

#### How to bring your own identity provider

```rust
// In your custom crate:
impl security_core::identity::IdentitySource for MyKeycloakAdapter {
    async fn resolve(&self, token: &str) -> Result<AuthenticatedIdentity, IdentityResolutionError> {
        // validate against Keycloak JWKS endpoint
    }
}

// secure_authz accepts it directly — no secure_identity needed
let authorizer = Authorizer::new(my_keycloak_adapter);
```

### `secure_authz` (M6 — OWASP C7)
Deny-by-default access control. `Authorizer` trait wrapping a policy engine. `SubjectResolver` accepts any `IdentitySource` implementor. Supports RBAC, closure-based ABAC guards, temporal permission windows, resource ownership, tenant scoping, and bulk authorization. All errors during authorization processing deny. Decision log events emitted to `security_events`.

**Key modules:**
- `decision`: `Decision` (`#[must_use]`, `#[non_exhaustive]`) with `Allow { obligations }` and `Deny { reason: DenyReason }`. Callers cannot silently ignore decisions.
- `enforcer`: `Authorizer` trait + `DefaultAuthorizer<P: PolicyEngine>`. Pipeline: subject validation → resource validation → tenant isolation → temporal checks → ABAC guard checks (when configured) → LRU cache lookup → policy evaluation → decision logging → cache insertion. Also exposes `authorize_bulk()` for batched checks.
- `policy`: `PolicyEngine` sealed trait + `DefaultPolicyEngine` backed by casbin v2. Simple subject-match model; each of the subject's roles is evaluated against the policy engine in turn.
- `cache`: `DecisionCache` — bounded LRU (via `lru` crate) with TTL and policy-version-keyed `CacheKey`. Version is incremented on every policy mutation. Cache keys include `tenant_id` (added M15) to prevent cross-tenant cache poisoning.
- `middleware`: `AuthzLayer<A>` Tower layer for axum 0.8. Reads `AuthenticatedIdentity` from request extensions; returns 403 on Deny. Enforces `Decision::Allow` obligations (added M15) — if obligations are non-empty but not satisfied via `ObligationFulfillment` in request extensions, returns 403.
- `ownership`: `is_owner()` / `is_same_tenant()` — cross-tenant access is blocked before policy evaluation, regardless of policy rules.
- `testkit`: `MockAuthorizer`, `test_subject`, `test_subject_with_tenant` — available to downstream crate tests.

### `secure_network` (MASVS M1 — MASVS-NETWORK)

Mobile network transport security: TLS configuration validation (`TlsPolicy`), certificate pinning verification (`CertPinValidator` with SPKI SHA-256 hashing), and cleartext traffic detection (`CleartextDetector` with localhost exemptions). All types are pure Rust policy objects — no TLS handshakes or platform SDK imports. Consuming apps provide raw certificate chains and TLS parameters; the crate validates against configurable policies and emits `TlsViolation`, `CertPinFailure`, and `CleartextBlocked` security events. Covers MASVS-NETWORK-1 (secure connections) and MASVS-NETWORK-2 (custom certificate validation).

### `secure_resilience` (MASVS M5 — MASVS-RESILIENCE)

Anti-tampering and environment detection: environment signal types (`EnvironmentSignal` — root/jailbreak, emulator, debugger), app integrity verification (`IntegrityCheck` — signature hash, store origin, resource integrity), and RASP policy engine (`RaspEngine` with configurable `RaspPolicy`). The crate is a pure policy engine — consuming apps implement platform-specific detection and feed signals into this crate. Responses are configurable per signal type (`ResponseAction`: Allow/Warn/Block/Degrade). The engine maintains aggregate `ThreatLevel` from accumulated signals using weighted scoring with confidence multipliers. Emits `EnvironmentThreat` and `IntegrityViolation` security events. Covers MASVS-RESILIENCE-1 (environment detection), MASVS-RESILIENCE-2 (integrity verification), and MASVS-RESILIENCE-3 (RASP responses).

### `secure_data` (M7 — OWASP C8, M20 — OWASP C2/C7, M25 — OWASP C2)
Data protection: `SecretBox<T>` wrapper (no `Debug`/`Display`/`Serialize`), envelope encryption (`encrypt_for_storage`/`decrypt_for_use`), key lifecycle management, `KeyProvider` trait for KMS/Vault/FIPS HSM backends. `zeroize`-on-drop for key material. Password hashing via Argon2id (`hash_password`/`verify_password`) with PHC string format output, constant-time verification, and redacted `PasswordHash` type (feature `password`). Crypto agility via `CryptoAlgorithm` enum (AES-256-GCM, XChaCha20-Poly1305) and `AlgorithmPolicy` for algorithm selection/enforcement. Algorithm tag and key version stored in encrypted envelopes for transparent migration. Azure Key Vault provider behind `azure-kv` feature flag (wrap/unwrap only — key material never exposed).

### `secure_reference_service` (M8)

Reference axum service demonstrating full integration of all eight library crates. Provides working CRUD routes with end-to-end security coverage and startup configuration validation.

#### Mandatory Middleware Ordering

```
Request →
  1. TraceLayer           (tower-http)        — distributed tracing span (outermost)
  2. CatchPanicLayer      (tower-http)        — catch panics, return safe 500
  3. SetRequestIdLayer    (tower-http)        — assign X-Request-Id header
  3b. PropagateRequestIdLayer (tower-http)   — echo X-Request-Id to response
  4. SecurityHeadersLayer (secure_boundary)  — HSTS, CSP, X-Content-Type-Options, etc.
  5. TimeoutLayer         (tower-http)        — request-level timeout (resilience)
  6. ConcurrencyLimitLayer (tower)            — bulkhead / bounded concurrency (resilience)
  7. DevAuthLayer         (reference service) — identity resolution from X-Dev-Subject header
  8. Route handler        — SecureJson<T> extraction → authz check → business logic
← Response
```

**Note**: `SecurityHeadersLayer` requires `Response<Body>` directly. `TraceLayer` (which wraps the body type) must therefore be applied as the outermost layer separately, not chained inside the same `ServiceBuilder`.

#### Key Design Choices

- `DevAuthLayer` is **development only** — extracts actor identity from `X-Dev-Subject` / `X-Dev-Tenant` / `X-Dev-Roles` headers. Must be replaced with a real `IdentitySource` implementation before production.
- `SecurityConfig::validate()` runs at startup and calls `std::process::exit(1)` on any misconfiguration — the service never binds a port with invalid config.
- Route handlers call `DefaultSubjectResolver::resolve()` to convert `AuthenticatedIdentity` → `Subject` before every `Authorizer::authorize()` call, demonstrating the `IdentitySource` → `SubjectResolver` → `Authorizer` composition chain.
- Tenant isolation is enforced in the GET handler: if an item's `tenant_id` is set, the requesting subject's tenant must match.
- `StaticDevKeyProvider` and `KeyRing` are wired into `AppState` for demonstration — dev/test only.
- Resilience: `TimeoutLayer` (request-level timeout) + `ConcurrencyLimitLayer` (bulkhead) prevent resource exhaustion.

### `secure_smoke_service` (M16, M8)

Security smoke-test microservice with 54 routes, each exercising a specific security control against a known attack class. Includes 15 mobile security routes covering MASVS controls (NETWORK, STORAGE, AUTH, PLATFORM, RESILIENCE, PRIVACY). Designed for automated DAST scanning with OWASP ZAP.

**Differences from `secure_reference_service`:**

- Uses `TokenValidator` (HS256 JWT) for authentication instead of `DevAuthLayer` — closer to production authentication flow.
- No `ConcurrencyLimitLayer` / `TimeoutLayer` — smoke tests focus on security controls, not resilience.
- Every route targets a single attack class, making failures easy to diagnose.

#### Route Categories (54 routes)

| Category | Count | Routes |
|---|---|---|
| Input validation | 12 | xss, sqli, cmdi, path-traversal, xxe, deserialization, mass-assignment, header-injection, unicode-bypass, body-bomb, deep-nesting, field-flood |
| Output encoding | 4 | reflect-html, reflect-url, reflect-json, headers |
| Authentication | 6 | jwt, expired, alg-none, tampered, wrong-issuer, session |
| Authorization | 5 | allow, deny, cross-tenant, privilege-escalation, idor |
| Data protection | 5 | encrypt, decrypt, decrypt-tampered, secret-debug, key-rotation |
| Error handling | 4 | internal, dependency, panic, validation |
| Security events | 2 | log-injection, redaction |
| Mobile — Network | 3 | tls-version, cert-pin, cleartext |
| Mobile — Storage | 2 | storage-policy, sensitive-buffer |
| Mobile — Auth | 2 | biometric, step-up |
| Mobile — Platform | 3 | deep-link, webview-url, clipboard |
| Mobile — Resilience | 2 | root-detect, app-integrity |
| Mobile — Privacy | 3 | pii-classify, pseudonymize, consent |
| Health | 1 | /health |

#### OpenAPI Spec

`openapi.yaml` documents all routes with request/response schemas for OWASP ZAP DAST scanning (M17).

### OWASP ZAP DAST Pipeline (M17)

Automated Dynamic Application Security Testing using OWASP ZAP (Checkmarx ZAP) validates security controls from an external attacker's perspective.

**Pipeline flow:**

```
cargo build -p secure_smoke_service
       │
       ▼
cargo run -p secure_smoke_service   (127.0.0.1:3001)
       │
       ▼
Generate HS256 JWT  ──────────────▶  ZAP Replacer (Authorization header)
       │
       ▼
docker run zaproxy/zaproxy zap-api-scan.py
  ├── Input:  openapi.yaml  (OpenAPI 3.1 spec)
  ├── Config: zap-rules.tsv (rule actions: IGNORE/WARN/FAIL)
  ├── Auth:   Bearer JWT    (via Replacer add-on)
  └── Output: zap-report.html, zap-report.json
       │
       ▼
python3 scripts/zap_check.py
  ├── Parse:    zap-report.json
  ├── Baseline: zap-baseline.json (suppressed false positives)
  └── Gate:     exit 1 on High/Critical (risk code ≥ 3)
```

**Key files:**

| File | Purpose |
|---|---|
| `scripts/zap_scan.sh` | Orchestrator: build, start service, run ZAP Docker, check results |
| `scripts/zap_check.py` | Report parser: gates on high/critical findings, respects baseline |
| `scripts/zap-rules.tsv` | ZAP rule customisation (per-rule IGNORE/WARN/FAIL) |
| `scripts/zap-baseline.json` | Known false positives with mandatory written justification |
| `.github/workflows/zap.yml` | CI workflow (Linux only, runs on push/PR to main) |

**Authentication**: ZAP uses a valid HS256 JWT injected via the Replacer add-on so it can test authenticated routes (`/smoke/auth/*`, `/smoke/authz/*`). The JWT is generated with the smoke service's dev-only secret.

**CI gating**: The build fails if any High or Critical finding is detected that is not suppressed in the baseline file. Medium/Low/Informational findings are reported but do not block.

### Dastardly (Burp Suite) DAST Pipeline

[Dastardly](https://portswigger.net/burp/dastardly) from PortSwigger complements ZAP with a crawl-based scan powered by Burp Scanner's engine. It checks for XSS, SQL injection, OS command injection, path traversal, SSRF, XXE, and improper input handling.

**Pipeline flow:**

```
cargo run -p secure_smoke_service   (127.0.0.1:3001)
       │
       ▼
docker run public.ecr.aws/portswigger/dastardly:latest
  ├── Start URL:  /dast-index  (HTML page linking all routes)
  ├── Crawl:      Follows links & forms to discover endpoints
  ├── Audit:      Burp Scanner active + passive checks
  └── Output:     dastardly-report.xml (JUnit XML)
       │
       ▼
Gate on Dastardly exit code
  ├── 0 = No LOW/MEDIUM/HIGH findings
  └── non-zero = Actionable findings detected
```

**Route discovery**: Dastardly is crawl-based (no OpenAPI input). The smoke service exposes a `/dast-index` route that serves an HTML page with anchor links to all GET routes and forms for all POST routes, giving the crawler full attack surface coverage.

**Key files:**

| File | Purpose |
|---|---|
| `scripts/dastardly_scan.sh` | Orchestrator: build, start service, run Dastardly Docker, check results |
| `.github/workflows/dastardly.yml` | CI workflow (uses official `PortSwigger/dastardly-github-action`) |
| `/dast-index` route (in `lib.rs`) | HTML link/form index for crawler discovery |

**CI gating**: Dastardly exits non-zero on LOW/MEDIUM/HIGH findings; Info-level items are reported but do not block.

---

## Security Headers (added in M4)

Every response includes:
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- `Content-Security-Policy: default-src 'none'; ...`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: ...`

---

## Trust Boundaries

```
[Internet / Untrusted Clients]
        │
        ▼ TLS (mTLS for service-to-service)
[HTTP Edge — axum Router + tower Middleware]
        │  secure_boundary (validates all input)
        │  secure_output (encodes all output)
        │  security headers applied
        ▼
[Application Logic — Handlers]
        │  secure_authz (deny-by-default)
        │  secure_identity (authenticates subject)
        ▼
[Data Tier]
        │  secure_data (envelope encryption)
        │  security_events (tamper-evident audit)
        ▼
[External Systems: KMS, Vault, IdP, SIEM]
```

---

## Data Protection (`secure_data` — M7)

### Secret Types

Application code never holds raw `String` for secret values. Dedicated wrapper types use `zeroize::Zeroizing<T>` to zero memory on drop, suppress `Debug` and `Display` output, and serialize as `"[REDACTED]"`:

| Type | Purpose |
|---|---|
| `SecretString` | Generic secret string (passwords, tokens, API keys) |
| `SecretBytes` | Raw secret bytes (encryption key material, HMAC keys) |
| `ApiToken` | API token values |
| `DbPassword` | Database credentials |
| `SigningKeyRef` | Reference to a signing key alias (not raw key material) |

All types implement `expose_secret()` for controlled access to the inner value.

### Envelope Encryption

Application code calls `encrypt_for_storage()` and `decrypt_for_use()` — never raw AEAD primitives.

```
encrypt_for_storage(plaintext, key_alias, provider)
  → GenerateDataKey(alias) → (DEK, WrappedDEK, version)
  → AES-256-GCM(plaintext, DEK, nonce=OsRng, aad=metadata)
  → EnvelopeEncrypted { version, algorithm, key_alias, key_version,
                        wrapped_data_key, nonce, ciphertext, aad }

decrypt_for_use(envelope, provider)
  → UnwrapDataKey(wrapped_data_key, alias, version)
  → AES-256-GCM-Decrypt(ciphertext, DEK, nonce, aad)
  → plaintext
```

The AAD (`additional authenticated data`) binds the metadata to the ciphertext — any tampering with `key_alias`, `key_version`, or `algorithm` fields causes AEAD authentication to fail.

### Key Lifecycle

The `KeyRing` manages named key aliases with versioned lifecycle states:

```
Active      → encrypt + decrypt
DecryptOnly → decrypt only (rotation in progress)
Deactivated → no operations permitted
```

Rotation protocol:
1. `keyring.rotate(alias)` — current Active → DecryptOnly; new version → Active
2. Existing ciphertext is still decryptable (dual-read window)
3. `re_encrypt(old_envelope, new_alias, provider)` — migrates data to new key
4. `keyring.deactivate(alias, version)` — only after all data migrated; fails if last usable version

Safety invariant: deactivating the last active/decrypt-only version is rejected with `DataError::CannotDeactivateLastVersion`.

### Key Provider Abstraction

```rust
pub trait KeyProvider: Sealed + Send + Sync {
    fn generate_data_key(alias) → (DEK, WrappedDEK, version);
    fn unwrap_data_key(wrapped, alias, version) → DEK;
}
```

Available implementations:
- `StaticDevKeyProvider` — deterministic XOR-based wrapping (dev/test only)
- `VaultKeyProvider` — HashiCorp Vault Transit secrets engine (feature flag: `vault`). Uses `POST /v1/transit/datakey/plaintext/{alias}` to generate data keys and `POST /v1/transit/decrypt/{alias}` to unwrap them. Auth via `X-Vault-Token` header. Requires `reqwest` with `rustls-tls`.
- `AwsKmsKeyProvider` — AWS KMS `GenerateDataKey`/`Decrypt` (feature flag: `aws-kms`). Uses `aws-sdk-kms` with standard AWS credential chain. Supports custom endpoint URLs for LocalStack/mock testing.

All providers are behind Cargo feature flags and off by default. The workspace builds and all tests pass without any provider features enabled.

### Secret References in Config

Config files carry references to secrets, not the secrets themselves:

| Scheme | Example | Resolves to |
|---|---|---|
| `vault://` | `vault://kv/db-credentials#password` | Vault KV secret field |
| `kms://` | `kms://alias/app-prod-key` | KMS key alias (not resolvable to string secret) |
| `env://` | `env://MY_SECRET_VAR` | Environment variable |

Invalid scheme strings are rejected with `DataError::InvalidSecretReference`.

### Secret Resolution

`resolve_secret()` resolves a `SecretReference` to a `SecretString` at runtime:
- `env://VAR` — reads `std::env::var(VAR)` at call time (not at parse time)
- `vault://path#field` — fetches from Vault KV v1 API (requires `vault` feature and `VAULT_ADDR`/`VAULT_TOKEN` env vars)
- `kms://...` — returns `DataError::InvalidSecretReference` (KMS keys are not string secrets)

### FIPS Readiness

The `fips` Cargo feature gates `aws-lc-rs` as an alternative AEAD backend. When enabled, FIPS 140-2/3 validated cryptographic primitives replace the default `aes-gcm` (RustCrypto) backend. Application code is unchanged — the backend swap is transparent.

### Mobile Storage Extensions (MASVS-STORAGE — M2)

The `mobile-storage` Cargo feature enables mobile-specific secure storage types (MASVS-STORAGE-1):

| Type | Purpose |
|---|---|
| `SensitiveBuffer` | Zeroize-on-drop byte buffer for transient sensitive data (biometric templates, PINs). Supports explicit `wipe()` and optional TTL-based expiry. Debug/Display output is `[REDACTED]`. |
| `BackupExclusion` | Metadata marker for backup exclusion policy. Defaults to `Exclude` (secure by default, per MASWE-0004). Serializable to JSON for platform integration. |
| `MobileStoragePolicy` | Policy type enforcing encryption and hardware keystore requirements based on `DataClassification`. `check_compliance()` returns `SecurityEvent` violations with `StoragePolicyViolation` kind. |

Classification-based policy auto-selection (`MobileStoragePolicy::for_classification`):
- `Public` / `Internal`: no encryption or hardware required
- `Confidential` / `PII` / `Regulated`: encryption required
- `Secret` / `Credentials`: encryption + hardware keystore required

All types are pure Rust policy objects — no platform-specific code or `unsafe` blocks. Actual platform keystore integration happens at the FFI boundary in the consuming mobile app.

---

## Adversarial Testing (Milestone 9)

Every public-facing parser, deserializer, and validator has adversarial test coverage via three complementary mechanisms:

### Fuzz Targets (`cargo-fuzz` / `libfuzzer-sys`)

Fuzz targets are located at `crates/<crate>/fuzz/fuzz_targets/`. They require nightly Rust and `cargo-fuzz`:

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz

# Run a target (example — 60-second minimum)
cd crates/secure_boundary
cargo +nightly fuzz run fuzz_normalize -- -max_total_time=60
```

| Crate | Fuzz Target | Entry Point |
|---|---|---|
| `secure_boundary` | `fuzz_normalize` | `normalize::to_nfc`, `normalize::normalize` |
| `secure_boundary` | `fuzz_validate` | `normalize::trim_whitespace`, `normalize::normalize_email` |
| `secure_boundary` | `fuzz_deep_link` | `SafeDeepLink::try_from` with arbitrary URLs |
| `secure_boundary` | `fuzz_webview_url` | `SafeWebViewUrl::try_from` with arbitrary URLs |
| `secure_output` | `fuzz_html_encode` | `HtmlEncoder::encode` |
| `secure_output` | `fuzz_url_encode` | `UrlEncoder::encode` |
| `secure_identity` | `fuzz_token_validate` | `TokenValidator` JWT parsing with arbitrary bytes |
| `secure_data` | `fuzz_encrypt_decrypt` | `decrypt_for_use` with corrupted ciphertext |
| `secure_data` | `fuzz_sensitive_buffer` | `SensitiveBuffer` lifecycle with arbitrary bytes |
| `secure_network` | `fuzz_tls_policy` | `TlsPolicy::validate()` with arbitrary TLS parameters |
| `secure_network` | `fuzz_cert_pin` | `CertPinValidator::validate()` with arbitrary DER bytes |
| `secure_network` | `fuzz_cleartext` | `CleartextDetector::check()` with arbitrary URLs |
| `secure_resilience` | `fuzz_rasp_signals` | `RaspEngine::process()` with arbitrary signal sequences |
| `secure_privacy` | `fuzz_pii_classifier` | `PiiClassifier::classify()` with arbitrary strings |
| `secure_privacy` | `fuzz_pseudonymizer` | `Pseudonymizer::pseudonymize()` with arbitrary identifiers |
| `security_events` | `fuzz_sanitize` | `sanitize_for_text_sink` with arbitrary control characters |
| `security_events` | `fuzz_mobile_redaction` | `MobileRedactionEngine` with arbitrary strings |

### Property Tests (`proptest`)

Property tests use `proptest = "1"` and run as part of the normal `cargo test --workspace` suite. Each test generates 256–1000 random cases per run.

| Test File | Property Verified |
|---|---|
| `secure_boundary/tests/prop_validation.rs` | NFC idempotency, normalize no-panic, trim never grows |
| `secure_boundary/tests/prop_deep_link_webview.rs` | Dangerous scheme rejection, file:// URL rejection, no-panic |
| `secure_output/tests/prop_encoding.rs` | No raw `<>"'` after HTML encoding, no `<script>` tag |
| `secure_identity/tests/prop_session.rs` | Session IDs always unique, creation succeeds |
| `secure_data/tests/prop_encryption.rs` | Encrypt→decrypt roundtrip; tampered ciphertext always rejected |
| `secure_network/tests/prop_tls_cleartext.rs` | TLS version rejection below minimum, cleartext HTTP always blocked, HTTPS always secure |
| `secure_resilience/tests/prop_rasp.rs` | Block decision consistency, permissive policy allows all, process no-panic |
| `secure_privacy/tests/prop_pseudonymizer.rs` | Deterministic output, non-reversibility, salt isolation, classify no-panic |
| `security_events/tests/prop_redaction.rs` | Secret values never appear verbatim after redaction; no raw newlines after sanitization |
| `secure_authz/tests/prop_deny_default.rs` | Empty policy always returns `Decision::Deny` for any subject/action/resource |

### Timing Tests (Welch's t-test)

Timing tests are marked `#[ignore]` for CI because they require a stable, low-noise environment. Run them locally:

```bash
cargo test -- timing_ --ignored
```

| Test File | What Is Verified |
|---|---|
| `secure_identity/tests/timing_token_compare.rs` | JWT validation timing shows no statistically significant difference (Welch's t-test p > 0.05) |
| `secure_data/tests/timing_crypto.rs` | AEAD tag verification timing shows no statistically significant difference |

Timing correctness for HMAC-SHA256 and AES-256-GCM is enforced at the library level (`ring` / `aes-gcm`). These tests catch regressions, not prove constant-time — use `dudect` or `ctgrind` for formal verification.

### CVE Regression Tests

| Test File | CVE / Attack Pattern |
|---|---|
| `security_events/tests/cve_regression.rs` | Log injection (CWE-117 / CVE-2019-10081 pattern); null byte injection; `AuditChain` tamper detection |
| `secure_identity/tests/cve_regression.rs` | JWT `alg:none` bypass (CVE-2015-9235); tampered signature rejected; expired/wrong-issuer JWT rejected |
| `secure_boundary/tests/cve_regression.rs` | Unicode normalization bypass; CRLF injection; homograph attack; email normalization |
| `secure_network/tests/cve_maswe_0050_cleartext.rs` | MASWE-0050: Cleartext traffic variants (HTTP, FTP, telnet, custom ports) always detected |
| `secure_network/tests/cve_maswe_0052_cert_validation.rs` | MASWE-0052: Insecure certificate validation (empty pins, random DER, pin matching) |
| `secure_boundary/tests/cve_maswe_0058_deep_links.rs` | MASWE-0058: Deep link scheme hijacking (javascript, data, vbscript, blob, path traversal) |
| `secure_boundary/tests/cve_maswe_0069_webview_files.rs` | MASWE-0069: WebView file access (file://, content://, data scheme, domain allowlist) |
| `secure_resilience/tests/cve_maswe_0097_root_detection.rs` | MASWE-0097: Root/jailbreak detection signal processing and threat escalation |
| `secure_privacy/tests/cve_maswe_0109_pii_leakage.rs` | MASWE-0109: PII leakage in log/event data (email, phone, IP, IMEI, custom patterns) |
| `security_events/tests/cve_maswe_0001_sensitive_logs.rs` | MASWE-0001: Sensitive device identifiers in logs (IMEI, MAC, GPS, IDFV, IDFA, GAID) |

### Memory Safety (`cargo miri`)

`cargo miri` requires nightly. All crates use `#![forbid(unsafe_code)]` and should be clean:

```bash
cargo +nightly miri test --workspace
```

### Hash-Chain Audit Trail (`AuditChain`)

`security_events::AuditChain` provides a tamper-evident SHA-256 hash-linked chain:

- Each entry hash = `SHA256(previous_entry_hash_hex || event_json)`
- `AuditChain::verify()` recomputes all hashes and detects any retroactive tampering
- Genesis entry uses empty-string prefix for the hash computation

---

## Attack Trees

Four attack trees document concrete attack paths and mitigations:

- [`docs/attack-trees/identity.md`](./docs/attack-trees/identity.md) — authentication/identity bypass
- [`docs/attack-trees/authorization.md`](./docs/attack-trees/authorization.md) — privilege escalation, tenant escape
- [`docs/attack-trees/data-protection.md`](./docs/attack-trees/data-protection.md) — secret exfiltration, crypto failures
- [`docs/attack-trees/input-output.md`](./docs/attack-trees/input-output.md) — injection via input and output paths

---

## Milestone Progress

See the [Milestone Tracker](./docs/slo/completed/runbook-sunlit-security-libraries.md#milestone-tracker) in the runbook.

---

## Supply-Chain Security

### Tools & Enforcement

| Tool | Version | Purpose |
|---|---|---|
| `cargo-audit` | ≥ 0.22 | Scans `Cargo.lock` against the RustSec advisory database |
| `cargo-deny` | ≥ 0.19 | Enforces license policy, bans, and source registry restrictions |
| `cargo-vet` | ≥ 0.10 | Maintains a third-party crate audit trail |

### Dependency Policy

Configured in [`deny.toml`](./deny.toml):

- **Advisories**: Known vulnerabilities are errors. Unmaintained and yanked crates are errors. Advisory ignores require written justification.
- **Licenses**: Allowlist-based. Permitted: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, CC0-1.0. Copyleft denied by default; narrow per-crate exceptions with justification.
- **Bans**: Multiple versions warn. No wildcard version requirements.
- **Sources**: Only crates.io is permitted. Unknown registries and git sources denied.

### Audit Trail (`supply-chain/`)

`cargo-vet` maintains an audit trail in `supply-chain/`:
- `config.toml` — vet configuration
- `audits.toml` — self-audits for first-party crates; manual audits for third-party crates
- `imports.lock` — cryptographically-locked import from trusted auditors

All 248 third-party dependencies are accounted for via exemptions (bootstrapped at workspace initialization, requiring `safe-to-deploy` or `safe-to-run` criteria as appropriate).

### CI Enforcement

`.github/workflows/ci.yml` runs on every push and pull request:
- **test** job: matrix across Linux, macOS, Windows — format, clippy, tests, docs
- **supply-chain** job: Linux only — `cargo audit`, `cargo deny check`, `cargo vet`

Local developers run the same checks via `bash scripts/audit.sh` (Linux/macOS) or `pwsh scripts/audit.ps1` (Windows).

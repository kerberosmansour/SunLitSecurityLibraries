# Completion — M26 Documentation & Ergonomics Retrofit

**Status**: done
**Started**: 2026-04-12
**Completed**: 2026-04-12

## Objective

Add `# Examples` doc sections to every public type, trait, function, and method across
all 8 security crates. Add `# Errors` sections to fallible functions where missing.
Add convenience free functions to `secure_output` for one-line encoding.

## Deliverables

### Doc examples added (116 new doc tests)

| Crate | Items documented | Notes |
|-------|-----------------|-------|
| security_core | DataClassification, SecuritySeverity, ReasonCode, SecretRef, CorrelationContext, RedactedDisplay, SystemTimeSource, MockTimeSource, AuthenticatedIdentity, ActorId, TenantId, RequestId, TraceId, ResourceId, PolicyVersion | + `# Errors` on IdentitySource::resolve |
| secure_errors | capture_backtrace, attach_context, ErrorClassification, AppError, PublicError, into_response_parts, retry_after_seconds, ErrorContext, catch_panic_to_safe_response, ErrorReportBuilder, ErrorMappingLayer | Converted `ignore` example to real |
| security_events | EventOutcome, EventValue, EventKind, emit_security_event, RedactionStrategy, RedactionPolicy, RedactionEngine, RateLimiter, DetectionEngine, DetectionPoint, sanitize_for_text_sink, SecurityContext | |
| secure_output | OutputEncoder, HtmlEncoder, UrlEncoder, JsStringEncoder, CssEncoder, XmlEncoder, JsonEncoder, sanitize_uri_scheme | + `# Errors` on sanitize_uri_scheme |
| secure_boundary | ViolationKind, BoundaryViolation, SafePath, SafeFilename, SafeCommandArg, SafeUrl, SafeRedirectUrl, SqlIdentifier, LdapSafeString, ValidationContext, SecureValidate, RequestLimits, BoundaryRejection, sanitize_header_value, SecurityHeadersLayer, UserId, OrderId, OpaquePublicId, SecureDto, SecureJson, SecureQuery, SecurePath, to_nfc, trim_whitespace, normalize_email, normalize | |
| secure_data | SecretString, SecretBytes, ApiToken, DbPassword, SigningKeyRef, ReadOnce, KeyVersionStatus, KeyVersionEntry, KeyRing, EnvelopeEncrypted, SecretReferenceProvider, SecretReference, DataError, RotationPlan, StaticDevKeyProvider, redact, RedactedField | |
| secure_identity | TokenKind, AuthenticationRequest, IdentityError, Session, SessionManager, InMemorySessionManager, ApiKeyAuthenticator, TokenValidatorConfig, TokenValidator, AsymmetricTokenValidator | |
| secure_authz | Subject, Action, ResourceRef, Decision, DenyReason, Authorizer, DefaultAuthorizer, MockAuthorizer, test_subject, is_owner, is_same_tenant, DecisionCache, PolicyError | |

### Convenience free functions (6 new)

- `secure_output::html::encode()`
- `secure_output::url::encode()`
- `secure_output::js::encode()`
- `secure_output::css::encode()`
- `secure_output::xml::encode()`
- `secure_output::json::encode()`

## Verification

- `cargo test --doc --workspace` → 168 passed, 0 failed
- `cargo test --workspace` → all pass, 0 failures
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` → 0 warnings
- No logic changes, no API breaking changes

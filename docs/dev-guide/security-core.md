# `security_core` — Developer Guide

> **OWASP C1**: Shared foundation types for the SunLit security workspace.

`security_core` provides the foundational types, traits, and abstractions that every other SunLit crate depends on. It contains no business logic and no I/O — only type definitions, sealed traits, and identity abstractions.
It also includes the typed variant-analysis report schema used to record follow-up searches after a security finding.

---

## Quick Start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
security_core = "0.1.2"
```

---

## Core Concepts

### ID Newtypes

All identifiers are newtype wrappers around `uuid::Uuid`. They are **not** type aliases — you cannot accidentally pass an `ActorId` where a `TenantId` is expected.

```rust
use security_core::types::{ActorId, TenantId, RequestId, TraceId, ResourceId, PolicyVersion};
use uuid::Uuid;

// Create from an existing UUID
let actor = ActorId::from(Uuid::new_v4());
let tenant = TenantId::from(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());

// Auto-generate (only RequestId and TraceId support this)
let req_id = RequestId::generate();
let trace_id = TraceId::generate();

// Access the inner UUID explicitly — no implicit Deref
let uuid: &Uuid = actor.as_inner();
let uuid: Uuid = actor.into_inner();

// Display delegates to UUID formatting
println!("Actor: {actor}"); // → "550e8400-e29b-41d4-a716-446655440000"
```

**Design rationale**: Newtypes prevent accidental ID mixing at compile time. Without them, all IDs would be `Uuid` and a function like `check_access(user: Uuid, tenant: Uuid)` could silently accept swapped arguments.

### Data Classification

Every piece of data in the system has a sensitivity level. The `DataClassification` enum drives automatic redaction in `security_events`:

```rust
use security_core::classification::DataClassification;

// Ordered from least to most sensitive
assert!(DataClassification::Public < DataClassification::Internal);
assert!(DataClassification::Internal < DataClassification::Confidential);
assert!(DataClassification::Confidential < DataClassification::PII);
assert!(DataClassification::PII < DataClassification::Regulated);
assert!(DataClassification::Regulated < DataClassification::Secret);
assert!(DataClassification::Secret < DataClassification::Credentials);
```

| Classification | When to Use | Redaction Behavior |
|---|---|---|
| `Public` | Publicly shareable data | Passed through unchanged |
| `Internal` | Not for public disclosure | Passed through unchanged |
| `Confidential` | Business-sensitive data | Replaced with `[REDACTED]` |
| `PII` | Names, emails, addresses | Hashed (`SHA256:<hex>`) |
| `Regulated` | HIPAA/GDPR regulated | Hashed (`SHA256:<hex>`) |
| `Secret` | Keys, tokens, passwords | Replaced with `[REDACTED]` |
| `Credentials` | Authentication credentials | Dropped entirely from logs |

### Correlation Context

Bundle request-scoped IDs for propagating through the call stack:

```rust
use security_core::context::CorrelationContext;
use security_core::types::{RequestId, TraceId, ActorId};

let ctx = CorrelationContext::new(RequestId::generate())
    .with_trace(TraceId::generate())
    .with_actor(ActorId::from(uuid::Uuid::new_v4()));

// Access individual IDs
let req_id = ctx.request_id();
let trace = ctx.trace_id();   // Option<&TraceId>
let actor = ctx.actor_id();   // Option<&ActorId>
```

### Secret References

`SecretRef` is a safe wrapper for secrets-manager URIs. Its `Debug` output is always redacted:

```rust
use security_core::context::SecretRef;

let secret = SecretRef::new("vault://kv/prod-db#password".to_string());

// Safe for logging — never leaks the URI
println!("{:?}", secret); // → SecretRef(REDACTED)

// Explicit access when needed
let uri: &str = secret.as_uri();
```

### Reason Codes

Stable, machine-readable codes for security decisions:

```rust
use security_core::context::ReasonCode;

const POLICY_DENIED: ReasonCode = ReasonCode::new("policy_denied");
const TENANT_MISMATCH: ReasonCode = ReasonCode::new("tenant_mismatch");

println!("{POLICY_DENIED}"); // → "policy_denied"
```

---

## Implementing `IdentitySource`

`IdentitySource` is the **only open trait** in `security_core`. It is the integration point between your identity provider and the rest of the SunLit stack. Every identity provider — whether it's `secure_identity`, Keycloak, Auth0, or a custom OIDC client — implements this trait.

```rust
use security_core::identity::{AuthenticatedIdentity, IdentityResolutionError, IdentitySource};
use security_core::types::ActorId;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

struct MyKeycloakAdapter {
    jwks_url: String,
}

impl IdentitySource for MyKeycloakAdapter {
    async fn resolve(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, IdentityResolutionError> {
        // Validate JWT against your IdP's JWKS endpoint
        let claims = validate_jwt(token, &self.jwks_url)
            .map_err(|_| IdentityResolutionError::InvalidToken)?;

        Ok(AuthenticatedIdentity {
            actor_id: ActorId::from(claims.sub),
            tenant_id: claims.tenant.map(|t| t.into()),
            roles: claims.roles,
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}
```

**Key invariant**: `secure_authz` depends on `IdentitySource`, not `secure_identity`. Any type implementing `IdentitySource` works with the authorization engine.

### `AuthenticatedIdentity` Fields

| Field | Type | Description |
|---|---|---|
| `actor_id` | `ActorId` | The authenticated user or service account |
| `tenant_id` | `Option<TenantId>` | Multi-tenant context (if applicable) |
| `roles` | `Vec<String>` | Roles assigned to this identity |
| `attributes` | `HashMap<String, String>` | Additional claims (e.g., department, clearance level) |
| `authenticated_at` | `OffsetDateTime` | When authentication occurred |

### Error Handling

```rust
use security_core::identity::IdentityResolutionError;

// Available error variants
let err = IdentityResolutionError::InvalidToken;      // Bad signature/format
let err = IdentityResolutionError::Expired;            // Token expired
let err = IdentityResolutionError::ProviderUnavailable; // IdP temporarily down
let err = IdentityResolutionError::Other(              // Unexpected errors
    Box::new(std::io::Error::new(std::io::ErrorKind::Other, "connection reset"))
);
```

---

## Redaction

The `Redact` trait is **sealed** — only internal types can implement it. Use `RedactedDisplay` to wrap any value for safe logging:

```rust
use security_core::redact::RedactedDisplay;

let password = RedactedDisplay::new("super-secret-pass");

// Safe for logging — always shows [REDACTED]
println!("{}", password);   // → [REDACTED]
println!("{:?}", password); // → [REDACTED]

// Access the real value when needed
let actual: &str = password.inner();
assert_eq!(actual, "super-secret-pass");
```

---

## Security Severity

Used throughout the workspace for event classification:

```rust
use security_core::severity::SecuritySeverity;

// Ordered from least to most severe
assert!(SecuritySeverity::Info < SecuritySeverity::Low);
assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
assert!(SecuritySeverity::Medium < SecuritySeverity::High);
assert!(SecuritySeverity::High < SecuritySeverity::Critical);
```

---

## Testable Time

The `TimeSource` trait is sealed, but provides both real and mock implementations:

```rust
use security_core::time::{TimeSource, SystemTimeSource, MockTimeSource};
use time::macros::datetime;

// Real time — for production
let clock = SystemTimeSource;
let now = clock.now(); // OffsetDateTime::now_utc()

// Fixed time — for deterministic tests
let mock = MockTimeSource::new(datetime!(2025-01-01 00:00:00 UTC));
assert_eq!(mock.now(), datetime!(2025-01-01 00:00:00 UTC));
```

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `ActorId` | `types` | User/service account identifier |
| `TenantId` | `types` | Multi-tenant system tenant |
| `RequestId` | `types` | Inbound request ID (supports `generate()`) |
| `TraceId` | `types` | Distributed trace ID (supports `generate()`) |
| `ResourceId` | `types` | Resource (file/record/object) ID |
| `PolicyVersion` | `types` | Policy version identifier |
| `DataClassification` | `classification` | 7-level data sensitivity enum |
| `CorrelationContext` | `context` | Request-scoped correlation IDs |
| `ReasonCode` | `context` | Stable security decision code |
| `SecretRef` | `context` | Redacted secrets-manager URI |
| `IdentitySource` | `identity` | Open trait — implement for your IdP |
| `AuthenticatedIdentity` | `identity` | Resolved identity with roles/attributes |
| `IdentityResolutionError` | `identity` | Identity resolution failures |
| `RedactedDisplay<T>` | `redact` | Safe logging wrapper |
| `SecuritySeverity` | `severity` | 5-level severity enum |
| `SystemTimeSource` | `time` | Real system clock |
| `MockTimeSource` | `time` | Fixed clock for tests |

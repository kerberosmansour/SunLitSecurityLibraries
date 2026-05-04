# `secure_errors` — Developer Guide

> **OWASP C10**: Centralized error handling — no internal details ever leak to HTTP responses.

`secure_errors` provides a three-layer error model that separates internal diagnostic information from what clients see. SQL queries, hostnames, stack traces, and policy names stay inside the service boundary.

---

## Quick Start

```toml
[dependencies]
secure_errors = { path = "../secure_errors" }
```

---

## The Three-Layer Error Model

```
┌─────────────────────────────────────────────┐
│  Internal Layer (AppError)                  │
│  Full details: SQL text, hostnames, deps    │
│  NEVER sent to clients                      │
├─────────────────────────────────────────────┤
│  Operational Layer (ErrorClassification)    │
│  Retryable? Alertable? Security signal?     │
│  Used for routing/monitoring decisions      │
├─────────────────────────────────────────────┤
│  Public Layer (PublicError)                 │
│  Stable code + safe message + request_id    │
│  The ONLY thing sent over HTTP              │
└─────────────────────────────────────────────┘
```

### Layer 1: Internal Errors (`AppError`)

`AppError` is the central error type for your application. Use it throughout your business logic:

```rust
use secure_errors::kind::AppError;

fn process_order(order_id: &str) -> Result<(), AppError> {
    // Validation failure — client can fix this
    if order_id.is_empty() {
        return Err(AppError::Validation { code: "order_id_required" });
    }

    // Access denied — security signal
    if !user_has_access(order_id) {
        return Err(AppError::Forbidden { policy: "order_owner_policy" });
    }

    // Downstream dependency failure — retryable
    call_payment_service()
        .map_err(|_| AppError::Dependency { dep: "payment-service" })?;

    Ok(())
}
```

**All `AppError` variants:**

| Variant | Fields | HTTP Status | When to Use |
|---|---|---|---|
| `Validation` | `code: &'static str` | 400 | Client sent invalid input |
| `Forbidden` | `policy: &'static str` | 403 | Authorization denied |
| `NotFound` | — | 404 | Resource doesn't exist |
| `Conflict` | — | 409 | Duplicate/conflicting state |
| `Dependency` | `dep: &'static str` | 503 | Downstream service failure |
| `Crypto` | — | 500 | Cryptographic operation failed |
| `Internal` | — | 500 | Unexpected internal error |
| `RateLimit` | `retry_after_seconds: Option<u64>` | 429 | Too many requests |

### Layer 2: Operational Classification

`ErrorClassification` tells your monitoring/routing code how to handle an error:

```rust
use secure_errors::classify::ErrorClassification;
use secure_errors::kind::AppError;

let err = AppError::Dependency { dep: "postgres" };
let cls = ErrorClassification::for_error(&err);

if cls.is_retryable() {
    // Queue for retry
}
if cls.is_alertable() {
    // Page the on-call engineer
}
if cls.is_security_signal() {
    // Trigger security incident response
}
if cls.is_user_fixable() {
    // Show a helpful error message to the user
}
```

**Classification matrix:**

| Variant | Retryable | Alertable | Security Signal | User Fixable |
|---|---|---|---|---|
| `Validation` | — | — | — | ✓ |
| `Forbidden` | — | ✓ | ✓ | — |
| `NotFound` | — | — | — | ✓ |
| `Conflict` | — | — | — | ✓ |
| `Dependency` | ✓ | ✓ | — | — |
| `Crypto` | — | ✓ | ✓ | — |
| `Internal` | — | ✓ | — | — |
| `RateLimit` | ✓ | — | — | ✓ |

### Layer 3: Public Errors (`PublicError`)

`PublicError` is the **only** struct that should be serialized to HTTP responses:

```rust
use secure_errors::http::into_response_parts;
use secure_errors::kind::AppError;

let err = AppError::Dependency { dep: "SELECT * FROM users WHERE id = 42" };
let (status, public_err) = into_response_parts(&err);

// status == 503
// public_err.code == "temporarily_unavailable"
// public_err.message == "A downstream dependency is temporarily unavailable."
//
// The SQL query NEVER appears in the response.

let json = serde_json::to_string(&public_err).unwrap();
// {"code":"temporarily_unavailable","message":"A downstream dependency is temporarily unavailable."}
```

---

## Integrating with axum

### Option 1: Manual Mapping (Explicit Control)

```rust
use axum::{response::{IntoResponse, Response}, Json};
use http::StatusCode;
use secure_errors::{http::into_response_parts, kind::AppError};

async fn get_user(/* params */) -> Result<Json<UserResponse>, Response> {
    let user = find_user(id)
        .map_err(|e| {
            let (status, public_err) = into_response_parts(&e);
            (StatusCode::from_u16(status).unwrap(), Json(public_err)).into_response()
        })?;
    Ok(Json(user))
}
```

### Option 2: `ErrorMappingLayer` (Automatic)

Apply the layer once and return `AppError` directly from handlers:

```rust
use axum::{Router, routing::get};
use secure_errors::{kind::AppError, middleware::ErrorMappingLayer};

async fn get_user() -> Result<String, AppError> {
    Err(AppError::RateLimit { retry_after_seconds: Some(30) })
    // Automatically becomes: 429, {"code":"rate_limited",...}, Retry-After: 30
}

let app = Router::new()
    .route("/users", get(get_user))
    .layer(ErrorMappingLayer);
```

The `IntoResponse` impl for `AppError`:
- Maps each variant to the correct HTTP status code
- Serializes a safe `PublicError` JSON body
- Adds `Retry-After` header for `RateLimit` errors

### Extracting Retry-After

```rust
use secure_errors::http::retry_after_seconds;
use secure_errors::kind::AppError;

let err = AppError::RateLimit { retry_after_seconds: Some(60) };
assert_eq!(retry_after_seconds(&err), Some(60));

let err = AppError::NotFound;
assert_eq!(retry_after_seconds(&err), None);
```

---

## Panic Boundary

Catch panics at the service boundary without leaking internal details:

```rust
use secure_errors::panic::catch_panic_to_safe_response;

let (status, body) = catch_panic_to_safe_response(|| {
    panic!("connection pool exhausted on host db-primary-3.internal");
});

// status == 500
// body == {"code":"internal_error","message":"An internal error occurred."}
// The panic message (with hostname) is NOT in the response.
```

Use this at the outermost handler boundary or combine with Tower's `CatchPanicLayer`.

---

## Error Reports (Internal Logging)

For internal diagnostics, build a forensic error report with the builder:

```rust
use secure_errors::report::ErrorReport;
use security_core::types::{RequestId, ActorId, TenantId};

let report = ErrorReport::builder()
    .component("order-service")
    .cause("Connection refused to postgres-primary:5432".to_string())
    .request_id(RequestId::generate())
    .actor_id(ActorId::from(uuid::Uuid::new_v4()))
    .with_backtrace("at order_service::db::query (line 42)".to_string())
    .build();

// Log internally — never send to clients
tracing::error!(
    component = report.component(),
    cause = report.cause(),
    "Service error"
);
```

---

## Context Propagation

Store and retrieve request-scoped metadata in task-local storage:

```rust
use secure_errors::context_propagation::{
    set_error_context, get_error_context, clear_error_context, ErrorContext
};

// At the start of a request (e.g., in middleware)
set_error_context(ErrorContext {
    request_id: Some("req-abc-123".into()),
    actor_id: Some("user-456".into()),
    tenant_id: Some("tenant-789".into()),
});

// Later, in error handling code — no need to thread params through
if let Some(ctx) = get_error_context() {
    tracing::error!(
        request_id = ctx.request_id.as_deref().unwrap_or("unknown"),
        "Error occurred"
    );
}

// Clean up at the end of the request
clear_error_context();
```

---

## Security Incident Integration

`AppError` implements the sealed `SecurityIncident` trait. When security-relevant errors occur, emit them as audit events:

```rust
use secure_errors::incident::emit_event_for_incident;
use secure_errors::kind::AppError;

let err = AppError::Forbidden { policy: "admin_only" };

// Emits a SecurityEvent with:
//   kind: AuthzDeny (for Forbidden)
//   severity: High
//   outcome: Blocked
emit_event_for_incident(&err);
```

**Mapping table:**

| AppError Variant | Event Kind | Severity |
|---|---|---|
| `Forbidden` | `AuthzDeny` | High |
| `Crypto` | `ErrorEscalation` | High |
| `Dependency` | `ErrorEscalation` | Medium |
| `Internal` | `ErrorEscalation` | Medium |
| Others | — | Info |

---

## No-Leakage Guarantee

The following information **never** appears in HTTP responses:

- SQL queries or database identifiers
- Internal hostnames or IP addresses
- Stack traces or file paths
- Policy names or authorization rule details
- Dependency names or connection strings
- Panic messages

Every `AppError` variant maps to exactly one stable `code` string in the public response. The mapping is defined in `http::into_response_parts` and nowhere else.

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `AppError` | `kind` | Internal error enum (8 variants) |
| `PublicError` | `public` | Client-safe error struct |
| `ErrorClassification` | `classify` | Operational decision flags |
| `ErrorReport` | `report` | Forensic internal report |
| `ErrorReportBuilder` | `report` | Builder for `ErrorReport` |
| `ErrorContext` | `context_propagation` | Task-local request context |
| `ErrorMappingLayer` | `middleware` | Tower layer for automatic mapping |
| `into_response_parts()` | `http` | `AppError` → `(status, PublicError)` |
| `retry_after_seconds()` | `http` | Extract retry-after from `RateLimit` |
| `catch_panic_to_safe_response()` | `panic` | Panic boundary |
| `emit_event_for_incident()` | `incident` | Error → security event |
| `capture_backtrace()` | `capture` | Optional backtrace capture |

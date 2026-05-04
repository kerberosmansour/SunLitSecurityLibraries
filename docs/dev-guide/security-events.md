# `security_events` — Developer Guide

> **OWASP C9**: Security telemetry with classification-driven redaction, tamper-evident audit chains, and anomaly detection.

`security_events` provides structured security logging that ensures sensitive data is automatically redacted based on its classification. It includes AppSensor-style anomaly detection, threshold-based alerting, rate limiting, injection-safe formatting, per-event HMAC tamper evidence, event correlation helpers, and pluggable sinks for stdout, tracing, files, batching, and optional HTTP webhooks.

---

## Quick Start

```toml
[dependencies]
security_events = { path = "../security_events" }
```

---

## Emitting Security Events

Every security-relevant action in your application should produce a `SecurityEvent`:

```rust
use security_events::{SecurityEvent, EventKind, EventOutcome};
use security_events::emit::emit_security_event;
use security_core::severity::SecuritySeverity;

// Create an event
let event = SecurityEvent::new(
    EventKind::AdminAction,
    SecuritySeverity::High,
    EventOutcome::Success,
);

// Emit it (serializes to JSON via tracing)
emit_security_event(event);
```

### Enriching Events with Context

Add labeled metadata to events. Each label carries a `DataClassification` that controls how it's redacted:

```rust
use security_events::{SecurityEvent, EventKind, EventOutcome, EventValue};
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_core::types::{RequestId, TenantId};
use uuid::Uuid;

let mut event = SecurityEvent::new(
    EventKind::AuthnFailure,
    SecuritySeverity::High,
    EventOutcome::Failure,
);

// Set correlation fields
event.actor = Some("user@example.com".to_string());
event.request_id = Some(RequestId::generate());
event.tenant = Some(TenantId::from(Uuid::new_v4()));
event.source_ip = Some("203.0.113.42".parse().unwrap());
event.reason_code = Some("invalid_signature");

// Add classified labels — redaction is automatic
event.labels.insert("username".into(), EventValue::Classified {
    value: "alice@corp.com".into(),
    classification: DataClassification::PII,  // → hashed in output
});

event.labels.insert("token".into(), EventValue::Classified {
    value: "eyJhbGc...".into(),
    classification: DataClassification::Credentials,  // → dropped entirely
});

event.labels.insert("endpoint".into(), EventValue::Classified {
    value: "/api/v1/users".into(),
    classification: DataClassification::Public,  // → passed through
});
```

### Using `SecurityContext` for Enrichment

Build a reusable context for the duration of a request:

```rust
use security_events::context::SecurityContext;
use security_core::types::{RequestId, TraceId, ActorId, TenantId};

let ctx = SecurityContext::new()
    .with_request_id(RequestId::generate())
    .with_trace_id(TraceId::generate())
    .with_actor_id(ActorId::from(uuid::Uuid::new_v4()))
    .with_tenant_id(TenantId::from(uuid::Uuid::new_v4()))
    .with_session_id("sess_abc123".to_string());
```

### HMAC Signing for Tamper Evidence

Sign audit events before they cross a trust boundary or land in durable storage:

```rust
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::hmac::HmacEventSigner;
use security_events::kind::EventKind;

let signer = HmacEventSigner::new("audit-hmac-key")?;
let mut event = SecurityEvent::new(
    EventKind::AdminAction,
    SecuritySeverity::High,
    EventOutcome::Success,
);
signer.sign_event(&mut event)?;
assert!(signer.verify_event(&event)?);
# Ok::<(), security_events::hmac::HmacError>(())
```

### Correlating Related Events

Use `parent_event_id` to connect a root event to its follow-up actions during an investigation:

```rust
use security_core::severity::SecuritySeverity;
use security_events::correlation::{filter_by_parent, with_parent};
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;

let parent = SecurityEvent::new(
    EventKind::AdminAction,
    SecuritySeverity::Info,
    EventOutcome::Success,
);
let child = with_parent(
    SecurityEvent::new(
        EventKind::AuthzDeny,
        SecuritySeverity::Medium,
        EventOutcome::Blocked,
    ),
    parent.event_id,
);

let events = vec![parent.clone(), child];
assert_eq!(filter_by_parent(&events, parent.event_id).len(), 1);
```

### File, Batching, and Webhook Sinks

Compose the built-in sinks when you need local persistence or lower hot-path overhead:

```rust
use security_events::sink::{BatchingSink, FileSink};
use std::sync::Arc;
use std::time::Duration;

let dir = std::env::temp_dir().join("security-events-guide-example");
std::fs::create_dir_all(&dir)?;
let path = dir.join("audit.jsonl");
let file_sink = Arc::new(FileSink::new(&path)?);
let batching = BatchingSink::new(file_sink, 50, Duration::from_millis(50));
batching.flush()?;
let _ = std::fs::remove_dir_all(&dir);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Enable the optional `http-sink` feature to forward events to an external HTTPS webhook with `HttpWebhookSink`.

---

## Event Kinds

Use the appropriate `EventKind` for each security-relevant action:

| EventKind | When to Emit |
|---|---|
| `BoundaryViolation` | Invalid input rejected at the boundary |
| `AuthnFailure` | Failed authentication attempt |
| `MfaEvent` | MFA challenge issued or verified |
| `AuthzDeny` | Authorization denied |
| `CrossTenantAttempt` | Access attempted across tenant boundaries |
| `SecretAccess` | Secret material accessed |
| `KeyRotation` | Encryption key rotated |
| `AdminAction` | Administrative operation performed |
| `FileUploadAnomaly` | Suspicious file upload detected |
| `DeserializationAnomaly` | Unusual deserialization pattern |
| `ErrorEscalation` | Error promoted to security incident |
| `RateLimitBlock` | Request blocked by rate limiter |
| `AntiAutomation` | Automated attack pattern detected |

All kinds are `#[non_exhaustive]` — always include a wildcard arm in match statements.

---

## Redaction Engine

The redaction engine processes events before they're written to sinks. Sensitive labels are automatically redacted based on their classification:

```rust
use security_events::{RedactionEngine, RedactionPolicy, SecurityEvent, EventKind, EventOutcome, EventValue};
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;

// Use default redaction policy
let engine = RedactionEngine::with_default_policy();

let mut event = SecurityEvent::new(
    EventKind::AuthnFailure,
    SecuritySeverity::High,
    EventOutcome::Failure,
);

event.labels.insert("email".into(), EventValue::Classified {
    value: "alice@example.com".into(),
    classification: DataClassification::PII,
});

event.labels.insert("password".into(), EventValue::Classified {
    value: "hunter2".into(),
    classification: DataClassification::Credentials,
});

event.labels.insert("action".into(), EventValue::Classified {
    value: "login".into(),
    classification: DataClassification::Public,
});

let safe_event = engine.process_event(event);
// "email"    → "SHA256:a1b2c3..."  (PII is hashed for correlation without exposing data)
// "password" → (dropped entirely)  (Credentials are removed from the event)
// "action"   → "login"             (Public data passes through unchanged)
```

### Default Redaction Policy

| Classification | Strategy | Output |
|---|---|---|
| `Public` | Allow | Original value |
| `Internal` | Allow | Original value |
| `Confidential` | Redact | `[REDACTED]` |
| `PII` | Hash | `SHA256:<hex>` |
| `Regulated` | Hash | `SHA256:<hex>` |
| `Secret` | Redact | `[REDACTED]` |
| `Credentials` | Drop | Label removed entirely |

### Custom Redaction Policy

```rust
use security_events::redact::{RedactionPolicy, RedactionStrategy};

let policy = RedactionPolicy {
    public: RedactionStrategy::Allow,
    internal: RedactionStrategy::Allow,
    confidential: RedactionStrategy::Hash,   // hash instead of redact
    pii: RedactionStrategy::Redact,          // redact instead of hash
    regulated: RedactionStrategy::Redact,
    secret: RedactionStrategy::Drop,         // drop instead of redact
    credentials: RedactionStrategy::Drop,
};

let engine = RedactionEngine::new(policy);
```

---

## Anomaly Detection

The `DetectionEngine` provides AppSensor-style threshold-based escalation. It tracks per-actor activity and fires security events when thresholds are exceeded:

### Brute Force Detection

```rust
use security_events::detect::DetectionEngine;

// Escalate after 5 authorization denials within 60 seconds
let engine = DetectionEngine::new(5, 60);

// Record authorization failures — returns None until threshold hit
let result = engine.record_authz_denied("attacker@evil.com"); // None (1/5)
let result = engine.record_authz_denied("attacker@evil.com"); // None (2/5)
let result = engine.record_authz_denied("attacker@evil.com"); // None (3/5)
let result = engine.record_authz_denied("attacker@evil.com"); // None (4/5)
let result = engine.record_authz_denied("attacker@evil.com"); // None (5/5)
let result = engine.record_authz_denied("attacker@evil.com"); // Some(SecurityEvent) — Critical!

if let Some(escalation_event) = result {
    // escalation_event.kind == EventKind::AntiAutomation
    // escalation_event.severity == SecuritySeverity::Critical
    // Take action: block the actor, alert security team, etc.
}
```

### Cross-Tenant Probe Detection

Cross-tenant probes are **always** escalated immediately — no threshold:

```rust
use security_events::detect::DetectionEngine;

let engine = DetectionEngine::new(5, 60);

// Always returns a Critical security event
let event = engine.record_cross_tenant_probe(
    "user-123",     // actor
    "tenant-A",     // actor's tenant
    "tenant-B",     // resource's tenant (different!)
);

// event.kind == EventKind::CrossTenantAttempt
// event.severity == SecuritySeverity::Critical
// event.outcome == EventOutcome::Blocked
```

---

## Rate Limiting Events

Prevent log flooding with per-event-kind rate limiting:

```rust
use security_events::rate_limit::RateLimiter;
use security_events::EventKind;

// Allow max 10 events per kind within 60 seconds
let limiter = RateLimiter::new(10, 60);

if limiter.should_allow(&EventKind::AuthnFailure) {
    emit_security_event(event);
} else {
    // Suppressed — too many AuthnFailure events
}

// Each kind has independent counters
limiter.should_allow(&EventKind::AdminAction); // true (different kind)
```

---

## Tamper-Evident Audit Chain

For compliance requirements (SOC 2, NIST AU-9), use the `AuditChain` to create a SHA-256 hash-linked chain of events:

```rust
use security_events::{AuditChain, SecurityEvent, EventKind, EventOutcome};
use security_core::severity::SecuritySeverity;

let mut chain = AuditChain::new();

// Each event is linked to the previous via SHA-256
let event1 = SecurityEvent::new(EventKind::AdminAction, SecuritySeverity::High, EventOutcome::Success);
chain.append(event1);

let event2 = SecurityEvent::new(EventKind::KeyRotation, SecuritySeverity::Medium, EventOutcome::Success);
chain.append(event2);

// Verify the chain — detects any tampering
assert!(chain.verify());

// Access entries
for entry in chain.entries() {
    println!("Event: {:?}", entry.event.kind);
    println!("Hash: {}", entry.hash);
    println!("Previous: {:?}", entry.previous_hash);
}
```

---

## Log Injection Prevention

Always sanitize strings before writing to text-based sinks:

```rust
use security_events::sanitize::sanitize_for_text_sink;

let user_input = "admin\nINJECTED_LOG_LINE\rAnother line";
let safe = sanitize_for_text_sink(user_input);
// "admin\\nINJECTED_LOG_LINE\\rAnother line"
// No raw newlines or carriage returns — injection blocked

let with_control_chars = "normal\x00\x01\x02text";
let safe = sanitize_for_text_sink(with_control_chars);
// Control characters (0x00–0x1F except 0x0A/0x0D) → U+FFFD
```

---

## Sinks

Write events to different outputs using the sealed `SecuritySink` trait:

```rust
use security_events::sink::{StdoutJsonSink, TracingSink, SecuritySink};
use security_events::{SecurityEvent, EventKind, EventOutcome};
use security_core::severity::SecuritySeverity;

let event = SecurityEvent::new(
    EventKind::AuthzDeny,
    SecuritySeverity::High,
    EventOutcome::Blocked,
);

// NDJSON to stdout (one JSON object per line, atomic write via stdout lock)
let stdout_sink = StdoutJsonSink;
stdout_sink.write_event(&event);

// Via tracing (integrates with existing tracing subscribers)
let tracing_sink = TracingSink;
tracing_sink.write_event(&event);
```

---

## Integration with `secure_errors`

Security incidents from errors are automatically bridged:

```rust
use secure_errors::incident::emit_event_for_incident;
use secure_errors::kind::AppError;

// This automatically emits a SecurityEvent:
//   Forbidden → EventKind::AuthzDeny at High severity
//   Dependency → EventKind::ErrorEscalation at Medium severity
emit_event_for_incident(&AppError::Forbidden { policy: "admin_only" });
```

---

## Putting It All Together

A typical request flow with security events:

```rust
use security_events::{SecurityEvent, EventKind, EventOutcome, EventValue, RedactionEngine};
use security_events::emit::emit_security_event;
use security_events::detect::DetectionEngine;
use security_events::rate_limit::RateLimiter;
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use std::sync::Arc;

// App-level singletons
let detection = Arc::new(DetectionEngine::new(5, 60));
let limiter = Arc::new(RateLimiter::new(100, 60));
let redaction = RedactionEngine::with_default_policy();

// In a request handler...
async fn handle_login(
    username: &str,
    _password: &str,
) {
    // Authentication failed
    let mut event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::High,
        EventOutcome::Failure,
    );
    event.actor = Some(username.to_string());
    event.labels.insert("username".into(), EventValue::Classified {
        value: username.to_string(),
        classification: DataClassification::PII,
    });

    // Redact before emission
    let safe_event = RedactionEngine::with_default_policy().process_event(event);

    // Rate-limit check
    let limiter = RateLimiter::new(100, 60);
    if limiter.should_allow(&EventKind::AuthnFailure) {
        emit_security_event(safe_event);
    }

    // Check for brute force
    let detection = DetectionEngine::new(5, 60);
    if let Some(escalation) = detection.record_authz_denied(username) {
        emit_security_event(escalation);
        // Trigger account lockout, alert security team, etc.
    }
}
```

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `SecurityEvent` | `event` | Core audit event struct |
| `EventOutcome` | `event` | Success / Failure / Blocked / Unknown |
| `EventValue` | `event` | Classified label value |
| `EventKind` | `kind` | 14 event categories |
| `SecurityContext` | `context` | Request-scoped enrichment context |
| `RedactionEngine` | `redact` | Classification-driven redaction |
| `RedactionPolicy` | `redact` | Configurable redaction rules |
| `RedactionStrategy` | `redact` | Allow / Redact / Hash / Drop / Pseudonymize |
| `DetectionEngine` | `detect` | AppSensor-style anomaly detection |
| `DetectionPoint` | `detect` | Detection point categories |
| `RateLimiter` | `rate_limit` | Per-kind event throttling |
| `AuditChain` | `audit_chain` | SHA-256 tamper-evident chain |
| `ChainedAuditEntry` | `audit_chain` | Single chain entry |
| `StdoutJsonSink` | `sink` | NDJSON stdout sink |
| `TracingSink` | `sink` | tracing-based sink |
| `emit_security_event()` | `emit` | Emit an event via tracing |
| `sanitize_for_text_sink()` | `sanitize` | Injection-safe formatting |

# Integration Guide — Building a Secure axum Service

This guide shows how to compose all eight SunLit crates into a production axum service, following the patterns demonstrated by the `secure_reference_service`.

---

## Middleware Ordering

The order in which middleware layers are applied is critical. In axum, the **last `.layer()` call is the outermost** (handles the request first):

```
Request flow (outside → inside):
─────────────────────────────────────────────
1. TraceLayer             — distributed tracing span
2. CatchPanicLayer        — catch panics → safe 500
3. SetRequestIdLayer      — assign X-Request-Id
4. CORS layer             — deny-all by default; explicit allowlists only
5. FetchMetadataLayer     — block unsafe `Sec-Fetch-Site: cross-site` requests
6. SecurityHeadersLayer   — HSTS, CSP nonce, Permissions-Policy
7. TimeoutLayer           — request timeout
8. ConcurrencyLimitLayer  — bulkhead pattern
9. Identity middleware    — resolve AuthenticatedIdentity
─────────────────────────────────────────────
              ↓
       Route Handler
      (SecureJson + authz)
```

### Implementation

```rust
use axum::{Router, routing::{get, post}};
use secure_boundary::{
    fetch_metadata::FetchMetadataLayer,
    headers::SecurityHeadersLayer,
    secure_cors_defaults,
};
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{SetRequestIdLayer, PropagateRequestIdLayer, MakeRequestUuid},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use std::time::Duration;

// Health endpoint — no security middleware
let health_routes = Router::new()
    .route("/health", get(|| async { "ok" }));

// Protected routes
let api_routes = Router::new()
    .route("/items", post(create_item))
    .route("/items/{id}", get(get_item));

// Apply security middleware stack
let api_routes = api_routes.layer(
    ServiceBuilder::new()
        .layer(ConcurrencyLimitLayer::new(100))          // 8. Bulkhead
        .layer(TimeoutLayer::new(Duration::from_secs(30))) // 7. Timeout
        .layer(SecurityHeadersLayer::default().with_csp_nonce()) // 6. Security headers
        .layer(FetchMetadataLayer::new())                  // 5. Fetch Metadata validation
        .layer(secure_cors_defaults())                     // 4. Deny-all CORS by default
        .layer(PropagateRequestIdLayer::x_request_id())    // 3b. Echo request ID
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid)) // 3. Assign ID
        .layer(CatchPanicLayer::new())                     // 2. Panic boundary
);

// TraceLayer must be outermost (applied separately)
let app = Router::new()
    .merge(health_routes)
    .merge(api_routes)
    .layer(TraceLayer::new_for_http());                    // 1. Tracing
```

> **Why is `TraceLayer` separate?** It wraps the response body type, which would conflict with `SecurityHeadersLayer` if applied in the same `ServiceBuilder`.

---

## The Request Handler Pattern

Every secured handler follows this pattern:

```rust
use axum::{extract::{Path, State}, Extension, response::Response};
use secure_authz::{
    DefaultAuthorizer, DefaultSubjectResolver, SubjectResolver,
    Action, ResourceRef, Decision,
};
use secure_boundary::extract::SecureJson;
use secure_errors::http::into_response_parts;
use security_core::identity::AuthenticatedIdentity;

async fn create_item(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    payload: SecureJson<CreateItemDto>,
) -> Response {
    // 1. Resolve identity → subject
    let subject = DefaultSubjectResolver::resolve(&identity);

    // 2. Define what's being accessed
    let resource = ResourceRef::new("items");

    // 3. Authorize (deny by default)
    let decision = state.authorizer
        .authorize(&subject, &Action::Create, &resource)
        .await;

    if let Decision::Deny { .. } = decision {
        let (status, public_err) = into_response_parts(
            &secure_errors::kind::AppError::Forbidden { policy: "items_create" }
        );
        return (
            http::StatusCode::from_u16(status).unwrap(),
            axum::Json(public_err),
        ).into_response();
    }

    // 4. Extract validated input
    let dto = payload.into_inner();

    // 5. Business logic...
    todo!()
}
```

---

## Application State

```rust
use secure_authz::{DefaultAuthorizer, DefaultPolicyEngine};
use secure_data::{kms::StaticDevKeyProvider, keyring::KeyRing};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    pub authorizer: Arc<DefaultAuthorizer<DefaultPolicyEngine>>,
    pub key_provider: Arc<StaticDevKeyProvider>,
    pub key_ring: Arc<RwLock<KeyRing>>,
    // your application data...
}

impl AppState {
    async fn new() -> Self {
        // 1. Set up policy engine
        let engine = DefaultPolicyEngine::new_empty().await.unwrap();
        engine.add_policy("admin", "items", "read").await.unwrap();
        engine.add_policy("admin", "items", "create").await.unwrap();
        engine.add_policy("admin", "items", "write").await.unwrap();
        engine.add_policy("admin", "items", "delete").await.unwrap();
        engine.add_policy("reader", "items", "read").await.unwrap();

        let authorizer = Arc::new(DefaultAuthorizer::new(Arc::new(engine)));

        // 2. Set up encryption
        let key_provider = Arc::new(StaticDevKeyProvider::new());
        let mut key_ring = KeyRing::new();
        key_ring.add_key("app-data".into(), "v1".into());

        Self {
            authorizer,
            key_provider,
            key_ring: Arc::new(RwLock::new(key_ring)),
        }
    }
}
```

---

## Startup Validation

Validate configuration at startup — fail fast before binding a port:

```rust
#[tokio::main]
async fn main() {
    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // 2. Validate configuration
    validate_config();

    // 3. Build state and router
    let state = AppState::new().await;
    let app = build_router(state);

    // 4. Bind and serve
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("listening on 127.0.0.1:3000");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn validate_config() {
    use secure_data::config::SecretReference;

    // Validate secret references parse correctly
    if let Err(e) = SecretReference::parse("env://DATABASE_URL") {
        eprintln!("Invalid secret reference: {e}");
        std::process::exit(1);
    }

    // Validate identity provider configuration...
    // Validate policy engine has rules loaded...
}
```

---

## Output Encoding in Responses

When returning user-derived data in HTML, JSON-in-HTML, or other contexts:

```rust
use secure_output::{HtmlEncoder, JsStringEncoder, OutputEncoder, sanitize_uri_scheme};

// HTML response
async fn render_profile(username: &str) -> String {
    let enc = HtmlEncoder;
    let safe_name = enc.encode(username);
    format!("<h1>Welcome, {safe_name}</h1>")
}

// JSON embedded in HTML
async fn render_page_with_data(data: &str) -> String {
    let enc = secure_output::JsonEncoder;
    let safe_data = enc.encode(data);
    format!(r#"<script>var config = {safe_data};</script>"#)
}

// Validate user-provided URLs before redirect
async fn redirect(url: &str) -> Result<(), String> {
    sanitize_uri_scheme(url).map_err(|e| format!("Blocked: {}", e.scheme))?;
    Ok(())
}
```

---

## Security Event Flow

Security events are emitted automatically by most crates, but you can also emit custom events and seal them before delivery:

```rust
use security_events::{SecurityEvent, EventKind, EventOutcome};
use security_events::emit::emit_security_event;
use security_events::hmac::HmacEventSigner;
use security_core::severity::SecuritySeverity;

async fn admin_action(actor: &str, action: &str) -> Result<(), security_events::hmac::HmacError> {
    // Perform the action...

    // Emit a tamper-evident audit event
    let signer = HmacEventSigner::new("audit-hmac-key")?;
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::High,
        EventOutcome::Success,
    );
    event.actor = Some(actor.to_string());
    event.resource = Some(action.to_string());
    signer.sign_event(&mut event)?;
    emit_security_event(event);
    Ok(())
}
```

For higher event volume, queue a `BatchingSink<FileSink>` or feature-gated `HttpWebhookSink` behind the same event creation flow.

---

## Encrypting Data Before Storage

```rust
use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
use secure_data::kms::StaticDevKeyProvider;

async fn store_sensitive_field(
    data: &str,
    provider: &StaticDevKeyProvider,
) -> String {
    let envelope = encrypt_for_storage(
        data.as_bytes(),
        "user-data-key",
        provider,
    ).await.unwrap();

    // Store this JSON in your database
    serde_json::to_string(&envelope).unwrap()
}
```

---

## Checklist: Production Readiness

Before deploying, verify:

- [ ] Replace `DevAuthLayer` / `DevAuthenticator` with a real `IdentitySource`
- [ ] Replace `StaticDevKeyProvider` with `VaultKeyProvider` or `AwsKmsKeyProvider`
- [ ] Configure `SecurityHeadersLayer` CSP for your domain
- [ ] Set up `DetectionEngine` thresholds appropriate for your traffic
- [ ] Configure `RateLimiter` windows to match your SLA
- [ ] Enable FIPS feature if required (`--features fips`)
- [ ] Run `cargo audit && cargo deny check && cargo vet` in CI
- [ ] Verify all `SecureValidate` implementations cover business rules
- [ ] Set `RequestLimits` appropriate for your API
- [ ] Review `DataClassification` labels on all security event fields

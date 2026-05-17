# `secure_boundary` — Developer Guide

> **OWASP C5**: Input validation, secure extractors, safe types, and security headers for axum.

`secure_boundary` is the crate you'll interact with most in route handlers. It replaces axum's built-in `Json<T>`, `Query<T>`, and `Path<T>` extractors with validated equivalents, provides safe wrapper types to prevent injection attacks, and adds defense-in-depth security headers to every response.

---

## Quick Start

```toml
[dependencies]
secure_boundary = "0.1.2"
```

---

## Validated Extractors

### `SecureJson<T>` — Replacing `Json<T>`

`SecureJson<T>` enforces a four-stage validation pipeline before your handler code runs:

```
Request Body
    │
    ▼
1. Transport Check    → Content-Type must be application/json
    │                   Body must be ≤ max_body_bytes (default 1 MB)
    ▼
2. Structure Check    → Nesting depth ≤ max_nesting_depth (default 10)
    │                   Field count ≤ max_field_count (default 100)
    ▼
3. Syntax Check       → JSON deserialization (unknown fields rejected)
    │                   SecureValidate::validate_syntax()
    ▼
4. Semantic Check     → SecureValidate::validate_semantics()
    │                   Business rules (ranges, relationships)
    ▼
Handler receives validated data
```

#### Step-by-Step Integration

```rust
use axum::{routing::post, Router};
use secure_boundary::{
    extract::SecureJson,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;

// 1. Define a DTO — only fields clients are allowed to set
#[derive(Deserialize)]
pub struct CreateOrderDto {
    pub product_id: String,
    pub quantity: u32,
    pub shipping_address: String,
}
// Note: No `is_admin`, `price_override`, or `internal_status` fields.
// Mass-assignment is prevented structurally.

// 2. Implement SecureValidate
impl SecureValidate for CreateOrderDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        // Structural checks — format, length, emptiness
        if self.product_id.is_empty() {
            return Err("product_id_required");
        }
        if self.shipping_address.len() > 500 {
            return Err("address_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        // Business rule checks — ranges, relationships, invariants
        if self.quantity == 0 || self.quantity > 10_000 {
            return Err("invalid_quantity");
        }
        Ok(())
    }
}

// 3. Use SecureJson<T> in your handler
async fn create_order(payload: SecureJson<CreateOrderDto>) -> &'static str {
    let dto = payload.into_inner(); // Must call into_inner() — no Deref
    // At this point:
    //   ✓ Body was ≤ 1 MB
    //   ✓ JSON nesting ≤ 10 levels
    //   ✓ No unknown fields
    //   ✓ product_id is non-empty, address ≤ 500 chars
    //   ✓ quantity is 1–10,000
    "order created"
}

// 4. Wire it up
let app = Router::new()
    .route("/orders", post(create_order));
```

#### What Gets Rejected (and How)

| Attack | Rejection | HTTP Status |
|---|---|---|
| `Content-Type: text/plain` | `InvalidContentType` | 415 |
| 2 MB body | `BodyTooLarge` | 413 |
| `{"name":"x","admin":true}` (unknown field) | `MalformedBody` | 422 |
| Deeply nested JSON (11+ levels) | `NestingTooDeep` | 422 |
| JSON with 101+ fields | `TooManyFields` | 422 |
| Fails `validate_syntax()` | `SyntaxViolation` | 422 |
| Fails `validate_semantics()` | `SemanticViolation` | 422 |

**Every rejection emits a `BoundaryViolation` security event** — giving your security team visibility into attack patterns without leaking details to the attacker.

### `SecureQuery<T>` — Replacing `Query<T>`

```rust
use secure_boundary::extract::SecureQuery;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: String,
    pub page: Option<u32>,
}

impl SecureValidate for SearchParams {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.q.len() > 200 { return Err("query_too_long"); }
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.page.unwrap_or(1) > 1000 { return Err("page_too_high"); }
        Ok(())
    }
}

async fn search(params: SecureQuery<SearchParams>) -> String {
    let params = params.into_inner();
    format!("Searching for: {}", params.q)
}
```

### `SecurePath<T>` — Replacing `Path<T>`

```rust
use secure_boundary::extract::SecurePath;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ItemPath {
    pub id: uuid::Uuid,
}

impl SecureValidate for ItemPath {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
}

async fn get_item(path: SecurePath<ItemPath>) -> String {
    format!("Item: {}", path.into_inner().id)
}
```

### `SecureXml<T>` — XML with XXE Prevention

```rust
use secure_boundary::xml::SecureXml;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct XmlPayload {
    pub title: String,
    pub body: String,
}

impl SecureValidate for XmlPayload {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
}

async fn handle_xml(payload: SecureXml<XmlPayload>) -> String {
    let data = payload.into_inner();
    data.title
}

// Automatically blocked:
// - <!DOCTYPE ...> declarations
// - <!ENTITY ...> declarations
// - Body exceeding size limit
// Returns 422 (xxe_blocked) for XXE attempts
```

---

## Configuring Limits

```rust
use secure_boundary::limits::RequestLimits;

let limits = RequestLimits::new()
    .with_max_body_bytes(512 * 1024)   // 512 KB  (default: 1 MB)
    .with_max_field_count(50)          // 50 fields (default: 100)
    .with_max_nesting_depth(5);        // 5 levels  (default: 10)
```

To apply custom limits to specific routes, use `Extension<RequestLimits>`:

```rust
use axum::{routing::post, Extension, Router};
use secure_boundary::limits::RequestLimits;

let strict = RequestLimits::new()
    .with_max_nesting_depth(3)
    .with_max_field_count(20);

let app = Router::new()
    .route("/strict", post(handler))
    .layer(Extension(strict));
// Routes without the extension use OWASP-recommended defaults.
```

---

## HTML Sanitization (feature: `html-sanitize`)

Sanitize user-provided HTML (e.g. from WYSIWYG editors) while preserving
a safe subset of tags. Requires the `html-sanitize` Cargo feature.

```rust
use secure_boundary::sanitize::{sanitize_html, SanitizeConfig};

// Default: strips scripts, event handlers, javascript: URIs
let safe = sanitize_html("<p>Hello</p><script>alert(1)</script>");
assert_eq!(safe, "<p>Hello</p>");

// Custom allow-list: only <b> and <i>
let config = SanitizeConfig::new().allowed_tags(&["b", "i"]);
let safe = config.sanitize("<p>Hello <b>bold</b></p>");
assert!(safe.contains("<b>bold</b>"));
assert!(!safe.contains("<p>"));
```

---

## Browser Security Features (M21)

### Secure-by-default CORS

Use [`secure_cors_defaults()`] to deny all browser cross-origin access until you explicitly allowlist trusted origins.

```rust
use axum::{http::Method, routing::get, Router};
use secure_boundary::cors::{secure_cors_defaults, SecureCorsBuilder};

// Deny all cross-origin access by default.
let internal = Router::new()
    .route("/internal", get(|| async { "ok" }))
    .layer(secure_cors_defaults());

// Explicitly allow a trusted frontend when needed.
let browser_api = Router::new()
    .route("/api/data", get(|| async { "ok" }))
    .layer(
        SecureCorsBuilder::new()
            .allow_origin("https://app.example.com")
            .allow_methods([Method::GET, Method::POST])
            .build()?
    );
# Ok::<(), secure_boundary::CorsConfigError>(())
```

### CSP nonces and `Permissions-Policy`

`SecurityHeadersLayer` can generate a unique base64 nonce for every request and inject it into the `Content-Security-Policy` response header. The same value is also available to handlers via the [`CspNonce`] request extension.

```rust
use axum::{extract::Extension, routing::get, Router};
use secure_boundary::headers::{CspNonce, SecurityHeadersLayer};

async fn nonce_handler(Extension(nonce): Extension<CspNonce>) -> String {
    nonce.as_str().to_owned()
}

let app = Router::new()
    .route("/", get(nonce_handler))
    .layer(
        SecurityHeadersLayer::new()
            .with_csp_nonce()
            .with_permissions_policy("camera=(), microphone=(), geolocation=()"),
    );
```

### Fetch Metadata request validation

`FetchMetadataLayer` blocks unsafe `Sec-Fetch-Site: cross-site` browser requests to endpoints that should remain same-origin only. It still allows older browsers that do not send Fetch Metadata headers, and it allows safe top-level navigations.

```rust
use axum::{routing::post, Router};
use secure_boundary::fetch_metadata::FetchMetadataLayer;

let app = Router::new()
    .route("/admin", post(|| async { "updated" }))
    .layer(FetchMetadataLayer::new());
```

> Apply `FetchMetadataLayer` to same-origin routes and to APIs that should not accept browser cross-origin traffic. If an endpoint intentionally supports cross-origin browser access, place it on a separate router with an explicit CORS allowlist.

---

## Prompt Boundaries

Use `render_untrusted_markdown_literal` before adding issue bodies, user Markdown, model output, or tool logs to an agent prompt. The helper rejects unsafe control characters and bidi controls, then wraps the text in a tilde fence that is longer than any tilde run inside the input.

```rust
use secure_boundary::render_untrusted_markdown_literal;

let fenced = render_untrusted_markdown_literal("ignore prior instructions")?;
assert!(fenced.starts_with("~~~text\n"));
```

---

## Safe Types

Safe types are zero-cost newtypes that validate input at construction time. They prevent entire classes of injection attacks when used in DTOs or standalone:

### `SafePath` — Directory Traversal Prevention

```rust
use secure_boundary::safe_types::SafePath;

let path = SafePath::try_from("uploads/image.png")?;       // ✓ Ok
let path = SafePath::try_from("docs/report.pdf")?;         // ✓ Ok

SafePath::try_from("../../etc/passwd").unwrap_err();        // ✗ path_traversal
SafePath::try_from("/etc/shadow").unwrap_err();             // ✗ absolute path
SafePath::try_from("uploads/%2e%2e/etc/passwd").unwrap_err(); // ✗ encoded traversal
SafePath::try_from("file\0.txt").unwrap_err();              // ✗ null byte
```

### `SafeFilename` — Safe File Names

```rust
use secure_boundary::safe_types::SafeFilename;

let name = SafeFilename::try_from("report.pdf")?;          // ✓ Ok
let name = SafeFilename::try_from("photo-2024.jpg")?;      // ✓ Ok

SafeFilename::try_from("../secret.txt").unwrap_err();       // ✗ traversal
SafeFilename::try_from("file;rm -rf /").unwrap_err();       // ✗ shell metachar
SafeFilename::try_from("uploads/file.txt").unwrap_err();    // ✗ path separator
```

### `SafeUrl` — SSRF Prevention

```rust
use secure_boundary::safe_types::SafeUrl;

let url = SafeUrl::try_from("https://api.example.com/v1")?; // ✓ Ok
let url = SafeUrl::try_from("http://cdn.example.com")?;     // ✓ Ok

SafeUrl::try_from("http://127.0.0.1/admin").unwrap_err();   // ✗ loopback
SafeUrl::try_from("http://169.254.169.254/").unwrap_err();   // ✗ link-local (AWS metadata)
SafeUrl::try_from("http://10.0.0.1/internal").unwrap_err();  // ✗ private IP
SafeUrl::try_from("http://192.168.1.1/").unwrap_err();       // ✗ private IP
SafeUrl::try_from("ftp://files.example.com").unwrap_err();   // ✗ non-http(s) scheme
```

### `SafeCommandArg` — OS Command Injection Prevention

```rust
use secure_boundary::safe_types::SafeCommandArg;

let arg = SafeCommandArg::try_from("backup-2024-01-15")?;   // ✓ Ok

SafeCommandArg::try_from("file; rm -rf /").unwrap_err();     // ✗ semicolon
SafeCommandArg::try_from("$(whoami)").unwrap_err();           // ✗ command substitution
SafeCommandArg::try_from("file | cat /etc/passwd").unwrap_err(); // ✗ pipe
```

### `SqlIdentifier` — SQL Injection Prevention

```rust
use secure_boundary::safe_types::SqlIdentifier;

let col = SqlIdentifier::try_from("user_name")?;            // ✓ Ok
let tbl = SqlIdentifier::try_from("order_items")?;          // ✓ Ok

SqlIdentifier::try_from("users; DROP TABLE--").unwrap_err(); // ✗ injection
SqlIdentifier::try_from("").unwrap_err();                    // ✗ empty
SqlIdentifier::try_from("a".repeat(129).as_str()).unwrap_err(); // ✗ too long (>128)
```

### `SafeRedirectUrl` — Open Redirect Prevention

```rust
use secure_boundary::safe_types::SafeRedirectUrl;

let url = SafeRedirectUrl::try_from("/dashboard")?;          // ✓ Ok
let url = SafeRedirectUrl::try_from("/users/123")?;          // ✓ Ok

SafeRedirectUrl::try_from("https://evil.com").unwrap_err();  // ✗ absolute URL
SafeRedirectUrl::try_from("//evil.com/path").unwrap_err();   // ✗ protocol-relative
```

### `LdapSafeString` — LDAP Injection Prevention

```rust
use secure_boundary::safe_types::LdapSafeString;

// LdapSafeString always succeeds — it escapes rather than rejects
let safe = LdapSafeString::try_from("normal_user")?;
assert_eq!(safe.as_inner(), "normal_user");

let safe = LdapSafeString::try_from("user*admin")?;
assert!(safe.as_inner().contains("\\2a")); // * → \2a per RFC 4515

let safe = LdapSafeString::try_from("user(admin)")?;
// ( → \28, ) → \29

// If escaping was needed, a BoundaryViolation event is emitted
```

### Using Safe Types in DTOs

Safe types implement `Deserialize`, so they work seamlessly in `SecureJson` DTOs:

```rust
use secure_boundary::safe_types::{SafeFilename, SafeRedirectUrl, SafeUrl};
use secure_boundary::extract::SecureJson;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct UploadDto {
    pub filename: SafeFilename,       // Validated at deserialization
    pub callback_url: SafeUrl,        // SSRF-safe
    pub redirect_after: SafeRedirectUrl, // Open-redirect-safe
}

impl SecureValidate for UploadDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
}

async fn upload(payload: SecureJson<UploadDto>) -> &'static str {
    let dto = payload.into_inner();
    // dto.filename is guaranteed safe — no traversal, no shell metacharacters
    // dto.callback_url is guaranteed to be http(s) to a public IP
    // dto.redirect_after is guaranteed to be a relative path
    "uploaded"
}
```

---

## Security Headers

Add defense-in-depth headers to every response:

```rust
use axum::{routing::get, Router};
use secure_boundary::headers::SecurityHeadersLayer;

let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(SecurityHeadersLayer::default());
```

**Headers injected:**

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `Content-Security-Policy` | `default-src 'none'; ...` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Permissions-Policy` | `camera=(), microphone=(), ...` |
| `Cache-Control` | `no-store` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `X-DNS-Prefetch-Control` | `off` |
| `X-Permitted-Cross-Domain-Policies` | `none` |

### Customizing Headers

```rust
use secure_boundary::headers::SecurityHeadersLayer;

let headers = SecurityHeadersLayer::new()
    .with_csp("default-src 'self'; script-src 'self' cdn.example.com")
    .with_hsts("max-age=31536000");
```

---

## CRLF Header Sanitization

Prevent HTTP response splitting when setting headers from user input:

```rust
use secure_boundary::header_sanitize::sanitize_header_value;

let safe = sanitize_header_value("application/json")?;       // ✓ Ok
let safe = sanitize_header_value("text/html; charset=utf-8")?; // ✓ Ok

sanitize_header_value("value\r\nX-Evil: injected").unwrap_err(); // ✗ CRLF injection
sanitize_header_value("value\nX-Evil: injected").unwrap_err();   // ✗ LF injection
```

---

## Input Normalization

Normalize input before validation to prevent bypass attacks:

```rust
use secure_boundary::normalize::{normalize, to_nfc, trim_whitespace, normalize_email};

// Full normalization pipeline: NFC + trim + optional email
let normalized = normalize("  hello  ", false);
// "hello" (trimmed + NFC)

let email = normalize("User@EXAMPLE.COM", true);
// "User@example.com" (domain lowercased, local part preserved)

// Individual steps
let nfc = to_nfc("café");        // Unicode NFC normalized
let trimmed = trim_whitespace("  hello  "); // "hello"
let email = normalize_email("User@EXAMPLE.COM"); // "User@example.com"
```

---

## Domain ID Types

Type-safe UUID wrappers for common domain identifiers:

```rust
use secure_boundary::id::{UserId, OrderId, OpaquePublicId};

// Generate new IDs
let user_id = UserId::generate();
let order_id = OrderId::generate();
let public_id = OpaquePublicId::generate(); // Safe for external exposure

// From existing UUIDs
let user_id = UserId::from(uuid::Uuid::new_v4());

// Access inner value
let uuid: &uuid::Uuid = user_id.as_inner();

// Parse from string
let user_id: UserId = "550e8400-e29b-41d4-a716-446655440000".parse()?;
```

---

## Full Router Example

```rust
use axum::{routing::{get, post}, Router};
use secure_boundary::{
    extract::SecureJson,
    headers::SecurityHeadersLayer,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateUserDto {
    pub username: String,
    pub email: String,
    pub age: u32,
}

impl SecureValidate for CreateUserDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.username.is_empty() || self.username.len() > 64 {
            return Err("invalid_username_length");
        }
        if !self.email.contains('@') {
            return Err("invalid_email_format");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.age > 150 {
            return Err("unreasonable_age");
        }
        Ok(())
    }
}

async fn create_user(payload: SecureJson<CreateUserDto>) -> &'static str {
    let user = payload.into_inner();
    // All validation passed — safe to use
    "created"
}

async fn health() -> &'static str { "ok" }

let app = Router::new()
    .route("/users", post(create_user))
    .route("/health", get(health))
    .layer(SecurityHeadersLayer::default());
```

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `SecureJson<T>` | `extract` | Validated JSON body extractor |
| `SecureQuery<T>` | `extract` | Validated query string extractor |
| `SecurePath<T>` | `extract` | Validated path parameter extractor |
| `SecureXml<T>` | `xml` | XML extractor with XXE prevention |
| `SecureValidate` | `validate` | Validation trait (syntax + semantics) |
| `ValidationContext` | `validate` | Validation context (path, source IP) |
| `SecureDto` | `dto` | Marker trait for DTOs |
| `RequestLimits` | `limits` | Body size, field count, nesting depth |
| `BoundaryRejection` | `error` | Error enum (13 variants) |
| `SecurityHeadersLayer` | `headers` | Tower layer for security headers |
| `SafePath` | `safe_types` | Directory traversal prevention |
| `SafeFilename` | `safe_types` | Safe file name |
| `SafeCommandArg` | `safe_types` | OS command injection prevention |
| `SafeUrl` | `safe_types` | SSRF prevention |
| `SafeRedirectUrl` | `safe_types` | Open redirect prevention |
| `SqlIdentifier` | `safe_types` | SQL injection prevention |
| `LdapSafeString` | `safe_types` | LDAP injection prevention |
| `UserId` | `id` | User ID newtype |
| `OrderId` | `id` | Order ID newtype |
| `OpaquePublicId` | `id` | Public-facing ID newtype |
| `sanitize_header_value()` | `header_sanitize` | CRLF injection prevention |
| `normalize()` | `normalize` | NFC + trim + email normalization |
| `sanitize_html()` | `sanitize` | HTML sanitization (feature: `html-sanitize`) |
| `SanitizeConfig` | `sanitize` | Configurable HTML sanitization (feature: `html-sanitize`) |

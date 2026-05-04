# `secure_boundary` on Actix-web 4 — integration guide

> Part of the [SunLitSecurityLibraries dev-guide](./README.md). Target audience: engineers and security agents adding `secure_boundary` to an Actix-web 4 service.

## What you get

Three drop-in Actix-web 4 adapters that mirror the axum versions byte-for-byte:

| Adapter | What it does | Replaces |
|---|---|---|
| `SecureJson<T>` | Extracts a JSON body and runs the four-stage validation pipeline (content-type → body size → JSON nesting/field limits → serde parse → `SecureValidate::validate_syntax` → `SecureValidate::validate_semantics`). Rejection gives a safe, code-only JSON error body; no raw input is ever echoed. | Hand-rolled `web::Json<T>` + ad-hoc checks in every handler. |
| `SecurityHeadersTransform` | Injects the OWASP-recommended header set (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, Cache-Control, COEP, COOP, CORP, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies) on every response — including error responses. Optional per-request CSP nonces. | A dozen lines of `HttpResponse::insert_header` per endpoint. |
| `FetchMetadataTransform` | Blocks suspicious cross-site browser requests based on the `Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest` headers, preserving backward compatibility for older clients that don't send them. | Hand-written cross-site request filtering that rots as browser behavior changes. |

All three are behavior-identical to their axum twins. A service on Actix with these three middlewares gets the same defense-in-depth posture as an axum service using `SecureJson` + `SecurityHeadersLayer` + `FetchMetadataLayer`.

## Adding the dependency

```toml
[dependencies]
secure_boundary = { version = "0.1", default-features = false, features = ["actix-web"] }
actix-web = "4"
```

- `default-features = false` turns off the (default) `axum` feature so your build doesn't pull in axum.
- If your workspace hosts services on both frameworks, you can enable both features at once: `features = ["axum", "actix-web"]`. The crate composes.
- If you prefer git-rev pinning during Era 2 of Sunlit Guardian, replace `version = "0.1"` with `git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "<sha>"`.

## Minimal working example (copy-paste)

The complete runnable version lives at [`crates/secure_boundary/examples/actix_minimal.rs`](../../crates/secure_boundary/examples/actix_minimal.rs). Build and run it with:

```sh
cargo run --example actix_minimal -p secure_boundary --features actix-web
```

Test it with:

```sh
curl -v -X POST http://127.0.0.1:8080/items \
     -H "content-type: application/json" \
     -d '{"name":"widget"}'
```

You'll see every OWASP security header set on the response, and the CSP line contains a fresh nonce per request.

The shape of the code:

```rust,ignore
use actix_web::{web, App, HttpResponse, HttpServer};
use secure_boundary::actix::{FetchMetadataTransform, SecurityHeadersTransform};
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::SecureJson;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)] // Rejects extra/unknown fields at parse time.
struct CreateItem {
    name: String,
}

impl SecureValidate for CreateItem {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() { return Err("name_empty"); }
        if self.name.len() > 64 { return Err("name_too_long"); }
        Ok(())
    }
    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        Ok(()) // business-rule checks go here
    }
}

async fn create_item(item: SecureJson<CreateItem>) -> HttpResponse {
    HttpResponse::Ok().body(format!("created: {}", item.into_inner().name))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(SecurityHeadersTransform::new().with_csp_nonce())
            .wrap(FetchMetadataTransform::new())
            .route("/items", web::post().to(create_item))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

> Every line of this snippet is exercised by the [runnable example](../../crates/secure_boundary/examples/actix_minimal.rs) and the E2E test suite at [`crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs`](../../crates/secure_smoke_service/tests/e2e_sg_gate_a_m1.rs). If this guide drifts out of sync with code, those tests fail.

## How each adapter composes

### Extractor + middleware order

Apply `.wrap()` in the order you want middlewares to **wrap** the inner service. Actix executes the outermost wrap first on request, last on response. Recommended:

```text
wrap(SecurityHeadersTransform::new())   ← outermost: sets response headers on EVERY response, including error responses and short-circuits from inner middleware.
wrap(FetchMetadataTransform::new())     ← inner: short-circuits cross-site requests before they reach the handler (or `SecureJson`).
route("/items", web::post().to(h))      ← innermost: handler with SecureJson<T> extractor.
```

This ordering means a cross-site request still gets OWASP security headers on the 403 response, and a malformed JSON request still gets security headers on the 422 response. If you reverse the order, you may leak 403/422 responses without the full header set.

### Per-route `RequestLimits` override

By default `SecureJson<T>` uses OWASP-recommended limits (1 MiB body, 10 nesting levels, 100 top-level fields). Override per-route via `app_data`:

```rust,ignore
use secure_boundary::limits::RequestLimits;

App::new()
    .wrap(SecurityHeadersTransform::new())
    .service(
        web::scope("/upload")
            .app_data(RequestLimits::new()
                .with_max_body_bytes(4 * 1024 * 1024) // 4 MiB for this scope
                .with_max_field_count(500))
            .route("", web::post().to(upload_handler)),
    )
    .route("/items", web::post().to(create_item)) // inherits OWASP defaults
```

### CSP nonce propagation to handlers

With `.with_csp_nonce()` enabled, each request gets a fresh cryptographically-random nonce inserted into the `SecurityHeadersTransform`. Handlers can read it via `actix_web::HttpMessage::extensions()`:

```rust,ignore
use actix_web::{HttpMessage, HttpRequest, HttpResponse};
use secure_boundary::headers::CspNonce;

async fn render(req: HttpRequest) -> HttpResponse {
    let nonce_str = req
        .extensions()
        .get::<CspNonce>()
        .map(|n| n.as_str().to_owned())
        .unwrap_or_default();
    HttpResponse::Ok().body(format!(
        "<!doctype html><script nonce='{}'>console.log('hi')</script>",
        nonce_str
    ))
}
```

The same `CspNonce` value appears in the `script-src 'nonce-...'` directive on the response's CSP header, so browsers execute only scripts with the matching nonce.

## Common pitfalls

### 1. Forgetting `default-features = false`

```toml
secure_boundary = { version = "0.1", features = ["actix-web"] }  # pulls axum too
```

This compiles, but you'll pay for compiling axum + tower + tower-http you won't use. If that's acceptable (e.g., because a sibling crate in the workspace uses the axum path), it's fine. Otherwise:

```toml
secure_boundary = { version = "0.1", default-features = false, features = ["actix-web"] }
```

### 2. Wrapping middleware in the wrong order

If you `wrap(FetchMetadataTransform)` OUTSIDE `wrap(SecurityHeadersTransform)`, a blocked cross-site request will return 403 **without** security headers. That weakens defense-in-depth. See the order recommendation above.

### 3. Content-Type check is strict

`SecureJson<T>` checks `Content-Type` starts with `application/json` — nothing more, nothing less. If a client sends `application/json; charset=utf-8`, that's fine. If they send `text/plain`, they get 415 Unsupported Media Type with the code `invalid_content_type`.

### 4. `deny_unknown_fields` is your friend

Always annotate your `T` with `#[serde(deny_unknown_fields)]`. Otherwise an attacker who can send JSON with extra fields may find new attack surface. The example above does this; so should yours.

### 5. `SecureValidate` error codes must be stable strings

Return `&'static str` reason codes from `validate_syntax` / `validate_semantics`. These strings are logged as part of the `BoundaryViolation` security event for variant analysis; changing them breaks historical queries. Treat them like error codes in an API contract.

## Comparison with axum adapters (for mixed-framework services)

If your workspace has both axum and Actix services and wants identical security posture across them:

| | axum | actix-web 4 |
|---|---|---|
| JSON extractor | `SecureJson<T>` as `FromRequest` | `SecureJson<T>` as `actix_web::FromRequest` |
| Security headers | `SecurityHeadersLayer` (tower `Layer`) | `SecurityHeadersTransform` (actix `Transform`) |
| Fetch-Metadata | `FetchMetadataLayer` (tower `Layer`) | `FetchMetadataTransform` (actix `Transform`) |
| Rejection status codes | Same | Same — verified by cross-framework parity tests in [`sg_gate_a_parity_boundary.rs`](../../crates/secure_boundary/tests/sg_gate_a_parity_boundary.rs) |
| Response header bytes | Same | Same — verified by the same parity suite |

The cross-framework parity tests run on every PR via the CI feature-matrix gate (M4). A diff between axum and Actix output causes CI to fail, so both paths stay in lockstep.

## See also

- `SecureJson<T>` rustdoc — API reference and doctest examples
- [`actix` module rustdoc](../../crates/secure_boundary/src/actix/mod.rs) — adapter overview
- [`examples/actix_minimal.rs`](../../crates/secure_boundary/examples/actix_minimal.rs) — full runnable example (what this guide is built on)
- `SecurityHeadersLayer` rustdoc — header value defaults and customisation
- `FetchMetadataLayer` rustdoc — allow/block semantics
- [`docs/dev-guide/README.md`](./README.md) — dev-guide index

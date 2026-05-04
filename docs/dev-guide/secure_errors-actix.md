# `secure_errors` on Actix-web 4 — integration guide

> Part of the [SunLitSecurityLibraries dev-guide](./README.md). Target audience: engineers adding typed error handling to an Actix-web 4 service.

## The three-layer error model in 60 seconds

`secure_errors` enforces a strict separation:

1. **Internal layer** (`AppError`) — rich context (SQL text, hostnames, policy names). Never serialized.
2. **Public layer** (`PublicError`) — the only type that hits the HTTP response. Fields: `code` (stable machine-readable), `message` (user-safe), `request_id` (optional correlation).
3. **Operational layer** (`ErrorClassification`) — retryability, alerting, signals (consumed by observability code, not the wire).

The mapping table from `AppError` variant → (HTTP status, `PublicError`) lives in [`http::into_response_parts`](../../crates/secure_errors/src/http.rs) — the **single source of truth**. No other code in the workspace is allowed to compute status codes or PublicError bodies.

## What you get on Actix-web 4

With the `actix-web` feature enabled, `AppError` gains an `impl actix_web::ResponseError`. Any handler returning `Result<_, AppError>` gets automatic:

- HTTP status code mapping (`into_response_parts`).
- JSON `PublicError` response body.
- `Retry-After` header on `AppError::RateLimit { retry_after_seconds: Some(_) }`.

Byte-identical output to the axum path for the same `AppError` — verified by [`sg_gate_a_parity_errors.rs`](../../crates/secure_errors/tests/sg_gate_a_parity_errors.rs) for all 8 variants.

## Adding the dependency

```toml
[dependencies]
secure_errors = { version = "0.1", default-features = false, features = ["actix-web"] }
actix-web = "4"
```

Drop `default-features = false` if your workspace also uses the axum tower `ErrorMappingLayer`.

## Using `AppError` in Actix handlers

```rust,ignore
use actix_web::{web, App, HttpResponse};
use secure_errors::kind::AppError;

async fn get_item(id: web::Path<u64>) -> Result<HttpResponse, AppError> {
    // Your lookup returns Option<Item>; map None to NotFound.
    let item = fetch_item(*id).await.ok_or(AppError::NotFound)?;
    Ok(HttpResponse::Ok().json(item))
}
```

Handlers return `Result<HttpResponse, AppError>`. Actix's machinery, via `impl ResponseError for AppError`, converts the `Err(AppError::NotFound)` into:

```
HTTP/1.1 404 Not Found
content-type: application/json

{"code":"not_found","message":"The requested resource was not found."}
```

No internal details. No raw input. No hostnames or SQL.

## Status-code mapping table (canonical)

| `AppError` variant | HTTP status | `PublicError.code` | `Retry-After`? |
|---|---|---|---|
| `Validation { .. }` | 400 Bad Request | `invalid_request` | — |
| `Forbidden { .. }` | 403 Forbidden | `forbidden` | — |
| `NotFound` | 404 Not Found | `not_found` | — |
| `Conflict` | 409 Conflict | `conflict` | — |
| `RateLimit { retry_after_seconds }` | 429 Too Many Requests | `rate_limited` | Yes, if `Some(_)` |
| `Dependency { .. }` | 503 Service Unavailable | `temporarily_unavailable` | — |
| `Crypto` | 500 Internal Server Error | `internal_error` | — |
| `Internal` | 500 Internal Server Error | `internal_error` | — |

These mappings are enforced by [`http::into_response_parts`](../../crates/secure_errors/src/http.rs); the Actix adapter delegates to that function. If the mapping table changes, both axum and Actix follow automatically.

## Retry-After header behaviour

```rust,ignore
Err(AppError::RateLimit { retry_after_seconds: Some(30) }) // → 429 + Retry-After: 30
Err(AppError::RateLimit { retry_after_seconds: None })     // → 429, no Retry-After header
```

## Composing with `SecureJson` rejections

`SecureJson<T>`'s rejections are handled inside the `secure_boundary` extractor (see the [boundary integration guide](./secure_boundary-actix.md)). Those rejections map to 4xx status codes via the `BoundaryRejection` type — they do NOT flow through `AppError`. So the two systems are complementary:

- `secure_boundary` → rejects malformed/oversized/content-type-wrong requests at the extractor boundary with codes like `invalid_content_type`, `malformed_body`.
- `secure_errors::AppError` → conveys business/internal failures (NotFound, Conflict, Dependency, etc.) that arise AFTER the extractor succeeded.

Your handler signature pattern:

```rust,ignore
async fn create_item(
    body: SecureJson<CreateItemDto>,   // extractor: `secure_boundary`'s rejection logic
) -> Result<HttpResponse, AppError> { // handler: `secure_errors`'s rejection logic
    let dto = body.into_inner();
    let item = persist(dto).await.map_err(|_| AppError::Dependency { dep: "postgres" })?;
    Ok(HttpResponse::Created().json(item))
}
```

## Cross-reference with axum

| | axum | actix-web 4 |
|---|---|---|
| Mechanism | `impl IntoResponse for AppError` | `impl ResponseError for AppError` |
| Mapping source | `http::into_response_parts` | `http::into_response_parts` (shared) |
| Body shape | JSON `PublicError` | JSON `PublicError` |
| `Retry-After` for `RateLimit` | Yes | Yes |
| `ErrorMappingLayer` tower layer | Yes (pass-through enabling impl) | N/A (Actix has no analogue; `ResponseError` impl is sufficient) |

The tower `ErrorMappingLayer` is an axum-only concept — it's a pass-through Layer whose sole purpose is to document the integration point. On Actix, `impl ResponseError for AppError` is the integration point directly.

## Common pitfalls

### 1. Leaking internal `code` in `PublicError.message`

`AppError::Validation { code: "email_invalid" }` logs `"email_invalid"` internally but the `PublicError.message` reads `"The request contains invalid data."` — the stable public string. Don't try to bypass `into_response_parts` to forward the internal code into the user-visible message.

### 2. Forgetting `content-type: application/json`

The `impl ResponseError` sets this automatically — don't override. If you wrap the response in another middleware that mangles headers, put `secure_errors`'s impl at the innermost position.

### 3. `Retry-After` integer vs HTTP-date

`secure_errors` emits the integer-seconds form (`Retry-After: 30`). If your downstream consumers require the HTTP-date form, convert before the response leaves your gateway — not inside `secure_errors`.

## Minimal runnable example

See [`crates/secure_errors/examples/actix_error_minimal.rs`](../../crates/secure_errors/examples/actix_error_minimal.rs) and run:

```sh
cargo run --example actix_error_minimal -p secure_errors --features actix-web
```

Probe the variants:

```sh
curl -v http://127.0.0.1:8080/not-found
curl -v http://127.0.0.1:8080/rate-limit
curl -v http://127.0.0.1:8080/dep
```

## See also

- [`AppError` rustdoc](../../crates/secure_errors/src/kind.rs)
- [`http::into_response_parts` rustdoc](../../crates/secure_errors/src/http.rs) — canonical mapping
- [`docs/dev-guide/secure_authz-actix.md`](./secure_authz-actix.md) — pairs with this guide
- [`docs/dev-guide/secure_boundary-actix.md`](./secure_boundary-actix.md) — handler-entry extractor
- [`docs/dev-guide/README.md`](./README.md) — dev-guide index

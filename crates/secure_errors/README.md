# secure_errors

[![crates.io](https://img.shields.io/crates/v/secure_errors.svg)](https://crates.io/crates/secure_errors)
[![docs.rs](https://docs.rs/secure_errors/badge.svg)](https://docs.rs/secure_errors)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secure-by-default error handling for HTTP services (OWASP C10). Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## The problem this crate solves

Most Rust web services accidentally leak internal details — SQL fragments, hostnames, stack traces — through error responses. This crate enforces a **three-layer model**:

1. **`AppError`** — internal layer, full detail, **never serialized to the wire**.
2. **`PublicError`** — the only type that may be serialized to HTTP responses. Stable, redaction-safe.
3. **`ErrorClassification`** — operational metadata: retryability, alerting hints, signals.

A single source-of-truth mapper (`http::into_response_parts`) turns `AppError` into HTTP responses, so an axum service and an actix-web service emit **byte-identical** wire payloads for the same error.

## Install

```toml
[dependencies]
secure_errors = "0.1"  # default: axum

# For actix-web instead of axum:
# secure_errors = { version = "0.1", default-features = false, features = ["actix-web"] }

# Both at once (e.g. workspace with services on both):
# secure_errors = { version = "0.1", features = ["axum", "actix-web"] }
```

## Quick example (axum)

```rust
use axum::{routing::get, Router};
use secure_errors::kind::AppError;
use secure_errors::middleware::ErrorMappingLayer;

async fn not_found() -> Result<&'static str, AppError> {
    Err(AppError::NotFound)
}

async fn rate_limited() -> Result<&'static str, AppError> {
    Err(AppError::RateLimit { retry_after_seconds: Some(30) })
}

let app = Router::new()
    .route("/missing", get(not_found))
    .route("/throttled", get(rate_limited))
    .layer(ErrorMappingLayer::default());

// Both routes emit a stable PublicError JSON. /throttled adds Retry-After: 30.
// Internal details (dependency name, validation code) never reach the client.
```

## Quick example (actix-web)

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use secure_errors::kind::AppError;

async fn dep_down() -> Result<HttpResponse, AppError> {
    Err(AppError::Dependency { dep: "postgres" })  // dep name stays internal
}

HttpServer::new(|| App::new().route("/dep", web::get().to(dep_down)))
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
```

See [`examples/actix_error_minimal.rs`](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/crates/secure_errors/examples/actix_error_minimal.rs) for a complete runnable service.

## Design invariants

- **`PublicError` is the only type that may reach an HTTP wire.**
- **`http::into_response_parts` is the only place that maps errors to HTTP status codes** — guaranteed cross-framework parity.
- **No internal text** (SQL fragments, hostnames, stack traces, validation reason codes) may appear in `PublicError`.
- The internal `AppError::Internal { detail }` variant carries free-form detail for logs; the public response says only "internal_error".

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | `middleware::ErrorMappingLayer` (tower) and `impl IntoResponse for AppError` |
| `actix-web` | off | `impl actix_web::ResponseError for AppError` (see `actix` module) |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, `#![deny(clippy::all, clippy::pedantic)]`

## Status

Alpha.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

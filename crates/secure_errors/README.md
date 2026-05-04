# secure_errors

[![crates.io](https://img.shields.io/crates/v/secure_errors.svg)](https://crates.io/crates/secure_errors)
[![docs.rs](https://docs.rs/secure_errors/badge.svg)](https://docs.rs/secure_errors)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Centralized, secure-by-default error handling (OWASP C10). Part of the **SunLit Security Libraries** workspace.

A three-layer error model:

- **Internal layer** (`AppError`) — full internal detail, never serialized to clients.
- **Public layer** (`PublicError`) — the *only* type that may be serialized to HTTP responses.
- **Operational layer** (`ErrorClassification`) — retryability, alerting hints, signals.

## Design invariants

- `PublicError` is the only type that may reach an HTTP wire.
- `http::into_response_parts` is the single source of truth that maps errors to HTTP status codes — `axum` and `actix-web` responses for the same `AppError` are byte-identical.
- No internal text (SQL fragments, hostnames, stack traces) may appear in `PublicError`.

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | `middleware::ErrorMappingLayer` tower layer + `impl IntoResponse for AppError` |
| `actix-web` | off | `impl actix_web::ResponseError for AppError` (see `actix` module) |

## Install

```toml
[dependencies]
secure_errors = "0.1"
# or with actix-web instead of the default axum:
# secure_errors = { version = "0.1", default-features = false, features = ["actix-web"] }
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

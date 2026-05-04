# secure_boundary

[![crates.io](https://img.shields.io/crates/v/secure_boundary.svg)](https://crates.io/crates/secure_boundary)
[![docs.rs](https://docs.rs/secure_boundary/badge.svg)](https://docs.rs/secure_boundary)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Input validation, secure HTTP extractors, security headers, and browser boundary protections (OWASP **C4** + **C5** + **C8**). Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## What this gives you

- **`SecureValidate`** — a structured four-stage validation pipeline (syntax → semantics → contextual → cross-field), enforced at the framework boundary.
- **Validating extractors** — `SecureJson<T>`, `SecureQuery<T>`, `SecurePath<T>`, `SecureXml<T>` (XXE-safe) — same ergonomics as axum/actix native extractors plus size limits and validation.
- **Security-headers middleware** — OWASP-recommended headers including a CSP-with-nonce option.
- **Fetch Metadata middleware** — blocks browser cross-site requests that don't pass `Sec-Fetch-*` checks.
- **Secure CORS** — `secure_cors_defaults` and a builder that won't let you ship `Access-Control-Allow-Origin: *` with credentials.
- **Boundary error type** — `BoundaryRejection` with stable HTTP mappings, no internal-detail leakage.

Framework-neutral core; pick `axum` (default), `actix-web`, or both.

## Install

```toml
[dependencies]
secure_boundary = "0.1"  # default features: ["axum"]

# For actix-web:
# secure_boundary = { version = "0.1", default-features = false, features = ["actix-web"] }
```

## Quick example (axum)

```rust
use axum::{routing::post, Router};
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::SecureJson;
use secure_boundary::SecurityHeadersLayer;
use secure_boundary::FetchMetadataLayer;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateItem { name: String }

impl SecureValidate for CreateItem {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() { return Err("name_empty"); }
        if self.name.len() > 64 { return Err("name_too_long"); }
        Ok(())
    }
    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
}

async fn create(item: SecureJson<CreateItem>) -> String {
    format!("created: {}", item.into_inner().name)
}

let app = Router::new()
    .route("/items", post(create))
    .layer(SecurityHeadersLayer::new().with_csp_nonce())
    .layer(FetchMetadataLayer::new());
```

## Quick example (actix-web)

See [`examples/actix_minimal.rs`](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/crates/secure_boundary/examples/actix_minimal.rs) — a runnable actix-web service wiring `SecurityHeadersTransform`, `FetchMetadataTransform`, and `SecureJson<T>`.

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | `SecureJson` / `SecureQuery` / `SecurePath` / `SecureXml` extractors; `SecurityHeadersLayer`, `FetchMetadataLayer`, `cors`. |
| `actix-web` | off | actix `FromRequest` extractor + `SecurityHeadersTransform` / `FetchMetadataTransform` middleware. |
| `html-sanitize` | off | HTML-sanitization helpers backed by `ammonia`. |
| `mobile-platform` | off | Mobile-specific platform guards (e.g. deep-link safety). |

`axum` and `actix-web` can both be enabled in a workspace that hosts services on different frameworks.

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Status

Alpha.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

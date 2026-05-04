# secure_boundary

[![crates.io](https://img.shields.io/crates/v/secure_boundary.svg)](https://crates.io/crates/secure_boundary)
[![docs.rs](https://docs.rs/secure_boundary/badge.svg)](https://docs.rs/secure_boundary)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Input validation, secure extractors, security headers, and browser boundary protections (OWASP C4 + C5 + C8). Part of the **SunLit Security Libraries** workspace.

Framework-neutral validation core plus `axum` and `actix-web` adapters.

## What this crate gives you

- `SecureValidate` — Structured four-stage validation pipelines.
- `SecureJson` / `SecureQuery` / `SecurePath` / `SecureXml` — Framework extractors with size limits, validation, and XXE defenses.
- `SecurityHeadersLayer` — OWASP security headers and CSP-nonce middleware.
- `cors::secure_cors_defaults` / `cors::SecureCorsBuilder` — Secure-by-default CORS for `axum`.
- `FetchMetadataLayer` — Blocks unsafe cross-site browser requests via Sec-Fetch-* headers.
- `BoundaryRejection` — Structured rejection type with safe HTTP response mapping.

## Feature flags

| Flag | Default | Enables |
|---|---|---|
| `axum` | ✅ | Axum extractors and tower layers (`SecureJson`, `SecurityHeadersLayer`, `FetchMetadataLayer`, `cors`). |
| `actix-web` | off | Actix `FromRequest` extractor + `SecurityHeadersTransform` / `FetchMetadataTransform`. |
| `html-sanitize` | off | HTML sanitization helpers backed by `ammonia`. |
| `mobile-platform` | off | Mobile-specific platform guards. |

`axum` and `actix-web` can both be enabled in a workspace that hosts services on different frameworks.

## Install

```toml
[dependencies]
secure_boundary = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_boundary` — Input validation, secure extractors, security headers, and browser protections (OWASP C4 + C5 + C8).
//!
//! # Feature Overview
//!
//! The crate ships a framework-neutral core plus optional HTTP framework
//! adapters. Pick exactly one of `axum` or `actix-web` (or both):
//!
//! | Feature flag | Default | Enables |
//! |---|---|---|
//! | `axum` | ✅ | [`SecureJson`] / [`SecureQuery`] / [`SecurePath`] as `FromRequest[Parts]`; [`SecurityHeadersLayer`] / [`FetchMetadataLayer`] as tower layers; [`cors::secure_cors_defaults`]; [`SecureXml`] |
//! | `actix-web` | | `SecureJson<T>` as an actix `FromRequest`; `SecurityHeadersTransform` / `FetchMetadataTransform` actix middleware (see [`actix`]) |
//! | `html-sanitize` | | HTML sanitization helpers backed by `ammonia` |
//! | `mobile-platform` | | Mobile-specific platform guards |
//!
//! Both `axum` and `actix-web` can be enabled at the same time (useful when a
//! workspace hosts services on different frameworks). `--no-default-features`
//! disables both and keeps only the framework-neutral types
//! (validation, `SafeUrl`, safe-types, limits, IDs).
//!
//! # What this crate gives you
//!
//! - [`SecureValidate`] trait for structured four-stage validation pipelines
//! - [`SecureJson`], [`SecureQuery`], [`SecurePath`] framework extractors
//! - [`SecureXml`] axum extractor with XXE prevention (`axum` feature)
//! - [`SecurityHeadersLayer`] middleware for OWASP security headers and CSP nonces
//! - [`cors::secure_cors_defaults`] and [`cors::SecureCorsBuilder`] for secure-by-default CORS (`axum` feature)
//! - [`FetchMetadataLayer`] for blocking unsafe cross-site browser requests
//! - [`BoundaryRejection`] error type with safe HTTP response mapping
//! - [`BoundaryViolation`] for flowing violations into the security events subsystem
//! - Safe types: [`safe_types::SafePath`], [`safe_types::SafeFilename`],
//!   [`safe_types::SafeCommandArg`], [`safe_types::SafeUrl`],
//!   [`safe_types::SafeRedirectUrl`], [`safe_types::SqlIdentifier`],
//!   [`safe_types::LdapSafeString`]
//! - [`sanitize_header_value`] for CRLF injection prevention
//! - Input normalization, strict deserialization, and configurable request limits
//!
//! # Framework selection quickstart
//!
//! ```toml
//! # Axum (default)
//! secure_boundary = "0.1"
//!
//! # Actix-web 4
//! secure_boundary = { version = "0.1", default-features = false, features = ["actix-web"] }
//!
//! # Both frameworks in the same crate
//! secure_boundary = { version = "0.1", features = ["actix-web"] }
//! ```

pub mod attack_signal;
pub mod content_type;
#[cfg(feature = "axum")]
pub mod cors;
pub mod dto;
pub mod error;
pub mod extract;
pub mod fetch_metadata;
pub mod header_sanitize;
pub mod headers;
pub mod id;
pub mod limits;
pub mod normalize;
pub mod safe_types;
pub mod serde;
pub mod validate;
#[cfg(feature = "axum")]
pub mod xml;

#[cfg(feature = "html-sanitize")]
pub mod sanitize;

#[cfg(feature = "mobile-platform")]
pub mod platform;

/// Actix-web 4 integration — adapters for `SecureJson<T>`,
/// `SecurityHeadersLayer`, and `FetchMetadataLayer`.
///
/// Gated on the `actix-web` feature. See [the integration guide] for
/// copy-paste examples.
///
/// [the integration guide]: https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/docs/dev-guide/secure_boundary-actix.md
#[cfg(feature = "actix-web")]
pub mod actix;

/// Kani proof harnesses (compiled only under `cargo kani`).
/// See `docs/dev-guide/formal-verification.md`.
#[cfg(kani)]
mod proofs;

pub use attack_signal::{BoundaryViolation, ViolationKind};
#[cfg(feature = "axum")]
pub use cors::{secure_cors_defaults, CorsConfigError, SecureCorsBuilder};
pub use dto::SecureDto;
pub use error::BoundaryRejection;
pub use extract::{SecureJson, SecurePath, SecureQuery};
pub use fetch_metadata::FetchMetadataLayer;
pub use header_sanitize::sanitize_header_value;
pub use headers::{CspNonce, SecurityHeadersLayer};
pub use id::{OpaquePublicId, OrderId, TenantId, UserId};
pub use limits::RequestLimits;
pub use safe_types::{
    LdapSafeString, SafeCommandArg, SafeFilename, SafePath, SafeRedirectUrl, SafeUrl, SqlIdentifier,
};
pub use validate::{SecureValidate, ValidationContext};
#[cfg(feature = "axum")]
pub use xml::SecureXml;

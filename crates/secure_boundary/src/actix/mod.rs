//! Actix-web 4 integration for `secure_boundary`.
//!
//! This module is gated on the `actix-web` feature. It ships three adapters
//! that mirror the axum-shaped types in the rest of the crate:
//!
//! - `SecureJson<T>` is re-exported from [`crate::extract`]; the Actix-
//!   specific `impl actix_web::FromRequest for SecureJson<T>` lives in
//!   the [`extract`] submodule.
//! - [`SecurityHeadersTransform`](crate::actix::headers::SecurityHeadersTransform)
//!   wraps [`crate::headers::SecurityHeadersLayer`] and emits byte-identical
//!   OWASP-recommended security headers on Actix responses.
//! - [`FetchMetadataTransform`](crate::actix::fetch_metadata::FetchMetadataTransform)
//!   wraps [`crate::fetch_metadata::FetchMetadataLayer`] and applies the same
//!   allow/block classification on Actix requests.
//!
//! # Minimal example
//!
//! ```
//! # #[cfg(feature = "actix-web")]
//! # fn _doc() {
//! use actix_web::{web, App, HttpResponse};
//! use secure_boundary::actix::{FetchMetadataTransform, SecurityHeadersTransform};
//! use secure_boundary::SecureJson;
//! use secure_boundary::validate::{SecureValidate, ValidationContext};
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! #[serde(deny_unknown_fields)]
//! struct CreateItem { name: String }
//!
//! impl SecureValidate for CreateItem {
//!     fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
//!         if self.name.is_empty() { Err("name_empty") } else { Ok(()) }
//!     }
//!     fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
//! }
//!
//! async fn create(item: SecureJson<CreateItem>) -> HttpResponse {
//!     HttpResponse::Ok().body(item.into_inner().name)
//! }
//!
//! let _app = App::new()
//!     .wrap(SecurityHeadersTransform::new())
//!     .wrap(FetchMetadataTransform::new())
//!     .route("/items", web::post().to(create));
//! # }
//! ```
//!
//! See `docs/dev-guide/secure_boundary-actix.md` in the repository for a full
//! integration guide.

pub mod extract;
pub mod fetch_metadata;
pub mod headers;

pub use fetch_metadata::FetchMetadataTransform;
pub use headers::SecurityHeadersTransform;

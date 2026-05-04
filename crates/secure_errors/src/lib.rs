#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
//! `secure_errors` — Centralized error handling (OWASP C10).
//!
//! Provides a three-layer error model:
//! - **Internal layer** (`kind::AppError`): full internal details, never serialized to clients.
//! - **Public layer** (`public::PublicError`): the only type serialized to HTTP responses.
//! - **Operational layer** (`classify::ErrorClassification`): retryability, alerting, signals.
//!
//! # Feature flags
//!
//! | Flag | Default | Enables |
//! |---|---|---|
//! | `axum` | ✅ | [`middleware::ErrorMappingLayer`] tower layer + `impl IntoResponse for AppError` |
//! | `actix-web` | | `impl actix_web::ResponseError for AppError` (see [`actix`]) |
//!
//! Both paths route through the single-source-of-truth mapping in
//! [`http::into_response_parts`], so axum and actix-web responses for the
//! same `AppError` are byte-identical.
//!
//! # Design invariants
//! - `PublicError` is the **only** type that may be serialized to HTTP responses.
//! - `http::into_response_parts` is the **only** place that maps errors to HTTP status codes.
//! - No internal error text (SQL, hostnames, stack traces) may appear in `PublicError`.

pub mod capture;
pub mod classify;
pub mod context_propagation;
pub mod http;
pub mod incident;
pub mod kind;
#[cfg(feature = "axum")]
pub mod middleware;
pub mod panic;
pub mod public;
pub mod report;

/// Actix-web 4 integration — `impl ResponseError for AppError`.
///
/// Gated on the `actix-web` feature.
#[cfg(feature = "actix-web")]
pub mod actix;

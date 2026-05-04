//! Secure-by-default CORS helpers built on [`tower_http::cors::CorsLayer`].
//!
//! The primary API is [`secure_cors_defaults`] for a deny-all configuration and
//! [`SecureCorsBuilder`] for explicit allowlists. This module is gated on the
//! `axum` feature because it depends on `tower-http`; consumers on other HTTP
//! frameworks should wire CORS via their framework's native middleware.

#![cfg(feature = "axum")]

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method};
use thiserror::Error;
use tower_http::cors::CorsLayer;

/// Returns a [`CorsLayer`] with secure deny-all defaults.
///
/// No origins, methods, or request headers are allowed unless the caller
/// explicitly configures them.
///
/// # Examples
///
/// ```
/// use secure_boundary::cors::secure_cors_defaults;
/// use tower_http::cors::CorsLayer;
///
/// let _: CorsLayer = secure_cors_defaults();
/// ```
pub fn secure_cors_defaults() -> CorsLayer {
    CorsLayer::new()
}

/// Builder for explicit CORS allowlists with secure defaults.
///
/// This builder starts from [`secure_cors_defaults`] so cross-origin access is
/// denied unless origins and methods are explicitly allowlisted.
///
/// # Examples
///
/// ```
/// use axum::http::Method;
/// use secure_boundary::cors::SecureCorsBuilder;
///
/// let _cors = SecureCorsBuilder::new()
///     .allow_origin("https://app.example.com")
///     .allow_methods([Method::GET, Method::POST])
///     .build()?;
/// # Ok::<(), secure_boundary::cors::CorsConfigError>(())
/// ```
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct SecureCorsBuilder {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<Method>,
    allowed_headers: Vec<HeaderName>,
    allow_credentials: bool,
    max_age: Option<Duration>,
}

impl SecureCorsBuilder {
    /// Creates a new builder with deny-all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an allowed origin to the CORS allowlist.
    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.push(origin.into());
        self
    }

    /// Adds allowed HTTP methods to the CORS allowlist.
    pub fn allow_methods<I>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = Method>,
    {
        self.allowed_methods.extend(methods);
        self
    }

    /// Adds allowed request headers to the CORS allowlist.
    pub fn allow_headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        self.allowed_headers.extend(headers);
        self
    }

    /// Enables or disables credential support.
    pub fn allow_credentials(mut self, allow_credentials: bool) -> Self {
        self.allow_credentials = allow_credentials;
        self
    }

    /// Sets the `Access-Control-Max-Age` value for successful preflight responses.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Builds the configured [`CorsLayer`].
    ///
    /// # Errors
    ///
    /// Returns [`CorsConfigError::InvalidOrigin`] if any configured origin is
    /// not a valid HTTP header value.
    pub fn build(self) -> Result<CorsLayer, CorsConfigError> {
        let mut layer = secure_cors_defaults();

        if !self.allowed_origins.is_empty() {
            let origins = self
                .allowed_origins
                .into_iter()
                .map(|origin| {
                    HeaderValue::from_str(&origin)
                        .map_err(|_| CorsConfigError::InvalidOrigin { origin })
                })
                .collect::<Result<Vec<_>, _>>()?;
            layer = layer.allow_origin(origins);
        }

        if !self.allowed_methods.is_empty() {
            layer = layer.allow_methods(self.allowed_methods);
        }

        if !self.allowed_headers.is_empty() {
            layer = layer.allow_headers(self.allowed_headers);
        }

        if self.allow_credentials {
            layer = layer.allow_credentials(true);
        }

        if let Some(max_age) = self.max_age {
            layer = layer.max_age(max_age);
        }

        Ok(layer)
    }
}

/// Errors returned when building a secure CORS configuration.
#[non_exhaustive]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CorsConfigError {
    /// An origin string could not be encoded as a valid HTTP header value.
    #[error("invalid CORS origin: {origin}")]
    InvalidOrigin {
        /// The invalid origin value supplied by the caller.
        origin: String,
    },
}

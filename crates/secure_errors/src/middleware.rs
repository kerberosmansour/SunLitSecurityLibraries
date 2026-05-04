//! Tower middleware for automatic `AppError` → HTTP response mapping.
//!
//! `ErrorMappingLayer` is an opt-in Tower [`Layer`] that ensures any handler
//! returning `Result<impl IntoResponse, AppError>` gets automatic HTTP status
//! code mapping, `Retry-After` header insertion, and JSON `PublicError` body
//! serialisation. This replaces manual `into_response_parts()` calls in handlers.
//!
//! Gated on the `axum` feature. The actix-web 4 analogue is
//! [`impl ResponseError for AppError`](crate::actix) behind the
//! `actix-web` feature.

#![cfg(feature = "axum")]

use axum_core::response::{IntoResponse, Response};
use http::StatusCode;
use tower_layer::Layer;

use crate::http::{into_response_parts, retry_after_seconds};
use crate::kind::AppError;

/// Opt-in Tower [`Layer`] for automatic `AppError` → HTTP response mapping.
///
/// Wrap an axum `Router` with this layer to enable automatic error conversion.
/// Handlers that return `Result<impl IntoResponse, AppError>` will have errors
/// mapped to the correct HTTP status code and `PublicError` JSON body.
///
/// # Examples
///
/// ```
/// use secure_errors::middleware::ErrorMappingLayer;
/// use tower_layer::Layer;
///
/// let layer = ErrorMappingLayer;
/// // Apply to any tower Service — the layer is a pass-through that enables
/// // AppError's IntoResponse impl.
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ErrorMappingLayer;

impl<S> Layer<S> for ErrorMappingLayer {
    type Service = S;

    fn layer(&self, inner: S) -> Self::Service {
        // The actual mapping is done by AppError's IntoResponse impl.
        // The layer exists as the opt-in mechanism and the place to add
        // future enhancements (e.g. context propagation, logging).
        inner
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, public_error) = into_response_parts(&self);
        let retry = retry_after_seconds(&self);

        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let json_body = serde_json::to_string(&public_error).unwrap_or_else(|_| {
            r#"{"code":"internal_error","message":"An internal error occurred."}"#.to_string()
        });

        let mut response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum_core::body::Body::from(json_body))
            .unwrap_or_else(|_| {
                let mut resp = Response::new(axum_core::body::Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                resp
            });

        if let Some(seconds) = retry {
            response
                .headers_mut()
                .insert("retry-after", seconds.to_string().parse().unwrap());
        }

        response
    }
}

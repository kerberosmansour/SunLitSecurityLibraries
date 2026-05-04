//! Actix-web 4 `FromRequest` implementation for [`SecureJson<T>`].
//!
//! Reuses the same framework-neutral validation pipeline the axum adapter
//! uses (four-stage: transport → syntactic → semantic → authz-adjacent),
//! so axum and Actix paths reject identical inputs with identical codes.

use std::future::Future;
use std::pin::Pin;

use actix_http::StatusCode;
use actix_web::{
    dev::Payload, web::Bytes, Error, FromRequest, HttpRequest, HttpResponse, ResponseError,
};
use serde::de::DeserializeOwned;

use crate::error::BoundaryRejection;
use crate::extract::{validate_json_bytes, SecureJson};
use crate::limits::RequestLimits;
use crate::validate::{SecureValidate, ValidationContext};

impl<T> FromRequest for SecureJson<T>
where
    T: DeserializeOwned + SecureValidate + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // Read per-route RequestLimits from app_data; default to OWASP-recommended.
        let limits = req.app_data::<RequestLimits>().cloned().unwrap_or_default();

        // Content-Type check (Stage 1: transport validity) before touching the body.
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        // Take ownership of the payload future so it can outlive `req`.
        let payload_future = Bytes::from_request(req, payload);

        Box::pin(async move {
            if !content_type.starts_with("application/json") {
                crate::attack_signal::BoundaryViolation::new(
                    crate::attack_signal::ViolationKind::InvalidContentType,
                    "invalid_content_type",
                )
                .emit();
                return Err(BoundaryRejectionError(BoundaryRejection::InvalidContentType).into());
            }

            let bytes = payload_future.await.map_err(|_| {
                Error::from(BoundaryRejectionError(BoundaryRejection::MalformedBody))
            })?;

            let ctx = ValidationContext::new();
            match validate_json_bytes::<T>(&bytes, &limits, &ctx) {
                Ok(value) => Ok(SecureJson::from_validated(value)),
                Err(rej) => Err(BoundaryRejectionError(rej).into()),
            }
        })
    }
}

/// Newtype wrapping [`BoundaryRejection`] so it can implement Actix's
/// [`ResponseError`] trait without touching the framework-neutral type.
#[derive(Debug)]
struct BoundaryRejectionError(BoundaryRejection);

impl std::fmt::Display for BoundaryRejectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ResponseError for BoundaryRejectionError {
    fn status_code(&self) -> StatusCode {
        // Both the actix and http crates export StatusCode — they are the same
        // u16-backed newtype underneath, so the conversion is mechanical.
        let code = self.0.status_code().as_u16();
        StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        let code = self.0.client_code();
        HttpResponse::build(self.status_code())
            .insert_header(("content-type", "application/json"))
            .body(format!(r#"{{"error":{{"code":"{code}"}}}}"#))
    }
}

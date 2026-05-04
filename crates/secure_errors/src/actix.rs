//! Actix-web 4 integration for `secure_errors`.
//!
//! Gated on the `actix-web` feature. Exposes
//! [`impl actix_web::ResponseError for AppError`] so handlers returning
//! `Result<_, AppError>` get automatic HTTP status-code mapping, JSON
//! [`PublicError`] body serialisation, and `Retry-After` emission for
//! `AppError::RateLimit` — all routed through the same
//! [`crate::http::into_response_parts`] mapping table the axum path uses.
//! The two frameworks therefore emit byte-identical responses for a given
//! `AppError`.
//!
//! [`impl actix_web::ResponseError for AppError`]: ../kind/enum.AppError.html
//! [`PublicError`]: crate::public::PublicError

#![cfg(feature = "actix-web")]

use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use actix_web::ResponseError;

use crate::http::{into_response_parts, retry_after_seconds};
use crate::kind::AppError;

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        let (code, _) = into_response_parts(self);
        StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        let (code, public) = into_response_parts(self);
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let body = serde_json::to_string(&public).unwrap_or_else(|_| {
            r#"{"code":"internal_error","message":"An internal error occurred."}"#.to_string()
        });

        let mut resp = HttpResponse::build(status);
        resp.insert_header(("content-type", "application/json"));

        if let Some(seconds) = retry_after_seconds(self) {
            resp.insert_header(("retry-after", seconds.to_string()));
        }

        resp.body(body)
    }
}

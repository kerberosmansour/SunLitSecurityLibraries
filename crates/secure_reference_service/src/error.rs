//! Application-level error type composing `secure_errors`.

use axum::{body::Body, response::IntoResponse};
use http::{Response, StatusCode};
use secure_errors::kind::AppError;
use secure_errors::public::PublicError;

/// Application error — wraps [`AppError`] for axum response mapping.
#[derive(Debug)]
pub struct AppHttpError(pub AppError);

impl From<AppError> for AppHttpError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

impl IntoResponse for AppHttpError {
    fn into_response(self) -> Response<Body> {
        let (status_code, public_err) = secure_errors::http::into_response_parts(&self.0);
        let body = serde_json::to_string(&public_err).unwrap_or_else(|_| {
            r#"{"code":"internal_error","message":"An internal error occurred."}"#.to_string()
        });
        Response::builder()
            .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| {
                let mut r = Response::new(Body::empty());
                *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                r
            })
    }
}

/// Build a 404 not found error response.
pub fn not_found_response() -> Response<Body> {
    let err = PublicError::new("not_found", "The requested resource was not found.", None);
    let body = serde_json::to_string(&err)
        .unwrap_or_else(|_| r#"{"code":"not_found","message":"Not found."}"#.to_string());
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        })
}

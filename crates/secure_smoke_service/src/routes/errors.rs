//! Error handling smoke routes.
//!
//! Each route exercises a specific error handling control from `secure_errors`.

use axum::response::Response;
use secure_boundary::extract::SecureJson;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_errors::kind::AppError;
use serde::{Deserialize, Serialize};

/// GET `/smoke/error/internal` — triggers an internal error.
pub async fn error_internal() -> Result<Response, AppError> {
    Err(AppError::Internal)
}

/// GET `/smoke/error/dependency` — triggers a dependency error.
pub async fn error_dependency() -> Result<Response, AppError> {
    Err(AppError::Dependency { dep: "database" })
}

/// GET `/smoke/error/panic` — triggers a panic (caught by CatchPanicLayer).
pub async fn error_panic() -> Response {
    panic!("deliberate panic for smoke test");
}

/// Request DTO for validation error test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequest {
    /// Must be non-empty.
    pub field: String,
}

impl SecureValidate for ValidationRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.field.is_empty() {
            return Err("field_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/error/validation` — returns a validation error.
pub async fn error_validation(
    payload: SecureJson<ValidationRequest>,
) -> Result<Response, AppError> {
    let _req = payload.into_inner();
    // If we get here, validation passed — force a validation error anyway for testing
    Err(AppError::Validation {
        code: "test_validation_error",
    })
}

//! BDD acceptance tests for error-to-HTTP mapping.
//!
//! Feature: Error-to-HTTP mapping
//! Proves that every `AppError` variant maps to the correct HTTP status code
//! and that the `PublicError` body contains only the allowed fields.

use secure_errors::{
    classify::ErrorClassification, http::into_response_parts, kind::AppError, public::PublicError,
};
use security_core::types::RequestId;

// ---------------------------------------------------------------------------
// Helper: convert AppError to (status_code, json_body)
// ---------------------------------------------------------------------------
fn error_to_parts(err: AppError) -> (u16, serde_json::Value) {
    let (status, public_error) = into_response_parts(&err);
    let json = serde_json::to_value(&public_error).expect("PublicError must be serializable");
    (status, json)
}

// ---------------------------------------------------------------------------
// Scenario: Validation error maps to 400
// ---------------------------------------------------------------------------
#[test]
fn validation_error_maps_to_400() {
    let err = AppError::Validation {
        code: "invalid_email",
    };
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 400);
    assert_eq!(body["code"], "invalid_request");
    // No internal details
    let body_str = body.to_string();
    assert!(
        !body_str.contains("invalid_email"),
        "internal code must not leak"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Forbidden error maps to 403
// ---------------------------------------------------------------------------
#[test]
fn forbidden_error_maps_to_403() {
    let err = AppError::Forbidden {
        policy: "delete_account",
    };
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 403);
    assert_eq!(body["code"], "forbidden");
    let body_str = body.to_string();
    assert!(
        !body_str.contains("delete_account"),
        "policy name must not leak"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Not found maps to 404
// ---------------------------------------------------------------------------
#[test]
fn not_found_maps_to_404() {
    let err = AppError::NotFound;
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 404);
    assert_eq!(body["code"], "not_found");
}

// ---------------------------------------------------------------------------
// Scenario: Dependency error maps to 503
// ---------------------------------------------------------------------------
#[test]
fn dependency_error_maps_to_503() {
    let err = AppError::Dependency { dep: "postgres" };
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 503);
    assert_eq!(body["code"], "temporarily_unavailable");
    let body_str = body.to_string();
    assert!(!body_str.contains("postgres"), "dep name must not leak");
}

// ---------------------------------------------------------------------------
// Scenario: Internal error maps to 500
// ---------------------------------------------------------------------------
#[test]
fn internal_error_maps_to_500() {
    let err = AppError::Internal;
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 500);
    assert_eq!(body["code"], "internal_error");
}

// ---------------------------------------------------------------------------
// Scenario: Rate limit maps to 429
// ---------------------------------------------------------------------------
#[test]
fn rate_limit_maps_to_429() {
    let err = AppError::RateLimit {
        retry_after_seconds: None,
    };
    let (status, body) = error_to_parts(err);
    assert_eq!(status, 429);
    assert_eq!(body["code"], "rate_limited");
}

// ---------------------------------------------------------------------------
// Scenario: Request ID propagated
// ---------------------------------------------------------------------------
#[test]
fn request_id_propagated() {
    let request_id = RequestId::generate();
    let public = PublicError::new("not_found", "Resource not found", Some(request_id.clone()));
    let json = serde_json::to_value(&public).expect("must serialize");
    assert_eq!(
        json["request_id"].as_str().unwrap(),
        request_id.to_string().as_str()
    );
}

// ---------------------------------------------------------------------------
// Scenario: Error classification — Dependency is retryable
// ---------------------------------------------------------------------------
#[test]
fn dependency_error_is_retryable() {
    let classification = ErrorClassification::for_error(&AppError::Dependency { dep: "redis" });
    assert!(classification.is_retryable());
}

// ---------------------------------------------------------------------------
// Scenario: Error classification — Validation is not retryable
// ---------------------------------------------------------------------------
#[test]
fn validation_error_not_retryable() {
    let classification = ErrorClassification::for_error(&AppError::Validation { code: "bad" });
    assert!(!classification.is_retryable());
}

// ---------------------------------------------------------------------------
// Scenario: Error classification — Forbidden is security signal
// ---------------------------------------------------------------------------
#[test]
fn forbidden_is_security_signal() {
    let classification = ErrorClassification::for_error(&AppError::Forbidden { policy: "x" });
    assert!(classification.is_security_signal());
}

#![cfg(feature = "axum")]

use axum::http::StatusCode;
use secure_boundary::{
    error::BoundaryRejection,
    validate::{SecureValidate, ValidationContext},
};

struct ValidDto {
    value: String,
}

impl SecureValidate for ValidDto {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.value.is_empty() {
            Err("empty_value")
        } else {
            Ok(())
        }
    }
    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn test_boundary_rejection_body_too_large_status() {
    let r = BoundaryRejection::BodyTooLarge;
    assert_eq!(r.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.client_code(), "body_too_large");
}

#[test]
fn test_boundary_rejection_invalid_content_type_status() {
    let r = BoundaryRejection::InvalidContentType;
    assert_eq!(r.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(r.client_code(), "invalid_content_type");
}

#[test]
fn test_boundary_rejection_malformed_body_status() {
    let r = BoundaryRejection::MalformedBody;
    assert_eq!(r.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.client_code(), "malformed_body");
}

#[test]
fn test_boundary_rejection_syntax_violation_status() {
    let r = BoundaryRejection::SyntaxViolation { code: "too_long" };
    assert_eq!(r.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.client_code(), "syntax_violation");
}

#[test]
fn test_boundary_rejection_semantic_violation_status() {
    let r = BoundaryRejection::SemanticViolation {
        code: "invalid_age",
    };
    assert_eq!(r.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.client_code(), "semantic_violation");
}

#[test]
fn test_secure_validate_syntax_ok() {
    let dto = ValidDto {
        value: "hello".to_owned(),
    };
    let ctx = ValidationContext::new();
    assert!(dto.validate_syntax(&ctx).is_ok());
}

#[test]
fn test_secure_validate_syntax_err() {
    let dto = ValidDto {
        value: String::new(),
    };
    let ctx = ValidationContext::new();
    assert_eq!(dto.validate_syntax(&ctx), Err("empty_value"));
}

#[test]
fn test_into_response_does_not_echo_raw_input() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    let r = BoundaryRejection::SyntaxViolation { code: "test_code" };
    let resp = r.into_response();
    // Status must be 422
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Body must not contain the raw code verbatim in a way that could be injected
    let (_parts, body) = resp.into_parts();
    let bytes = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(body.collect())
        .unwrap()
        .to_bytes();
    let body_str = std::str::from_utf8(&bytes).unwrap();
    // The stable client_code is present
    assert!(body_str.contains("syntax_violation"));
    // The internal code "test_code" is NOT echoed
    assert!(!body_str.contains("test_code"));
}

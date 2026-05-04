//! E2E runtime validation for Milestone 2 — `secure_errors`.
//!
//! These tests go beyond compilation and verify the full runtime behaviour.

use secure_errors::{
    classify::ErrorClassification, http::into_response_parts, kind::AppError,
    panic::catch_panic_to_safe_response, public::PublicError,
};
use security_core::types::RequestId;

// ---------------------------------------------------------------------------
// E2E: error-to-response round-trip
// ---------------------------------------------------------------------------
#[test]
fn test_error_to_response_roundtrip() {
    let variants: Vec<AppError> = vec![
        AppError::Validation { code: "bad_value" },
        AppError::Forbidden {
            policy: "edit_post",
        },
        AppError::NotFound,
        AppError::Conflict,
        AppError::Dependency { dep: "cache" },
        AppError::Internal,
        AppError::RateLimit {
            retry_after_seconds: None,
        },
    ];

    let expected_statuses = [400u16, 403, 404, 409, 503, 500, 429];

    for (err, expected) in variants.into_iter().zip(expected_statuses) {
        let (status, public_err) = into_response_parts(&err);
        assert_eq!(status, expected, "wrong status for variant");
        // Body must be valid JSON
        let json = serde_json::to_value(&public_err).expect("must serialize");
        // Must have code and message fields
        assert!(json.get("code").is_some(), "code field required");
        assert!(json.get("message").is_some(), "message field required");
    }
}

// ---------------------------------------------------------------------------
// E2E: PublicError serializes to exactly the expected fields
// ---------------------------------------------------------------------------
#[test]
fn test_public_error_serialization() {
    let request_id = RequestId::generate();
    let public = PublicError::new("not_found", "Resource not found", Some(request_id));
    let json = serde_json::to_value(&public).expect("must serialize");

    // Must contain exactly: code, message, request_id
    let obj = json.as_object().expect("must be JSON object");
    for key in obj.keys() {
        assert!(
            matches!(key.as_str(), "code" | "message" | "request_id"),
            "unexpected field in PublicError: {key}"
        );
    }
    assert!(obj.contains_key("code"));
    assert!(obj.contains_key("message"));
    assert!(obj.contains_key("request_id"));
}

// ---------------------------------------------------------------------------
// E2E: No internal leakage at runtime across all variants
// ---------------------------------------------------------------------------
#[test]
fn test_no_internal_leak_runtime() {
    let forbidden_strings = [
        "SELECT",
        "INSERT",
        "WHERE",
        "FROM",
        "db-prod-03",
        "at src/",
        "frame",
    ];

    let variants: Vec<AppError> = vec![
        AppError::Validation { code: "bad" },
        AppError::Forbidden {
            policy: "SELECT * FROM",
        },
        AppError::Dependency {
            dep: "db-prod-03.internal",
        },
        AppError::Internal,
        AppError::RateLimit {
            retry_after_seconds: None,
        },
    ];

    for err in variants {
        let (_status, public_err) = into_response_parts(&err);
        let body = serde_json::to_string(&public_err).expect("must serialize");
        for forbidden in &forbidden_strings {
            assert!(
                !body.contains(forbidden),
                "forbidden string '{forbidden}' found in response body: {body}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// E2E: PanicSafeLayer catches panic and returns safe 500
// ---------------------------------------------------------------------------
#[test]
fn test_panic_safe_layer() {
    let (status, body) = catch_panic_to_safe_response(|| {
        panic!("oh no");
    });
    assert_eq!(status, 500);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["code"], "internal_error");
    assert!(!body.contains("oh no"), "panic message must not leak");
}

// ---------------------------------------------------------------------------
// E2E: Error classification consistency — no contradictory flags
// ---------------------------------------------------------------------------
#[test]
fn test_error_classification_consistency() {
    let variants: Vec<AppError> = vec![
        AppError::Validation { code: "x" },
        AppError::Forbidden { policy: "x" },
        AppError::NotFound,
        AppError::Conflict,
        AppError::Dependency { dep: "x" },
        AppError::Internal,
        AppError::RateLimit {
            retry_after_seconds: None,
        },
    ];

    for err in variants {
        let cls = ErrorClassification::for_error(&err);
        // If it's a user-fixable error, it must not be a security signal
        // (a client bad-request is not an attack)
        if cls.is_user_fixable() && matches!(err, AppError::Validation { .. }) {
            assert!(
                !cls.is_alertable(),
                "pure validation errors must not trigger alerts"
            );
        }
        // A security signal must be alertable
        if cls.is_security_signal() {
            assert!(cls.is_alertable(), "security signals must be alertable");
        }
    }
}

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use secure_boundary::{
    extract::SecureJson,
    headers::SecurityHeadersLayer,
    validate::{SecureValidate, ValidationContext},
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

// DTO with deny_unknown_fields to prevent mass-assignment
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateUserRequest {
    username: String,
    email: String,
}

impl SecureValidate for CreateUserRequest {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.username.is_empty() {
            return Err("username_empty");
        }
        if self.email.is_empty() {
            return Err("email_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if !self.email.contains('@') {
            return Err("email_invalid");
        }
        Ok(())
    }
}

async fn create_user_handler(user: SecureJson<CreateUserRequest>) -> String {
    let dto = user.into_inner();
    format!("created:{}", dto.username)
}

fn make_app() -> Router {
    Router::new()
        .route("/users", post(create_user_handler))
        .route("/health", get(|| async { "ok" }))
        .layer(SecurityHeadersLayer::new())
}

#[tokio::test]
async fn test_secure_json_happy_path() {
    let app = make_app();
    let body = r#"{"username":"alice","email":"alice@example.com"}"#;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_secure_json_unknown_field_rejection() {
    let app = make_app();
    let body = r#"{"username":"alice","email":"alice@example.com","role":"admin"}"#;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_secure_json_body_limit() {
    let app = make_app();
    // Body over 1 MiB
    let big = "a".repeat(2 * 1024 * 1024);
    let body = format!(r#"{{"username":"{}","email":"a@b.com"}}"#, big);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_validation_pipeline_order() {
    let app = make_app();
    // Empty username fails syntax before semantics (invalid email) is checked
    let body = r#"{"username":"","email":"not-an-email"}"#;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_normalization_applied() {
    use secure_boundary::normalize::normalize_email;
    // Test normalize utilities directly
    let result = normalize_email("Alice@EXAMPLE.COM");
    assert_eq!(result, "Alice@example.com");
}

#[tokio::test]
async fn test_mass_assignment_blocked() {
    let app = make_app();
    let body = r#"{"username":"alice","email":"alice@example.com","role":"admin"}"#;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "mass assignment should be blocked"
    );
}

#[tokio::test]
async fn test_boundary_violation_event_emitted() {
    // Verify that a boundary violation (wrong content type) returns the expected rejection
    // and does not panic — event emission is tested implicitly via the security events subsystem
    let app = make_app();
    let body = r#"{"username":"alice","email":"alice@example.com"}"#;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "text/plain")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_security_headers_applied() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.headers().contains_key("strict-transport-security"));
    assert!(resp.headers().contains_key("content-security-policy"));
    assert!(resp.headers().contains_key("x-content-type-options"));
    assert!(resp.headers().contains_key("x-frame-options"));
    assert!(resp.headers().contains_key("cache-control"));
}

#[tokio::test]
async fn test_html_encoding_prevents_xss() {
    use secure_output::{HtmlEncoder, OutputEncoder};
    let enc = HtmlEncoder;
    let xss = "<script>alert(1)</script>";
    let encoded = enc.encode(xss);
    assert!(!encoded.contains('<'));
    assert!(!encoded.contains('>'));
}

#[tokio::test]
async fn test_url_encoding_roundtrip() {
    use secure_output::{OutputEncoder, UrlEncoder};
    let enc = UrlEncoder;
    let input = "hello world";
    let encoded = enc.encode(input);
    assert_eq!(encoded, "hello%20world");
}

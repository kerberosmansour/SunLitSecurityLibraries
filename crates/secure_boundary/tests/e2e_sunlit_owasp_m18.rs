//! End-to-end runtime validation tests for M18.
//!
//! These tests verify that depth/field enforcement and HTML sanitization
//! work correctly at runtime, not just at compile time.

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use http_body_util::BodyExt;
use secure_boundary::{
    extract::SecureJson,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Payload {
    value: serde_json::Value,
}

impl SecureValidate for Payload {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

fn app() -> Router {
    Router::new().route(
        "/submit",
        post(|dto: SecureJson<Payload>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

// ---------------------------------------------------------------------------
// E2E: Depth limit enforced at runtime
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_depth_limit_enforced_at_runtime() {
    // Build a deeply nested JSON during an actual HTTP request flow
    let depth = 15; // exceeds default 10
    let inner_open: String = r#"{"a":"#.repeat(depth - 1);
    let inner_close: String = "}".repeat(depth - 1);
    let json = format!(r#"{{"value":{}{}{}}}"#, inner_open, r#""x""#, inner_close);

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/submit")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "depth > limit must be rejected at runtime"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("nesting_too_deep"), "body: {body}");
}

// ---------------------------------------------------------------------------
// E2E: Field count enforced at runtime
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_field_count_enforced_at_runtime() {
    let count = 200; // exceeds default 100
    let fields: String = (0..count)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(r#"{{"value":{{{}}}}}"#, fields);

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/submit")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field count > limit must be rejected at runtime"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("too_many_fields"), "body: {body}");
}

// ---------------------------------------------------------------------------
// E2E: HTML sanitization removes XSS (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "html-sanitize")]
#[test]
fn test_html_sanitization_removes_xss() {
    use secure_boundary::sanitize::sanitize_html;

    let dangerous = r#"<p>Hello</p><script>alert('xss')</script><img src=x onerror=alert(1)>"#;
    let safe = sanitize_html(dangerous);

    assert!(!safe.contains("<script"), "script tag not removed");
    assert!(!safe.contains("onerror"), "event handler not removed");
    assert!(safe.contains("<p>Hello</p>"), "safe content lost");
}

// ---------------------------------------------------------------------------
// E2E: Existing routes still work with normal payloads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_existing_routes_still_work() {
    let json = r#"{"value":"hello"}"#;
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/submit")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "valid payloads must still be accepted"
    );
}

//! BDD tests for SecureJson nesting depth and field count enforcement (M18).
//!
//! Covers: depth boundary, field count boundary, custom limits, DoS rejection.

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Extension, Router,
};
use http_body_util::BodyExt;
use secure_boundary::{
    extract::SecureJson,
    limits::RequestLimits,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test DTO
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnyJson {
    value: serde_json::Value,
}

impl SecureValidate for AnyJson {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_router() -> Router {
    Router::new().route(
        "/json",
        post(|dto: SecureJson<AnyJson>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

fn custom_limit_router(limits: RequestLimits) -> Router {
    Router::new()
        .route(
            "/json",
            post(|dto: SecureJson<AnyJson>| async move {
                let _ = dto.into_inner();
                StatusCode::OK
            }),
        )
        .layer(Extension(limits))
}

/// Builds a JSON string nested `depth` levels deep inside `{"value": ...}`.
fn make_nested_json(depth: usize) -> String {
    // depth=1 → {"value":"x"}
    // depth=2 → {"value":{"a":"x"}}
    if depth <= 1 {
        return r#"{"value":"x"}"#.to_string();
    }
    let inner_open: String = r#"{"a":"#.repeat(depth - 1);
    let inner_close: String = "}".repeat(depth - 1);
    format!(r#"{{"value":{}{}{}}}"#, inner_open, r#""x""#, inner_close)
}

/// Builds a flat JSON object with `count` fields inside `{"value":{...}}`.
fn make_field_json(count: usize) -> String {
    let fields: String = (0..count)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"value":{{{}}}}}"#, fields)
}

async fn post_json(app: Router, body: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&bytes).to_string();
    (status, body_str)
}

// ===========================================================================
// Feature: JSON depth limit enforcement
// ===========================================================================

#[tokio::test]
async fn shallow_json_accepted() {
    // Given: A JSON body with nesting depth 3
    // When: Deserialized via SecureJson<T>
    // Then: Succeeds, inner value available
    let (status, _) = post_json(default_router(), &make_nested_json(3)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn exact_depth_limit_accepted() {
    // Given: A JSON body with nesting depth exactly 10 (default)
    // When: Deserialized via SecureJson<T>
    // Then: Succeeds
    let (status, _) = post_json(default_router(), &make_nested_json(10)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn depth_exceeds_limit_rejected() {
    // Given: A JSON body with nesting depth 11
    // When: Deserialized via SecureJson<T>
    // Then: Returns 422 with error code nesting_too_deep
    let (status, body) = post_json(default_router(), &make_nested_json(11)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("nesting_too_deep"), "body: {body}");
}

#[tokio::test]
async fn deeply_nested_bomb_rejected() {
    // Given: A JSON body with nesting depth 500 (DoS)
    // When: Deserialized via SecureJson<T>
    // Then: Returns 422; no OOM
    let (status, body) = post_json(default_router(), &make_nested_json(500)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("nesting_too_deep"), "body: {body}");
}

#[tokio::test]
async fn custom_depth_limit_honoured() {
    // Given: RequestLimits configured with max_nesting_depth = 5; JSON with depth 6
    // When: Deserialized
    // Then: Returns 422
    let limits = RequestLimits::new().with_max_nesting_depth(5);
    let (status, body) = post_json(custom_limit_router(limits), &make_nested_json(6)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("nesting_too_deep"), "body: {body}");
}

#[tokio::test]
async fn custom_depth_limit_accepts_within() {
    // Given: RequestLimits with max_nesting_depth = 5; JSON with depth 5
    // When: Deserialized
    // Then: Succeeds
    let limits = RequestLimits::new().with_max_nesting_depth(5);
    let (status, _) = post_json(custom_limit_router(limits), &make_nested_json(5)).await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Feature: JSON field count limit enforcement
// ===========================================================================

#[tokio::test]
async fn normal_field_count_accepted() {
    // Given: A JSON body with 5 fields
    // When: Deserialized via SecureJson<T>
    // Then: Succeeds
    let (status, _) = post_json(default_router(), &make_field_json(5)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn exact_field_limit_accepted() {
    // Given: A JSON body with exactly 100 fields (default)
    // When: Deserialized
    // Then: Succeeds
    //
    // Note: make_field_json(n) creates n fields inside the inner object,
    // plus the outer "value" key — so n+1 colons total. We need max_field_count
    // colons total ≤ 100. 99 inner fields + 1 outer = 100 colons.
    let (status, _) = post_json(default_router(), &make_field_json(99)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn field_count_exceeds_limit_rejected() {
    // Given: A JSON body with 101 fields
    // When: Deserialized
    // Then: Returns 422 with error code too_many_fields
    let (status, body) = post_json(default_router(), &make_field_json(101)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("too_many_fields"), "body: {body}");
}

#[tokio::test]
async fn field_flood_attack_rejected() {
    // Given: A JSON body with 10,000 fields (DoS)
    // When: Deserialized
    // Then: Returns 422; no excessive memory use
    let (status, body) = post_json(default_router(), &make_field_json(10_000)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("too_many_fields"), "body: {body}");
}

#[tokio::test]
async fn custom_field_limit_honoured() {
    // Given: RequestLimits with max_field_count = 10; JSON with 11 fields
    // When: Deserialized
    // Then: Returns 422
    let limits = RequestLimits::new().with_max_field_count(10);
    let (status, body) = post_json(custom_limit_router(limits), &make_field_json(11)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("too_many_fields"), "body: {body}");
}

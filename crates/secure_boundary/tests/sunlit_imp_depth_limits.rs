//! BDD tests for SecureJson nesting depth and field count enforcement (M11).

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use secure_boundary::{
    extract::SecureJson,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
#[allow(dead_code)]
struct SimpleDto {
    value: serde_json::Value,
}

impl SecureValidate for SimpleDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

fn json_router() -> Router {
    Router::new().route(
        "/json",
        post(|dto: SecureJson<SimpleDto>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

/// Builds a JSON string nested `depth` levels deep.
fn make_nested_json(depth: usize) -> String {
    let open: String = r#"{"value":"#.repeat(depth);
    let close: String = "}".repeat(depth);
    format!("{}{}{}", open, r#""x""#, close)
}

/// Builds a JSON object containing `count` fields inside the `value` key.
fn make_field_flood_json(count: usize) -> String {
    let fields: String = (0..count)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"value":{{{}}}}}"#, fields)
}

#[tokio::test]
async fn normal_json_within_limits_accepted() {
    // Given: 3-level nested JSON, well within defaults
    let app = json_router();
    let json = r#"{"value":{"a":{"b":"c"}}}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 200 OK
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn deeply_nested_json_rejected() {
    // Given: 500-level nested JSON (exceeds default max_nesting_depth = 10)
    let app = json_router();
    let json = make_nested_json(500);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 422 Unprocessable Entity
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn field_flood_rejected() {
    // Given: JSON with 10,000 fields (exceeds default max_field_count = 100)
    let app = json_router();
    let json = make_field_flood_json(10_000);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 422 Unprocessable Entity
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn default_limits_reasonable() {
    // Given: JSON with 50 fields (within default max_field_count = 100)
    let app = json_router();
    let fields: String = (0..50)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(r#"{{"value":{{{}}}}}"#, fields);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 200 OK
    assert_eq!(response.status(), StatusCode::OK);
}

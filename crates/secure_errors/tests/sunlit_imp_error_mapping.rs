//! BDD tests for M15: ErrorMappingLayer and retry-after.

#![cfg(feature = "axum")]

use axum::body::Body;
use axum::routing::get;
use axum::Router;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use secure_errors::kind::AppError;
use secure_errors::middleware::ErrorMappingLayer;
use tower::ServiceExt;

async fn validation_error_handler() -> Result<String, AppError> {
    Err(AppError::Validation { code: "bad_email" })
}

async fn forbidden_error_handler() -> Result<String, AppError> {
    Err(AppError::Forbidden {
        policy: "admin_only",
    })
}

async fn rate_limit_handler() -> Result<String, AppError> {
    Err(AppError::RateLimit {
        retry_after_seconds: Some(30),
    })
}

async fn rate_limit_no_retry_handler() -> Result<String, AppError> {
    Err(AppError::RateLimit {
        retry_after_seconds: None,
    })
}

async fn ok_handler() -> Result<String, AppError> {
    Ok("hello".to_string())
}

async fn send_get(app: Router, uri: &str) -> http::Response<Body> {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    app.oneshot(req).await.unwrap()
}

// ---------- Feature: ErrorMappingLayer ----------

#[tokio::test]
async fn apperror_validation_auto_mapped_to_400() {
    // Given: handler returns Err(AppError::Validation)
    let app = Router::new()
        .route("/test", get(validation_error_handler))
        .layer(ErrorMappingLayer);

    // When: through ErrorMappingLayer
    let resp = send_get(app, "/test").await;

    // Then: 400 response with PublicError
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "invalid_request");
}

#[tokio::test]
async fn apperror_forbidden_auto_mapped_to_403() {
    // Given: handler returns Err(AppError::Forbidden)
    let app = Router::new()
        .route("/test", get(forbidden_error_handler))
        .layer(ErrorMappingLayer);

    // When: through layer
    let resp = send_get(app, "/test").await;

    // Then: 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "forbidden");
}

#[tokio::test]
async fn apperror_ratelimit_with_retry_after() {
    // Given: handler returns Err(AppError::RateLimit { retry_after_seconds: Some(30) })
    let app = Router::new()
        .route("/test", get(rate_limit_handler))
        .layer(ErrorMappingLayer);

    // When: through layer
    let resp = send_get(app, "/test").await;

    // Then: 429 with Retry-After: 30 header
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers().get("retry-after").unwrap().to_str().unwrap(),
        "30"
    );
}

#[tokio::test]
async fn apperror_ratelimit_without_retry_after() {
    // Given: handler returns Err(AppError::RateLimit { retry_after_seconds: None })
    let app = Router::new()
        .route("/test", get(rate_limit_no_retry_handler))
        .layer(ErrorMappingLayer);

    // When: through layer
    let resp = send_get(app, "/test").await;

    // Then: 429 with no Retry-After header
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_none());
}

#[tokio::test]
async fn non_error_responses_pass_through() {
    // Given: handler returns Ok(Json(...))
    let app = Router::new()
        .route("/test", get(ok_handler))
        .layer(ErrorMappingLayer);

    // When: through layer
    let resp = send_get(app, "/test").await;

    // Then: 200 unchanged
    assert_eq!(resp.status(), StatusCode::OK);
}

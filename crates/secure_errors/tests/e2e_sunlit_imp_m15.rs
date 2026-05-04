//! E2E — Runtime validation for Milestone 15 (`secure_errors` error mapping layer).

#![cfg(feature = "axum")]

use axum::body::Body;
use axum::routing::get;
use axum::Router;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use secure_errors::kind::AppError;
use secure_errors::middleware::ErrorMappingLayer;
use tower::ServiceExt;

/// E2E: ErrorMappingLayer correctly maps all AppError variants at runtime.
#[tokio::test]
async fn test_error_mapping_layer_all_variants() {
    let app = Router::new()
        .route(
            "/validation",
            get(|| async { Err::<String, _>(AppError::Validation { code: "bad" }) }),
        )
        .route(
            "/forbidden",
            get(|| async { Err::<String, _>(AppError::Forbidden { policy: "x" }) }),
        )
        .route(
            "/not_found",
            get(|| async { Err::<String, _>(AppError::NotFound) }),
        )
        .route(
            "/conflict",
            get(|| async { Err::<String, _>(AppError::Conflict) }),
        )
        .route(
            "/dependency",
            get(|| async { Err::<String, _>(AppError::Dependency { dep: "db" }) }),
        )
        .route(
            "/crypto",
            get(|| async { Err::<String, _>(AppError::Crypto) }),
        )
        .route(
            "/internal",
            get(|| async { Err::<String, _>(AppError::Internal) }),
        )
        .route(
            "/rate_limit",
            get(|| async {
                Err::<String, _>(AppError::RateLimit {
                    retry_after_seconds: Some(60),
                })
            }),
        )
        .route("/ok", get(|| async { Ok::<String, AppError>("ok".into()) }))
        .layer(ErrorMappingLayer);

    // Validation → 400
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/validation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Forbidden → 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/forbidden")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // NotFound → 404
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/not_found")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Conflict → 409
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/conflict")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Dependency → 503
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dependency")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Crypto → 500
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/crypto")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Internal → 500
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/internal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // RateLimit → 429 with Retry-After header
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rate_limit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers().get("retry-after").unwrap().to_str().unwrap(),
        "60"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "rate_limited");

    // Ok → 200 unchanged
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// E2E: Context propagation stores and retrieves request/actor/tenant IDs.
#[tokio::test]
async fn test_context_propagation() {
    use secure_errors::context_propagation::{get_error_context, set_error_context, ErrorContext};

    // Setting context in current task
    let ctx = ErrorContext {
        request_id: Some("req-123".into()),
        actor_id: Some("actor-456".into()),
        tenant_id: Some("tenant-789".into()),
    };
    set_error_context(ctx);
    let retrieved = get_error_context();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.request_id.as_deref(), Some("req-123"));
    assert_eq!(retrieved.actor_id.as_deref(), Some("actor-456"));
    assert_eq!(retrieved.tenant_id.as_deref(), Some("tenant-789"));
}

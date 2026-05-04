//! End-to-end runtime validation for Milestone 21 browser security protections.

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{
        header::{ACCESS_CONTROL_REQUEST_METHOD, ORIGIN},
        Method, Request, StatusCode,
    },
    routing::get,
    Router,
};
use secure_boundary::{
    cors::{secure_cors_defaults, SecureCorsBuilder},
    fetch_metadata::FetchMetadataLayer,
    headers::SecurityHeadersLayer,
};
use tower::ServiceExt;

async fn ok_handler() -> &'static str {
    "ok"
}

#[tokio::test]
async fn test_cors_deny_all_default() {
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(secure_cors_defaults());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(ORIGIN, "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn test_cors_allowed_origin_works() {
    let cors = SecureCorsBuilder::new()
        .allow_origin("https://app.example.com")
        .allow_methods([Method::GET, Method::POST])
        .build()
        .expect("CORS builder should succeed");

    let app = Router::new().route("/", get(ok_handler)).layer(cors);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/")
                .header(ORIGIN, "https://app.example.com")
                .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://app.example.com"
    );
}

#[tokio::test]
async fn test_csp_nonce_unique_per_request() {
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new().with_csp_nonce());

    let first = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let second = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let first_csp = first
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let second_csp = second
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    assert!(first_csp.contains("'nonce-"));
    assert!(second_csp.contains("'nonce-"));
    assert_ne!(first_csp, second_csp);
}

#[tokio::test]
async fn test_fetch_metadata_blocks_cross_site() {
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(FetchMetadataLayer::new());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-dest", "empty")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_permissions_policy_present() {
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new());

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert!(response.headers().contains_key("permissions-policy"));
}

#[tokio::test]
async fn test_existing_headers_preserved() {
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new().with_csp_nonce());

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert!(response.headers().contains_key("strict-transport-security"));
    assert!(response.headers().contains_key("x-content-type-options"));
    assert!(response.headers().contains_key("x-frame-options"));
    assert!(response.headers().contains_key("content-security-policy"));
    assert!(response.headers().contains_key("permissions-policy"));
}

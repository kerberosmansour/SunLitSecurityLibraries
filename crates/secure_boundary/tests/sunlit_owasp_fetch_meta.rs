//! BDD scenarios for Milestone 21 Fetch Metadata and security header hardening.

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    extract::Extension,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use secure_boundary::{
    fetch_metadata::FetchMetadataLayer,
    headers::{defaults, CspNonce, SecurityHeadersLayer},
};
use tower::ServiceExt;

async fn ok_handler() -> &'static str {
    "ok"
}

async fn nonce_handler(Extension(nonce): Extension<CspNonce>) -> String {
    nonce.as_str().to_owned()
}

#[tokio::test]
async fn same_origin_request_accepted() {
    // Given: Fetch Metadata protection is enabled
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(FetchMetadataLayer::new());

    // When: a same-origin request is received
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("sec-fetch-site", "same-origin")
                .header("sec-fetch-mode", "cors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Then: the request is allowed through
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cross_site_request_rejected() {
    // Given: Fetch Metadata protection is enabled
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(FetchMetadataLayer::new());

    // When: a cross-site browser request targets the API
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

    // Then: the request is blocked
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_fetch_headers_allowed_for_older_browsers() {
    // Given: Fetch Metadata protection is enabled
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(FetchMetadataLayer::new());

    // When: an older browser sends no Sec-Fetch-* headers
    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Then: the request is allowed for backward compatibility
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn navigation_request_allowed() {
    // Given: Fetch Metadata protection is enabled
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(FetchMetadataLayer::new());

    // When: a top-level navigation request is made
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-dest", "document")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Then: the navigation is allowed through
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn csp_nonce_unique_per_request_and_in_header() {
    // Given: security headers with CSP nonces enabled
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new().with_csp_nonce());

    // When: two requests are processed sequentially
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

    // Then: each response carries a distinct nonce-bearing CSP value
    assert!(first_csp.contains("'nonce-"));
    assert!(second_csp.contains("'nonce-"));
    assert_ne!(first_csp, second_csp, "nonce must be unique per request");
}

#[tokio::test]
async fn csp_nonce_available_via_request_extension() {
    // Given: a handler that reads the generated nonce from request extensions
    let app = Router::new()
        .route("/nonce", get(nonce_handler))
        .layer(SecurityHeadersLayer::new().with_csp_nonce());

    // When: the request is processed
    let response = app
        .oneshot(
            Request::builder()
                .uri("/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let header_value = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let nonce_from_extension = String::from_utf8(body.to_vec()).unwrap();

    // Then: the body and CSP header refer to the same nonce
    assert!(header_value.contains(&format!("'nonce-{}'", nonce_from_extension)));
}

#[tokio::test]
async fn permissions_policy_defaults_and_customization_work() {
    // Given: one app with defaults and one with a custom policy
    let default_app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new());
    let custom_app = Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new().with_permissions_policy("camera=(self)"));

    // When: both apps serve a request
    let default_resp = default_app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let custom_resp = custom_app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Then: the secure default and custom override are both respected
    assert_eq!(
        default_resp.headers().get("permissions-policy").unwrap(),
        defaults::PERMISSIONS_POLICY
    );
    assert_eq!(
        custom_resp.headers().get("permissions-policy").unwrap(),
        "camera=(self)"
    );
}

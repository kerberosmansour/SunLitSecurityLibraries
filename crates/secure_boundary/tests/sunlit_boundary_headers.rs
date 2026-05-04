#![cfg(feature = "axum")]

use axum::{body::Body, http::Request, routing::get, Router};
use secure_boundary::headers::{defaults, SecurityHeadersLayer};
use tower::ServiceExt;

fn make_app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeadersLayer::new())
}

#[tokio::test]
async fn test_hsts_header_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let hsts = resp.headers().get("strict-transport-security").unwrap();
    assert_eq!(hsts.to_str().unwrap(), defaults::HSTS);
}

#[tokio::test]
async fn test_csp_header_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let csp = resp.headers().get("content-security-policy").unwrap();
    assert_eq!(csp.to_str().unwrap(), defaults::CSP);
}

#[tokio::test]
async fn test_xcto_header_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let xcto = resp.headers().get("x-content-type-options").unwrap();
    assert_eq!(xcto.to_str().unwrap(), "nosniff");
}

#[tokio::test]
async fn test_xfo_header_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let xfo = resp.headers().get("x-frame-options").unwrap();
    assert_eq!(xfo.to_str().unwrap(), "DENY");
}

#[tokio::test]
async fn test_permissions_policy_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let pp = resp.headers().get("permissions-policy").unwrap();
    assert_eq!(pp.to_str().unwrap(), defaults::PERMISSIONS_POLICY);
}

#[tokio::test]
async fn test_cache_control_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cc = resp.headers().get("cache-control").unwrap();
    assert_eq!(cc.to_str().unwrap(), "no-store");
}

#[tokio::test]
async fn test_custom_csp_override() {
    let custom_csp = "default-src 'self'";
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeadersLayer::new().with_csp(custom_csp));

    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let csp = resp.headers().get("content-security-policy").unwrap();
    assert_eq!(csp.to_str().unwrap(), custom_csp);
}

#[tokio::test]
async fn test_hsts_contains_required_directives() {
    let app = make_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(hsts.contains("max-age=63072000"));
    assert!(hsts.contains("includeSubDomains"));
    assert!(hsts.contains("preload"));
}

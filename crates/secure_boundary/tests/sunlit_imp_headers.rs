//! BDD scenarios: Cross-origin security headers (M12)
//!
//! Verifies that SecurityHeadersLayer injects the new cross-origin headers
//! and preserves all previously-existing headers.

#![cfg(feature = "axum")]

use axum::{body::Body, http::Request, routing::get, Router};
use secure_boundary::headers::SecurityHeadersLayer;
use tower::ServiceExt;

async fn ok_handler() -> &'static str {
    "OK"
}

fn make_app() -> Router {
    Router::new()
        .route("/", get(ok_handler))
        .layer(SecurityHeadersLayer::new())
}

async fn get_response_headers(app: Router) -> axum::http::HeaderMap {
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    resp.headers().clone()
}

// Scenario: COEP header present
#[tokio::test]
async fn headers_coep_present() {
    let headers = get_response_headers(make_app()).await;
    let val = headers
        .get("cross-origin-embedder-policy")
        .expect("COEP header must be present");
    assert_eq!(val, "require-corp");
}

// Scenario: COOP header present
#[tokio::test]
async fn headers_coop_present() {
    let headers = get_response_headers(make_app()).await;
    let val = headers
        .get("cross-origin-opener-policy")
        .expect("COOP header must be present");
    assert_eq!(val, "same-origin");
}

// Scenario: CORP header present
#[tokio::test]
async fn headers_corp_present() {
    let headers = get_response_headers(make_app()).await;
    let val = headers
        .get("cross-origin-resource-policy")
        .expect("CORP header must be present");
    assert_eq!(val, "same-origin");
}

// Scenario: X-DNS-Prefetch-Control header present
#[tokio::test]
async fn headers_x_dns_prefetch_control_present() {
    let headers = get_response_headers(make_app()).await;
    let val = headers
        .get("x-dns-prefetch-control")
        .expect("X-DNS-Prefetch-Control header must be present");
    assert_eq!(val, "off");
}

// Scenario: X-Permitted-Cross-Domain-Policies header present
#[tokio::test]
async fn headers_x_permitted_cross_domain_policies_present() {
    let headers = get_response_headers(make_app()).await;
    let val = headers
        .get("x-permitted-cross-domain-policies")
        .expect("X-Permitted-Cross-Domain-Policies header must be present");
    assert_eq!(val, "none");
}

// Scenario: Existing headers preserved
#[tokio::test]
async fn headers_existing_headers_preserved() {
    let headers = get_response_headers(make_app()).await;

    assert!(
        headers.contains_key("strict-transport-security"),
        "HSTS must still be present"
    );
    assert!(
        headers.contains_key("content-security-policy"),
        "CSP must still be present"
    );
    assert!(
        headers.contains_key("x-frame-options"),
        "X-Frame-Options must still be present"
    );
    assert!(
        headers.contains_key("x-content-type-options"),
        "X-Content-Type-Options must still be present"
    );
    assert!(
        headers.contains_key("permissions-policy"),
        "Permissions-Policy must still be present"
    );
    assert!(
        headers.contains_key("cache-control"),
        "Cache-Control must still be present"
    );
}

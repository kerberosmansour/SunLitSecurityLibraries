//! BDD scenarios for Milestone 21 CORS handling.

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
use secure_boundary::cors::{secure_cors_defaults, SecureCorsBuilder};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

async fn ok_handler() -> &'static str {
    "ok"
}

#[tokio::test]
async fn no_cors_config_rejects_cross_origin() {
    // Given: deny-all default CORS settings
    let _: CorsLayer = secure_cors_defaults();
    let app = Router::new()
        .route("/", get(ok_handler))
        .layer(secure_cors_defaults());

    // When: a cross-origin request is made from an untrusted origin
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

    // Then: no CORS allow header is returned
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "deny-all default must not emit allow-origin"
    );
}

#[tokio::test]
async fn allowed_origin_accepted() {
    // Given: an explicit allowlist for a trusted frontend origin
    let cors = SecureCorsBuilder::new()
        .allow_origin("https://app.example.com")
        .allow_methods([Method::GET, Method::POST])
        .build()
        .expect("CORS builder should succeed");

    let app = Router::new().route("/", get(ok_handler)).layer(cors);

    // When: the trusted origin sends a request
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(ORIGIN, "https://app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Then: the origin is echoed back in the response
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://app.example.com"
    );
}

#[tokio::test]
async fn disallowed_origin_rejected() {
    // Given: only the application origin is allowlisted
    let cors = SecureCorsBuilder::new()
        .allow_origin("https://app.example.com")
        .allow_methods([Method::GET, Method::POST])
        .build()
        .expect("CORS builder should succeed");

    let app = Router::new().route("/", get(ok_handler)).layer(cors);

    // When: a preflight request comes from a different origin
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/")
                .header(ORIGIN, "https://evil.example")
                .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Then: no allow-origin header is emitted
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "disallowed origins must not be granted CORS access"
    );
}

#[tokio::test]
async fn preflight_with_valid_method_allowed() {
    // Given: POST is explicitly allowlisted for the trusted origin
    let cors = SecureCorsBuilder::new()
        .allow_origin("https://app.example.com")
        .allow_methods([Method::GET, Method::POST])
        .build()
        .expect("CORS builder should succeed");

    let app = Router::new().route("/", get(ok_handler)).layer(cors);

    // When: a valid preflight request is sent
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

    // Then: CORS headers authorize the request
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://app.example.com"
    );
    assert!(response
        .headers()
        .get("access-control-allow-methods")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("POST"));
}

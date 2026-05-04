//! BDD: cross-framework parity for axum vs actix-web adapters — sg-gate-a M1.
//!
//! Each scenario drives the same input through both framework-specific adapters
//! and asserts identical observable behavior (status code, and where applicable,
//! the set of emitted security headers).

#![cfg(all(feature = "axum", feature = "actix-web"))]

use actix_web::{test as atest, web as aweb, App as AApp, HttpResponse as AResp};
use axum::{body::Body, extract::Request, routing::post, Router};
use secure_boundary::actix::{FetchMetadataTransform, SecurityHeadersTransform};
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::{FetchMetadataLayer, SecureJson, SecurityHeadersLayer};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dto {
    name: String,
}

impl SecureValidate for Dto {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() {
            Err("name_empty")
        } else {
            Ok(())
        }
    }
    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

async fn axum_handler(body: SecureJson<Dto>) -> String {
    body.into_inner().name
}

async fn actix_handler(body: SecureJson<Dto>) -> AResp {
    AResp::Ok().body(body.into_inner().name)
}

async fn axum_status(body: &'static str, content_type: &'static str) -> u16 {
    let app = Router::<()>::new().route("/dto", post(axum_handler));
    let req = Request::builder()
        .method("POST")
        .uri("/dto")
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    resp.status().as_u16()
}

async fn actix_status(body: &'static str, content_type: &'static str) -> u16 {
    let srv = atest::init_service(AApp::new().route("/dto", aweb::post().to(actix_handler))).await;
    let req = atest::TestRequest::post()
        .uri("/dto")
        .insert_header(("content-type", content_type))
        .set_payload(body)
        .to_request();
    let resp = atest::call_service(&srv, req).await;
    resp.status().as_u16()
}

#[tokio::test]
async fn parity_secure_json_happy_path_match() {
    let body = r#"{"name":"widget"}"#;
    let axum = axum_status(body, "application/json").await;
    let actix = actix_status(body, "application/json").await;
    assert_eq!(
        axum, actix,
        "happy-path status differs: axum={axum} actix={actix}"
    );
    assert_eq!(axum, 200);
}

#[tokio::test]
async fn parity_secure_json_bad_content_type_match() {
    let body = r#"{"name":"widget"}"#;
    let axum = axum_status(body, "application/xml").await;
    let actix = actix_status(body, "application/xml").await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 415);
}

#[tokio::test]
async fn parity_secure_json_malformed_match() {
    let body = r#"{not json"#;
    let axum = axum_status(body, "application/json").await;
    let actix = actix_status(body, "application/json").await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 422);
}

#[tokio::test]
async fn parity_secure_json_semantic_rejection_match() {
    let body = r#"{"name":""}"#;
    let axum = axum_status(body, "application/json").await;
    let actix = actix_status(body, "application/json").await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 422);
}

#[tokio::test]
async fn parity_security_headers_default_set_match() {
    // Axum
    let app = Router::<()>::new()
        .route("/", axum::routing::get(|| async { "ok" }))
        .layer(SecurityHeadersLayer::new());
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let axum_headers: std::collections::BTreeMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();

    // Actix
    let srv = atest::init_service(
        AApp::new()
            .wrap(SecurityHeadersTransform::new())
            .route("/", aweb::get().to(|| async { AResp::Ok().body("ok") })),
    )
    .await;
    let req2 = atest::TestRequest::get().uri("/").to_request();
    let resp2 = atest::call_service(&srv, req2).await;
    let actix_headers: std::collections::BTreeMap<String, String> = resp2
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();

    // The set of security headers must match between frameworks.
    let owasp_keys = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "permissions-policy",
        "cache-control",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "x-dns-prefetch-control",
        "x-permitted-cross-domain-policies",
    ];
    for key in owasp_keys {
        let a = axum_headers.get(key).cloned().unwrap_or_default();
        let b = actix_headers.get(key).cloned().unwrap_or_default();
        assert_eq!(a, b, "header {key} differs: axum={a} actix={b}");
    }
}

async fn axum_fetch_metadata_status(
    site: &'static str,
    mode: Option<&'static str>,
    method: &'static str,
) -> u16 {
    let app = Router::<()>::new()
        .route("/", axum::routing::get(|| async { "ok" }))
        .route("/", axum::routing::post(|| async { "ok" }))
        .layer(FetchMetadataLayer::new());
    let mut builder = Request::builder().method(method).uri("/");
    if !site.is_empty() {
        builder = builder.header("sec-fetch-site", site);
    }
    if let Some(m) = mode {
        builder = builder.header("sec-fetch-mode", m);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    resp.status().as_u16()
}

async fn actix_fetch_metadata_status(
    site: &'static str,
    mode: Option<&'static str>,
    method: &'static str,
) -> u16 {
    let srv = atest::init_service(
        AApp::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", aweb::get().to(|| async { AResp::Ok().body("ok") }))
            .route("/", aweb::post().to(|| async { AResp::Ok().body("ok") })),
    )
    .await;
    let mut builder = match method {
        "GET" => atest::TestRequest::get(),
        _ => atest::TestRequest::post(),
    };
    builder = builder.uri("/");
    if !site.is_empty() {
        builder = builder.insert_header(("sec-fetch-site", site));
    }
    if let Some(m) = mode {
        builder = builder.insert_header(("sec-fetch-mode", m));
    }
    let resp = atest::call_service(&srv, builder.to_request()).await;
    resp.status().as_u16()
}

#[tokio::test]
async fn parity_fetch_metadata_blocks_cross_site_match() {
    let axum = axum_fetch_metadata_status("cross-site", Some("cors"), "POST").await;
    let actix = actix_fetch_metadata_status("cross-site", Some("cors"), "POST").await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 403);
}

#[tokio::test]
async fn parity_fetch_metadata_allows_same_origin_match() {
    let axum = axum_fetch_metadata_status("same-origin", None, "POST").await;
    let actix = actix_fetch_metadata_status("same-origin", None, "POST").await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 200);
}

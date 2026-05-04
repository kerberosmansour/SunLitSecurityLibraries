//! E2E runtime validation for M11: safe types, depth/field limits, SecureXml,
//! and header sanitisation.

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use secure_boundary::{
    extract::SecureJson,
    header_sanitize::sanitize_header_value,
    safe_types::{SafePath, SafeUrl},
    validate::{SecureValidate, ValidationContext},
    xml::SecureXml,
};
use serde::Deserialize;
use tower::ServiceExt;

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct PathDto {
    path: SafePath,
}

impl SecureValidate for PathDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnyDto {
    value: serde_json::Value,
}

impl SecureValidate for AnyDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct XmlDto {
    name: String,
}

impl SecureValidate for XmlDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

// ── Routers ───────────────────────────────────────────────────────────────────

fn path_router() -> Router {
    Router::new().route(
        "/path",
        post(|dto: SecureJson<PathDto>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

fn json_router() -> Router {
    Router::new().route(
        "/json",
        post(|dto: SecureJson<AnyDto>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

fn xml_router() -> Router {
    Router::new().route(
        "/xml",
        post(|dto: SecureXml<XmlDto>| async move {
            let _ = dto.into_inner();
            StatusCode::OK
        }),
    )
}

// ── E2E Tests ─────────────────────────────────────────────────────────────────

/// Proves SafePath works inside SecureJson DTO end-to-end.
#[tokio::test]
async fn e2e_safe_path_in_dto_roundtrip() {
    let app = path_router();

    // Valid path → 200
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/path")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"images/photo.png"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "valid SafePath in DTO must be accepted"
    );

    // Traversal path → 422
    let bad = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/path")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"../../etc/passwd"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bad.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "traversal in SafePath DTO must be rejected"
    );
}

/// Proves max_nesting_depth is actually enforced.
#[tokio::test]
async fn e2e_depth_limit_enforced() {
    let app = json_router();

    // 5-deep → OK (within default limit of 10)
    let shallow = r#"{"value":{"a":{"b":{"c":{"d":"e"}}}}}"#;
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(shallow))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "5-deep JSON must be accepted");

    // 500-deep → 422
    let deep: String = {
        let mut s = String::new();
        for _ in 0..500 {
            s.push_str(r#"{"value":"#);
        }
        s.push_str(r#""x""#);
        for _ in 0..500 {
            s.push('}');
        }
        s
    };
    let bad = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(deep))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bad.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "500-deep JSON must be rejected"
    );
}

/// Proves max_field_count is actually enforced.
#[tokio::test]
async fn e2e_field_count_enforced() {
    let app = json_router();

    // 10 fields → OK
    let fields_10: String = (0..10)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    let json_10 = format!(r#"{{"value":{{{}}}}}"#, fields_10);
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json_10))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "10-field JSON must be accepted"
    );

    // 10,000 fields → 422
    let fields_10k: String = (0..10_000)
        .map(|i| format!(r#""f{}":"v""#, i))
        .collect::<Vec<_>>()
        .join(",");
    let json_10k = format!(r#"{{"value":{{{}}}}}"#, fields_10k);
    let bad = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header("content-type", "application/json")
                .body(Body::from(json_10k))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bad.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "10,000-field JSON must be rejected"
    );
}

/// Proves SecureXml blocks XXE entity expansion payload.
#[tokio::test]
async fn e2e_xml_xxe_blocked() {
    let app = xml_router();
    let xxe = concat!(
        r#"<?xml version="1.0"?>"#,
        r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
        r#"<XmlDto><name>&xxe;</name></XmlDto>"#
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xml")
                .header("content-type", "application/xml")
                .body(Body::from(xxe))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "XXE payload must be blocked"
    );
}

/// Proves CRLF header injection is blocked by sanitize_header_value.
#[tokio::test]
async fn e2e_header_crlf_blocked() {
    let result = sanitize_header_value("value\r\nInjected-Header: evil");
    assert!(
        result.is_err(),
        "CRLF in header value must be rejected by sanitize_header_value"
    );
}

/// Proves SafeUrl blocks SSRF to the AWS metadata endpoint (169.254.169.254).
#[tokio::test]
async fn e2e_safe_url_ssrf_blocked() {
    let result = SafeUrl::try_from("http://169.254.169.254/");
    assert!(
        result.is_err(),
        "link-local metadata endpoint must be blocked for SSRF prevention"
    );
}

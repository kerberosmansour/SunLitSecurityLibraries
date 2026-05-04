//! BDD tests for the SecureXml extractor (M11: XXE prevention).

#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use secure_boundary::{
    validate::{SecureValidate, ValidationContext},
    xml::SecureXml,
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct XmlPayload {
    name: String,
}

impl SecureValidate for XmlPayload {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

fn xml_router() -> Router {
    Router::new().route(
        "/xml",
        post(|p: SecureXml<XmlPayload>| async move { p.into_inner().name }),
    )
}

#[tokio::test]
async fn secure_xml_valid_accepted() {
    // Given: well-formed XML
    let app = xml_router();
    let xml = "<XmlPayload><name>test</name></XmlPayload>";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xml")
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: extracted successfully
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn secure_xml_xxe_payload_rejected() {
    // Given: XML with ENTITY declaration (XXE attack)
    let app = xml_router();
    let xml = concat!(
        r#"<?xml version="1.0"?>"#,
        r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
        r#"<XmlPayload><name>&xxe;</name></XmlPayload>"#
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xml")
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 422 with xxe_blocked
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn secure_xml_external_dtd_rejected() {
    // Given: XML with external DTD reference
    let app = xml_router();
    let xml = concat!(
        r#"<?xml version="1.0"?>"#,
        r#"<!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd">"#,
        r#"<XmlPayload><name>test</name></XmlPayload>"#
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xml")
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: 422
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn secure_xml_billion_laughs_rejected() {
    // Given: XML with nested entity expansion (billion laughs attack)
    let app = xml_router();
    let xml = concat!(
        r#"<?xml version="1.0"?>"#,
        r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>"#,
        r#"<XmlPayload><name>&lol2;</name></XmlPayload>"#
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xml")
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap(),
        )
        .await
        .unwrap();
    // Then: rejected (422 or 413)
    assert!(
        response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::PAYLOAD_TOO_LARGE
    );
}

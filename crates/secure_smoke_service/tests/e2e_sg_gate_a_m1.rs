//! E2E runtime validation — sg-gate-a M1.
//!
//! Boots a tiny Actix-web 4 service wiring all three adapters
//! (`SecurityHeadersTransform`, `FetchMetadataTransform`, `SecureJson<T>`)
//! and asserts end-to-end behavior via `actix_web::test::call_service`.

use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use secure_boundary::actix::{FetchMetadataTransform, SecurityHeadersTransform};
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::SecureJson;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestDto {
    name: String,
}

impl SecureValidate for TestDto {
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

async fn post_dto(dto: SecureJson<TestDto>) -> HttpResponse {
    HttpResponse::Ok().body(dto.into_inner().name)
}

macro_rules! service {
    () => {
        App::new()
            .wrap(SecurityHeadersTransform::new())
            .wrap(FetchMetadataTransform::new())
            .route("/dto", web::post().to(post_dto))
    };
}

#[actix_web::test]
async fn actix_service_boots_with_all_three_adapters() {
    let _srv = test::init_service(service!()).await;
}

#[actix_web::test]
async fn actix_e2e_happy_path_json_to_handler() {
    let srv = test::init_service(service!()).await;
    let req = test::TestRequest::post()
        .uri("/dto")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("content-security-policy"));
    assert!(resp.headers().contains_key("strict-transport-security"));
}

#[actix_web::test]
async fn actix_e2e_malformed_json_is_rejected() {
    let srv = test::init_service(service!()).await;
    let req = test::TestRequest::post()
        .uri("/dto")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{not json"#)
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(resp.headers().contains_key("content-security-policy"));
}

#[actix_web::test]
async fn actix_e2e_cross_site_request_blocked() {
    let srv = test::init_service(service!()).await;
    let req = test::TestRequest::post()
        .uri("/dto")
        .insert_header(("content-type", "application/json"))
        .insert_header(("sec-fetch-site", "cross-site"))
        .insert_header(("sec-fetch-mode", "cors"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_e2e_no_extractor_without_content_type() {
    let srv = test::init_service(service!()).await;
    let req = test::TestRequest::post()
        .uri("/dto")
        .insert_header(("content-type", "text/plain"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

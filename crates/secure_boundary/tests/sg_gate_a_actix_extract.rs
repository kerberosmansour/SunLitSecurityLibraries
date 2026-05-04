//! BDD: Actix-web 4 `SecureJson<T>` extractor — sg-gate-a M1.
//!
//! These tests exercise the full four-stage validation pipeline through
//! `actix_web`'s `FromRequest` path and assert identical rejection semantics
//! to the axum implementation. The test harness boots a tiny `App` per
//! scenario and calls `actix_web::test::call_service`.

#![cfg(feature = "actix-web")]

use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use secure_boundary::limits::RequestLimits;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::SecureJson;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateItem {
    name: String,
}

impl SecureValidate for CreateItem {
    fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() {
            Err("name_empty")
        } else {
            Ok(())
        }
    }

    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        if self.name == "forbidden" {
            Err("name_forbidden")
        } else {
            Ok(())
        }
    }
}

async fn handler(body: SecureJson<CreateItem>) -> HttpResponse {
    let _ = body.into_inner();
    HttpResponse::Ok().body("ok")
}

fn app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new().route("/items", web::post().to(handler))
}

#[actix_web::test]
async fn actix_secure_json_happy_path() {
    // Given: valid JSON with Content-Type application/json
    let srv = test::init_service(app()).await;
    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();

    // When: handler extracts SecureJson
    let resp = test::call_service(&srv, req).await;

    // Then: 200 and handler sees the validated value
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_secure_json_rejects_wrong_content_type() {
    let srv = test::init_service(app()).await;
    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/xml"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;

    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[actix_web::test]
async fn actix_secure_json_rejects_malformed_json() {
    let srv = test::init_service(app()).await;
    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{not json"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;

    // axum uses UNPROCESSABLE_ENTITY for malformed body (see BoundaryRejection::status_code)
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[actix_web::test]
async fn actix_secure_json_rejects_oversize_body() {
    let small_limits = RequestLimits::new().with_max_body_bytes(16);

    async fn limited_handler(body: SecureJson<CreateItem>) -> HttpResponse {
        let _ = body.into_inner();
        HttpResponse::Ok().finish()
    }

    let srv = test::init_service(
        App::new()
            .app_data(small_limits)
            .route("/items", web::post().to(limited_handler)),
    )
    .await;

    let big_body = format!(r#"{{"name":"{}"}}"#, "x".repeat(256));
    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/json"))
        .set_payload(big_body)
        .to_request();

    let resp = test::call_service(&srv, req).await;

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn actix_secure_json_rejects_nested_json() {
    let shallow = RequestLimits::new().with_max_nesting_depth(2);

    #[derive(Deserialize)]
    struct Nested {
        #[allow(dead_code)]
        a: serde_json::Value,
    }

    impl SecureValidate for Nested {
        fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
            Ok(())
        }
    }

    async fn h(_: SecureJson<Nested>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    let srv = test::init_service(App::new().app_data(shallow).route("/n", web::post().to(h))).await;

    let req = test::TestRequest::post()
        .uri("/n")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"a":{"b":{"c":{"d":1}}}}"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[actix_web::test]
async fn actix_secure_json_rejects_many_fields() {
    let strict = RequestLimits::new().with_max_field_count(2);

    #[derive(Deserialize)]
    struct Wide {
        #[allow(dead_code)]
        #[serde(flatten)]
        extra: std::collections::HashMap<String, serde_json::Value>,
    }

    impl SecureValidate for Wide {
        fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
            Ok(())
        }
    }

    async fn h(_: SecureJson<Wide>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    let srv = test::init_service(App::new().app_data(strict).route("/w", web::post().to(h))).await;

    let req = test::TestRequest::post()
        .uri("/w")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"a":1,"b":2,"c":3,"d":4}"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[actix_web::test]
async fn actix_secure_json_rejects_semantic_failure() {
    let srv = test::init_service(app()).await;
    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"name":"forbidden"}"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[actix_web::test]
async fn actix_secure_json_respects_per_route_limits() {
    // Default limits allow 1 MiB; override to something tiny that a typical
    // body would exceed.
    let tiny = RequestLimits::new().with_max_body_bytes(4);

    let srv = test::init_service(
        App::new()
            .app_data(tiny)
            .route("/items", web::post().to(handler)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/items")
        .insert_header(("content-type", "application/json"))
        .set_payload(r#"{"name":"widget"}"#)
        .to_request();

    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

//! BDD: Actix-web 4 `AppError` → HTTP mapping — sg-gate-a M2.
//!
//! Asserts that `impl actix_web::ResponseError for AppError` (gated on the
//! `actix-web` feature) maps every variant to the exact status code and
//! JSON `PublicError` body documented in `http::into_response_parts` — and
//! that `RateLimit` emits a `Retry-After` header.

#![cfg(feature = "actix-web")]

use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use secure_errors::kind::AppError;
use serde_json::Value;

macro_rules! assert_mapping {
    ($make_err:expr, $status:expr, $code:literal $(, retry = $retry:expr)? $(,)?) => {{
        let srv = test::init_service(App::new().route(
            "/",
            web::get().to(|| async move {
                let err: AppError = $make_err;
                Err::<HttpResponse, _>(err)
            }),
        ))
        .await;
        let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
        let status = resp.status();
        let retry = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).expect("body is JSON");
        assert_eq!(status, $status, "status for {} mismatch", $code);
        assert_eq!(
            json.get("code").and_then(Value::as_str),
            Some($code),
            "PublicError code mismatch"
        );
        assert!(
            json.get("message").is_some(),
            "PublicError must include a message"
        );
        $(
            assert_eq!(retry.as_deref(), $retry, "Retry-After header");
        )?
        let _ = retry;
    }};
}

#[actix_web::test]
async fn actix_error_validation_maps_to_400() {
    assert_mapping!(
        AppError::Validation {
            code: "email_invalid"
        },
        StatusCode::BAD_REQUEST,
        "invalid_request"
    );
}

#[actix_web::test]
async fn actix_error_forbidden_maps_to_403() {
    assert_mapping!(
        AppError::Forbidden {
            policy: "admin-only"
        },
        StatusCode::FORBIDDEN,
        "forbidden"
    );
}

#[actix_web::test]
async fn actix_error_not_found_maps_to_404() {
    assert_mapping!(AppError::NotFound, StatusCode::NOT_FOUND, "not_found");
}

#[actix_web::test]
async fn actix_error_conflict_maps_to_409() {
    assert_mapping!(AppError::Conflict, StatusCode::CONFLICT, "conflict");
}

#[actix_web::test]
async fn actix_error_dependency_maps_to_503() {
    assert_mapping!(
        AppError::Dependency { dep: "postgres" },
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable"
    );
}

#[actix_web::test]
async fn actix_error_crypto_maps_to_500() {
    assert_mapping!(
        AppError::Crypto,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error"
    );
}

#[actix_web::test]
async fn actix_error_internal_maps_to_500() {
    assert_mapping!(
        AppError::Internal,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error"
    );
}

#[actix_web::test]
async fn actix_error_rate_limit_maps_to_429_with_header() {
    assert_mapping!(
        AppError::RateLimit {
            retry_after_seconds: Some(30)
        },
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        retry = Some("30")
    );
}

#[actix_web::test]
async fn actix_error_rate_limit_no_retry_header_when_unset() {
    assert_mapping!(
        AppError::RateLimit {
            retry_after_seconds: None
        },
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        retry = None
    );
}

#[actix_web::test]
async fn actix_error_body_does_not_leak_internal_text() {
    let srv = test::init_service(App::new().route(
        "/",
        web::get().to(|| async {
            Err::<HttpResponse, _>(AppError::Validation {
                code: "INTERNAL_SQL_TEXT_MUST_NOT_LEAK",
            })
        }),
    ))
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    let body_bytes = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !body_str.contains("INTERNAL_SQL_TEXT_MUST_NOT_LEAK"),
        "internal validation code leaked into public body: {body_str}"
    );
}

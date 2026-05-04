//! BDD: cross-framework parity for `AppError` → HTTP — sg-gate-a M2.

#![cfg(all(feature = "axum", feature = "actix-web"))]

use actix_web::{test as atest, web as aweb, App as AApp, HttpResponse as AResp};
use axum::body::Body;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use http_body_util::BodyExt;
use secure_errors::kind::AppError;
use serde_json::Value;
use tower::ServiceExt;

fn make(err_kind: &'static str) -> AppError {
    match err_kind {
        "validation" => AppError::Validation {
            code: "email_invalid",
        },
        "forbidden" => AppError::Forbidden {
            policy: "admin-only",
        },
        "not_found" => AppError::NotFound,
        "conflict" => AppError::Conflict,
        "dependency" => AppError::Dependency { dep: "postgres" },
        "crypto" => AppError::Crypto,
        "internal" => AppError::Internal,
        "rate_limit_30" => AppError::RateLimit {
            retry_after_seconds: Some(30),
        },
        "rate_limit_none" => AppError::RateLimit {
            retry_after_seconds: None,
        },
        _ => panic!("unknown err_kind: {err_kind}"),
    }
}

async fn axum_response(err_kind: &'static str) -> (u16, Option<String>, Value) {
    let app = Router::<()>::new().route(
        "/",
        get(move || async move { make(err_kind).into_response() }),
    );
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let retry = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    (status, retry, json)
}

async fn actix_response(err_kind: &'static str) -> (u16, Option<String>, Value) {
    let srv = atest::init_service(AApp::new().route(
        "/",
        aweb::get().to(move || async move { Err::<AResp, _>(make(err_kind)) }),
    ))
    .await;
    let resp = atest::call_service(&srv, atest::TestRequest::get().uri("/").to_request()).await;
    let status = resp.status().as_u16();
    let retry = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = atest::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    (status, retry, json)
}

async fn assert_parity(err_kind: &'static str) {
    let (a_status, a_retry, a_json) = axum_response(err_kind).await;
    let (x_status, x_retry, x_json) = actix_response(err_kind).await;
    assert_eq!(a_status, x_status, "{err_kind}: status differs");
    assert_eq!(a_retry, x_retry, "{err_kind}: retry-after differs");
    assert_eq!(
        a_json.get("code"),
        x_json.get("code"),
        "{err_kind}: code differs"
    );
    assert_eq!(
        a_json.get("message"),
        x_json.get("message"),
        "{err_kind}: message differs"
    );
}

#[tokio::test]
async fn parity_error_validation() {
    assert_parity("validation").await;
}

#[tokio::test]
async fn parity_error_forbidden() {
    assert_parity("forbidden").await;
}

#[tokio::test]
async fn parity_error_not_found() {
    assert_parity("not_found").await;
}

#[tokio::test]
async fn parity_error_conflict() {
    assert_parity("conflict").await;
}

#[tokio::test]
async fn parity_error_dependency() {
    assert_parity("dependency").await;
}

#[tokio::test]
async fn parity_error_crypto() {
    assert_parity("crypto").await;
}

#[tokio::test]
async fn parity_error_internal() {
    assert_parity("internal").await;
}

#[tokio::test]
async fn parity_error_rate_limit_30s() {
    assert_parity("rate_limit_30").await;
}

#[tokio::test]
async fn parity_error_rate_limit_no_retry() {
    assert_parity("rate_limit_none").await;
}

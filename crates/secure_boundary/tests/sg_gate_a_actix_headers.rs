//! BDD: Actix-web 4 `SecurityHeadersTransform` middleware — sg-gate-a M1.
//!
//! Confirms every OWASP default header is emitted with byte-identical value
//! to the axum tower Layer, that overrides work, and that CSP nonces are
//! injected as a per-request `CspNonce` extension.

#![cfg(feature = "actix-web")]

use actix_web::{http::StatusCode, test, web, App, HttpMessage, HttpRequest, HttpResponse};
use secure_boundary::actix::SecurityHeadersTransform;
use secure_boundary::headers::{defaults, CspNonce};

async fn ok() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn reveal_nonce(req: HttpRequest) -> HttpResponse {
    // The nonce, if enabled, is inserted into request extensions by the transform.
    if let Some(n) = req.extensions().get::<CspNonce>() {
        HttpResponse::Ok().body(n.as_str().to_owned())
    } else {
        HttpResponse::Ok().body("<no-nonce>")
    }
}

#[actix_web::test]
async fn actix_security_headers_sets_all_defaults() {
    let srv = test::init_service(
        App::new()
            .wrap(SecurityHeadersTransform::new())
            .route("/", web::get().to(ok)),
    )
    .await;

    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();
    let pairs: &[(&str, &str)] = &[
        ("strict-transport-security", defaults::HSTS),
        ("content-security-policy", defaults::CSP),
        ("x-content-type-options", defaults::XCTO),
        ("x-frame-options", defaults::XFO),
        ("permissions-policy", defaults::PERMISSIONS_POLICY),
        ("cache-control", defaults::CACHE_CONTROL),
        ("cross-origin-embedder-policy", defaults::COEP),
        ("cross-origin-opener-policy", defaults::COOP),
        ("cross-origin-resource-policy", defaults::CORP),
        ("x-dns-prefetch-control", defaults::X_DNS_PREFETCH_CONTROL),
        (
            "x-permitted-cross-domain-policies",
            defaults::X_PERMITTED_CROSS_DOMAIN_POLICIES,
        ),
    ];
    for (name, expected) in pairs {
        let actual = headers
            .get(*name)
            .unwrap_or_else(|| panic!("missing header {name}"))
            .to_str()
            .unwrap();
        assert_eq!(actual, *expected, "header {name} mismatch");
    }
}

#[actix_web::test]
async fn actix_security_headers_overrides_csp() {
    let srv = test::init_service(
        App::new()
            .wrap(SecurityHeadersTransform::new().with_csp("default-src 'self'"))
            .route("/", web::get().to(ok)),
    )
    .await;

    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(csp, "default-src 'self'");
}

#[actix_web::test]
async fn actix_security_headers_csp_nonce() {
    let srv = test::init_service(
        App::new()
            .wrap(SecurityHeadersTransform::new().with_csp_nonce())
            .route("/", web::get().to(reveal_nonce)),
    )
    .await;

    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    let status = resp.status();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    assert_eq!(status, StatusCode::OK);
    // Default CSP contains no {nonce} marker so the transform appends
    // `script-src 'nonce-...'; style-src 'nonce-...'`.
    assert!(csp.contains("'nonce-"), "CSP should carry nonce: got {csp}");

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert_ne!(body_str, "<no-nonce>", "handler did not see nonce");
    assert!(
        csp.contains(body_str),
        "response CSP should carry the same nonce seen by the handler; csp={csp} body={body_str}"
    );
}

#[actix_web::test]
async fn actix_security_headers_still_set_on_handler_error() {
    async fn boom() -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }

    let srv = test::init_service(
        App::new()
            .wrap(SecurityHeadersTransform::new())
            .route("/", web::get().to(boom)),
    )
    .await;

    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(resp.headers().contains_key("content-security-policy"));
    assert!(resp.headers().contains_key("strict-transport-security"));
}

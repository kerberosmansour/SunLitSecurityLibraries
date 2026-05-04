//! BDD: Actix-web 4 `FetchMetadataTransform` middleware — sg-gate-a M1.

#![cfg(feature = "actix-web")]

use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use secure_boundary::actix::FetchMetadataTransform;

async fn ok() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[actix_web::test]
async fn actix_fetch_metadata_allows_same_origin() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", web::post().to(ok)),
    )
    .await;
    let req = test::TestRequest::post()
        .uri("/")
        .insert_header(("sec-fetch-site", "same-origin"))
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_fetch_metadata_allows_none() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", web::post().to(ok)),
    )
    .await;
    let req = test::TestRequest::post()
        .uri("/")
        .insert_header(("sec-fetch-site", "none"))
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_fetch_metadata_allows_missing_headers_by_default() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", web::post().to(ok)),
    )
    .await;
    let req = test::TestRequest::post().uri("/").to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_fetch_metadata_blocks_cross_site() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", web::post().to(ok)),
    )
    .await;
    let req = test::TestRequest::post()
        .uri("/")
        .insert_header(("sec-fetch-site", "cross-site"))
        .insert_header(("sec-fetch-mode", "cors"))
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_fetch_metadata_allows_cross_site_top_nav() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new())
            .route("/", web::get().to(ok)),
    )
    .await;
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("sec-fetch-site", "cross-site"))
        .insert_header(("sec-fetch-mode", "navigate"))
        .insert_header(("sec-fetch-dest", "document"))
        .to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_fetch_metadata_blocks_when_strict() {
    let srv = test::init_service(
        App::new()
            .wrap(FetchMetadataTransform::new().allow_missing_headers(false))
            .route("/", web::post().to(ok)),
    )
    .await;

    let req = test::TestRequest::post().uri("/").to_request();
    let resp = test::call_service(&srv, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

//! Minimal Actix-web 4 service demonstrating `AppError` error-mapping.
//!
//! Build and run:
//!
//! ```sh
//! cargo run --example actix_error_minimal -p secure_errors --features actix-web
//! ```
//!
//! Probe the different `AppError` variants:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080/not-found    # 404 {"code":"not_found",...}
//! curl -v http://127.0.0.1:8080/rate-limit   # 429 Retry-After: 30 {"code":"rate_limited",...}
//! curl -v http://127.0.0.1:8080/dep          # 503 {"code":"temporarily_unavailable",...}
//! ```
//!
//! Notice: every response body is the `PublicError` JSON shape; no internal
//! details (dependency name, policy name, validation code) ever leak.

use actix_web::{web, App, HttpResponse, HttpServer};
use secure_errors::kind::AppError;

async fn not_found() -> Result<HttpResponse, AppError> {
    Err(AppError::NotFound)
}

async fn rate_limited() -> Result<HttpResponse, AppError> {
    Err(AppError::RateLimit {
        retry_after_seconds: Some(30),
    })
}

async fn dependency() -> Result<HttpResponse, AppError> {
    Err(AppError::Dependency { dep: "postgres" })
}

async fn ok() -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().body("ok"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/ok", web::get().to(ok))
            .route("/not-found", web::get().to(not_found))
            .route("/rate-limit", web::get().to(rate_limited))
            .route("/dep", web::get().to(dependency))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

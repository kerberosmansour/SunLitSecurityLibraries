//! Minimal runnable Actix-web 4 service wiring all three `secure_boundary`
//! Actix adapters: `SecurityHeadersTransform`, `FetchMetadataTransform`,
//! and `SecureJson<T>`.
//!
//! Build and run:
//!
//! ```sh
//! cargo run --example actix_minimal -p secure_boundary --features actix-web
//! ```
//!
//! Then in another terminal:
//!
//! ```sh
//! curl -v -X POST http://127.0.0.1:8080/items \
//!      -H "content-type: application/json" \
//!      -d '{"name":"widget"}'
//! ```
//!
//! The response body echoes the item name and every response carries the
//! full OWASP-recommended security header set.

use actix_web::{web, App, HttpResponse, HttpServer};
use secure_boundary::actix::{FetchMetadataTransform, SecurityHeadersTransform};
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
            return Err("name_empty");
        }
        if self.name.len() > 64 {
            return Err("name_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

async fn create_item(item: SecureJson<CreateItem>) -> HttpResponse {
    let item = item.into_inner();
    HttpResponse::Ok().body(format!("created: {}", item.name))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            // Install security headers on every response.
            .wrap(SecurityHeadersTransform::new().with_csp_nonce())
            // Block suspicious cross-site fetches.
            .wrap(FetchMetadataTransform::new())
            // Routes use the SecureJson extractor for the four-stage validation.
            .route("/items", web::post().to(create_item))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#![forbid(unsafe_code)]
//! `secure_reference_service` — library façade for integration testing.
//!
//! Re-exports the modules needed by integration tests while keeping the binary entry point
//! in `main.rs`.

pub mod auth_dev;
pub mod config;
pub mod dto;
pub mod error;
pub mod middleware;
pub mod resilience;
pub mod routes;
pub mod state;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
    Router,
};

use resilience::ResilienceConfig;
use state::AppState;

/// Assembles the axum router with all middleware layers applied.
///
/// Exposed for integration testing.
pub fn build_router(state: AppState, resilience: &ResilienceConfig) -> Router {
    // Routes that require full security middleware (auth + authz)
    let secure_routes = Router::new()
        .route(
            "/device-trust/hardware",
            get(routes::device_trust::hardware_route),
        )
        .route("/device-trust/ci", get(routes::device_trust::ci_route))
        .route("/items", post(routes::items::create_item))
        .route("/items/{id}", get(routes::items::get_item))
        .route("/items/{id}", put(routes::items::update_item))
        .route("/items/{id}", delete(routes::items::delete_item))
        .route("/panic-test", get(routes::panic_test::panic_test))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state);

    let secure_routes = middleware::apply_security_stack(secure_routes, resilience);

    let health_routes = Router::new().route("/health", get(routes::health::health));

    Router::new().merge(health_routes).merge(secure_routes)
}

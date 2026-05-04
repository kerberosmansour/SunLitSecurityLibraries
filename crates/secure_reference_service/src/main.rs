#![forbid(unsafe_code)]
//! `secure_reference_service` — Reference Axum Integration Service.
//!
//! This binary composes all eight SunLit Security Library crates into a working application,
//! demonstrating canonical middleware ordering and full security coverage on every route.
//!
//! # WARNING — DevAuthLayer is NOT for production
//! The `DevAuthLayer` used here extracts identity from a request header. Replace it with a
//! real `IdentitySource` implementation before any production deployment.

use secure_reference_service::{
    build_router, config::SecurityConfig, resilience::ResilienceConfig, state::AppState,
};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    // Initialise tracing (structured logging via security_events infrastructure)
    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    // Pre-flight: validate security configuration — fail fast on misconfiguration
    let sec_config = SecurityConfig::dev();
    if let Err(e) = sec_config.validate() {
        eprintln!("FATAL: security configuration invalid — {e}");
        std::process::exit(1);
    }

    // Initialise shared state
    let state = AppState::new().await;

    // Build resilience configuration
    let resilience = ResilienceConfig::default();

    // Build the router with security middleware applied
    let app = build_router(state, &resilience);

    let addr = "127.0.0.1:3000";
    tracing::info!("secure_reference_service listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind to 127.0.0.1:3000");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Graceful shutdown signal using `tokio::signal::ctrl_c()` (cross-platform).
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received");
}

//! Entry point for the secure smoke-test microservice.

use secure_smoke_service::config::SecurityConfig;
use secure_smoke_service::state::AppState;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let config = SecurityConfig::dev();
    let state = AppState::new(&config)
        .await
        .expect("failed to initialise application state");

    let app = secure_smoke_service::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .expect("failed to bind listener");

    tracing::info!("secure_smoke_service listening on 127.0.0.1:3001");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("shutting down");
}

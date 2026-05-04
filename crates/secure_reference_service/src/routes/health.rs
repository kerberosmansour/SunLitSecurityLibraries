//! Health route — no security middleware, returns basic liveness response.

use axum::response::IntoResponse;
use http::StatusCode;

/// `GET /health` — liveness check.
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, r#"{"status":"ok"}"#)
}

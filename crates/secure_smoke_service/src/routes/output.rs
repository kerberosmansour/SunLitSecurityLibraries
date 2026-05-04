//! Output encoding smoke routes.
//!
//! Each route exercises a specific output encoding control from `secure_output`.

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use secure_output::encode::OutputEncoder;
use secure_output::html::HtmlEncoder;
use secure_output::js::JsStringEncoder;
use secure_output::json::JsonEncoder;
use secure_output::sanitize_uri_scheme;
use secure_output::url::UrlEncoder;
use serde::Deserialize;

/// Query parameter for reflection tests.
#[derive(Debug, Deserialize)]
pub struct ReflectQuery {
    /// User-provided input to reflect.
    pub input: String,
}

/// GET `/smoke/reflect-html` — reflects user input in an HTML context, HTML-encoded.
pub async fn reflect_html(Query(q): Query<ReflectQuery>) -> impl IntoResponse {
    let encoder = HtmlEncoder;
    let safe = encoder.encode(&q.input);
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!("<p>{safe}</p>"),
    )
}

/// GET `/smoke/reflect-url` — reflects user input in a URL context.
pub async fn reflect_url(Query(q): Query<ReflectQuery>) -> impl IntoResponse {
    // Check for dangerous URI schemes
    if sanitize_uri_scheme(&q.input).is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [("content-type", "application/json")],
            serde_json::json!({ "code": "dangerous_uri_scheme" }).to_string(),
        );
    }

    let encoder = UrlEncoder;
    let safe = encoder.encode(&q.input);
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({ "encoded_url": safe }).to_string(),
    )
}

/// GET `/smoke/reflect-json` — reflects user input in a JSON/script context.
pub async fn reflect_json(Query(q): Query<ReflectQuery>) -> impl IntoResponse {
    // First escape JS string special chars (quotes, backslash, newlines),
    // then apply JsonEncoder to neutralise </script> sequences.
    let js_safe = JsStringEncoder.encode(&q.input);
    let safe = JsonEncoder.encode(&js_safe);
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(r#"<script>var data = "{safe}";</script>"#),
    )
}

/// GET `/smoke/headers` — returns an empty response; security headers are applied by middleware.
pub async fn check_headers() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

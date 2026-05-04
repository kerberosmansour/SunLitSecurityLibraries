//! Input validation smoke routes.
//!
//! Each route exercises a specific input validation control from `secure_boundary`.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use secure_boundary::extract::SecureJson;
use secure_boundary::safe_types::{SafeCommandArg, SafeFilename, SafePath};
use secure_boundary::sanitize_header_value;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_boundary::xml::SecureXml;
use secure_output::encode::OutputEncoder;
use secure_output::html::HtmlEncoder;
use serde::{Deserialize, Serialize};

/// Request DTO for XSS test — reflects content back HTML-encoded.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XssRequest {
    /// User-provided content to be reflected.
    pub content: String,
}

impl SecureValidate for XssRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.content.is_empty() {
            return Err("content_empty");
        }
        if self.content.len() > 10_000 {
            return Err("content_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/xss` — reflects content back HTML-encoded.
pub async fn xss_reflect(payload: SecureJson<XssRequest>) -> impl IntoResponse {
    let req = payload.into_inner();
    let encoder = HtmlEncoder;
    let safe_content = encoder.encode(&req.content);
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        safe_content.into_owned(),
    )
}

/// Request DTO for SQL injection test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqliRequest {
    /// A search term that will be validated as a safe SQL identifier.
    pub search: String,
}

impl SecureValidate for SqliRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.search.is_empty() {
            return Err("search_empty");
        }
        if self.search.len() > 128 {
            return Err("search_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/sqli` — validates search parameter as a SQL-safe identifier.
pub async fn sqli_check(payload: SecureJson<SqliRequest>) -> Response {
    use secure_boundary::safe_types::SqlIdentifier;

    let req = payload.into_inner();
    match SqlIdentifier::try_from(req.search.as_str()) {
        Ok(safe_id) => (
            StatusCode::OK,
            serde_json::json!({ "safe_identifier": safe_id.as_inner() }).to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({ "code": "invalid_sql_identifier" }).to_string(),
        )
            .into_response(),
    }
}

/// Request DTO for command injection test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CmdiRequest {
    /// A filename intended for a command argument.
    pub filename: String,
}

impl SecureValidate for CmdiRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.filename.is_empty() {
            return Err("filename_empty");
        }
        if self.filename.len() > 255 {
            return Err("filename_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/cmdi` — validates filename as a safe command argument.
pub async fn cmdi_check(payload: SecureJson<CmdiRequest>) -> Response {
    let req = payload.into_inner();
    match SafeCommandArg::try_from(req.filename.as_str()) {
        Ok(safe_arg) => (
            StatusCode::OK,
            serde_json::json!({ "safe_argument": safe_arg.as_inner() }).to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({ "code": "invalid_command_arg" }).to_string(),
        )
            .into_response(),
    }
}

/// GET `/smoke/path-traversal/{path}` — validates path segment against traversal attacks.
pub async fn path_traversal_check(Path(user_path): Path<String>) -> Response {
    match SafePath::try_from(user_path.as_str()) {
        Ok(safe) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            serde_json::json!({ "safe_path": safe.as_inner() }).to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            [("content-type", "application/json")],
            serde_json::json!({ "code": "path_traversal_blocked" }).to_string(),
        )
            .into_response(),
    }
}

/// XML DTO for XXE test.
#[derive(Debug, Deserialize, Serialize)]
pub struct XxeRequest {
    /// A data field in the XML payload.
    pub data: String,
}

impl SecureValidate for XxeRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.data.is_empty() {
            return Err("data_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/xxe` — parses XML with XXE prevention.
pub async fn xxe_check(payload: SecureXml<XxeRequest>) -> impl IntoResponse {
    let req = payload.into_inner();
    (
        StatusCode::OK,
        serde_json::json!({ "data": req.data }).to_string(),
    )
}

/// Request DTO for deep nesting / deserialization test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeserializationRequest {
    /// A nested field.
    pub value: serde_json::Value,
}

impl SecureValidate for DeserializationRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/deserialization` — tests against malicious JSON payloads.
pub async fn deserialization_check(
    payload: SecureJson<DeserializationRequest>,
) -> impl IntoResponse {
    let _req = payload.into_inner();
    (
        StatusCode::OK,
        serde_json::json!({ "ok": true }).to_string(),
    )
}
/// Request DTO for mass assignment test — rejects unknown fields.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MassAssignmentRequest {
    /// The user's requested name.
    pub name: String,
    /// The user's email.
    pub email: String,
}

impl SecureValidate for MassAssignmentRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() {
            return Err("name_empty");
        }
        if self.email.is_empty() {
            return Err("email_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/mass-assignment` — rejects unknown fields (e.g., `is_admin`).
pub async fn mass_assignment_check(
    payload: SecureJson<MassAssignmentRequest>,
) -> impl IntoResponse {
    let req = payload.into_inner();
    (
        StatusCode::OK,
        serde_json::json!({ "name": req.name, "email": req.email }).to_string(),
    )
}

/// Request DTO for header injection test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderInjectionRequest {
    /// A value intended for use in an HTTP header.
    pub header_value: String,
}

impl SecureValidate for HeaderInjectionRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.header_value.is_empty() {
            return Err("header_value_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/header-injection` — sanitises header values against CRLF.
pub async fn header_injection_check(
    payload: SecureJson<HeaderInjectionRequest>,
) -> impl IntoResponse {
    let req = payload.into_inner();
    match sanitize_header_value(&req.header_value) {
        Ok(safe_value) => (
            StatusCode::OK,
            serde_json::json!({
                "original_length": req.header_value.len(),
                "sanitised": safe_value,
                "was_modified": false,
            })
            .to_string(),
        ),
        Err(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "crlf_injection_blocked",
                "original_length": req.header_value.len(),
            })
            .to_string(),
        ),
    }
}

/// Request DTO for unicode bypass test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnicodeBypassRequest {
    /// User input that may use unicode tricks.
    pub input: String,
}

impl SecureValidate for UnicodeBypassRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.input.is_empty() {
            return Err("input_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/unicode-bypass` — normalises unicode input.
pub async fn unicode_bypass_check(payload: SecureJson<UnicodeBypassRequest>) -> impl IntoResponse {
    let req = payload.into_inner();
    // SecureJson already normalises input via the validation pipeline.
    // We additionally try to construct a SafeFilename to test bypasses.
    let filename_result = SafeFilename::try_from(req.input.as_str());
    (
        StatusCode::OK,
        serde_json::json!({
            "input": req.input,
            "safe_filename_accepted": filename_result.is_ok(),
        })
        .to_string(),
    )
}

/// POST `/smoke/body-bomb` — rejects oversized bodies.
/// This route uses the default axum body limit. Nothing special here;
/// the middleware stack limits body size.
pub async fn body_bomb_check(body: axum::body::Bytes) -> Response {
    // If we get here, the body was within limits.
    (
        StatusCode::OK,
        serde_json::json!({ "size": body.len() }).to_string(),
    )
        .into_response()
}

/// POST `/smoke/deep-nesting` — rejects deeply nested JSON.
pub async fn deep_nesting_check(_payload: SecureJson<DeserializationRequest>) -> impl IntoResponse {
    // SecureJson enforces nesting depth limits. If we get here, the payload passed.
    (
        StatusCode::OK,
        serde_json::json!({ "ok": true }).to_string(),
    )
}

/// POST `/smoke/field-flood` — rejects JSON with too many fields.
pub async fn field_flood_check(_payload: SecureJson<DeserializationRequest>) -> impl IntoResponse {
    // SecureJson enforces field count limits. If we get here, the payload passed.
    (
        StatusCode::OK,
        serde_json::json!({ "ok": true }).to_string(),
    )
}

//! Security events smoke routes.
//!
//! Each route exercises security event logging controls from `security_events`.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use secure_boundary::extract::SecureJson;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use security_core::severity::SecuritySeverity;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use serde::{Deserialize, Serialize};

/// Request DTO for log injection test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogInjectionRequest {
    /// A field that may contain newlines or CRLF for log injection.
    pub field: String,
}

impl SecureValidate for LogInjectionRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.field.is_empty() {
            return Err("field_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/events/log-injection` — logs a field containing newlines.
/// The security events framework should sanitise or escape the output.
pub async fn log_injection(payload: SecureJson<LogInjectionRequest>) -> impl IntoResponse {
    let req = payload.into_inner();

    // Emit a security event with the potentially malicious field as actor
    let mut event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::Medium,
        EventOutcome::Blocked,
    );
    event.actor = Some(req.field.clone());
    emit_security_event(event);

    (
        StatusCode::OK,
        serde_json::json!({
            "logged": true,
            "field_length": req.field.len(),
        })
        .to_string(),
    )
}

/// Request DTO for PII redaction test.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionRequest {
    /// An email address (PII) that should be redacted in logs.
    pub email: String,
}

impl SecureValidate for RedactionRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.email.is_empty() {
            return Err("email_empty");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/events/redaction` — emits a PII field; should be redacted in output.
pub async fn redaction_check(payload: SecureJson<RedactionRequest>) -> impl IntoResponse {
    let req = payload.into_inner();

    let mut event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::Low,
        EventOutcome::Success,
    );
    // The email goes into the actor field — it should be redacted by the redaction engine
    event.actor = Some(req.email.clone());
    emit_security_event(event);

    (
        StatusCode::OK,
        serde_json::json!({
            "logged": true,
            "email_length": req.email.len(),
        })
        .to_string(),
    )
}

//! Data protection smoke routes.
//!
//! Each route exercises a specific data protection control from `secure_data`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use secure_boundary::extract::SecureJson;
use secure_boundary::validate::{SecureValidate, ValidationContext};
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage, EnvelopeEncrypted};
use secure_data::secret::SecretString;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Request DTO for encryption.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptRequest {
    /// Plaintext to encrypt.
    pub plaintext: String,
}

impl SecureValidate for EncryptRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.plaintext.is_empty() {
            return Err("plaintext_empty");
        }
        if self.plaintext.len() > 10_000 {
            return Err("plaintext_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/encrypt` — encrypts plaintext using envelope encryption.
pub async fn encrypt_data(
    State(state): State<AppState>,
    payload: SecureJson<EncryptRequest>,
) -> Response {
    let req = payload.into_inner();
    match encrypt_for_storage(
        req.plaintext.as_bytes(),
        "default",
        state.key_provider.as_ref(),
    )
    .await
    {
        Ok(envelope) => {
            let json = serde_json::to_string(&envelope).unwrap_or_default();
            (StatusCode::OK, json).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "code": "encryption_failed" }).to_string(),
        )
            .into_response(),
    }
}

/// Request DTO for decryption.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptRequest {
    /// The encrypted envelope.
    pub envelope: EnvelopeEncrypted,
}

impl SecureValidate for DecryptRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// POST `/smoke/decrypt` — decrypts a valid envelope.
pub async fn decrypt_data(
    State(state): State<AppState>,
    payload: SecureJson<DecryptRequest>,
) -> Response {
    let req = payload.into_inner();
    match decrypt_for_use(&req.envelope, state.key_provider.as_ref()).await {
        Ok(plaintext) => {
            let text = String::from_utf8_lossy(&plaintext);
            (
                StatusCode::OK,
                serde_json::json!({ "plaintext": text }).to_string(),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "code": "decryption_failed" }).to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/decrypt-tampered` — attempts to decrypt a tampered envelope.
/// Same handler as `/smoke/decrypt`; the test sends tampered data.
pub async fn decrypt_tampered(
    State(state): State<AppState>,
    payload: SecureJson<DecryptRequest>,
) -> Response {
    decrypt_data(State(state), payload).await
}

/// GET `/smoke/secret-debug` — ensures secret types print as `[REDACTED]`.
pub async fn secret_debug() -> impl IntoResponse {
    let secret = SecretString::new("super-secret-value-12345".to_string());
    let debug_output = format!("{secret:?}");
    (
        StatusCode::OK,
        serde_json::json!({
            "debug_output": debug_output,
            "contains_raw_secret": debug_output.contains("super-secret-value-12345"),
        })
        .to_string(),
    )
}

/// POST `/smoke/key-rotation` — rotates key, re-encrypts, and verifies old data is still decryptable.
pub async fn key_rotation(
    State(state): State<AppState>,
    payload: SecureJson<EncryptRequest>,
) -> Response {
    let req = payload.into_inner();

    // Encrypt with current key
    let envelope = match encrypt_for_storage(
        req.plaintext.as_bytes(),
        "default",
        state.key_provider.as_ref(),
    )
    .await
    {
        Ok(e) => e,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "code": "initial_encryption_failed" }).to_string(),
            )
                .into_response();
        }
    };

    // Add a new key version
    {
        let mut ring = state.key_ring.write().await;
        ring.add_key("default".to_string(), "v2".to_string());
    }

    // Decrypt the old envelope — should still work
    match decrypt_for_use(&envelope, state.key_provider.as_ref()).await {
        Ok(plaintext) => {
            let text = String::from_utf8_lossy(&plaintext);
            (
                StatusCode::OK,
                serde_json::json!({
                    "original_plaintext": req.plaintext,
                    "decrypted_plaintext": text,
                    "key_rotation_successful": text == req.plaintext,
                })
                .to_string(),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "code": "post_rotation_decryption_failed" }).to_string(),
        )
            .into_response(),
    }
}

//! Authentication smoke routes.
//!
//! Each route exercises a specific authentication control from `secure_identity`.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use secure_identity::authenticator::{AuthenticationRequest, Authenticator, TokenKind};
use secure_identity::session::SessionManager;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::state::AppState;

/// Extracts the Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
}

/// POST `/smoke/auth/jwt` — validates a JWT from the Authorization header.
pub async fn jwt_validate(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "code": "missing_token" }).to_string(),
            )
                .into_response();
        }
    };

    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };

    match state.token_validator.authenticate(&request).await {
        Ok(identity) => (
            StatusCode::OK,
            serde_json::json!({
                "actor_id": identity.actor_id.to_string(),
                "tenant_id": identity.tenant_id.as_ref().map(|t| t.to_string()),
                "roles": identity.roles,
            })
            .to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "code": "authentication_failed" }).to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/auth/expired` — attempts to validate an expired JWT.
/// The test sends an expired token; the handler returns 401.
pub async fn jwt_expired(State(state): State<AppState>, headers: HeaderMap) -> Response {
    jwt_validate(State(state), headers).await
}

/// POST `/smoke/auth/alg-none` — attempts to validate a JWT with `alg: none`.
/// The handler rejects it because `TokenValidator` only accepts HS256.
pub async fn jwt_alg_none(State(state): State<AppState>, headers: HeaderMap) -> Response {
    jwt_validate(State(state), headers).await
}

/// POST `/smoke/auth/tampered` — attempts to validate a JWT with a tampered signature.
pub async fn jwt_tampered(State(state): State<AppState>, headers: HeaderMap) -> Response {
    jwt_validate(State(state), headers).await
}

/// POST `/smoke/auth/wrong-issuer` — attempts to validate a JWT from a wrong issuer.
pub async fn jwt_wrong_issuer(State(state): State<AppState>, headers: HeaderMap) -> Response {
    jwt_validate(State(state), headers).await
}

/// Session lifecycle request DTO.
#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    /// Session action: "create", "validate", or "revoke".
    pub action: String,
    /// Session ID (for validate/revoke).
    pub session_id: Option<String>,
}

/// POST `/smoke/auth/session` — exercises session create/validate/revoke lifecycle.
pub async fn session_lifecycle(
    State(state): State<AppState>,
    _headers: HeaderMap,
    axum::Json(req): axum::Json<SessionRequest>,
) -> Response {
    match req.action.as_str() {
        "create" => {
            // Create an identity for the session
            let identity = security_core::identity::AuthenticatedIdentity {
                actor_id: security_core::types::ActorId::from(uuid::Uuid::new_v4()),
                tenant_id: None,
                roles: vec!["user".to_string()],
                attributes: HashMap::new(),
                authenticated_at: OffsetDateTime::now_utc(),
            };
            match state.session_manager.create_session(&identity, 3600).await {
                Ok(session) => (
                    StatusCode::OK,
                    serde_json::json!({
                        "session_id": session.id,
                        "actor_id": session.actor_id.to_string(),
                    })
                    .to_string(),
                )
                    .into_response(),
                Err(_e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({ "code": "session_create_failed" }).to_string(),
                )
                    .into_response(),
            }
        }
        "validate" => {
            let session_id = match &req.session_id {
                Some(id) => id,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({ "code": "missing_session_id" }).to_string(),
                    )
                        .into_response();
                }
            };
            match state.session_manager.validate_session(session_id).await {
                Ok(session) => (
                    StatusCode::OK,
                    serde_json::json!({
                        "session_id": session.id,
                        "valid": true,
                    })
                    .to_string(),
                )
                    .into_response(),
                Err(_) => (
                    StatusCode::UNAUTHORIZED,
                    serde_json::json!({ "code": "session_invalid" }).to_string(),
                )
                    .into_response(),
            }
        }
        "revoke" => {
            let session_id = match &req.session_id {
                Some(id) => id,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({ "code": "missing_session_id" }).to_string(),
                    )
                        .into_response();
                }
            };
            match state.session_manager.revoke_session(session_id).await {
                Ok(()) => (
                    StatusCode::OK,
                    serde_json::json!({ "revoked": true }).to_string(),
                )
                    .into_response(),
                Err(_) => (
                    StatusCode::NOT_FOUND,
                    serde_json::json!({ "code": "session_not_found" }).to_string(),
                )
                    .into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "code": "invalid_action" }).to_string(),
        )
            .into_response(),
    }
}

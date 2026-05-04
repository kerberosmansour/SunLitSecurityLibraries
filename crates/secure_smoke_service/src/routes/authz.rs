//! Authorization smoke routes.
//!
//! Each route exercises a specific authorization control from `secure_authz`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use secure_authz::action::Action;
use secure_authz::decision::Decision;
use secure_authz::enforcer::Authorizer;
use secure_authz::resolver::{DefaultSubjectResolver, SubjectResolver};
use secure_authz::resource::ResourceRef;
use secure_identity::authenticator::{AuthenticationRequest, Authenticator, TokenKind};

use crate::state::AppState;

/// Converts a `Decision` to an HTTP response.
fn decision_to_response(decision: Decision) -> Response {
    match decision {
        Decision::Allow { .. } => (
            StatusCode::OK,
            serde_json::json!({ "authorized": true }).to_string(),
        )
            .into_response(),
        Decision::Deny { reason } => (
            StatusCode::FORBIDDEN,
            serde_json::json!({ "code": "forbidden", "reason": format!("{reason:?}") }).to_string(),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "code": "unexpected_decision" }).to_string(),
        )
            .into_response(),
    }
}

/// Resolves identity from Authorization header.
async fn resolve_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<security_core::identity::AuthenticatedIdentity, Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "code": "missing_token" }).to_string(),
            )
                .into_response()
        })?;

    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };

    state
        .token_validator
        .authenticate(&request)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "code": "authentication_failed" }).to_string(),
            )
                .into_response()
        })
}

/// GET `/smoke/authz/allow` — authorised role + tenant accessing a permitted resource.
pub async fn authz_allow(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match resolve_identity(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items");
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;

    decision_to_response(decision)
}

/// GET `/smoke/authz/deny` — missing role attempts access.
pub async fn authz_deny(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match resolve_identity(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items");
    // Try an action the user's role doesn't permit
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Delete, &resource)
        .await;

    decision_to_response(decision)
}

/// GET `/smoke/authz/cross-tenant` — tenant A trying to access tenant B resource.
pub async fn authz_cross_tenant(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match resolve_identity(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let subject = DefaultSubjectResolver::resolve(&identity);
    // Resource belongs to a different tenant
    let resource = ResourceRef::new("items").with_tenant(uuid::Uuid::new_v4().to_string());
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;

    decision_to_response(decision)
}

/// POST `/smoke/authz/privilege-escalation` — low-privilege role attempts admin action.
pub async fn authz_privilege_escalation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let identity = match resolve_identity(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items");
    // Try admin action
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Admin, &resource)
        .await;

    decision_to_response(decision)
}

/// GET `/smoke/authz/idor` — access resource owned by another user.
pub async fn authz_idor(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match resolve_identity(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let subject = DefaultSubjectResolver::resolve(&identity);
    // Resource owned by a different user
    let resource = ResourceRef::new("items").with_owner(uuid::Uuid::new_v4().to_string());
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;

    decision_to_response(decision)
}

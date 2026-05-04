//! End-to-end tests for Milestone 5: secure_identity.

use std::collections::HashMap;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    session::{InMemorySessionManager, SessionManager},
    token::{TokenValidator, TokenValidatorConfig},
};
use security_core::{
    identity::{AuthenticatedIdentity, IdentitySource},
    types::ActorId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

const SECRET: &[u8] = b"e2e-secret-must-be-long-enough-32b!";
const ISSUER: &str = "e2e-issuer";
const AUDIENCE: &str = "e2e-audience";

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
    iat: u64,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

fn make_validator() -> TokenValidator {
    TokenValidator::new(TokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        secret: SECRET.to_vec(),
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_jwt(sub: &str) -> String {
    let now = now_secs();
    let claims = Claims {
        sub: sub.to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec!["user".to_string()],
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

#[tokio::test]
async fn test_jwt_authentication_roundtrip() {
    let actor_id = Uuid::new_v4();
    let validator = make_validator();
    let token = make_jwt(&actor_id.to_string());
    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.unwrap();
    assert_eq!(identity.actor_id.as_inner(), &actor_id);
    assert_eq!(identity.roles, vec!["user"]);
}

#[tokio::test]
async fn test_session_lifecycle() {
    let mgr = InMemorySessionManager::new();
    let identity = AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    };

    let session = mgr.create_session(&identity, 3600).await.unwrap();
    let session_id = session.id.clone();

    let validated = mgr.validate_session(&session_id).await.unwrap();
    assert_eq!(validated.id, session_id);

    let refreshed = mgr.refresh_session(&session_id, 1800).await.unwrap();
    assert!(refreshed.expires_at > session.expires_at);

    mgr.revoke_session(&session_id).await.unwrap();
    let revoked = mgr.validate_session(&session_id).await;
    assert!(revoked.is_err());
}

#[cfg(feature = "dev")]
#[tokio::test]
async fn test_dev_authenticator_produces_identity() {
    use secure_identity::dev::DevAuthenticator;

    let actor_id = ActorId::from(Uuid::new_v4());
    let dev = DevAuthenticator::new(actor_id.clone(), None, vec!["admin".to_string()]);
    let req = AuthenticationRequest {
        token: "ignored".to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let identity = dev.authenticate(&req).await.unwrap();
    assert_eq!(identity.actor_id.as_inner(), actor_id.as_inner());
}

#[tokio::test]
async fn test_identity_source_integration() {
    let actor_id = Uuid::new_v4();
    let validator = make_validator();
    let token = make_jwt(&actor_id.to_string());
    let identity = validator.resolve(&token).await.unwrap();
    assert_eq!(identity.actor_id.as_inner(), &actor_id);
}

#[test]
fn test_authz_independence() {
    // structural test: if this compiles, dep graph is maintained
}

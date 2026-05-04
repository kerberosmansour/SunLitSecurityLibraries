//! E2E runtime validation for OWASP Milestone 24.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    auth_events::{AuthEventContext, AuthEventEmitter},
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    session::{InMemorySessionManager, SessionManager},
    token::{TokenValidator, TokenValidatorConfig},
    totp::TotpProvider,
};
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use security_events::sink::InMemorySink;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
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

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: std::collections::HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

#[tokio::test]
async fn test_totp_generate_and_verify() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");
    let code = provider
        .generate_current_code(&enrollment.secret)
        .expect("code generation should succeed");

    let ok = provider
        .verify_code(&enrollment.secret, &code)
        .expect("verification should succeed");
    assert!(ok);
}

#[tokio::test]
async fn test_totp_wrong_code_rejected() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");

    let ok = provider
        .verify_code(&enrollment.secret, "000000")
        .expect("verification should succeed");
    assert!(!ok);
}

#[tokio::test]
async fn test_auth_success_event_emitted() {
    let sink = InMemorySink::new();
    let emitter = AuthEventEmitter::new(sink.clone());

    emitter.emit_success(AuthEventContext {
        user_id: "user-123".to_string(),
        method: "jwt".to_string(),
        source_ip: Some("127.0.0.1".parse().expect("valid ip")),
        user_agent: Some("sunlit-test".to_string()),
    });

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].outcome,
        security_events::event::EventOutcome::Success
    );
}

#[tokio::test]
async fn test_session_create_retrieve_delete() {
    let store = InMemorySessionManager::new();
    let created = store
        .create_session(&identity(), 60)
        .await
        .expect("create session should succeed");

    let loaded = store
        .validate_session(&created.id)
        .await
        .expect("session should load");
    assert_eq!(loaded.id, created.id);

    store
        .revoke_session(&created.id)
        .await
        .expect("session revoke should succeed");
    assert!(store.validate_session(&created.id).await.is_err());
}

#[tokio::test]
async fn test_existing_token_provider_works() {
    let secret = b"m24-backward-compat-secret";
    let validator = TokenValidator::new(TokenValidatorConfig {
        issuer: "m24-issuer".to_string(),
        audience: "m24-audience".to_string(),
        secret: secret.to_vec(),
    });

    let now = now_secs();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: "m24-issuer".to_string(),
        aud: "m24-audience".to_string(),
        tenant: None,
        roles: vec!["user".to_string()],
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("token encoding should succeed");

    let identity = validator
        .authenticate(&AuthenticationRequest {
            token,
            token_kind: TokenKind::BearerJwt,
        })
        .await
        .expect("token validator should remain compatible");

    assert_eq!(identity.roles, vec!["user"]);
}

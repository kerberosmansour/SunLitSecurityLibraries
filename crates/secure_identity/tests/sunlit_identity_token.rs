//! BDD tests for TokenValidator claims parsing.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    token::{TokenValidator, TokenValidatorConfig},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SECRET: &[u8] = b"test-secret-must-be-long-enough-32b";
const ISSUER: &str = "token-test-issuer";
const AUDIENCE: &str = "token-test-audience";

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

#[tokio::test]
async fn scenario_roles_extracted_from_claims() {
    let validator = make_validator();
    let now = now_secs();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec!["admin".to_string(), "editor".to_string()],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.unwrap();
    assert_eq!(identity.roles, vec!["admin", "editor"]);
}

#[tokio::test]
async fn scenario_tenant_extracted_from_claims() {
    let validator = make_validator();
    let now = now_secs();
    let tenant_uuid = Uuid::new_v4();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: Some(tenant_uuid.to_string()),
        roles: vec![],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.unwrap();
    assert!(identity.tenant_id.is_some());
    assert_eq!(identity.tenant_id.unwrap().as_inner(), &tenant_uuid);
}

#[tokio::test]
async fn scenario_no_tenant_in_claims_gives_none() {
    let validator = make_validator();
    let now = now_secs();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec![],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.unwrap();
    assert!(identity.tenant_id.is_none());
}

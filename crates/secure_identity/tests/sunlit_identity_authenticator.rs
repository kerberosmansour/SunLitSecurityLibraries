//! BDD tests for Authenticator / TokenValidator.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    error::IdentityError,
    token::{TokenValidator, TokenValidatorConfig},
};
use serde::{Deserialize, Serialize};

const SECRET: &[u8] = b"test-secret-must-be-long-enough-32b";
const ISSUER: &str = "test-issuer";
const AUDIENCE: &str = "test-audience";

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

fn make_jwt(claims: &Claims) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

fn valid_claims() -> Claims {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Claims {
        sub: uuid::Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec!["user".to_string()],
    }
}

#[tokio::test]
async fn scenario_valid_jwt_produces_identity() {
    let validator = make_validator();
    let token = make_jwt(&valid_claims());
    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(result.is_ok(), "valid JWT should succeed: {result:?}");
    let identity = result.unwrap();
    assert_eq!(identity.roles, vec!["user"]);
}

#[tokio::test]
async fn scenario_expired_jwt_rejected() {
    let validator = make_validator();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = valid_claims();
    claims.exp = now - 3600;
    claims.iat = now - 7200;
    let token = make_jwt(&claims);
    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(matches!(result, Err(IdentityError::TokenExpired)));
}

#[tokio::test]
async fn scenario_malformed_jwt_rejected() {
    let validator = make_validator();
    let request = AuthenticationRequest {
        token: "not.a.valid.jwt".to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(matches!(result, Err(IdentityError::TokenMalformed)));
}

#[tokio::test]
async fn scenario_wrong_issuer_rejected() {
    let validator = make_validator();
    let mut claims = valid_claims();
    claims.iss = "wrong-issuer".to_string();
    let token = make_jwt(&claims);
    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(
        matches!(
            result,
            Err(IdentityError::InvalidCredentials | IdentityError::TokenMalformed)
        ),
        "wrong issuer should fail: {result:?}"
    );
}

#[tokio::test]
async fn scenario_missing_sub_claim_rejected() {
    let validator = make_validator();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: "not-a-uuid".to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec![],
    };
    let token = make_jwt(&claims);
    let request = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(matches!(result, Err(IdentityError::TokenMalformed)));
}

#[tokio::test]
async fn scenario_authentication_failure_returns_error() {
    let validator = make_validator();
    let request = AuthenticationRequest {
        token: "bad-token".to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&request).await;
    assert!(result.is_err(), "bad token should fail");
}

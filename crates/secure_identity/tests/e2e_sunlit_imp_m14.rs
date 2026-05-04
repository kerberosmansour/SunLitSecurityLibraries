//! E2E runtime validation for Milestone 14 — Identity & Authentication Hardening.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    api_key::ApiKeyAuthenticator,
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    token::{
        AlgorithmConfig, AsymmetricTokenValidator, AsymmetricTokenValidatorConfig, TokenValidator,
        TokenValidatorConfig,
    },
};
use security_core::types::ActorId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const RS256_VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwNDA2NzIwMCwiaXNzIjoiZTJlLWlzc3VlciIsImF1ZCI6ImUyZS1hdWRpZW5jZSIsInRlbmFudCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMiIsInJvbGVzIjpbImFkbWluIl19.Q6egqvq84jRlE0cECe1HyYJSioWl8FTfqIWaOCDXW2FhZtvc5XTUOnEkmVL5cOWP9nxwT7b3XZJ-dWCzdor94HIdUyqWNZgKZb8NyoxTlPfrlS3JwQrcVMqf50df0JtiXMiO8x_fpA5b8lmjb4JKL_zO9FfHJHXLTs7pX1JxDy2t9sqsEC5oUDHYaBf6GRphvywShkFZ3XA-hMQTp0Haa9UAOmR2Ik8mbLmfpNPOqmR_VI-hB9Onb1rdu4hfR3D7Sp9gs5Us1F4rF2CZRW_Zs4equJYX2qdOYLGGNKwnMgNtW-gxYu1sG2r0NWfCSz9Wk9JM_DHTwFhng4PP1m5rwg";
const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty6bGXbajYywwukqPYf0
W2AxQiCPiwuZfNRDFWyP6Ge4hyv+YI3KsTGCmd2tH97F13tujrkUvpSlrI0ouIxe
AMw4AswldY+oKBef69Aod54jhhPcDumkbGlGneu5W0ibQUaA8+eAZfHDqNLNHtm7
p1QXD1/yfn3VPtB2BsDu+fdMfEWTqroanul0xQjqFUYb9ksdae1/a9bBztRyPL6y
Zb6n7w5Ukewv6Wi3O7LYLcqqp4rIr37/wQn7xY+8otdwDk47P7qpGlye04zphp8q
8INVo4ZossAjmxkQcl0mJqTSkXFA2XdtcC+qoMgCJZVQFAmY3QuO+DL+MFSVLnbx
dwIDAQAB
-----END PUBLIC KEY-----";

const ES256_VALID_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDUiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwNDA2NzIwMCwiaXNzIjoiZTJlLWVjLWlzc3VlciIsImF1ZCI6ImUyZS1lYy1hdWRpZW5jZSIsInJvbGVzIjpbInZpZXdlciJdfQ.9nEMurTME7UicurpmdLGVPTc617HeGYJArwc2bCliKMYeopv39WK1vaHfsnpeJ91LS2GDWkdCbWjvlp2MWS3mg";
const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElY+C08edNtYClhlXqw+9Mn3rghNo
fqPK+FtvUqkcuNL41thwhSmNWZnjHKJPiUN6UiWTXDZR0FyTUtb5yQ6tVw==
-----END PUBLIC KEY-----";

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

/// E2E: Verify RS256 full roundtrip — sign JWT, validate, get identity.
#[tokio::test]
async fn e2e_rs256_full_roundtrip() {
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: "e2e-issuer".to_string(),
        audience: "e2e-audience".to_string(),
        algorithm: AlgorithmConfig::RS256 { decoding_key },
    });

    let actor_id =
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("static actor id");

    let req = AuthenticationRequest {
        token: RS256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.expect("authenticate");

    assert_eq!(identity.actor_id.as_inner(), &actor_id);
    assert_eq!(identity.roles, vec!["admin"]);
    assert!(identity.tenant_id.is_some());
}

/// E2E: Verify HS256 backward compatibility after asymmetric additions.
#[tokio::test]
async fn e2e_hs256_backward_compat() {
    let secret = b"hs256-backward-compat-secret-key";
    let validator = TokenValidator::new(TokenValidatorConfig {
        issuer: "e2e-issuer".to_string(),
        audience: "e2e-audience".to_string(),
        secret: secret.to_vec(),
    });

    let now = now_secs();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: "e2e-issuer".to_string(),
        aud: "e2e-audience".to_string(),
        tenant: None,
        roles: vec!["user".to_string()],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("encode");

    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.expect("authenticate");
    assert_eq!(identity.roles, vec!["user"]);
}

/// E2E: Verify API key authentication roundtrip.
#[tokio::test]
async fn e2e_api_key_roundtrip() {
    let actor_id = ActorId::from(Uuid::new_v4());
    let api_key = "sunlit-e2e-api-key-abcdef123456";
    let authenticator = ApiKeyAuthenticator::new(
        api_key.to_string(),
        actor_id.clone(),
        vec!["api-user".to_string()],
    );

    // Valid key
    let req = AuthenticationRequest {
        token: api_key.to_string(),
        token_kind: TokenKind::ApiKey,
    };
    let identity = authenticator.authenticate(&req).await.expect("valid key");
    assert_eq!(identity.actor_id.as_inner(), actor_id.as_inner());

    // Invalid key
    let bad_req = AuthenticationRequest {
        token: "sunlit-wrong-key".to_string(),
        token_kind: TokenKind::ApiKey,
    };
    let result = authenticator.authenticate(&bad_req).await;
    assert!(result.is_err());
}

/// E2E: Verify ES256 full roundtrip.
#[tokio::test]
async fn e2e_es256_full_roundtrip() {
    let decoding_key =
        jsonwebtoken::DecodingKey::from_ec_pem(EC_PUBLIC_PEM.as_bytes()).expect("ec decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: "e2e-ec-issuer".to_string(),
        audience: "e2e-ec-audience".to_string(),
        algorithm: AlgorithmConfig::ES256 { decoding_key },
    });

    let req = AuthenticationRequest {
        token: ES256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await.expect("authenticate");
    assert_eq!(identity.roles, vec!["viewer"]);
}

/// E2E: Verify alg:none is rejected.
#[tokio::test]
async fn e2e_alg_none_rejected() {
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: "e2e-issuer".to_string(),
        audience: "e2e-audience".to_string(),
        algorithm: AlgorithmConfig::RS256 { decoding_key },
    });

    // Craft a token with alg: none manually
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let now = now_secs();
    let payload = b64.encode(format!(
        r#"{{"sub":"{}","exp":{},"iat":{},"iss":"e2e-issuer","aud":"e2e-audience","roles":["hacker"]}}"#,
        Uuid::new_v4(), now + 3600, now
    ));
    let token = format!("{header}.{payload}.");

    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&req).await;
    assert!(result.is_err(), "alg:none must be rejected");
}

//! BDD tests for asymmetric JWT validation (RS256, ES256).

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    error::IdentityError,
    token::{AlgorithmConfig, AsymmetricTokenValidator, AsymmetricTokenValidatorConfig},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ISSUER: &str = "asymmetric-test-issuer";
const AUDIENCE: &str = "asymmetric-test-audience";

const RS256_VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDEiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwNDA2NzIwMCwiaXNzIjoiYXN5bW1ldHJpYy10ZXN0LWlzc3VlciIsImF1ZCI6ImFzeW1tZXRyaWMtdGVzdC1hdWRpZW5jZSIsInJvbGVzIjpbInVzZXIiXX0.hbex1ZUGiD6SdrxqsvgOPGiAofezH50edvAgtxW6jlytYduJLAWtGCy9Wg36Fl3oniJjssrzw-IpuxgsjpewC164fDmR_2o0Yp4fXhtVRJLN1N7KXnaoAPiOgqEiqPW6Dze81Ct2Xd4icl0xkqUE_KLH96NmI6qblMZNBsRIKCa5L-ypTOxCfFZKqAHrekkQyXcSGOElnpoEl-b7Y6jDZ2EAfT5uuoKFDULQZNvxmbXbAelIJFJxEEOme42wmnDs7jkB4rz19JkuE7JzWP3E3Gww9815HJyG5Q6Rynr8aLOjixMIB-o27dRbrRUgbrh6PuIMiKrHtpiQzAL9pnankQ";
const RS256_EXPIRED_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDQiLCJleHAiOjk0NjY4NDgwMCwiaWF0Ijo5NDY2ODEyMDAsImlzcyI6ImFzeW1tZXRyaWMtdGVzdC1pc3N1ZXIiLCJhdWQiOiJhc3ltbWV0cmljLXRlc3QtYXVkaWVuY2UiLCJyb2xlcyI6W119.Q2r9JWhfFKzlqT9xCkSur2q_gdc0jk3DYzVC_olLG6pFVfQb2tYWPkM89FuzRZ26kl98z_Tl8476FUsrLuP5Po_7mAQF1JWwX-AVBWde5jCmJoGfNO6hiff61OoFf_JH9HpP3uX9emS_qULthjByIKENxTRLsAp2MHkiu_H1_huzNJx1Yu-2yaE9DXfZLNw7hEGKis2_aWpjjnMNq7tM7pWXLUPgCTY06G57csy-4TyOK2AqnGA7_yNPZ2A6FqcObl6ioJNZvNcO6MtogqA-XIhMmUE1wPiqEXUnOHUTSup4hnYgG0CSHkkd33dnUgosUslNedfZFs8bQ9oahlinkA";
const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty6bGXbajYywwukqPYf0
W2AxQiCPiwuZfNRDFWyP6Ge4hyv+YI3KsTGCmd2tH97F13tujrkUvpSlrI0ouIxe
AMw4AswldY+oKBef69Aod54jhhPcDumkbGlGneu5W0ibQUaA8+eAZfHDqNLNHtm7
p1QXD1/yfn3VPtB2BsDu+fdMfEWTqroanul0xQjqFUYb9ksdae1/a9bBztRyPL6y
Zb6n7w5Ukewv6Wi3O7LYLcqqp4rIr37/wQn7xY+8otdwDk47P7qpGlye04zphp8q
8INVo4ZossAjmxkQcl0mJqTSkXFA2XdtcC+qoMgCJZVQFAmY3QuO+DL+MFSVLnbx
dwIDAQAB
-----END PUBLIC KEY-----";

const ES256_VALID_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwNDA2NzIwMCwiaXNzIjoiYXN5bW1ldHJpYy10ZXN0LWlzc3VlciIsImF1ZCI6ImFzeW1tZXRyaWMtdGVzdC1hdWRpZW5jZSIsInRlbmFudCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMyIsInJvbGVzIjpbImFkbWluIl19.mZjnANclYwV4lJokWK-E4iXmCiPp6ELlhaEq_BShNYQ1i_SyeGR8ctOELNmH8lwAjoWgvdebfzj4SlJ1L3nUlg";
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

// --- Feature: Asymmetric JWT validation ---

#[tokio::test]
async fn scenario_valid_rs256_token_accepted() {
    // Given: RS256-signed JWT with valid claims
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        algorithm: AlgorithmConfig::RS256 { decoding_key },
    });

    // When: authenticate
    let req = AuthenticationRequest {
        token: RS256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await;

    // Then: returns AuthenticatedIdentity
    let identity = identity.expect("should authenticate");
    assert_eq!(identity.roles, vec!["user"]);
}

#[tokio::test]
async fn scenario_valid_es256_token_accepted() {
    // Given: ES256-signed JWT with valid claims
    let decoding_key =
        jsonwebtoken::DecodingKey::from_ec_pem(EC_PUBLIC_PEM.as_bytes()).expect("ec decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        algorithm: AlgorithmConfig::ES256 { decoding_key },
    });

    // When: authenticate
    let req = AuthenticationRequest {
        token: ES256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await;

    // Then: returns identity with tenant and roles
    let identity = identity.expect("should authenticate");
    assert_eq!(identity.roles, vec!["admin"]);
    assert!(identity.tenant_id.is_some());
}

#[tokio::test]
async fn scenario_expired_rs256_token_rejected() {
    // Given: RS256 JWT past `exp`
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        algorithm: AlgorithmConfig::RS256 { decoding_key },
    });

    // When: authenticate
    let req = AuthenticationRequest {
        token: RS256_EXPIRED_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&req).await;

    // Then: IdentityError::TokenExpired
    assert!(matches!(result, Err(IdentityError::TokenExpired)));
}

#[tokio::test]
async fn scenario_wrong_key_rejection() {
    // Given: RS256 JWT signed with RSA key, verified with EC key (wrong key type)
    let wrong_decoding_key =
        jsonwebtoken::DecodingKey::from_ec_pem(EC_PUBLIC_PEM.as_bytes()).expect("wrong key");

    // Validator expects ES256 but token is RS256
    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        algorithm: AlgorithmConfig::ES256 {
            decoding_key: wrong_decoding_key,
        },
    });

    // When: authenticate
    let req = AuthenticationRequest {
        token: RS256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&req).await;

    // Then: IdentityError::TokenMalformed
    assert!(matches!(result, Err(IdentityError::TokenMalformed)));
}

#[tokio::test]
async fn scenario_hs256_still_works_after_asymmetric_addition() {
    // Given: HS256 JWT (existing config)
    use secure_identity::token::{TokenValidator, TokenValidatorConfig};

    let secret = b"existing-hs256-secret-32-bytes!!";
    let validator = TokenValidator::new(TokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        secret: secret.to_vec(),
    });

    let now = now_secs();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        exp: now + 3600,
        iat: now,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        tenant: None,
        roles: vec!["user".to_string()],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("encode HS256");

    // When: authenticate
    let req = AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    };
    let identity = validator.authenticate(&req).await;

    // Then: returns identity (backward compat)
    let identity = identity.expect("HS256 should still work");
    assert_eq!(identity.roles, vec!["user"]);
}

#[tokio::test]
async fn scenario_wrong_issuer_rejected_rs256() {
    // Given: RS256 JWT whose issuer does not match validator config
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("decoding key");

    let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
        issuer: "required-other-issuer".to_string(),
        audience: AUDIENCE.to_string(),
        algorithm: AlgorithmConfig::RS256 { decoding_key },
    });

    // When: authenticate
    let req = AuthenticationRequest {
        token: RS256_VALID_TOKEN.to_string(),
        token_kind: TokenKind::BearerJwt,
    };
    let result = validator.authenticate(&req).await;

    // Then: InvalidCredentials
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
}

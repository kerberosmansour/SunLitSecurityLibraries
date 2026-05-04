//! CVE regression tests — JWT security vulnerabilities.
//!
//! Milestone 9 — BDD: Known JWT vulnerabilities must be blocked.
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    token::{TokenValidator, TokenValidatorConfig},
};

const SECRET: &[u8] = b"test-secret-must-be-long-enough-32b";
const ISSUER: &str = "cve-test-issuer";
const AUDIENCE: &str = "cve-test-audience";

fn make_validator() -> TokenValidator {
    TokenValidator::new(TokenValidatorConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        secret: SECRET.to_vec(),
    })
}

fn make_request(token: &str) -> AuthenticationRequest {
    AuthenticationRequest {
        token: token.to_string(),
        token_kind: TokenKind::BearerJwt,
    }
}

/// CVE-2015-9235 pattern: JWT algorithm confusion — `alg: "none"`.
///
/// A JWT with `alg: "none"` has no signature. Accepting it would allow
/// arbitrary claims without authentication.
/// The validator must reject tokens with `alg: none`.
#[tokio::test]
async fn cve_jwt_alg_none_rejected() {
    let validator = make_validator();
    // JWT with alg:none — header: {"alg":"none","typ":"JWT"}
    // Payload: {"sub":"00000000-0000-0000-0000-000000000001","exp":9999999999,"iat":1700000000,"iss":"cve-test-issuer","aud":"cve-test-audience"}
    // Signature: empty (none algorithm)
    let alg_none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
                          eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoiY3ZlLXRlc3QtaXNzdWVyIiwiYXVkIjoiY3ZlLXRlc3QtYXVkaWVuY2UifQ.";

    let result = validator.authenticate(&make_request(alg_none_token)).await;
    assert!(
        result.is_err(),
        "CVE-2015-9235: JWT with alg=none must be rejected, got: {result:?}"
    );
}

/// CVE pattern: JWT with tampered signature must be rejected.
///
/// Flipping a single byte in the signature must cause authentication failure.
#[tokio::test]
async fn cve_jwt_tampered_signature_rejected() {
    let validator = make_validator();
    // A structurally valid JWT with a wrong (all-zeros) signature
    let tampered = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                    eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoiY3ZlLXRlc3QtaXNzdWVyIiwiYXVkIjoiY3ZlLXRlc3QtYXVkaWVuY2UifQ.\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let result = validator.authenticate(&make_request(tampered)).await;
    assert!(
        result.is_err(),
        "Tampered JWT signature must be rejected, got: {result:?}"
    );
}

/// CVE pattern: Expired JWT must be rejected.
///
/// A JWT with `exp` in the past must not be accepted.
#[tokio::test]
async fn cve_jwt_expired_token_rejected() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: u64,
        iat: u64,
        iss: String,
        aud: String,
    }

    let expired_claims = Claims {
        sub: uuid::Uuid::new_v4().to_string(),
        exp: 1, // epoch + 1 second = definitely expired
        iat: 0,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &expired_claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();

    let validator = make_validator();
    let result = validator.authenticate(&make_request(&token)).await;
    assert!(
        result.is_err(),
        "Expired JWT must be rejected, got: {result:?}"
    );
}

/// CVE pattern: JWT with wrong issuer must be rejected.
///
/// Prevents cross-service token reuse attacks.
#[tokio::test]
async fn cve_jwt_wrong_issuer_rejected() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: u64,
        iat: u64,
        iss: String,
        aud: String,
    }

    let claims = Claims {
        sub: uuid::Uuid::new_v4().to_string(),
        exp: 9_999_999_999,
        iat: 1_700_000_000,
        iss: "evil-issuer".to_string(), // wrong issuer
        aud: AUDIENCE.to_string(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();

    let validator = make_validator();
    let result = validator.authenticate(&make_request(&token)).await;
    assert!(
        result.is_err(),
        "JWT with wrong issuer must be rejected, got: {result:?}"
    );
}

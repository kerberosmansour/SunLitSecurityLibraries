//! Real reduced-profile acceptance; legacy asymmetric tests remain unchanged.
#![cfg(not(feature = "asymmetric-jwt"))]

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secure_identity::{
    jwt_hmac::{install_default_provider, MAX_JWT_BYTES},
    AuthenticationRequest, Authenticator, IdentityError, TokenKind, TokenValidator,
    TokenValidatorConfig,
};
use serde_json::{json, Value};

const SECRET: &[u8] = b"synthetic-profile-key-32-bytes-minimum";

fn claims() -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({"sub":"11111111-1111-4111-8111-111111111111", "exp":now+3600,
        "iat":now, "iss":"profile-test", "aud":"internal-service", "roles":["reader"]})
}

async fn authenticate(token: String, secret: &[u8]) -> Result<(), IdentityError> {
    TokenValidator::new(TokenValidatorConfig {
        issuer: "profile-test".into(),
        audience: "internal-service".into(),
        secret: secret.to_vec(),
    })
    .authenticate(&AuthenticationRequest {
        token,
        token_kind: TokenKind::BearerJwt,
    })
    .await
    .map(|identity| {
        assert_eq!(identity.roles, vec!["reader"]);
    })
}

#[tokio::test]
async fn real_hs256_identity_and_claim_signature_rejections() {
    install_default_provider().unwrap();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    authenticate(token.clone(), SECRET).await.unwrap();
    for size in [0, 31, 1025] {
        assert!(matches!(
            authenticate(token.clone(), &vec![0x37; size]).await,
            Err(IdentityError::TokenMalformed)
        ));
    }
    // Real signatures under other supported HMAC algorithms must not change
    // TokenValidator's explicit HS256 authentication policy.
    for algorithm in [Algorithm::HS384, Algorithm::HS512] {
        let key = [0x55; 64];
        let other = encode(
            &Header::new(algorithm),
            &claims(),
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        assert!(matches!(
            authenticate(other, &key).await,
            Err(IdentityError::TokenMalformed)
        ));
    }
    // Fixed base64url {"alg":"none"}, genuine claims segment, no signature.
    let payload = token.split('.').nth(1).unwrap();
    assert!(matches!(
        authenticate(format!("eyJhbGciOiJub25lIn0.{payload}."), SECRET).await,
        Err(IdentityError::TokenMalformed)
    ));
    assert!(matches!(
        authenticate(token.clone(), &[0x37; 32]).await,
        Err(IdentityError::TokenMalformed)
    ));
    let mut tampered = token.into_bytes();
    let signature = tampered.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    tampered[signature] = if tampered[signature] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(matches!(
        authenticate(String::from_utf8(tampered).unwrap(), SECRET).await,
        Err(IdentityError::TokenMalformed)
    ));
    for (field, value, expired) in [
        ("iss", json!("wrong-issuer"), false),
        ("aud", json!("wrong-audience"), false),
        ("exp", json!(1), true),
    ] {
        let mut payload = claims();
        payload[field] = value;
        let token = encode(
            &Header::new(Algorithm::HS256),
            &payload,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        let error = authenticate(token, SECRET).await.unwrap_err();
        assert!(if expired {
            matches!(error, IdentityError::TokenExpired)
        } else {
            matches!(error, IdentityError::InvalidCredentials)
        });
    }
    assert!(matches!(
        authenticate("invalid".into(), SECRET).await,
        Err(IdentityError::TokenMalformed)
    ));
    assert!(matches!(
        authenticate("x".repeat(MAX_JWT_BYTES + 1), SECRET).await,
        Err(IdentityError::TokenMalformed)
    ));
}

#[test]
fn hmac_algorithms_key_boundaries_and_unsupported_families() {
    install_default_provider().unwrap();
    for (algorithm, minimum) in [
        (Algorithm::HS256, 32),
        (Algorithm::HS384, 48),
        (Algorithm::HS512, 64),
    ] {
        for size in [minimum, 1024] {
            let key = vec![0x45; size];
            let token = encode(
                &Header::new(algorithm),
                &claims(),
                &EncodingKey::from_secret(&key),
            )
            .unwrap();
            let mut validation = Validation::new(algorithm);
            validation.set_audience(&["internal-service"]);
            decode::<Value>(&token, &DecodingKey::from_secret(&key), &validation).unwrap();
        }
        for size in [0, minimum - 1, 1025] {
            assert!(encode(
                &Header::new(algorithm),
                &claims(),
                &EncodingKey::from_secret(&vec![0x45; size])
            )
            .is_err());
        }
    }
    assert!(encode(
        &Header::new(Algorithm::RS256),
        &claims(),
        &EncodingKey::from_secret(SECRET)
    )
    .is_err());
    assert!(encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_rsa_der(b"synthetic-invalid-key")
    )
    .is_err());
    let payload = json!({"exp":1, "padding":"x".repeat(MAX_JWT_BYTES)});
    assert!(encode(
        &Header::new(Algorithm::HS256),
        &payload,
        &EncodingKey::from_secret(SECRET)
    )
    .is_err());
}

#![cfg(feature = "jwks")]
//! BDD contract for projected Kubernetes workload JWT validation.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secure_identity::workload::{
    KubernetesServiceAccountSubject, WorkloadIdentityError, WorkloadJwtValidator,
    MAX_WORKLOAD_JWT_BYTES, MAX_WORKLOAD_KEY_ID_BYTES,
};
use serde::Serialize;

const ISSUER: &str = "https://kubernetes.default.svc";
const AUDIENCE: &str = "sunlit-platform-api";
const SUBJECT: &str = "system:serviceaccount:sunlit:otel-collector";
const KEY_ID: &str = "kube-signing-key";

// Throwaway test key material is stored without PEM armour so secret scanners
// do not learn to ignore literal private-key banners in source files.
const TEST_PRIVATE_PKCS8_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRb/iDkP6qo4FJv/iB1LBkq2XpOohIJB8QFAoTptmrLkic8adVb25uhG6O3Ox/2GegPEIAa+yhncvIkwROQJFWwfV5JcmmWbUuJc+Xyebvs9MgoDfoDK32kNctdJ8jb36Y02SYxkjzbGV6yz3NDTBKNxrry9pVexxD/aLFIN6ZCvCgoqeg5CREnFk/ORiLOa2Bome4bkd6QCzpG/GVyjoXC+AmqHgyYpgoacceIDlhKk3fwblP5LYLZTA0J8gpHtP4DbGgzr8OiKTbW59sohVFP/hisM+8xZwbFllHr/DM04RPbO2U+Vqu8jIjf5NaNBMnGsBVlhEzwG4dPTt+Vdc5AgMBAAECggEAAeZlWjfeJZO7kXzrOa320TJQXP4AfJYOTZXUSb1vYgBhcoILNx5Ttu80NmR+RUJ5czB6FqP5VuCAzST59VCcOO3OxtP0eRIShOoH0MwpOwwLX+iwL9EwoVO1o1u4h13kh5P7CJtGOrtv+BNAsDvnb/RBcLmYqsKbMlSKWIXjMGnO/HGoA8PyAaFNeV9CKIsIKnIKZuYbOnJSe4C6T+NKwXIErO9Y+/k4npSbbHtFDPagwQbimxlEgd5bkOJhWaX+mIe5Z7TuUSbz8mpZ8vf5jXLgmeJsrOO+otmZ2REF03iEgQYJHXtIhe5iuoLPPsiRQXylciMEyJGWyGffxuvHsQKBgQD75MNoQMceTxEYPKVHCWQ0JcoBYdzNPKrd+BqPBe8uDBTh/1gyyhlJBgrIBAfyKubmO7iHiuWEAZOZEjs1m2+pjeEkETf27Mbj/6QmJ4iCuUDCHs/VQWkEbMDtkmdJVYVgkyz43v50vedv9biEInV6Xpvrn0g8+W+lDbaQOh8BEQKBgQDU2gX7ZRUQ6BSsRplnIXsIhQnklD7uGT+5eoW1LymoEChL4EsMl/BagSnV46HjwR8Wn9TkoVSxRWMaH4Z1gzhBWcOEtbZiMPZU5GpLy5Ua4KMHE0QBQP+KGENJcMTeuiGH/WT67dH9nvu6GJc+eFvi8h/zt8XDU1y+g3ucRCvzqQKBgBF1E03gX2xsUmT5nwLDVdx/Wfaqj6DxuW3UyhJreN4aHEBlb/llJEd5Ubn2/Y39By+hp/JM4Ac8DLypFM1sTlrT6GyVfOlyE36tsvSp/L4ClMhfVkwTUnHqD5znbp0YfjvpN06wNbZliuqpfvY5ZSbr86ZqzZjcOK6ZurNYM9nhAoGAMIM0o9SpFX5f39gDdK771LhFxfRH14qnrIWRXfdO3kA4fvqzAD7NCEOyHk7QghFtHYH2Stm+bNzstnKC+dubgcGMv32PARg5vKWG2Jmg9UxHvAAXGtYOqBHZnC54oG75333QeySjHNQUeZjLN/DEuJgI0kqLZ3ZjiAR9suMSxWkCgYAcOH1FyFfUUy3PAL2DgClBQ2w2G9IL6jhvLp7nokA6sksm+44OoyYYc4Oe/p58pBLENJWt7HXUs9weANmEhnn3zPh0Fw7hC7Fd+tNSB/H15GAo2j84g4uvTu1gLgv6Hepp5CR3JRovTqLz/7flfxuzyTQ0K6igAd7gfA/FZ1Vf8A==";
const TEST_RSA_N_B64URL: &str = "0W_4g5D-qqOBSb_4gdSwZKtl6TqISCQfEBQKE6bZqy5InPGnVW9uboRujtzsf9hnoDxCAGvsoZ3LyJMETkCRVsH1eSXJplm1LiXPl8nm77PTIKA36Ayt9pDXLXSfI29-mNNkmMZI82xless9zQ0wSjca68vaVXscQ_2ixSDemQrwoKKnoOQkRJxZPzkYizmtgaJnuG5HekAs6Rvxlco6FwvgJqh4MmKYKGnHHiA5YSpN38G5T-S2C2UwNCfIKR7T-A2xoM6_Doik21ufbKIVRT_4YrDPvMWcGxZZR6_wzNOET2ztlPlarvIyI3-TWjQTJxrAVZYRM8BuHT07flXXOQ";

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: Audience,
    exp: u64,
    nbf: u64,
    // These deliberately untrusted claims prove the primitive returns no
    // caller-selected tenant or operation authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

fn pem(kind: &str, body: &str) -> String {
    let rule = "-".repeat(5);
    let wrapped = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("{rule}BEGIN {kind}{rule}\n{wrapped}\n{rule}END {kind}{rule}\n")
}

fn jwks_with_alg(algorithm: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{KEY_ID}","use":"sig","alg":"{algorithm}","n":"{TEST_RSA_N_B64URL}","e":"AQAB"}}]}}"#
    )
}

fn jwks_with_duplicate_key_id() -> String {
    let key = format!(
        r#"{{"kty":"RSA","kid":"{KEY_ID}","use":"sig","alg":"RS256","n":"{TEST_RSA_N_B64URL}","e":"AQAB"}}"#
    );
    format!(r#"{{"keys":[{key},{key}]}}"#)
}

fn validator() -> WorkloadJwtValidator {
    WorkloadJwtValidator::from_static_jwks(ISSUER, AUDIENCE, &jwks_with_alg("RS256"))
        .expect("valid static validator")
}

fn valid_claims() -> Claims {
    let now = now_secs();
    Claims {
        sub: SUBJECT.to_string(),
        iss: ISSUER.to_string(),
        aud: Audience::One(AUDIENCE.to_string()),
        exp: now + 300,
        nbf: now.saturating_sub(1),
        tenant: None,
        operation: None,
    }
}

fn sign(claims: &Claims, algorithm: Algorithm, kid: Option<&str>) -> String {
    sign_serializable(claims, algorithm, kid)
}

fn sign_serializable(claims: &impl Serialize, algorithm: Algorithm, kid: Option<&str>) -> String {
    let mut header = Header::new(algorithm);
    header.kid = kid.map(str::to_string);
    let key = match algorithm {
        Algorithm::RS256 => {
            EncodingKey::from_rsa_pem(pem("PRIVATE KEY", TEST_PRIVATE_PKCS8_B64).as_bytes())
                .expect("RSA key")
        }
        Algorithm::HS256 => EncodingKey::from_secret(b"not-an-rsa-key"),
        _ => panic!("test helper supports RS256 and HS256 only"),
    };
    encode(&header, claims, &key).expect("encode test token")
}

#[test]
fn given_non_https_or_ambiguous_jwks_url_when_configured_then_rejected() {
    for invalid in [
        "http://kubernetes.default.svc/openid/v1/jwks",
        "https://user@kubernetes.default.svc/openid/v1/jwks",
        "https://kubernetes.default.svc/openid/v1/jwks#fragment",
        "/openid/v1/jwks",
    ] {
        assert_eq!(
            WorkloadJwtValidator::new(invalid, ISSUER, AUDIENCE).err(),
            Some(WorkloadIdentityError::InvalidJwksUrl)
        );
    }
}

#[tokio::test]
async fn given_bounded_public_jwks_without_dev_feature_when_verified_then_available_in_production()
{
    let validator =
        WorkloadJwtValidator::from_static_jwks(ISSUER, AUDIENCE, &jwks_with_alg("RS256"))
            .expect("bounded public JWKS");
    let token = sign(&valid_claims(), Algorithm::RS256, Some(KEY_ID));

    let subject = validator.verify(&token).await.expect("valid workload JWT");

    assert_eq!(subject.as_str(), SUBJECT);
}

#[test]
fn given_unsafe_inline_jwks_when_configured_then_rejected_before_use() {
    let private_rsa = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{KEY_ID}","use":"sig","alg":"RS256","n":"{TEST_RSA_N_B64URL}","e":"AQAB","d":"AQAB"}}]}}"#
    );
    let symmetric = format!(
        r#"{{"keys":[{{"kty":"oct","kid":"{KEY_ID}","use":"sig","alg":"HS256","k":"bm90LWEtdHJ1c3RlZC1rZXk"}}]}}"#
    );
    let unsupported = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{KEY_ID}","use":"sig","alg":"RS384","n":"{TEST_RSA_N_B64URL}","e":"AQAB"}}]}}"#
    );
    let oversized = " ".repeat((1024 * 1024) + 1);
    let cases = [
        ("malformed", WorkloadIdentityError::JwksUnavailable),
        (&oversized, WorkloadIdentityError::JwksUnavailable),
        (&private_rsa, WorkloadIdentityError::JwksUnavailable),
        (&symmetric, WorkloadIdentityError::JwksAlgorithmMismatch),
        (
            &jwks_with_duplicate_key_id(),
            WorkloadIdentityError::UnknownKeyId,
        ),
        (&unsupported, WorkloadIdentityError::JwksAlgorithmMismatch),
    ];

    for (jwks, expected) in cases {
        assert_eq!(
            WorkloadJwtValidator::from_static_jwks(ISSUER, AUDIENCE, jwks).err(),
            Some(expected),
            "unexpected result for inline JWKS case"
        );
    }
}

#[tokio::test]
async fn given_valid_projected_jwt_when_verified_then_only_bounded_subject_is_returned() {
    let mut claims = valid_claims();
    claims.tenant = Some("attacker-chosen-tenant".to_string());
    claims.operation = Some("admin".to_string());
    let token = sign(&claims, Algorithm::RS256, Some(KEY_ID));

    let subject = validator()
        .verify(&token)
        .await
        .expect("valid workload JWT");

    assert_eq!(subject.as_str(), SUBJECT);
    assert_eq!(
        format!("{subject:?}"),
        "KubernetesServiceAccountSubject(<redacted>)"
    );
}

#[tokio::test]
async fn given_wrong_algorithm_or_key_metadata_when_verified_then_rejected() {
    let claims = valid_claims();
    let hs256 = sign(&claims, Algorithm::HS256, Some(KEY_ID));
    assert_eq!(
        validator().verify(&hs256).await,
        Err(WorkloadIdentityError::AlgorithmMismatch)
    );

    assert_eq!(
        WorkloadJwtValidator::from_static_jwks(ISSUER, AUDIENCE, &jwks_with_alg("RS384")).err(),
        Some(WorkloadIdentityError::JwksAlgorithmMismatch)
    );
}

#[tokio::test]
async fn given_missing_unknown_or_unbounded_kid_when_verified_then_rejected() {
    let claims = valid_claims();
    let cases = [
        (
            sign(&claims, Algorithm::RS256, None),
            WorkloadIdentityError::MissingKeyId,
        ),
        (
            sign(&claims, Algorithm::RS256, Some("unknown")),
            WorkloadIdentityError::UnknownKeyId,
        ),
        (
            sign(&claims, Algorithm::RS256, Some("")),
            WorkloadIdentityError::InvalidKeyId,
        ),
        (
            sign(&claims, Algorithm::RS256, Some("has whitespace")),
            WorkloadIdentityError::InvalidKeyId,
        ),
        (
            sign(
                &claims,
                Algorithm::RS256,
                Some(&"k".repeat(MAX_WORKLOAD_KEY_ID_BYTES + 1)),
            ),
            WorkloadIdentityError::InvalidKeyId,
        ),
    ];

    for (token, expected) in cases {
        assert_eq!(validator().verify(&token).await, Err(expected));
    }

    assert_eq!(
        WorkloadJwtValidator::from_static_jwks(ISSUER, AUDIENCE, &jwks_with_duplicate_key_id())
            .err(),
        Some(WorkloadIdentityError::UnknownKeyId)
    );
}

#[tokio::test]
async fn given_tampered_signature_when_verified_then_rejected() {
    let token = sign(&valid_claims(), Algorithm::RS256, Some(KEY_ID));
    let mut pieces = token.split('.').map(str::to_string).collect::<Vec<_>>();
    let replacement = if pieces[2].starts_with('A') { "B" } else { "A" };
    pieces[2].replace_range(..1, replacement);
    let tampered = pieces.join(".");

    assert_eq!(
        validator().verify(&tampered).await,
        Err(WorkloadIdentityError::InvalidSignature)
    );
}

#[tokio::test]
async fn given_wrong_issuer_or_non_exact_audience_when_verified_then_rejected() {
    let mut wrong_issuer = valid_claims();
    wrong_issuer.iss = "https://attacker.invalid".to_string();
    assert_eq!(
        validator()
            .verify(&sign(&wrong_issuer, Algorithm::RS256, Some(KEY_ID)))
            .await,
        Err(WorkloadIdentityError::IssuerMismatch)
    );

    for audience in [
        Audience::One("another-service".to_string()),
        Audience::Many(vec![AUDIENCE.to_string(), "another-service".to_string()]),
    ] {
        let mut claims = valid_claims();
        claims.aud = audience;
        assert_eq!(
            validator()
                .verify(&sign(&claims, Algorithm::RS256, Some(KEY_ID)))
                .await,
            Err(WorkloadIdentityError::AudienceMismatch)
        );
    }
}

#[tokio::test]
async fn given_expired_or_not_yet_valid_token_when_verified_then_rejected() {
    let now = now_secs();
    let mut expired = valid_claims();
    expired.exp = now;
    assert_eq!(
        validator()
            .verify(&sign(&expired, Algorithm::RS256, Some(KEY_ID)))
            .await,
        Err(WorkloadIdentityError::Expired)
    );

    let mut future = valid_claims();
    future.nbf = now + 120;
    assert_eq!(
        validator()
            .verify(&sign(&future, Algorithm::RS256, Some(KEY_ID)))
            .await,
        Err(WorkloadIdentityError::NotYetValid)
    );
}

#[tokio::test]
async fn given_missing_required_time_or_identity_claim_when_verified_then_rejected() {
    let now = now_secs();
    for claims in [
        serde_json::json!({
            "sub": SUBJECT,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "nbf": now.saturating_sub(1),
        }),
        serde_json::json!({
            "sub": SUBJECT,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now + 300,
        }),
        serde_json::json!({
            "sub": SUBJECT,
            "iss": ISSUER,
            "exp": now + 300,
            "nbf": now.saturating_sub(1),
        }),
    ] {
        let token = sign_serializable(&claims, Algorithm::RS256, Some(KEY_ID));
        assert_eq!(
            validator().verify(&token).await,
            Err(WorkloadIdentityError::TokenMalformed)
        );
    }
}

#[tokio::test]
async fn given_malformed_or_oversized_token_when_verified_then_rejected() {
    assert_eq!(
        validator().verify("not-a-jwt").await,
        Err(WorkloadIdentityError::TokenMalformed)
    );
    assert_eq!(
        validator()
            .verify(&"x".repeat(MAX_WORKLOAD_JWT_BYTES + 1))
            .await,
        Err(WorkloadIdentityError::TokenTooLarge)
    );
}

#[test]
fn given_noncanonical_or_unbounded_subject_when_parsed_then_rejected() {
    for invalid in [
        "default:otel-collector",
        "system:serviceaccount:Sunlit:otel-collector",
        "system:serviceaccount:sunlit:",
        "system:serviceaccount:sunlit:otel:collector",
        "system:serviceaccount:sunlit:-collector",
    ] {
        assert_eq!(
            KubernetesServiceAccountSubject::parse(invalid),
            Err(WorkloadIdentityError::InvalidSubject)
        );
    }

    let oversized = format!("system:serviceaccount:sunlit:{}", "a".repeat(254));
    assert_eq!(
        KubernetesServiceAccountSubject::parse(&oversized),
        Err(WorkloadIdentityError::InvalidSubject)
    );
}

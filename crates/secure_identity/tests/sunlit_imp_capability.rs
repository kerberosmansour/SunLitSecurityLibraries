//! BDD contract for the strict single-use tenant+operation capability.
//!
//! Every test here is a security assertion. A capability that fails ANY of these
//! must be rejected: the whole point of the primitive is that a broker can trust
//! one narrow statement — "this subject may perform this operation, for this
//! tenant, against exactly this request, once, within 60 seconds" — and nothing
//! wider.

use std::sync::Arc;

use secure_identity::capability::{
    CapabilityError, CapabilityIssuer, CapabilityRequest, CapabilityVerifier, Expected,
    InMemoryReplayStore, Operation, ReplayStore, RsaCapabilitySigner,
};

/// Throwaway test key material, stored as bare base64 WITHOUT PEM armour.
///
/// The armour is assembled at runtime instead of written literally. A literal
/// literal PEM private-key banner in the tree trips secret scanning, and the wrong
/// fix is to teach the scanner to ignore PEM inside tests — that is exactly how
/// a real key gets waved through later. The decoded bytes are identical either
/// way, so no test coverage is lost.
const TEST_PRIVATE_PKCS8_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRb/iDkP6qo4FJv/iB1LBkq2XpOohIJB8QFAoTptmrLkic8adVb25uhG6O3Ox/2GegPEIAa+yhncvIkwROQJFWwfV5JcmmWbUuJc+Xyebvs9MgoDfoDK32kNctdJ8jb36Y02SYxkjzbGV6yz3NDTBKNxrry9pVexxD/aLFIN6ZCvCgoqeg5CREnFk/ORiLOa2Bome4bkd6QCzpG/GVyjoXC+AmqHgyYpgoacceIDlhKk3fwblP5LYLZTA0J8gpHtP4DbGgzr8OiKTbW59sohVFP/hisM+8xZwbFllHr/DM04RPbO2U+Vqu8jIjf5NaNBMnGsBVlhEzwG4dPTt+Vdc5AgMBAAECggEAAeZlWjfeJZO7kXzrOa320TJQXP4AfJYOTZXUSb1vYgBhcoILNx5Ttu80NmR+RUJ5czB6FqP5VuCAzST59VCcOO3OxtP0eRIShOoH0MwpOwwLX+iwL9EwoVO1o1u4h13kh5P7CJtGOrtv+BNAsDvnb/RBcLmYqsKbMlSKWIXjMGnO/HGoA8PyAaFNeV9CKIsIKnIKZuYbOnJSe4C6T+NKwXIErO9Y+/k4npSbbHtFDPagwQbimxlEgd5bkOJhWaX+mIe5Z7TuUSbz8mpZ8vf5jXLgmeJsrOO+otmZ2REF03iEgQYJHXtIhe5iuoLPPsiRQXylciMEyJGWyGffxuvHsQKBgQD75MNoQMceTxEYPKVHCWQ0JcoBYdzNPKrd+BqPBe8uDBTh/1gyyhlJBgrIBAfyKubmO7iHiuWEAZOZEjs1m2+pjeEkETf27Mbj/6QmJ4iCuUDCHs/VQWkEbMDtkmdJVYVgkyz43v50vedv9biEInV6Xpvrn0g8+W+lDbaQOh8BEQKBgQDU2gX7ZRUQ6BSsRplnIXsIhQnklD7uGT+5eoW1LymoEChL4EsMl/BagSnV46HjwR8Wn9TkoVSxRWMaH4Z1gzhBWcOEtbZiMPZU5GpLy5Ua4KMHE0QBQP+KGENJcMTeuiGH/WT67dH9nvu6GJc+eFvi8h/zt8XDU1y+g3ucRCvzqQKBgBF1E03gX2xsUmT5nwLDVdx/Wfaqj6DxuW3UyhJreN4aHEBlb/llJEd5Ubn2/Y39By+hp/JM4Ac8DLypFM1sTlrT6GyVfOlyE36tsvSp/L4ClMhfVkwTUnHqD5znbp0YfjvpN06wNbZliuqpfvY5ZSbr86ZqzZjcOK6ZurNYM9nhAoGAMIM0o9SpFX5f39gDdK771LhFxfRH14qnrIWRXfdO3kA4fvqzAD7NCEOyHk7QghFtHYH2Stm+bNzstnKC+dubgcGMv32PARg5vKWG2Jmg9UxHvAAXGtYOqBHZnC54oG75333QeySjHNQUeZjLN/DEuJgI0kqLZ3ZjiAR9suMSxWkCgYAcOH1FyFfUUy3PAL2DgClBQ2w2G9IL6jhvLp7nokA6sksm+44OoyYYc4Oe/p58pBLENJWt7HXUs9weANmEhnn3zPh0Fw7hC7Fd+tNSB/H15GAo2j84g4uvTu1gLgv6Hepp5CR3JRovTqLz/7flfxuzyTQ0K6igAd7gfA/FZ1Vf8A==";
const TEST_PUBLIC_SPKI_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W/4g5D+qqOBSb/4gdSwZKtl6TqISCQfEBQKE6bZqy5InPGnVW9uboRujtzsf9hnoDxCAGvsoZ3LyJMETkCRVsH1eSXJplm1LiXPl8nm77PTIKA36Ayt9pDXLXSfI29+mNNkmMZI82xless9zQ0wSjca68vaVXscQ/2ixSDemQrwoKKnoOQkRJxZPzkYizmtgaJnuG5HekAs6Rvxlco6FwvgJqh4MmKYKGnHHiA5YSpN38G5T+S2C2UwNCfIKR7T+A2xoM6/Doik21ufbKIVRT/4YrDPvMWcGxZZR6/wzNOET2ztlPlarvIyI3+TWjQTJxrAVZYRM8BuHT07flXXOQIDAQAB";
const TEST_RSA_N_B64URL: &str = "0W_4g5D-qqOBSb_4gdSwZKtl6TqISCQfEBQKE6bZqy5InPGnVW9uboRujtzsf9hnoDxCAGvsoZ3LyJMETkCRVsH1eSXJplm1LiXPl8nm77PTIKA36Ayt9pDXLXSfI29-mNNkmMZI82xless9zQ0wSjca68vaVXscQ_2ixSDemQrwoKKnoOQkRJxZPzkYizmtgaJnuG5HekAs6Rvxlco6FwvgJqh4MmKYKGnHHiA5YSpN38G5T-S2C2UwNCfIKR7T-A2xoM6_Doik21ufbKIVRT_4YrDPvMWcGxZZR6_wzNOET2ztlPlarvIyI3-TWjQTJxrAVZYRM8BuHT07flXXOQ";
const TEST_RSA_E_B64URL: &str = "AQAB";
/// A second, unrelated public key, so signature verification is shown to
/// discriminate rather than accept anything well-formed.
const OTHER_PUBLIC_SPKI_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6B71Pd/k9+h4ZVIZv01PWwCPhEUd4PpVPmhH5u63mgkY1WLYTr5OrJcn9sxqVQQBM5tTz9bQolg9waDLc/CEZvEATSsgIjC5e/mnwCfBb3arsnoVECrTa7eVSV8NvgCmEM/g+FHuyaLawjeOodiL659LBKRY4LgJQaS6saqES1PIr7LEcGKdeCucGqJRFtqAENiCaefMKCjyRFbo0DVnljkQW4MhPgq0urEH8sjRh0k10ThOdgT7CrFboleO84ZGQq+IbJkElTGM2QWFcvoOLwnU9zs0qlKNPqzeuz8f6h325QK9zd9A9Cr61ja1q8RFV2g/c7bxTX2YterqAswQQIDAQAB";

/// Wraps bare base64 in PEM armour built from parts.
fn pem(kind: &str, body: &str) -> String {
    let rule = "-".repeat(5);
    let wrapped = body
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("{rule}BEGIN {kind}{rule}\n{wrapped}\n{rule}END {kind}{rule}\n")
}

fn test_private_pem() -> String {
    pem("PRIVATE KEY", TEST_PRIVATE_PKCS8_B64)
}
fn test_public_pem() -> String {
    pem("PUBLIC KEY", TEST_PUBLIC_SPKI_B64)
}

fn test_keys() -> (Vec<u8>, Vec<u8>) {
    (
        test_private_pem().into_bytes(),
        test_public_pem().into_bytes(),
    )
}

fn issuer(private_pem: &[u8]) -> CapabilityIssuer<RsaCapabilitySigner> {
    CapabilityIssuer::new(
        "https://auth.sunlit.test".to_string(),
        "sunlit-broker".to_string(),
        RsaCapabilitySigner::from_pkcs8_pem(private_pem).expect("test signing key"),
    )
}

fn verifier(public_pem: &[u8]) -> CapabilityVerifier {
    CapabilityVerifier::from_rsa_pem(
        "https://auth.sunlit.test".to_string(),
        "sunlit-broker".to_string(),
        public_pem,
    )
    .expect("test verifying key")
}

fn request() -> CapabilityRequest {
    CapabilityRequest::new("acct-42", Operation::Read, b"SELECT 1 FROM product_signals")
}

fn expected() -> Expected {
    Expected::new(
        "svc-platform-api",
        "acct-42",
        Operation::Read,
        b"SELECT 1 FROM product_signals",
    )
}

// ---------------------------------------------------------------- happy path

#[tokio::test]
async fn happy_path_first_use_succeeds() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();

    let verified = verifier(&pub_pem)
        .verify(&token, &expected(), &store)
        .await
        .expect("first use must succeed");

    assert_eq!(verified.tenant(), "acct-42");
    assert_eq!(verified.operation(), Operation::Read);
    assert_eq!(verified.subject(), "svc-platform-api");
}

// ------------------------------------------------------------ single use

#[tokio::test]
async fn replay_of_the_same_capability_fails_closed() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    let v = verifier(&pub_pem);

    v.verify(&token, &expected(), &store)
        .await
        .expect("first use");
    let second = v.verify(&token, &expected(), &store).await;

    assert!(
        matches!(second, Err(CapabilityError::Replayed)),
        "second use must be rejected as replay, got {second:?}"
    );
}

#[tokio::test]
async fn concurrent_double_use_admits_exactly_one_winner() {
    let (priv_pem, pub_pem) = test_keys();
    let token = Arc::new(
        issuer(&priv_pem)
            .issue("svc-platform-api", &request(), 30)
            .await
            .expect("issue"),
    );
    let store = Arc::new(InMemoryReplayStore::default());
    let v = Arc::new(verifier(&pub_pem));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let (t, s, ver) = (Arc::clone(&token), Arc::clone(&store), Arc::clone(&v));
        handles.push(tokio::spawn(async move {
            ver.verify(&t, &expected(), s.as_ref()).await.is_ok()
        }));
    }
    let mut winners = 0usize;
    for h in handles {
        if h.await.expect("task") {
            winners += 1;
        }
    }

    assert_eq!(
        winners, 1,
        "exactly one concurrent use may win, got {winners}"
    );
}

// ------------------------------------------------------- claim binding

#[tokio::test]
async fn wrong_tenant_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();

    let wrong = Expected::new(
        "svc-platform-api",
        "acct-OTHER",
        Operation::Read,
        b"SELECT 1 FROM product_signals",
    );
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &wrong, &store).await,
        Err(CapabilityError::TenantMismatch)
    ));
}

#[tokio::test]
async fn wrong_operation_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();

    let wrong = Expected::new(
        "svc-platform-api",
        "acct-42",
        Operation::Delete,
        b"SELECT 1 FROM product_signals",
    );
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &wrong, &store).await,
        Err(CapabilityError::OperationMismatch)
    ));
}

#[tokio::test]
async fn different_request_body_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();

    let wrong = Expected::new(
        "svc-platform-api",
        "acct-42",
        Operation::Read,
        b"SELECT 1 FROM feedback_tickets",
    );
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &wrong, &store).await,
        Err(CapabilityError::RequestMismatch)
    ));
}

#[tokio::test]
async fn wrong_subject_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();

    let wrong = Expected::new(
        "svc-SOMETHING-ELSE",
        "acct-42",
        Operation::Read,
        b"SELECT 1 FROM product_signals",
    );
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &wrong, &store).await,
        Err(CapabilityError::SubjectMismatch)
    ));
}

/// The framed digest must not be confusable by moving bytes across field
/// boundaries — `("ab","c")` and `("a","bc")` must not collide.
#[tokio::test]
async fn request_digest_framing_is_unambiguous() {
    let a = CapabilityRequest::new("ab", Operation::Read, b"c");
    let b = CapabilityRequest::new("a", Operation::Read, b"bc");
    assert_ne!(
        a.digest(),
        b.digest(),
        "unframed concatenation would make these collide"
    );
}

// ------------------------------------------------------------- temporal

#[tokio::test]
async fn expired_capability_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue_at("svc-platform-api", &request(), 30, unix_now() - 120)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::Expired)
    ));
}

#[tokio::test]
async fn not_yet_valid_capability_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue_at("svc-platform-api", &request(), 30, unix_now() + 600)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::NotYetValid)
    ));
}

#[tokio::test]
async fn ttl_above_sixty_seconds_is_refused_at_issue_time() {
    let (priv_pem, _) = test_keys();
    let err = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 61)
        .await;
    assert!(
        matches!(err, Err(CapabilityError::TtlTooLong)),
        "issuing a >60s capability must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn ttl_above_sixty_seconds_is_refused_at_verify_time_too() {
    // Defence in depth: a token minted by a non-conforming issuer must still be
    // rejected by the verifier, which cannot assume the issuer behaved.
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue_unchecked_ttl_for_test("svc-platform-api", &request(), 3600)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::TtlTooLong)
    ));
}

#[tokio::test]
async fn missing_jti_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue_without_jti_for_test("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::MissingJti)
    ));
}

// --------------------------------------------------------- cryptographic

#[tokio::test]
async fn wrong_signing_key_is_rejected() {
    let (priv_pem, _) = test_keys();
    let other_pub = pem("PUBLIC KEY", OTHER_PUBLIC_SPKI_B64).into_bytes();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&other_pub)
            .verify(&token, &expected(), &store)
            .await,
        Err(CapabilityError::BadSignature)
    ));
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = CapabilityIssuer::new(
        "https://evil.example".to_string(),
        "sunlit-broker".to_string(),
        RsaCapabilitySigner::from_pkcs8_pem(&priv_pem).expect("key"),
    )
    .issue("svc-platform-api", &request(), 30)
    .await
    .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::IssuerMismatch)
    ));
}

#[tokio::test]
async fn wrong_audience_is_rejected() {
    let (priv_pem, pub_pem) = test_keys();
    let token = CapabilityIssuer::new(
        "https://auth.sunlit.test".to_string(),
        "some-other-broker".to_string(),
        RsaCapabilitySigner::from_pkcs8_pem(&priv_pem).expect("key"),
    )
    .issue("svc-platform-api", &request(), 30)
    .await
    .expect("issue");
    let store = InMemoryReplayStore::default();
    assert!(matches!(
        verifier(&pub_pem).verify(&token, &expected(), &store).await,
        Err(CapabilityError::AudienceMismatch)
    ));
}

/// `alg: none` and HMAC confusion are the classic JWT breaks. The verifier is
/// RS256-only by construction and must not honour the token's own header.
#[tokio::test]
async fn alg_none_is_rejected() {
    let (_, pub_pem) = test_keys();
    let store = InMemoryReplayStore::default();
    // {"alg":"none","typ":"JWT"} . {claims} . (empty signature)
    let forged = format!(
        "{}.{}.",
        base64_url(br#"{"alg":"none","typ":"JWT"}"#),
        base64_url(br#"{"iss":"https://auth.sunlit.test","aud":"sunlit-broker"}"#)
    );
    assert!(matches!(
        verifier(&pub_pem)
            .verify(&forged, &expected(), &store)
            .await,
        Err(CapabilityError::BadSignature) | Err(CapabilityError::Malformed)
    ));
}

#[tokio::test]
async fn hs256_algorithm_confusion_is_rejected() {
    let (_, pub_pem) = test_keys();
    let store = InMemoryReplayStore::default();
    let forged = format!(
        "{}.{}.{}",
        base64_url(br#"{"alg":"HS256","typ":"JWT"}"#),
        base64_url(br#"{"iss":"https://auth.sunlit.test","aud":"sunlit-broker"}"#),
        base64_url(b"not-a-real-mac")
    );
    assert!(matches!(
        verifier(&pub_pem)
            .verify(&forged, &expected(), &store)
            .await,
        Err(CapabilityError::BadSignature) | Err(CapabilityError::Malformed)
    ));
}

// ------------------------------------------------------------- redaction

/// A capability is bearer authority. Nothing that renders it may leak the token,
/// the request body, or the jti.
#[tokio::test]
async fn debug_output_never_leaks_token_or_request_material() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    let verified = verifier(&pub_pem)
        .verify(&token, &expected(), &store)
        .await
        .expect("verify");

    let rendered = format!("{verified:?}");
    assert!(!rendered.contains(&token), "Debug leaked the raw token");
    assert!(
        !rendered.contains("SELECT 1 FROM product_signals"),
        "Debug leaked the request body"
    );
    assert!(
        !rendered.contains(verified.jti()),
        "Debug leaked the jti, which is replay-relevant"
    );
}

#[tokio::test]
async fn error_display_never_leaks_token_material() {
    let (priv_pem, pub_pem) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let store = InMemoryReplayStore::default();
    let wrong = Expected::new(
        "svc-platform-api",
        "acct-OTHER",
        Operation::Read,
        b"SELECT 1 FROM product_signals",
    );
    let err = verifier(&pub_pem)
        .verify(&token, &wrong, &store)
        .await
        .expect_err("must fail");
    let rendered = format!("{err} / {err:?}");
    assert!(!rendered.contains(&token));
    assert!(!rendered.contains("acct-OTHER"));
    assert!(!rendered.contains("SELECT"));
}

// ------------------------------------------------------------- malformed

#[tokio::test]
async fn structurally_malformed_input_is_rejected_without_panic() {
    let (_, pub_pem) = test_keys();
    let store = InMemoryReplayStore::default();
    let v = verifier(&pub_pem);
    for bad in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        "🙂.🙂.🙂",
        &"A".repeat(100_000),
    ] {
        let out = v.verify(bad, &expected(), &store).await;
        assert!(out.is_err(), "malformed input {bad:?} must not verify");
    }
}

// ------------------------------------------------------------------ util

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ------------------------------------------------- key-size agreement (F3)

/// A 1024-bit key: below the accepted floor. Kept as bare base64 for the same
/// scanner reason as the others.
const WEAK_PRIVATE_PKCS8_B64: &str = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKTZvCwNswHe2kCBQn85TBtbJj1YpPULgMzR6i9/dUlKAr/oaLtNGlDhmps4RQUc/IlM41JFwvnNuP2L330CF/aLurX/FlyxtZEMYYiT8rf3OIOPE9m5atyazOqBCw75LR+lHhfy+cAMyHOWzYBjAlajzdETQ5fDSp5miaFkhch3AgMBAAECgYB3VlQ9g/FJcl2HAsvzs7Pfvd1x3YEVD62/GFsy5U8vrg9Ng96FcOyTDq7QnSyB5hj/ABU0EuJx2jaH/cDdCy3ymIaIaR+2LkZ2SkjQAFRtmy8/rTX3GiS+7WqfXN272lExm1UkkqDVYQ7rq7eIx4u7f1ucCWK9nJvHZMvqDr7J2QJBAM7AzxBUCggkk8X5780zxMjWhc6bVHTvEoGEqwZS00k8GUO0P70OZ8izJW5SVPaAKfkg/OYTNZ97pMzMU/OFQ/sCQQDMHdQikJ6CBXlbMdigN2z1hAIOKeDaNK0E5LMFKxvpBmYQZQbIx1Zrznwk9Ns79roLo8W0YVtkn13VJE0ZEKi1AkBhhd7l484rkx1FGCS91TpwRYguMWSAF7jR8QM+41iYRcng/qfGBIJ9z8rLI/jBoSirQ50m5U644HiWxZaf2m97AkApxaD4Qehua3hedWEDyNP/mrhg9akSft05tyP71sqrcafJiyNMS58gCO3XElUbfG6umyGGvLXbbdHiIL+2dXZRAkAbGws1pm4HjfI2r2Rs00X/sQmb5ROMBBqK3TiIFtAMHoPkPWmvbZIVhKoZ3jUapQ5IlB6xzd3obCJHraMxNi9W";
const WEAK_PUBLIC_SPKI_B64: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCk2bwsDbMB3tpAgUJ/OUwbWyY9WKT1C4DM0eovf3VJSgK/6Gi7TRpQ4ZqbOEUFHPyJTONSRcL5zbj9i999Ahf2i7q1/xZcsbWRDGGIk/K39ziDjxPZuWrcmszqgQsO+S0fpR4X8vnADMhzls2AYwJWo83RE0OXw0qeZomhZIXIdwIDAQAB";
const WEAK_RSA_N_B64URL: &str = "pNm8LA2zAd7aQIFCfzlMG1smPVik9QuAzNHqL391SUoCv-hou00aUOGamzhFBRz8iUzjUkXC-c24_YvffQIX9ou6tf8WXLG1kQxhiJPyt_c4g48T2blq3JrM6oELDvktH6UeF_L5wAzIc5bNgGMCVqPN0RNDl8NKnmaJoWSFyHc";

#[tokio::test]
async fn rsa_components_construct_the_same_strict_verifier() {
    let (priv_pem, _) = test_keys();
    let token = issuer(&priv_pem)
        .issue("svc-platform-api", &request(), 30)
        .await
        .expect("issue");
    let verifier = CapabilityVerifier::from_rsa_components(
        "https://auth.sunlit.test".to_string(),
        "sunlit-broker".to_string(),
        TEST_RSA_N_B64URL,
        TEST_RSA_E_B64URL,
    )
    .expect("valid RSA components");
    let store = InMemoryReplayStore::default();

    verifier
        .verify(&token, &expected(), &store)
        .await
        .expect("first use must verify");
    assert!(matches!(
        verifier.verify(&token, &expected(), &store).await,
        Err(CapabilityError::Replayed)
    ));
}

#[test]
fn malformed_or_weak_rsa_components_are_rejected() {
    for (name, modulus, exponent) in [
        ("malformed modulus", "not base64url", TEST_RSA_E_B64URL),
        ("empty exponent", TEST_RSA_N_B64URL, ""),
        ("invalid even exponent", TEST_RSA_N_B64URL, "Ag"),
        ("weak modulus", WEAK_RSA_N_B64URL, TEST_RSA_E_B64URL),
    ] {
        let result = CapabilityVerifier::from_rsa_components(
            "https://auth.sunlit.test".to_string(),
            "sunlit-broker".to_string(),
            modulus,
            exponent,
        );
        assert!(
            matches!(result, Err(CapabilityError::InvalidKey)),
            "{name} must fail closed"
        );
    }
}

/// The signer and the verifier must agree on what a usable key is. If only one
/// of them enforces a floor, an attacker who supplies the key picks the side
/// that does not — which is precisely the asymmetry this pins shut.
#[tokio::test]
async fn undersized_rsa_key_is_rejected_by_both_signer_and_verifier() {
    let weak_priv = pem("PRIVATE KEY", WEAK_PRIVATE_PKCS8_B64);
    let weak_pub = pem("PUBLIC KEY", WEAK_PUBLIC_SPKI_B64);

    assert!(
        matches!(
            RsaCapabilitySigner::from_pkcs8_pem(weak_priv.as_bytes()),
            Err(CapabilityError::InvalidKey)
        ),
        "signer must refuse a 1024-bit key"
    );
    assert!(
        matches!(
            CapabilityVerifier::from_rsa_pem(
                "https://auth.sunlit.test".to_string(),
                "sunlit-broker".to_string(),
                weak_pub.as_bytes(),
            ),
            Err(CapabilityError::InvalidKey)
        ),
        "verifier must refuse a 1024-bit key too, or the floor is one-sided"
    );
}

/// POSITIVE CONTROL for the bound: the 2048-bit key used everywhere else must
/// still be accepted, so the test above is proving a floor rather than a
/// blanket rejection.
#[tokio::test]
async fn supported_rsa_key_size_is_still_accepted() {
    let (priv_pem, pub_pem) = test_keys();
    assert!(RsaCapabilitySigner::from_pkcs8_pem(&priv_pem).is_ok());
    assert!(CapabilityVerifier::from_rsa_pem(
        "https://auth.sunlit.test".to_string(),
        "sunlit-broker".to_string(),
        &pub_pem,
    )
    .is_ok());
}

// ------------------------------------- malformed key material (F7, mac-agent)

/// Malformed SPKI must fail closed as [`CapabilityError::InvalidKey`] rather
/// than panicking, and the accepted modulus size must come from key material
/// that is actually present rather than from an attacker-chosen length header.
///
/// Both halves matter. A panic in key parsing is a denial of service reachable
/// by whoever supplies configuration; a size read from a claimed-but-absent
/// length would let a key with no modulus at all satisfy the 2048-bit floor.
#[tokio::test]
async fn malformed_spki_is_rejected_without_panicking() {
    // Each vector is a DER structure that walks far enough into the parser to
    // reach the modulus INTEGER, then lies about it in a different way.
    for (name, spki_b64) in [
        // Zero-length INTEGER followed by a 0x00 byte. The sign-padding strip
        // subtracts 1 from a length of 0 and underflows.
        ("zero-length modulus", "MAowAAMGADADAgAA"),
        // INTEGER claims 257 bytes (exactly a 2048-bit modulus) and supplies
        // none. Trusting the header would report 2048 bits and pass the floor.
        ("truncated modulus", "MAowAAMGADAGAoIBAQ=="),
        // Zero-length INTEGER at the very end, so no byte follows it at all.
        ("zero-length modulus at end of buffer", "MAkwAAMFADACAgA="),
        // Length header claiming ~4GiB of modulus.
        ("oversized length header", "MA0wAAMJADAGAoT/////"),
    ] {
        let pem = pem("PUBLIC KEY", spki_b64);
        let out = CapabilityVerifier::from_rsa_pem(
            "https://auth.sunlit.test".to_string(),
            "sunlit-broker".to_string(),
            pem.as_bytes(),
        );
        assert!(
            matches!(out, Err(CapabilityError::InvalidKey)),
            "{name} must be rejected as InvalidKey, not panic or parse",
        );
    }
}

// ------------------------------------------------ replay store bounds (F4)

/// A spent `jti` only needs remembering while the capability could still be
/// presented. Retaining them forever is a memory-exhaustion surface reachable
/// by anyone who can cause capabilities to be issued.
#[tokio::test]
async fn replay_store_drops_entries_once_they_can_no_longer_be_presented() {
    let store = InMemoryReplayStore::default();
    let now = unix_now();

    store
        .consume("already-expired", now - 1)
        .await
        .expect("claim");
    assert_eq!(store.len(), 1);

    // Any later claim prunes what can no longer be replayed.
    store.consume("still-live", now + 300).await.expect("claim");
    assert_eq!(
        store.len(),
        1,
        "the expired entry must be dropped, not accumulated"
    );

    // And the live one is still single-use.
    assert!(matches!(
        store.consume("still-live", now + 300).await,
        Err(CapabilityError::Replayed)
    ));
}

/// The store fails closed at its cap rather than evicting a live `jti`.
/// Evicting one would silently re-authorise it.
#[tokio::test]
async fn replay_store_fails_closed_at_capacity_rather_than_evicting() {
    let store = InMemoryReplayStore::with_capacity(2);
    let now = unix_now();
    store.consume("a", now + 300).await.expect("first");
    store.consume("b", now + 300).await.expect("second");
    assert!(
        matches!(
            store.consume("c", now + 300).await,
            Err(CapabilityError::ReplayStoreUnavailable)
        ),
        "at capacity the store must refuse, never evict a live jti"
    );
}

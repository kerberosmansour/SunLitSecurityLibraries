//! BDD scenarios for pq-readiness M3: cross-version compatibility matrix
//! and the `AlgorithmPolicy::min_envelope_version` downgrade defence.
//!
//! Closes GH issue #9.
//!
//! Compatibility matrix (4 cells):
//!
//! | producer | consumer (pq feature)            | expected     |
//! |----------|----------------------------------|--------------|
//! | v1       | OFF (M1+M3, no `--features pq`)  | round-trip   |
//! | v1       | ON (M1+M3 + `--features pq`)     | round-trip   |
//! | v2       | OFF (M1+M3, no `--features pq`)  | PqFeatureRequired (no AEAD work) |
//! | v2       | ON (M1+M3 + `--features pq`)     | PqUnavailable (M2 fills the encrypt path) |
//!
//! Plus abuse cases:
//! - `tm-pqd-abuse-6`: downgrade — v1 envelope under a `min_envelope_version=2` policy → AlgorithmRejectedByPolicy.
//! - `tm-pqd-abuse-7`: version-byte tamper — fail at deserialise/validate_structure boundary.

use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{
    decrypt_for_use, decrypt_with_policy, encrypt_for_storage, EnvelopeEncrypted,
};
use secure_data::error::DataError;
use secure_data::kms::StaticDevKeyProvider;

// ── Cell 1: v1 producer × consumer-no-pq → round-trip ────────────────────────

#[tokio::test]
async fn cell_v1_producer_consumer_no_pq_round_trips() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"v1 producer, consumer without pq feature";

    let envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("v1 encrypt must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("v1 decrypt must succeed");

    assert_eq!(recovered, plaintext);
    assert_eq!(envelope.version, "1");
    assert_eq!(envelope.combiner_id, None);
}

// ── Cell 2: v1 producer × consumer-with-pq → round-trip ─────────────────────

// Note: identical to cell 1 in behaviour because the pq feature only
// affects the hybrid-encrypt path; classical envelopes remain
// algorithm-tagged and decrypt unchanged regardless of the build's
// feature flags. This test runs in both build modes (with and without
// `--features pq`) and proves the property.

#[tokio::test]
async fn cell_v1_producer_round_trips_regardless_of_pq_feature() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"v1 envelope is feature-flag-agnostic on the read side";

    let envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("v1 encrypt");

    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("v1 decrypt");
    assert_eq!(recovered, plaintext);
}

// ── Cell 3: v2 producer × consumer-no-pq → PqFeatureRequired ────────────────

#[tokio::test]
#[cfg(not(feature = "pq"))]
async fn cell_v2_producer_consumer_no_pq_returns_pq_feature_required() {
    // Hand-craft a v2 envelope (M2 will produce one for real; in M3 we
    // construct it to exercise the cross-version-failure path).
    let v2_json = serde_json::json!({
        "version": "2",
        "algorithm": "X25519+ML-KEM-768/HKDF-SHA-256",
        "key_alias": "default",
        "key_version": "1",
        "wrapped_data_key": vec![0u8; 32],
        "nonce": vec![0u8; 12],
        "ciphertext": vec![0u8; 16],
        "aad": vec![0u8; 16],
        "combiner_id": 1,
    });
    let envelope: EnvelopeEncrypted = serde_json::from_value(v2_json).unwrap();
    let provider = StaticDevKeyProvider::new();

    let result = decrypt_for_use(&envelope, &provider).await;
    match result {
        Err(DataError::PqFeatureRequired) => {}
        other => panic!(
            "expected PqFeatureRequired on v2-without-pq build, got: {:?}",
            other
        ),
    }
}

// ── Cell 4: v2 producer × consumer-with-pq → PqUnavailable (M2 fills) ───────

#[tokio::test]
#[cfg(feature = "pq")]
async fn cell_v2_producer_consumer_with_pq_returns_pq_unavailable_until_m2() {
    let v2_json = serde_json::json!({
        "version": "2",
        "algorithm": "X25519+ML-KEM-768/HKDF-SHA-256",
        "key_alias": "default",
        "key_version": "1",
        "wrapped_data_key": vec![0u8; 32],
        "nonce": vec![0u8; 12],
        "ciphertext": vec![0u8; 16],
        "aad": vec![0u8; 16],
        "combiner_id": 1,
    });
    let envelope: EnvelopeEncrypted = serde_json::from_value(v2_json).unwrap();
    let provider = StaticDevKeyProvider::new();

    let result = decrypt_for_use(&envelope, &provider).await;
    // M2 will route this to a real hybrid decrypt path. Until then,
    // M3 exercises the dispatch — `is_post_quantum()` short-circuits
    // to `PqUnavailable` before any AEAD work.
    match result {
        Err(DataError::PqUnavailable) => {}
        other => panic!(
            "expected PqUnavailable on v2-with-pq build (M3 — M2 fills the path), got: {:?}",
            other
        ),
    }
}

// ── Abuse case tm-pqd-abuse-6: downgrade attack ─────────────────────────────

#[tokio::test]
async fn tm_pqd_abuse_6_downgrade_attack_rejected_by_policy() {
    // Producer creates a v1 envelope.
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"protected by min_envelope_version=2 policy";
    let v1_envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt");
    assert_eq!(v1_envelope.version, "1");

    // Consumer enforces "v2 or above" via AlgorithmPolicy.
    let strict =
        AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768).with_min_envelope_version(2);

    // Attacker substitutes the v1 envelope where v2 is expected.
    let result = decrypt_with_policy(&v1_envelope, &provider, &strict).await;

    match result {
        Err(DataError::AlgorithmRejectedByPolicy { reason }) => {
            assert!(reason.contains("envelope_version"));
            assert!(reason.contains("min_envelope_version"));
        }
        other => panic!(
            "expected AlgorithmRejectedByPolicy on downgrade, got: {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn default_policy_accepts_v1_envelope() {
    // Sanity: without `min_envelope_version`, default-policy decrypt is
    // identical to `decrypt_for_use` and accepts v1 envelopes.
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"default policy is permissive";
    let envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt");

    let policy = AlgorithmPolicy::default();
    let recovered = decrypt_with_policy(&envelope, &provider, &policy)
        .await
        .expect("default policy must accept v1");
    assert_eq!(recovered, plaintext);
}

// ── Abuse case tm-pqd-abuse-7: version-byte tamper ──────────────────────────

#[tokio::test]
async fn tm_pqd_abuse_7_version_byte_tamper_fails_at_aead_authentication() {
    // Producer creates a valid v1 envelope.
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"version-byte tamper";
    let mut envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt");

    // Attacker tampers with the version field. The AAD is bound to the
    // envelope-version string at encrypt time; any change here will
    // cause AEAD authentication to fail at decrypt.
    envelope.version = "9".into();

    let result = decrypt_for_use(&envelope, &provider).await;

    // The actual error is AuthenticationFailure (the AEAD MAC fails)
    // because the AAD includes the original version string. Either way,
    // decrypt MUST fail — never silently produce the plaintext.
    match result {
        Err(DataError::AuthenticationFailure) => {}
        Err(DataError::AlgorithmRejectedByPolicy { .. }) => {}
        Err(DataError::EnvelopeMalformed { .. }) => {}
        other => panic!(
            "version-byte tamper must NOT silently decrypt; got: {:?}",
            other
        ),
    }
}

// ── min_envelope_version builder + accessor ─────────────────────────────────

#[test]
fn min_envelope_version_builder_and_accessor() {
    let policy = AlgorithmPolicy::default();
    assert_eq!(policy.min_envelope_version(), None);

    let strict =
        AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768).with_min_envelope_version(2);
    assert_eq!(strict.min_envelope_version(), Some(2));

    // Sanity: `validate_envelope_version` accepts envelopes ≥ min and
    // rejects envelopes < min.
    assert!(strict.validate_envelope_version("2").is_ok());
    assert!(strict.validate_envelope_version("3").is_ok());
    assert!(strict.validate_envelope_version("1").is_err());
}

#[test]
fn unparseable_envelope_version_under_min_policy_fails_closed() {
    let strict = AlgorithmPolicy::default().with_min_envelope_version(2);
    let result = strict.validate_envelope_version("not-a-number");
    match result {
        Err(DataError::AlgorithmRejectedByPolicy { reason }) => {
            assert!(reason.contains("cannot be parsed"));
        }
        other => panic!("expected AlgorithmRejectedByPolicy, got: {:?}", other),
    }
}

#[test]
fn no_min_policy_accepts_any_version_string() {
    // Backward compat: a default policy (no min) accepts even
    // unparseable version strings — it only validates if the policy
    // actively requires it.
    let permissive = AlgorithmPolicy::default();
    assert!(permissive.validate_envelope_version("1").is_ok());
    assert!(permissive.validate_envelope_version("not-a-number").is_ok());
}

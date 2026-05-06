//! BDD scenarios for pq-readiness M1: envelope wire-format versioning,
//! reserved CryptoAlgorithm slot, and the structural invariants the M2
//! hybrid KEM will rely on. See:
//!
//! - Runbook: `docs/slo/future/RUNBOOK-pq-readiness-secure-data.md` M1
//! - Migration plan: `docs/slo/design/pq-migration-plan.md`
//! - Closes GH issue #7.

use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage, EnvelopeEncrypted};
use secure_data::error::DataError;
use secure_data::kms::StaticDevKeyProvider;
use secure_data::pq;

// ── Happy path: M1 leaves classical encrypt+decrypt unchanged ────────────────

#[tokio::test]
async fn classical_envelope_round_trips_unchanged() {
    // Given: a default StaticDevKeyProvider and AES-256-GCM (the default)
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"pq-m1 round-trip should be byte-identical";

    // When: encrypt then decrypt
    let envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decrypt must succeed");

    // Then: classical envelope; combiner_id is None; round-trip is exact
    assert_eq!(recovered, plaintext);
    assert_eq!(envelope.algorithm, "AES-256-GCM");
    assert_eq!(
        envelope.combiner_id, None,
        "classical envelope must have combiner_id == None"
    );
}

#[tokio::test]
async fn xchacha_envelope_round_trips_unchanged() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"xchacha is also unchanged";
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);

    let envelope =
        secure_data::envelope::encrypt_with_policy(plaintext, "default", &provider, &policy)
            .await
            .expect("encrypt must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decrypt must succeed");

    assert_eq!(recovered, plaintext);
    assert_eq!(envelope.algorithm, "XChaCha20-Poly1305");
    assert_eq!(envelope.combiner_id, None);
}

// ── Backward compatibility: deserializing pre-M1 envelopes ───────────────────

#[test]
fn pre_m1_envelope_without_combiner_id_field_deserializes_with_none() {
    // Given: a JSON envelope shaped exactly as it would have been before
    // the combiner_id field was added (e.g., serialized by the previous
    // crate version and persisted in a database).
    let pre_m1_json = serde_json::json!({
        "version": "1",
        "algorithm": "AES-256-GCM",
        "key_alias": "default",
        "key_version": "1",
        "wrapped_data_key": [1, 2, 3, 4],
        "nonce": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5],
        "ciphertext": [9, 10, 11, 12],
        "aad": [13, 14, 15, 16],
    });

    // When: deserialize through serde
    let envelope: EnvelopeEncrypted = serde_json::from_value(pre_m1_json)
        .expect("pre-M1 envelopes must deserialize cleanly via serde default");

    // Then: combiner_id defaults to None (this is the backward-compat
    // contract — an old persisted envelope must not carry a sentinel
    // value that fools structural validation later).
    assert_eq!(envelope.combiner_id, None);
    assert_eq!(envelope.algorithm, "AES-256-GCM");
}

// ── Abuse case tm-pqd-abuse-1: PqUnavailable on hybrid request ──────────────

#[tokio::test]
async fn hybrid_kem_request_returns_pq_unavailable_in_m1() {
    // Given: a policy that prefers the new hybrid PQ algorithm
    let provider = StaticDevKeyProvider::new();
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768);

    // When: encrypt
    let result = secure_data::envelope::encrypt_with_policy(
        b"never reaches the wire",
        "default",
        &provider,
        &policy,
    )
    .await;

    // Then: PqUnavailable — never panics, never falls back to classical,
    // never silently produces a v1 envelope. Documents the M2-pending
    // state explicitly to consumers.
    match result {
        Err(DataError::PqUnavailable) => {}
        other => panic!(
            "expected DataError::PqUnavailable on hybrid request in M1, got: {:?}",
            other
        ),
    }
}

// ── Abuse case tm-pqd-abuse-2: malformed v1 envelope with combiner_id ───────

#[tokio::test]
async fn classical_envelope_with_non_zero_combiner_is_rejected() {
    // Given: a hand-crafted envelope with a non-zero combiner_id but a
    // classical algorithm — what an attacker might inject by tampering
    // with stored ciphertext metadata to confuse the decrypt path.
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"ignored -- we never reach decrypt";
    let mut envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt must succeed");
    envelope.combiner_id = Some(0x42);

    // When: validate_structure (called from decrypt_for_use pre-flight)
    let validate_result = envelope.validate_structure();
    assert!(
        validate_result.is_err(),
        "validate_structure must reject a classical envelope carrying combiner_id"
    );
    match validate_result {
        Err(DataError::EnvelopeMalformed { reason }) => {
            assert!(
                reason.contains("combiner_id"),
                "EnvelopeMalformed reason must name combiner_id"
            );
        }
        other => panic!("expected EnvelopeMalformed, got: {:?}", other),
    }

    // And: decrypt_for_use also fails — defense in depth, no AEAD work happens
    let decrypt_result = decrypt_for_use(&envelope, &provider).await;
    assert!(
        matches!(decrypt_result, Err(DataError::EnvelopeMalformed { .. })),
        "decrypt_for_use must reject the malformed envelope before any AEAD work"
    );
}

#[tokio::test]
async fn classical_envelope_with_zero_combiner_id_is_accepted() {
    // Given: a serialiser that emitted Some(0) instead of None for the
    // optional combiner_id (e.g., a permissive third-party serde codec)
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"zero combiner is the legacy default";
    let mut envelope = encrypt_for_storage(plaintext, "default", &provider)
        .await
        .expect("encrypt must succeed");
    envelope.combiner_id = Some(0);

    // When: validate_structure
    let validate_result = envelope.validate_structure();
    assert!(
        validate_result.is_ok(),
        "Some(0) is acceptable as a synonym for None per validate_structure"
    );

    // And: decrypt round-trip succeeds
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("decrypt must succeed for Some(0) combiner_id");
    assert_eq!(recovered, plaintext);
}

// ── pq::sizes module: M1 reserves wire-format dimensions ─────────────────────

#[test]
fn pq_sizes_module_is_publicly_available_without_pq_feature() {
    // The pq::sizes module must be compileable on a non-pq build so
    // downstream consumers can pin against the wire-format dimensions
    // even if they themselves haven't enabled the pq feature yet.
    assert_eq!(pq::sizes::ML_KEM_768_CIPHERTEXT_LEN, 1088);
    assert_eq!(pq::sizes::ML_KEM_768_PUBLIC_KEY_LEN, 1184);
    assert_eq!(pq::sizes::ML_KEM_768_SHARED_SECRET_LEN, 32);
    assert_eq!(pq::sizes::X25519_SHARE_LEN, 32);
    assert_eq!(pq::sizes::X25519_SHARED_SECRET_LEN, 32);
    assert_eq!(pq::sizes::HKDF_SHA256_OUTPUT_LEN, 32);
    assert_eq!(pq::sizes::AES_256_GCM_NONCE_LEN, 12);
}

#[test]
fn combiner_id_constants_match_migration_plan() {
    assert_eq!(pq::COMBINER_ID_X25519_ML_KEM_768, 0x01);
    assert_eq!(pq::COMBINER_ID_FAIL_CLOSED, 0xFF);
    assert!(pq::is_recognised_combiner(
        pq::COMBINER_ID_X25519_ML_KEM_768
    ));
    assert!(!pq::is_recognised_combiner(pq::COMBINER_ID_FAIL_CLOSED));
    assert!(!pq::is_recognised_combiner(0x42));
}

// ── CryptoAlgorithm::HybridX25519MlKem768 surface ────────────────────────────

#[test]
fn hybrid_algorithm_round_trips_via_envelope_string() {
    let alg = CryptoAlgorithm::HybridX25519MlKem768;
    assert_eq!(alg.as_str(), "X25519+ML-KEM-768/HKDF-SHA-256");
    assert!(alg.is_post_quantum());
    assert_eq!(alg.nonce_len(), 12, "hybrid uses AES-GCM 12-byte nonce");

    let parsed =
        CryptoAlgorithm::from_envelope_str("X25519+ML-KEM-768/HKDF-SHA-256").expect("must parse");
    assert_eq!(parsed, alg);
}

#[test]
fn classical_algorithms_are_not_post_quantum() {
    assert!(!CryptoAlgorithm::Aes256Gcm.is_post_quantum());
    assert!(!CryptoAlgorithm::XChaCha20Poly1305.is_post_quantum());
}

// ── New error variants are reachable and useful ─────────────────────────────

#[test]
fn new_data_error_variants_format_intelligibly() {
    let pq_unavailable = DataError::PqUnavailable;
    assert!(pq_unavailable.to_string().contains("post-quantum"));
    assert!(pq_unavailable.to_string().contains("pq"));

    let pq_required = DataError::PqFeatureRequired;
    assert!(pq_required.to_string().contains("pq"));

    let policy_reject = DataError::AlgorithmRejectedByPolicy {
        reason: "minimum version=2 required".to_string(),
    };
    assert!(policy_reject.to_string().contains("policy"));
    assert!(policy_reject.to_string().contains("version=2"));

    let malformed = DataError::EnvelopeMalformed {
        reason: "combiner_id present on classical envelope".to_string(),
    };
    assert!(malformed.to_string().contains("malformed"));
    assert!(malformed.to_string().contains("combiner_id"));
}

// ── Migration plan doc invariant ─────────────────────────────────────────────

#[test]
fn migration_plan_doc_exists_and_is_non_trivial() {
    // The migration plan is a load-bearing M1 deliverable. The doc must
    // exist, be non-trivial, and reference the locked-in ML-KEM crate
    // recommendation from the research synthesis.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root resolves")
        .join("docs/slo/design/pq-migration-plan.md");
    assert!(
        path.exists(),
        "migration plan must exist at docs/slo/design/pq-migration-plan.md"
    );
    let body = std::fs::read_to_string(&path).expect("readable");
    assert!(
        body.len() > 1500,
        "migration plan must be substantive (>1500 chars), got {} chars",
        body.len()
    );
    assert!(
        body.contains("ML-KEM-768"),
        "must reference ML-KEM-768 (the locked KEM choice)"
    );
    assert!(
        body.contains("HKDF-SHA-256") || body.contains("HKDF/SHA-256"),
        "must reference the HKDF-SHA-256 combiner choice"
    );
    assert!(
        body.contains("FIPS"),
        "must address FIPS-track posture (research called this out as monitor-only as of 2026-05)"
    );
    assert!(
        body.contains("84e6ae18") || body.contains("ml-kem"),
        "must cite the locked dep (`ml-kem` v0.3.0) or otherwise pin the source"
    );
}

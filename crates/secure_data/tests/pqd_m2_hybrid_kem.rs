//! BDD scenarios for pq-readiness M2: hybrid X25519 + ML-KEM-768
//! envelope key wrap behind `--features pq`.

#[cfg(feature = "pq")]
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
#[cfg(feature = "pq")]
use secure_data::envelope::encrypt_with_policy;
use secure_data::envelope::{decrypt_for_use, EnvelopeEncrypted};
use secure_data::error::DataError;
use secure_data::kms::StaticDevKeyProvider;

#[tokio::test]
#[cfg(feature = "pq")]
async fn v2_hybrid_envelope_round_trips_with_pq_feature() {
    let provider = StaticDevKeyProvider::new();
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768);
    let plaintext = b"pq m2 hybrid envelope round-trip";

    let envelope = encrypt_with_policy(plaintext, "default", &provider, &policy)
        .await
        .expect("hybrid encrypt must succeed");
    let recovered = decrypt_for_use(&envelope, &provider)
        .await
        .expect("hybrid decrypt must succeed");

    assert_eq!(recovered, plaintext);
    assert_eq!(envelope.version, "2");
    assert_eq!(envelope.algorithm, "X25519+ML-KEM-768/HKDF-SHA-256");
    assert_eq!(
        envelope.combiner_id,
        Some(secure_data::pq::COMBINER_ID_X25519_ML_KEM_768)
    );
    assert!(
        String::from_utf8_lossy(&envelope.aad).contains("combiner=0x01"),
        "hybrid AAD must bind combiner_id"
    );
    assert_eq!(
        envelope.wrapped_data_key.len(),
        secure_data::pq::sizes::ML_KEM_768_CIPHERTEXT_LEN
            + secure_data::pq::sizes::X25519_SHARE_LEN
            + 48,
        "wrapped_data_key is ML-KEM ct || X25519 share || AES-GCM-wrapped 32-byte DEK"
    );
}

#[tokio::test]
#[cfg(feature = "pq")]
async fn tm_pqd_abuse_3_tampered_ml_kem_ciphertext_fails_cleanly() {
    let provider = StaticDevKeyProvider::new();
    let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768);
    let mut envelope = encrypt_with_policy(b"tamper target", "default", &provider, &policy)
        .await
        .expect("hybrid encrypt");

    envelope.wrapped_data_key[0] ^= 0x80;
    let result = decrypt_for_use(&envelope, &provider).await;

    assert!(
        matches!(
            result,
            Err(DataError::AuthenticationFailure) | Err(DataError::EnvelopeMalformed { .. })
        ),
        "tampered ML-KEM ciphertext must not decrypt; got {result:?}"
    );
}

#[tokio::test]
async fn tm_pqd_abuse_4_fail_closed_combiner_is_rejected() {
    let envelope = EnvelopeEncrypted {
        version: "2".to_string(),
        algorithm: "X25519+ML-KEM-768/HKDF-SHA-256".to_string(),
        key_alias: "default".to_string(),
        key_version: "v1".to_string(),
        wrapped_data_key: vec![0; 32],
        nonce: vec![0; 12],
        ciphertext: vec![0; 16],
        aad: vec![0; 16],
        combiner_id: Some(secure_data::pq::COMBINER_ID_FAIL_CLOSED),
    };

    let result = envelope.validate_structure();
    #[cfg(feature = "pq")]
    assert!(
        matches!(result, Err(DataError::AlgorithmRejectedByPolicy { .. })),
        "0xff combiner must fail closed on pq builds; got {result:?}"
    );
    #[cfg(not(feature = "pq"))]
    assert!(
        matches!(result, Err(DataError::PqFeatureRequired)),
        "non-pq builds must require pq before inspecting the combiner; got {result:?}"
    );
}

#[tokio::test]
#[cfg(not(feature = "pq"))]
async fn tm_pqd_abuse_5_v2_envelope_without_pq_returns_feature_required() {
    let envelope = EnvelopeEncrypted {
        version: "2".to_string(),
        algorithm: "X25519+ML-KEM-768/HKDF-SHA-256".to_string(),
        key_alias: "default".to_string(),
        key_version: "v1".to_string(),
        wrapped_data_key: vec![0; 32],
        nonce: vec![0; 12],
        ciphertext: vec![0; 16],
        aad: vec![0; 16],
        combiner_id: Some(secure_data::pq::COMBINER_ID_X25519_ML_KEM_768),
    };
    let provider = StaticDevKeyProvider::new();

    let result = decrypt_for_use(&envelope, &provider).await;
    assert!(matches!(result, Err(DataError::PqFeatureRequired)));
}

#[test]
#[cfg(feature = "pq")]
fn hybrid_encapsulation_uses_fresh_x25519_share() {
    use ml_kem::{
        kem::{Kem, KeyExport},
        MlKem768,
    };
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let (_ml_kem_sk, ml_kem_pk) = MlKem768::generate_keypair();
    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let first =
        secure_data::pq::hybrid_encapsulate(ml_kem_pk.to_bytes().as_slice(), x25519_pk.as_bytes())
            .expect("first encapsulation");
    let second =
        secure_data::pq::hybrid_encapsulate(ml_kem_pk.to_bytes().as_slice(), x25519_pk.as_bytes())
            .expect("second encapsulation");

    assert_ne!(
        first.x25519_share, second.x25519_share,
        "X25519 share must be fresh per encapsulation"
    );
    assert_ne!([0u8; 32], first.derived_key);
    assert_ne!([0u8; 32], second.derived_key);
}

#[test]
#[cfg(feature = "pq")]
fn ml_kem_768_acvp_kat_decapsulates_through_hybrid_combiner() {
    let fixture = parse_kat(include_str!("fixtures/ml_kem_768_kat.bin"));
    let derived = secure_data::pq::hybrid_decapsulate(
        &fixture.ml_kem_ciphertext,
        &fixture.x25519_sender_share,
        &fixture.ml_kem_expanded_sk,
        &fixture.x25519_recipient_sk,
    )
    .expect("NIST ACVP KAT decapsulation must succeed");

    let expected =
        expected_hybrid_key(&fixture.ml_kem_shared_secret, &fixture.x25519_shared_secret);
    assert_eq!(derived, expected);
}

#[cfg(feature = "pq")]
struct KatFixture {
    ml_kem_expanded_sk: Vec<u8>,
    ml_kem_ciphertext: Vec<u8>,
    ml_kem_shared_secret: Vec<u8>,
    x25519_recipient_sk: Vec<u8>,
    x25519_sender_share: Vec<u8>,
    x25519_shared_secret: Vec<u8>,
}

#[cfg(feature = "pq")]
fn parse_kat(input: &str) -> KatFixture {
    fn field(input: &str, name: &str) -> Vec<u8> {
        let value = input
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value.trim()))
            .unwrap_or_else(|| panic!("missing KAT field {name}"));
        decode_hex(value)
    }

    KatFixture {
        ml_kem_expanded_sk: field(input, "ml_kem_expanded_sk"),
        ml_kem_ciphertext: field(input, "ml_kem_ciphertext"),
        ml_kem_shared_secret: field(input, "ml_kem_shared_secret"),
        x25519_recipient_sk: field(input, "x25519_recipient_sk"),
        x25519_sender_share: field(input, "x25519_sender_share"),
        x25519_shared_secret: field(input, "x25519_shared_secret"),
    }
}

#[cfg(feature = "pq")]
fn expected_hybrid_key(ml_kem_shared: &[u8], x25519_shared: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ml_kem_shared);
    ikm[32..].copy_from_slice(x25519_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hk.expand(secure_data::pq::combiner::HYBRID_KDF_INFO, &mut output)
        .expect("32-byte HKDF expand is within SHA-256 output limit");
    output
}

#[cfg(feature = "pq")]
fn decode_hex(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    assert_eq!(bytes.len() % 2, 0, "hex input must have even length");
    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0]);
            let low = hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

#[cfg(feature = "pq")]
fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        other => panic!("invalid hex byte: {other}"),
    }
}

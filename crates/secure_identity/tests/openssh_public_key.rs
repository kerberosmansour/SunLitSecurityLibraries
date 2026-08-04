use base64::Engine as _;
use proptest::prelude::*;
use secure_identity::{
    validate_openssh_public_key, validate_openssh_public_key_with_rsa_minimum_bits,
    OpenSshPublicKeyError, MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES,
    MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES, OPENSSH_RSA_MAX_MODULUS_BITS,
    OPENSSH_RSA_MIN_MODULUS_BITS,
};
use serde::Deserialize;

const SSH_ED25519: &str = "ssh-ed25519";
const SSH_RSA: &str = "ssh-rsa";
const SSH_ECDSA_NISTP256: &str = "ecdsa-sha2-nistp256";
const SSH_ECDSA_NISTP384: &str = "ecdsa-sha2-nistp384";
const SSH_ECDSA_NISTP521: &str = "ecdsa-sha2-nistp521";

#[derive(Debug, Deserialize)]
struct SshKeygenFixture {
    algorithm: String,
    payload: String,
    source: String,
}

fn fixtures() -> Vec<SshKeygenFixture> {
    serde_json::from_str(include_str!("fixtures/openssh_public_keys.json"))
        .expect("OpenSSH fixture corpus must be valid JSON")
}

fn fixture(algorithm: &str) -> SshKeygenFixture {
    fixtures()
        .into_iter()
        .find(|fixture| fixture.algorithm == algorithm)
        .expect("requested fixture must exist")
}

fn encode_ssh_fields(fields: &[&[u8]]) -> String {
    let mut blob = Vec::new();
    for field in fields {
        blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
        blob.extend_from_slice(field);
    }
    base64::engine::general_purpose::STANDARD.encode(blob)
}

fn decode_ssh_fields(payload: &str) -> Vec<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .expect("fixture payload must be valid Base64");
    let mut fields = Vec::new();
    let mut remaining = decoded.as_slice();
    while !remaining.is_empty() {
        let length = u32::from_be_bytes(
            remaining[..4]
                .try_into()
                .expect("fixture field must have a length prefix"),
        ) as usize;
        remaining = &remaining[4..];
        fields.push(remaining[..length].to_vec());
        remaining = &remaining[length..];
    }
    fields
}

#[test]
fn accepts_genuine_ssh_keygen_public_keys() {
    for fixture in fixtures() {
        assert!(
            validate_openssh_public_key(&fixture.algorithm, &fixture.payload).is_ok(),
            "{} output for {} must validate",
            fixture.source,
            fixture.algorithm
        );
    }

    let rsa = fixture(SSH_RSA);
    let fields = decode_ssh_fields(&rsa.payload);
    assert_eq!(rsa::BigUint::from_bytes_be(&fields[2]).bits(), 1_024);
}

#[test]
fn rejects_malformed_and_oversized_payloads() {
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, "not-base64!"),
        Err(OpenSshPublicKeyError::MalformedPayload)
    );
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, ""),
        Err(OpenSshPublicKeyError::MalformedPayload)
    );
    assert_eq!(
        validate_openssh_public_key(
            SSH_ED25519,
            &"A".repeat(MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES + 1),
        ),
        Err(OpenSshPublicKeyError::PayloadTooLarge)
    );

    let exact_limit = base64::engine::general_purpose::STANDARD
        .encode(vec![0_u8; MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES]);
    assert_eq!(exact_limit.len(), MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES);
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, &exact_limit),
        Err(OpenSshPublicKeyError::AlgorithmMismatch),
        "an exactly 16 KiB decode must reach borrowed-field validation"
    );

    let above_limit = base64::engine::general_purpose::STANDARD.encode(vec![
        0_u8;
        MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES
            + 1
    ]);
    assert_eq!(above_limit.len(), MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES);
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, &above_limit),
        Err(OpenSshPublicKeyError::PayloadTooLarge)
    );

    let noncanonical = fixture(SSH_ECDSA_NISTP256).payload;
    assert!(noncanonical.ends_with('='));
    assert_eq!(
        validate_openssh_public_key(SSH_ECDSA_NISTP256, noncanonical.trim_end_matches('=')),
        Err(OpenSshPublicKeyError::MalformedPayload)
    );
}

#[test]
fn rejects_outer_and_embedded_algorithm_confusion() {
    let ed25519 = fixture(SSH_ED25519);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &ed25519.payload),
        Err(OpenSshPublicKeyError::AlgorithmMismatch)
    );
    assert_eq!(
        validate_openssh_public_key("rsa-sha2-256", &ed25519.payload),
        Err(OpenSshPublicKeyError::UnsupportedAlgorithm)
    );

    let rsa = fixture(SSH_RSA);
    let rsa_fields = decode_ssh_fields(&rsa.payload);
    for signature_algorithm in ["rsa-sha2-256", "rsa-sha2-512"] {
        let signature_labeled_blob = encode_ssh_fields(&[
            signature_algorithm.as_bytes(),
            &rsa_fields[1],
            &rsa_fields[2],
        ]);
        assert_eq!(
            validate_openssh_public_key(SSH_RSA, &signature_labeled_blob),
            Err(OpenSshPublicKeyError::AlgorithmMismatch),
            "an embedded signature algorithm must not alias ssh-rsa"
        );
        assert_eq!(
            validate_openssh_public_key(signature_algorithm, &rsa.payload),
            Err(OpenSshPublicKeyError::UnsupportedAlgorithm),
            "an outer signature algorithm must not alias ssh-rsa"
        );

        let label_only_blob = encode_ssh_fields(&[signature_algorithm.as_bytes()]);
        assert_eq!(
            validate_openssh_public_key(SSH_RSA, &label_only_blob),
            Err(OpenSshPublicKeyError::AlgorithmMismatch),
            "raw embedded labels must be rejected before later fields are interpreted"
        );
    }

    assert_eq!(
        validate_openssh_public_key("ssh-rsa\0", &rsa.payload),
        Err(OpenSshPublicKeyError::UnsupportedAlgorithm)
    );
}

#[test]
fn rejects_impossible_field_lengths_without_allocating_from_them() {
    let payload = base64::engine::general_purpose::STANDARD.encode(u32::MAX.to_be_bytes());
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, &payload),
        Err(OpenSshPublicKeyError::MalformedPayload)
    );
}

#[test]
fn rejects_trailing_wire_data() {
    let fixture = fixture(SSH_ED25519);
    let mut blob = base64::engine::general_purpose::STANDARD
        .decode(fixture.payload)
        .expect("fixture payload must decode");
    blob.extend_from_slice(&[0, 0, 0, 0]);
    let payload = base64::engine::general_purpose::STANDARD.encode(blob);
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, &payload),
        Err(OpenSshPublicKeyError::MalformedPayload)
    );
}

#[test]
fn rejects_undersized_and_invalid_rsa_parameters() {
    // Historical 1,017-bit shape fixture from the downstream regression.
    let undersized = "AAAAB3NzaC1yc2EAAAADAQABAAAAgAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+A";
    let fields = decode_ssh_fields(undersized);
    assert_eq!(rsa::BigUint::from_bytes_be(&fields[2]).bits(), 1_017);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, undersized),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    let exponent = [0x01, 0x00, 0x01];
    let mut even_modulus = vec![0; 129];
    even_modulus[1] = 0x80;
    let even_modulus_payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), &exponent, &even_modulus]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &even_modulus_payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    let mut modulus = vec![0; 129];
    modulus[1] = 0x80;
    modulus[128] = 1;
    let even_exponent = [2];
    let even_exponent_payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), &even_exponent, &modulus]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &even_exponent_payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    for invalid_exponent in [&[][..], &[1][..]] {
        let payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), invalid_exponent, &modulus]);
        assert_eq!(
            validate_openssh_public_key(SSH_RSA, &payload),
            Err(OpenSshPublicKeyError::InvalidKeyParameters)
        );
    }
}

#[test]
fn rejects_noncanonical_positive_rsa_mpints() {
    let rsa = fixture(SSH_RSA);
    let fields = decode_ssh_fields(&rsa.payload);
    assert_eq!(
        fields[2].first(),
        Some(&0),
        "fixture modulus needs a sign byte"
    );
    assert_eq!(fields[2].get(1).map(|byte| byte & 0x80), Some(0x80));

    let mut redundant_modulus = vec![0];
    redundant_modulus.extend_from_slice(&fields[2]);
    let redundant_modulus_payload =
        encode_ssh_fields(&[SSH_RSA.as_bytes(), &fields[1], &redundant_modulus]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &redundant_modulus_payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    let negative_modulus_payload =
        encode_ssh_fields(&[SSH_RSA.as_bytes(), &fields[1], &fields[2][1..]]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &negative_modulus_payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    for invalid_exponent in [&[0][..], &[0, 1, 0, 1][..], &[0x80][..]] {
        let payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), invalid_exponent, &fields[2]]);
        assert_eq!(
            validate_openssh_public_key(SSH_RSA, &payload),
            Err(OpenSshPublicKeyError::InvalidKeyParameters)
        );
    }
}

#[test]
fn explicit_rsa_minimum_policy_is_enforced_in_the_validation_call() {
    let rsa_1024 = fixture(SSH_RSA);
    assert_eq!(
        validate_openssh_public_key_with_rsa_minimum_bits(
            SSH_RSA,
            &rsa_1024.payload,
            OPENSSH_RSA_MIN_MODULUS_BITS,
        ),
        Ok(())
    );
    assert_eq!(
        validate_openssh_public_key_with_rsa_minimum_bits(SSH_RSA, &rsa_1024.payload, 2_048),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    let exponent = [0x01, 0x00, 0x01];
    let mut modulus_2048 = vec![0; 257];
    modulus_2048[1] = 0x80;
    *modulus_2048.last_mut().expect("modulus is non-empty") = 1;
    let rsa_2048 = encode_ssh_fields(&[SSH_RSA.as_bytes(), &exponent, &modulus_2048]);
    assert_eq!(
        validate_openssh_public_key_with_rsa_minimum_bits(SSH_RSA, &rsa_2048, 2_048),
        Ok(())
    );
    assert_eq!(
        validate_openssh_public_key_with_rsa_minimum_bits(SSH_RSA, &rsa_2048, 2_049),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );

    for invalid_minimum in [
        OPENSSH_RSA_MIN_MODULUS_BITS - 1,
        OPENSSH_RSA_MAX_MODULUS_BITS + 1,
    ] {
        assert_eq!(
            validate_openssh_public_key_with_rsa_minimum_bits(
                SSH_ED25519,
                &fixture(SSH_ED25519).payload,
                invalid_minimum,
            ),
            Err(OpenSshPublicKeyError::InvalidPolicy),
            "invalid policy must fail even before an RSA key is observed"
        );
    }
}

#[test]
fn enforces_rsa_modulus_maximum_at_exact_bit_precision() {
    let exponent = [0x01, 0x00, 0x01];

    let mut maximum_modulus = vec![0; OPENSSH_RSA_MAX_MODULUS_BITS / 8 + 1];
    maximum_modulus[1] = 0x80;
    *maximum_modulus.last_mut().expect("modulus is non-empty") = 1;
    assert_eq!(
        rsa::BigUint::from_bytes_be(&maximum_modulus).bits(),
        OPENSSH_RSA_MAX_MODULUS_BITS
    );
    let maximum_payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), &exponent, &maximum_modulus]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &maximum_payload),
        Ok(())
    );

    let mut modulus = vec![0; OPENSSH_RSA_MAX_MODULUS_BITS / 8 + 1];
    modulus[0] = 1;
    *modulus.last_mut().expect("modulus is non-empty") = 1;
    assert_eq!(
        rsa::BigUint::from_bytes_be(&modulus).bits(),
        OPENSSH_RSA_MAX_MODULUS_BITS + 1
    );
    let payload = encode_ssh_fields(&[SSH_RSA.as_bytes(), &exponent, &modulus]);
    assert_eq!(
        validate_openssh_public_key(SSH_RSA, &payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );
}

#[test]
fn rejects_off_curve_and_compressed_nist_points() {
    for (algorithm, curve_name, uncompressed_len, coordinate_len) in [
        (SSH_ECDSA_NISTP256, b"nistp256".as_slice(), 65, 32),
        (SSH_ECDSA_NISTP384, b"nistp384".as_slice(), 97, 48),
        (SSH_ECDSA_NISTP521, b"nistp521".as_slice(), 133, 66),
    ] {
        let mut off_curve = vec![0; uncompressed_len];
        off_curve[0] = 0x04;
        let payload = encode_ssh_fields(&[algorithm.as_bytes(), curve_name, &off_curve]);
        assert_eq!(
            validate_openssh_public_key(algorithm, &payload),
            Err(OpenSshPublicKeyError::InvalidKeyParameters)
        );

        let fixture = fixture(algorithm);
        let fields = decode_ssh_fields(&fixture.payload);
        let point = &fields[2];
        let mut compressed = Vec::with_capacity(coordinate_len + 1);
        compressed.push(0x02 | (point[uncompressed_len - 1] & 1));
        compressed.extend_from_slice(&point[1..=coordinate_len]);
        let payload = encode_ssh_fields(&[&fields[0], &fields[1], &compressed]);
        assert_eq!(
            validate_openssh_public_key(algorithm, &payload),
            Err(OpenSshPublicKeyError::InvalidKeyParameters)
        );
    }
}

#[test]
fn rejects_ecdsa_curve_identifier_confusion() {
    let fixture = fixture(SSH_ECDSA_NISTP256);
    let fields = decode_ssh_fields(&fixture.payload);
    let payload = encode_ssh_fields(&[&fields[0], b"nistp384", &fields[2]]);
    assert_eq!(
        validate_openssh_public_key(SSH_ECDSA_NISTP256, &payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );
}

#[test]
fn rejects_weak_ed25519_points() {
    let weak_key = [0u8; 32];
    let payload = encode_ssh_fields(&[SSH_ED25519.as_bytes(), &weak_key]);
    assert_eq!(
        validate_openssh_public_key(SSH_ED25519, &payload),
        Err(OpenSshPublicKeyError::InvalidKeyParameters)
    );
}

#[test]
fn diagnostics_never_echo_caller_input() {
    let marker = "owner-comment@do-not-log.invalid!";
    let error = validate_openssh_public_key(SSH_ED25519, marker)
        .expect_err("marker is not a public-key payload");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(marker));

    let weak_key = [0u8; 32];
    let payload = encode_ssh_fields(&[SSH_ED25519.as_bytes(), &weak_key]);
    let error = validate_openssh_public_key(SSH_ED25519, &payload)
        .expect_err("weak public key must be rejected");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(&payload));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_trailing_data_always_fails_closed(
        trailing in proptest::collection::vec(any::<u8>(), 1..256)
    ) {
        let fixture = fixture(SSH_ED25519);
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(fixture.payload)
            .expect("fixture payload must decode");
        blob.extend_from_slice(&trailing);
        let payload = base64::engine::general_purpose::STANDARD.encode(blob);
        prop_assert_eq!(
            validate_openssh_public_key(SSH_ED25519, &payload),
            Err(OpenSshPublicKeyError::MalformedPayload)
        );
    }

    #[test]
    fn arbitrary_non_base64_input_never_panics_or_validates(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let payload = format!("!{}", base64::engine::general_purpose::STANDARD.encode(bytes));
        prop_assert_eq!(
            validate_openssh_public_key(SSH_ED25519, &payload),
            Err(OpenSshPublicKeyError::MalformedPayload)
        );
    }
}

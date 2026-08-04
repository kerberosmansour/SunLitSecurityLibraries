//! Bounded, fail-closed validation for OpenSSH public-key blobs.
//!
//! This module validates the algorithm and Base64 fields from an OpenSSH
//! public-key line. It deliberately does not accept or return a comment, and
//! it does not retain, log, fingerprint, or otherwise expose decoded key
//! material. Consumers should use a successful result only as evidence that
//! the two supplied fields form one supported public key.

use base64::{DecodeSliceError, Engine as _};
use std::{error::Error, fmt};

/// Maximum decoded OpenSSH public-key blob size.
///
/// Decoding uses one fixed-capacity stack buffer of exactly this size. SSH
/// fields borrow from that buffer, so caller-controlled field lengths cannot
/// trigger parser allocations.
pub const MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES: usize = 16 * 1024;

/// Maximum canonical Base64 field length that can encode
/// [`MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES`].
pub const MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES: usize =
    MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES.div_ceil(3) * 4;

/// Minimum RSA modulus size accepted by the compatibility validator.
///
/// Use [`validate_openssh_public_key_with_rsa_minimum_bits`] when deployment
/// policy requires a stronger minimum.
pub const OPENSSH_RSA_MIN_MODULUS_BITS: usize = 1_024;

/// Maximum RSA modulus size accepted by the validator.
pub const OPENSSH_RSA_MAX_MODULUS_BITS: usize = 16_384;

const SSH_ED25519: &str = "ssh-ed25519";
const SSH_RSA: &str = "ssh-rsa";
const SSH_ECDSA_NISTP256: &str = "ecdsa-sha2-nistp256";
const SSH_ECDSA_NISTP384: &str = "ecdsa-sha2-nistp384";
const SSH_ECDSA_NISTP521: &str = "ecdsa-sha2-nistp521";

/// A redaction-safe OpenSSH public-key validation error.
///
/// Variants contain no caller-provided algorithm, payload, key, fingerprint,
/// or comment data, so both [`Debug`](fmt::Debug) and [`Display`](fmt::Display)
/// are safe to surface in ordinary diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OpenSshPublicKeyError {
    /// The caller supplied an algorithm outside the supported closed set.
    UnsupportedAlgorithm,
    /// The Base64 field could decode beyond
    /// [`MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES`].
    PayloadTooLarge,
    /// The Base64 or SSH wire encoding was malformed or contained trailing data.
    MalformedPayload,
    /// The caller-supplied algorithm did not exactly match the raw algorithm
    /// bytes in the key blob.
    AlgorithmMismatch,
    /// The public-key parameters failed cryptographic validation or policy bounds.
    InvalidKeyParameters,
    /// The requested RSA minimum was outside the supported compatibility range.
    InvalidPolicy,
}

impl fmt::Display for OpenSshPublicKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedAlgorithm => "unsupported OpenSSH public-key algorithm",
            Self::PayloadTooLarge => "OpenSSH public-key payload exceeds the size limit",
            Self::MalformedPayload => "malformed OpenSSH public-key payload",
            Self::AlgorithmMismatch => "OpenSSH public-key algorithm mismatch",
            Self::InvalidKeyParameters => "invalid OpenSSH public-key parameters",
            Self::InvalidPolicy => "invalid OpenSSH public-key validation policy",
        };
        formatter.write_str(message)
    }
}

impl Error for OpenSshPublicKeyError {}

/// Validate one OpenSSH public-key algorithm and Base64 payload field.
///
/// The supported closed set is `ssh-ed25519`, `ssh-rsa`, and the NIST P-256,
/// P-384, and P-521 ECDSA algorithms used by OpenSSH. Validation requires:
///
/// - canonical Base64 and SSH wire encoding with no trailing data;
/// - exact byte-for-byte caller-supplied and embedded algorithm agreement;
/// - a decompressible, non-weak Ed25519 public point;
/// - canonical positive RSA `mpint` fields, a 1,024–16,384-bit modulus, and
///   RSA public parameters accepted by the audited `rsa` implementation; and
/// - an uncompressed NIST point that is a member of the selected curve.
///
/// This compatibility entry point accepts RSA keys at OpenSSH's 1,024-bit
/// floor. Call [`validate_openssh_public_key_with_rsa_minimum_bits`] to enforce
/// a stronger deployment minimum during the same validation operation.
///
/// The decoded key exists only for the duration of this call and is not
/// returned or logged. Public-key comments are intentionally outside this API.
pub fn validate_openssh_public_key(
    algorithm: &str,
    payload: &str,
) -> Result<(), OpenSshPublicKeyError> {
    validate_openssh_public_key_with_rsa_minimum_bits(
        algorithm,
        payload,
        OPENSSH_RSA_MIN_MODULUS_BITS,
    )
}

/// Validate an OpenSSH public key while enforcing an explicit RSA minimum.
///
/// `rsa_minimum_modulus_bits` must be in the inclusive range
/// [`OPENSSH_RSA_MIN_MODULUS_BITS`] through
/// [`OPENSSH_RSA_MAX_MODULUS_BITS`]. The policy is checked for every algorithm
/// so a configuration error cannot remain latent until an RSA key is observed.
pub fn validate_openssh_public_key_with_rsa_minimum_bits(
    algorithm: &str,
    payload: &str,
    rsa_minimum_modulus_bits: usize,
) -> Result<(), OpenSshPublicKeyError> {
    if !(OPENSSH_RSA_MIN_MODULUS_BITS..=OPENSSH_RSA_MAX_MODULUS_BITS)
        .contains(&rsa_minimum_modulus_bits)
    {
        return Err(OpenSshPublicKeyError::InvalidPolicy);
    }

    let algorithm = SupportedAlgorithm::from_outer_label(algorithm)?;

    if payload.len() > MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES {
        return Err(OpenSshPublicKeyError::PayloadTooLarge);
    }

    let mut decoded = [0_u8; MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES];
    let decoded_len =
        match base64::engine::general_purpose::STANDARD.decode_slice(payload, &mut decoded) {
            Ok(decoded_len) => decoded_len,
            Err(DecodeSliceError::OutputSliceTooSmall) => {
                return Err(OpenSshPublicKeyError::PayloadTooLarge);
            }
            Err(DecodeSliceError::DecodeError(_)) => {
                return Err(OpenSshPublicKeyError::MalformedPayload);
            }
        };

    validate_decoded_key(algorithm, &decoded[..decoded_len], rsa_minimum_modulus_bits)
}

#[derive(Clone, Copy)]
enum SupportedAlgorithm {
    Ed25519,
    Rsa,
    EcdsaNistP256,
    EcdsaNistP384,
    EcdsaNistP521,
}

impl SupportedAlgorithm {
    fn from_outer_label(algorithm: &str) -> Result<Self, OpenSshPublicKeyError> {
        match algorithm {
            SSH_ED25519 => Ok(Self::Ed25519),
            SSH_RSA => Ok(Self::Rsa),
            SSH_ECDSA_NISTP256 => Ok(Self::EcdsaNistP256),
            SSH_ECDSA_NISTP384 => Ok(Self::EcdsaNistP384),
            SSH_ECDSA_NISTP521 => Ok(Self::EcdsaNistP521),
            _ => Err(OpenSshPublicKeyError::UnsupportedAlgorithm),
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => SSH_ED25519.as_bytes(),
            Self::Rsa => SSH_RSA.as_bytes(),
            Self::EcdsaNistP256 => SSH_ECDSA_NISTP256.as_bytes(),
            Self::EcdsaNistP384 => SSH_ECDSA_NISTP384.as_bytes(),
            Self::EcdsaNistP521 => SSH_ECDSA_NISTP521.as_bytes(),
        }
    }
}

fn validate_decoded_key(
    algorithm: SupportedAlgorithm,
    decoded: &[u8],
    rsa_minimum_modulus_bits: usize,
) -> Result<(), OpenSshPublicKeyError> {
    let mut fields = SshFields::new(decoded);
    let embedded_algorithm = fields.next()?;

    // Deliberately compare the raw borrowed field before interpreting or
    // normalizing it. Signature algorithm names such as rsa-sha2-256 and
    // rsa-sha2-512 are not public-key format aliases for ssh-rsa.
    if embedded_algorithm != algorithm.label() {
        return Err(OpenSshPublicKeyError::AlgorithmMismatch);
    }

    match algorithm {
        SupportedAlgorithm::Ed25519 => validate_ed25519(fields),
        SupportedAlgorithm::Rsa => validate_rsa(fields, rsa_minimum_modulus_bits),
        SupportedAlgorithm::EcdsaNistP256
        | SupportedAlgorithm::EcdsaNistP384
        | SupportedAlgorithm::EcdsaNistP521 => validate_ecdsa(algorithm, fields),
    }
}

fn validate_ed25519(mut fields: SshFields<'_>) -> Result<(), OpenSshPublicKeyError> {
    let key: &[u8; 32] = fields
        .next()?
        .try_into()
        .map_err(|_| OpenSshPublicKeyError::InvalidKeyParameters)?;
    fields.finish()?;

    let key = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| OpenSshPublicKeyError::InvalidKeyParameters)?;
    if key.is_weak() {
        return Err(OpenSshPublicKeyError::InvalidKeyParameters);
    }
    Ok(())
}

fn validate_rsa(
    mut fields: SshFields<'_>,
    rsa_minimum_modulus_bits: usize,
) -> Result<(), OpenSshPublicKeyError> {
    let exponent =
        positive_mpint(fields.next()?).ok_or(OpenSshPublicKeyError::InvalidKeyParameters)?;
    let modulus =
        positive_mpint(fields.next()?).ok_or(OpenSshPublicKeyError::InvalidKeyParameters)?;
    fields.finish()?;

    let modulus_bits =
        unsigned_bit_length(modulus).ok_or(OpenSshPublicKeyError::InvalidKeyParameters)?;
    if !(rsa_minimum_modulus_bits..=OPENSSH_RSA_MAX_MODULUS_BITS).contains(&modulus_bits) {
        return Err(OpenSshPublicKeyError::InvalidKeyParameters);
    }

    let exponent = rsa::BigUint::from_bytes_be(exponent);
    let modulus = rsa::BigUint::from_bytes_be(modulus);
    rsa::RsaPublicKey::new_with_max_size(modulus, exponent, OPENSSH_RSA_MAX_MODULUS_BITS)
        .map(|_| ())
        .map_err(|_| OpenSshPublicKeyError::InvalidKeyParameters)
}

fn validate_ecdsa(
    algorithm: SupportedAlgorithm,
    mut fields: SshFields<'_>,
) -> Result<(), OpenSshPublicKeyError> {
    let expected_curve = match algorithm {
        SupportedAlgorithm::EcdsaNistP256 => b"nistp256".as_slice(),
        SupportedAlgorithm::EcdsaNistP384 => b"nistp384".as_slice(),
        SupportedAlgorithm::EcdsaNistP521 => b"nistp521".as_slice(),
        SupportedAlgorithm::Ed25519 | SupportedAlgorithm::Rsa => {
            return Err(OpenSshPublicKeyError::InvalidKeyParameters);
        }
    };
    let curve = fields.next()?;
    let point = fields.next()?;
    fields.finish()?;

    if curve != expected_curve {
        return Err(OpenSshPublicKeyError::InvalidKeyParameters);
    }

    let valid = match algorithm {
        SupportedAlgorithm::EcdsaNistP256 => {
            is_uncompressed_point(point, 65) && p256::PublicKey::from_sec1_bytes(point).is_ok()
        }
        SupportedAlgorithm::EcdsaNistP384 => {
            is_uncompressed_point(point, 97) && p384::PublicKey::from_sec1_bytes(point).is_ok()
        }
        SupportedAlgorithm::EcdsaNistP521 => {
            is_uncompressed_point(point, 133) && p521::PublicKey::from_sec1_bytes(point).is_ok()
        }
        SupportedAlgorithm::Ed25519 | SupportedAlgorithm::Rsa => false,
    };

    valid
        .then_some(())
        .ok_or(OpenSshPublicKeyError::InvalidKeyParameters)
}

/// Accept only RFC 4251 canonical, non-zero, positive `mpint` values and
/// return their unsigned magnitude without the sign-preserving zero byte.
fn positive_mpint(encoded: &[u8]) -> Option<&[u8]> {
    let first = *encoded.first()?;
    if first == 0 {
        let magnitude = encoded.get(1..)?;
        if magnitude.is_empty() || magnitude[0] & 0x80 == 0 {
            return None;
        }
        Some(magnitude)
    } else if first & 0x80 != 0 {
        None
    } else {
        Some(encoded)
    }
}

fn unsigned_bit_length(value: &[u8]) -> Option<usize> {
    let first = *value.first()?;
    let high_bits = usize::try_from(u8::BITS - first.leading_zeros()).ok()?;
    value
        .len()
        .checked_sub(1)?
        .checked_mul(8)?
        .checked_add(high_bits)
}

fn is_uncompressed_point(point: &[u8], expected_len: usize) -> bool {
    point.len() == expected_len && point.first() == Some(&0x04)
}

/// A zero-allocation RFC 4251 `string` reader over the bounded decode buffer.
struct SshFields<'a> {
    remaining: &'a [u8],
}

impl<'a> SshFields<'a> {
    const fn new(decoded: &'a [u8]) -> Self {
        Self { remaining: decoded }
    }

    fn next(&mut self) -> Result<&'a [u8], OpenSshPublicKeyError> {
        let length_bytes: [u8; 4] = self
            .remaining
            .get(..4)
            .ok_or(OpenSshPublicKeyError::MalformedPayload)?
            .try_into()
            .map_err(|_| OpenSshPublicKeyError::MalformedPayload)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| OpenSshPublicKeyError::MalformedPayload)?;
        let after_length = self
            .remaining
            .get(4..)
            .ok_or(OpenSshPublicKeyError::MalformedPayload)?;
        let field = after_length
            .get(..length)
            .ok_or(OpenSshPublicKeyError::MalformedPayload)?;
        self.remaining = after_length
            .get(length..)
            .ok_or(OpenSshPublicKeyError::MalformedPayload)?;
        Ok(field)
    }

    fn finish(self) -> Result<(), OpenSshPublicKeyError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(OpenSshPublicKeyError::MalformedPayload)
        }
    }
}

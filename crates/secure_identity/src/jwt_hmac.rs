//! Reduced HMAC-only JWT provider, selected when asymmetric JWT features are off.
//!
//! Call [`install_default_provider`] before direct consumer JWT encoding. The
//! TokenValidator calls it before decoding. A foreign registration fails closed;
//! no provider compatibility is guessed and no failed install is ignored.
//! Key material is held by ring; internal SDK copies are not guaranteed wiped.

use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::signature::{Error as SignatureError, Signer, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey};
use ring::{digest, hmac};
use std::sync::OnceLock;

use crate::error::IdentityError;

/// Maximum complete token size accepted by the reduced TokenValidator.
pub const MAX_JWT_BYTES: usize = 64 * 1024;
const MAX_KEY_BYTES: usize = 1024;

#[derive(Clone, Copy)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum HmacKind {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacKind {
    fn from_algorithm(algorithm: Algorithm) -> JwtResult<Self> {
        match algorithm {
            Algorithm::HS256 => Ok(Self::Sha256),
            Algorithm::HS384 => Ok(Self::Sha384),
            Algorithm::HS512 => Ok(Self::Sha512),
            _ => Err(ErrorKind::InvalidAlgorithm.into()),
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::Sha256 => Algorithm::HS256,
            Self::Sha384 => Algorithm::HS384,
            Self::Sha512 => Algorithm::HS512,
        }
    }
    fn bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
    fn encoded_signature_bytes(self) -> usize {
        match self {
            Self::Sha256 => 43,
            Self::Sha384 => 64,
            Self::Sha512 => 86,
        }
    }
    fn ring_algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
    fn key_fits(self, length: usize) -> bool {
        length >= self.bytes() && length <= MAX_KEY_BYTES
    }
    fn message_fits(self, length: usize) -> bool {
        length
            .checked_add(1 + self.encoded_signature_bytes())
            .is_some_and(|total| total <= MAX_JWT_BYTES)
    }
}

/// Reject oversized/short HS256 configuration before a vendor key-vector copy.
pub(crate) fn accepts_hs256_key_length(length: usize) -> bool {
    HmacKind::Sha256.key_fits(length)
}

// Deliberately no Debug implementation on either secret-bearing owner.
struct HmacSigner {
    key: hmac::Key,
    kind: HmacKind,
}
struct HmacVerifier {
    key: hmac::Key,
    kind: HmacKind,
}

impl Signer<Vec<u8>> for HmacSigner {
    fn try_sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        if !self.kind.message_fits(message.len()) {
            return Err(SignatureError::new());
        }
        Ok(hmac::sign(&self.key, message).as_ref().to_vec())
    }
}
impl JwtSigner for HmacSigner {
    fn algorithm(&self) -> Algorithm {
        self.kind.algorithm()
    }
}
impl Verifier<Vec<u8>> for HmacVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> Result<(), SignatureError> {
        if !self.kind.message_fits(message.len()) || signature.len() != self.kind.bytes() {
            return Err(SignatureError::new());
        }
        hmac::verify(&self.key, message, signature).map_err(|_| SignatureError::new())
    }
}
impl JwtVerifier for HmacVerifier {
    fn algorithm(&self) -> Algorithm {
        self.kind.algorithm()
    }
}

fn signer_factory(algorithm: &Algorithm, key: &EncodingKey) -> JwtResult<Box<dyn JwtSigner>> {
    let kind = HmacKind::from_algorithm(*algorithm)?;
    if key.family() != AlgorithmFamily::Hmac || !kind.key_fits(key.as_bytes().len()) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    Ok(Box::new(HmacSigner {
        key: hmac::Key::new(kind.ring_algorithm(), key.as_bytes()),
        kind,
    }))
}
fn verifier_factory(algorithm: &Algorithm, key: &DecodingKey) -> JwtResult<Box<dyn JwtVerifier>> {
    let kind = HmacKind::from_algorithm(*algorithm)?;
    if key.family() != AlgorithmFamily::Hmac {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let bytes = key.try_get_as_bytes()?;
    if !kind.key_fits(bytes.len()) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    Ok(Box::new(HmacVerifier {
        key: hmac::Key::new(kind.ring_algorithm(), bytes),
        kind,
    }))
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory,
    verifier_factory,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        rsa_pub_components_from_public_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        ec_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        ed_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        compute_digest: |data, algorithm| {
            if data.len() > MAX_JWT_BYTES {
                return Err(ErrorKind::InvalidKeyFormat.into());
            }
            let algorithm = match algorithm {
                ThumbprintHash::SHA256 => &digest::SHA256,
                ThumbprintHash::SHA384 => &digest::SHA384,
                ThumbprintHash::SHA512 => &digest::SHA512,
                _ => return Err(ErrorKind::InvalidAlgorithm.into()),
            };
            Ok(digest::digest(algorithm, data).as_ref().to_vec())
        },
    },
};
static INSTALLED: OnceLock<bool> = OnceLock::new();

/// Initialize before consumer JWT encoding; repeated own calls are idempotent.
///
/// A preexisting provider (including an upstream default frozen before this hook)
/// returns fixed ProviderUnavailable. Initialize once at trusted application
/// startup, before any other JWT user. This never replaces or delegates to a
/// foreign provider. Cargo feature unification can restore asymmetric packages;
/// check the actual standalone consumer graph when claiming the reduced profile.
pub fn install_default_provider() -> Result<(), IdentityError> {
    if *INSTALLED.get_or_init(|| PROVIDER.install_default().is_ok()) {
        Ok(())
    } else {
        Err(IdentityError::ProviderUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_key_utilities_return_errors_without_panics() {
        let key = b"synthetic invalid asymmetric key";
        assert!((PROVIDER.key_utils.rsa_pub_components_from_private_key)(key).is_err());
        assert!((PROVIDER.key_utils.rsa_pub_components_from_public_key)(key).is_err());
        assert!(
            (PROVIDER.key_utils.ec_pub_components_from_private_key)(key, Algorithm::ES256).is_err()
        );
        assert!((PROVIDER.key_utils.ed_pub_components_from_private_key)(
            key,
            &jsonwebtoken::jwk::EllipticCurve::Ed25519
        )
        .is_err());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn key_acceptance_has_required_length_and_allocation_bounds() {
        let kind: HmacKind = kani::any();
        let length: usize = kani::any();
        // Independent JWA contract, not the implementation's bytes() helper.
        let required = match kind {
            HmacKind::Sha256 => 32,
            HmacKind::Sha384 => 48,
            HmacKind::Sha512 => 64,
        };
        assert_eq!(kind.key_fits(length), length >= required && length <= 1024);
    }
    #[kani::proof]
    fn signing_size_never_wraps_or_exceeds_complete_token_bound() {
        let kind: HmacKind = kani::any();
        let length: usize = kani::any();
        // Independent canonical unpadded base64 tag lengths for JWA SHA-2.
        let encoded_tag = match kind {
            HmacKind::Sha256 => 43,
            HmacKind::Sha384 => 64,
            HmacKind::Sha512 => 86,
        };
        let complete = length.checked_add(1 + encoded_tag);
        assert_eq!(
            kind.message_fits(length),
            complete.is_some_and(|total| total <= 65536)
        );
    }
}

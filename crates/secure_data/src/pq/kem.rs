// Hybrid X25519 + ML-KEM-768 KEM.

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit},
    DecapsulationKey768, EncapsulationKey768, MlKem768,
};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::DataError;

const ML_KEM_768_SEED_LEN: usize = 64;
const ML_KEM_768_EXPANDED_SECRET_KEY_LEN: usize = 2400;

/// Result of hybrid encapsulation to an ML-KEM-768 + X25519 recipient.
///
/// # Examples
///
/// ```
/// # fn example() -> Result<(), secure_data::error::DataError> {
/// use ml_kem::{MlKem768, kem::{Kem, KeyExport}};
/// use rand::rngs::OsRng;
/// use secure_data::pq::{hybrid_decapsulate, hybrid_encapsulate};
/// use x25519_dalek::{PublicKey, StaticSecret};
///
/// let (ml_kem_sk, ml_kem_pk) = MlKem768::generate_keypair();
/// let x25519_sk = StaticSecret::random_from_rng(OsRng);
/// let x25519_pk = PublicKey::from(&x25519_sk);
///
/// let encapsulated = hybrid_encapsulate(
///     ml_kem_pk.to_bytes().as_slice(),
///     x25519_pk.as_bytes(),
/// )?;
/// let decapsulated = hybrid_decapsulate(
///     &encapsulated.kem_ciphertext,
///     &encapsulated.x25519_share,
///     ml_kem_sk.to_bytes().as_slice(),
///     x25519_sk.as_bytes(),
/// )?;
///
/// assert_eq!(encapsulated.derived_key, decapsulated);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridEncapsulation {
    /// ML-KEM-768 ciphertext, 1088 bytes.
    pub kem_ciphertext: Vec<u8>,
    /// Ephemeral X25519 public share, 32 bytes.
    pub x25519_share: Vec<u8>,
    /// Combined HKDF-SHA-256 output, suitable as an AES-256-GCM key.
    pub derived_key: [u8; 32],
}

/// Encapsulates to a recipient ML-KEM-768 public key and X25519 public key.
///
/// # Errors
///
/// Returns [`DataError::EnvelopeMalformed`] for invalid key lengths or
/// non-contributory X25519 inputs, and [`DataError::EncryptionFailed`] if the
/// HKDF combiner fails.
pub fn hybrid_encapsulate(
    recipient_pk_ml_kem: &[u8],
    recipient_pk_x25519: &[u8],
) -> Result<HybridEncapsulation, DataError> {
    let ml_kem_pk = EncapsulationKey768::new_from_slice(recipient_pk_ml_kem).map_err(|_| {
        DataError::EnvelopeMalformed {
            reason: format!(
                "ML-KEM-768 public key length or validation failed: expected {} bytes",
                crate::pq::sizes::ML_KEM_768_PUBLIC_KEY_LEN
            ),
        }
    })?;

    let recipient_x25519 = x25519_public_from_slice(recipient_pk_x25519)?;

    let (kem_ciphertext, ml_kem_shared) = ml_kem_pk.encapsulate();
    let ephemeral_x25519 = EphemeralSecret::random_from_rng(OsRng);
    let x25519_share = PublicKey::from(&ephemeral_x25519);
    let x25519_shared = ephemeral_x25519.diffie_hellman(&recipient_x25519);
    if !x25519_shared.was_contributory() {
        return Err(DataError::EnvelopeMalformed {
            reason: "X25519 shared secret was non-contributory".to_string(),
        });
    }

    let derived_key = crate::pq::combiner::combine_shared_secrets(
        ml_kem_shared.as_slice(),
        x25519_shared.as_ref(),
    )?;
    reject_zero_derived_key(&derived_key)?;

    Ok(HybridEncapsulation {
        kem_ciphertext: kem_ciphertext.as_slice().to_vec(),
        x25519_share: x25519_share.as_bytes().to_vec(),
        derived_key,
    })
}

/// Decapsulates a hybrid ML-KEM-768 + X25519 shared key.
///
/// `recipient_sk_ml_kem` accepts either the 64-byte ML-KEM seed form or the
/// 2400-byte expanded ML-KEM-768 decapsulation key form used by NIST ACVP KATs.
///
/// # Errors
///
/// Returns [`DataError::EnvelopeMalformed`] for malformed ciphertexts, key
/// material, or non-contributory X25519 inputs, and [`DataError::EncryptionFailed`]
/// if HKDF expansion fails.
pub fn hybrid_decapsulate(
    kem_ciphertext: &[u8],
    x25519_share: &[u8],
    recipient_sk_ml_kem: &[u8],
    recipient_sk_x25519: &[u8],
) -> Result<[u8; 32], DataError> {
    if kem_ciphertext.len() != crate::pq::sizes::ML_KEM_768_CIPHERTEXT_LEN {
        return Err(DataError::EnvelopeMalformed {
            reason: format!(
                "ML-KEM-768 ciphertext length mismatch: expected {}, got {}",
                crate::pq::sizes::ML_KEM_768_CIPHERTEXT_LEN,
                kem_ciphertext.len()
            ),
        });
    }

    let ciphertext: ml_kem::ml_kem_768::Ciphertext =
        kem_ciphertext
            .try_into()
            .map_err(|_| DataError::EnvelopeMalformed {
                reason: "ML-KEM-768 ciphertext could not be decoded".to_string(),
            })?;
    let ml_kem_sk = decapsulation_key_from_slice(recipient_sk_ml_kem)?;
    let ml_kem_shared = ml_kem_sk.decapsulate(&ciphertext);

    let recipient_x25519 = x25519_static_secret_from_slice(recipient_sk_x25519)?;
    let sender_x25519 = x25519_public_from_slice(x25519_share)?;
    let x25519_shared = recipient_x25519.diffie_hellman(&sender_x25519);
    if !x25519_shared.was_contributory() {
        return Err(DataError::EnvelopeMalformed {
            reason: "X25519 shared secret was non-contributory".to_string(),
        });
    }

    let derived_key = crate::pq::combiner::combine_shared_secrets(
        ml_kem_shared.as_slice(),
        x25519_shared.as_ref(),
    )?;
    reject_zero_derived_key(&derived_key)?;
    Ok(derived_key)
}

pub(crate) fn ml_kem_keypair_from_seed(
    seed: &[u8],
) -> Result<(Vec<u8>, [u8; ML_KEM_768_SEED_LEN]), DataError> {
    let seed = ml_kem_seed_from_slice(seed)?;
    let decapsulation_key = DecapsulationKey768::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    Ok((public_key.as_slice().to_vec(), seed.into()))
}

pub(crate) fn x25519_keypair_from_seed(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), DataError> {
    let secret = x25519_static_secret_from_slice(seed)?;
    let public = PublicKey::from(&secret);
    Ok((secret.to_bytes(), *public.as_bytes()))
}

fn decapsulation_key_from_slice(key_bytes: &[u8]) -> Result<DecapsulationKey768, DataError> {
    match key_bytes.len() {
        ML_KEM_768_SEED_LEN => Ok(DecapsulationKey768::from_seed(ml_kem_seed_from_slice(
            key_bytes,
        )?)),
        ML_KEM_768_EXPANDED_SECRET_KEY_LEN => {
            let expanded: ml_kem::ExpandedDecapsulationKey<MlKem768> =
                key_bytes
                    .try_into()
                    .map_err(|_| DataError::EnvelopeMalformed {
                        reason:
                            "ML-KEM-768 expanded decapsulation key could not be decoded"
                                .to_string(),
                    })?;
            #[allow(deprecated)]
            DecapsulationKey768::from_expanded_bytes(&expanded).map_err(|_| {
                DataError::EnvelopeMalformed {
                    reason: "ML-KEM-768 expanded decapsulation key failed validation"
                        .to_string(),
                }
            })
        }
        actual => Err(DataError::EnvelopeMalformed {
            reason: format!(
                "ML-KEM-768 secret key length mismatch: expected {}-byte seed or {}-byte expanded key, got {}",
                ML_KEM_768_SEED_LEN, ML_KEM_768_EXPANDED_SECRET_KEY_LEN, actual
            ),
        }),
    }
}

fn ml_kem_seed_from_slice(seed: &[u8]) -> Result<ml_kem::Seed, DataError> {
    if seed.len() != ML_KEM_768_SEED_LEN {
        return Err(DataError::EnvelopeMalformed {
            reason: format!(
                "ML-KEM-768 seed length mismatch: expected {}, got {}",
                ML_KEM_768_SEED_LEN,
                seed.len()
            ),
        });
    }
    seed.try_into().map_err(|_| DataError::EnvelopeMalformed {
        reason: "ML-KEM-768 seed could not be decoded".to_string(),
    })
}

fn x25519_public_from_slice(public_key: &[u8]) -> Result<PublicKey, DataError> {
    let public_key: [u8; crate::pq::sizes::X25519_SHARE_LEN] =
        public_key
            .try_into()
            .map_err(|_| DataError::EnvelopeMalformed {
                reason: format!(
                    "X25519 public key length mismatch: expected {}, got {}",
                    crate::pq::sizes::X25519_SHARE_LEN,
                    public_key.len()
                ),
            })?;
    Ok(PublicKey::from(public_key))
}

fn x25519_static_secret_from_slice(secret_key: &[u8]) -> Result<StaticSecret, DataError> {
    let secret_key: [u8; crate::pq::sizes::X25519_SHARE_LEN] =
        secret_key
            .try_into()
            .map_err(|_| DataError::EnvelopeMalformed {
                reason: format!(
                    "X25519 secret key length mismatch: expected {}, got {}",
                    crate::pq::sizes::X25519_SHARE_LEN,
                    secret_key.len()
                ),
            })?;
    Ok(StaticSecret::from(secret_key))
}

fn reject_zero_derived_key(derived_key: &[u8; 32]) -> Result<(), DataError> {
    if derived_key.iter().all(|byte| *byte == 0) {
        return Err(DataError::EncryptionFailed {
            reason: "hybrid combiner derived an all-zero key".to_string(),
        });
    }
    Ok(())
}

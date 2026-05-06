// HKDF-SHA-256 combiner for the X25519 + ML-KEM-768 hybrid KEM.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::DataError;

/// HKDF info string locked by the PQ migration plan.
pub const HYBRID_KDF_INFO: &[u8] = b"sunlit-pq-x25519-ml-kem-768/v1";

/// Derives the 32-byte AES-256-GCM wrap key from ML-KEM and X25519 shared secrets.
///
/// # Errors
///
/// Returns [`DataError::EncryptionFailed`] if HKDF expansion fails. With the
/// fixed 32-byte output length this should not occur, but keeping the error
/// path structured avoids panics in production code.
pub fn combine_shared_secrets(
    ml_kem_shared_secret: &[u8],
    x25519_shared_secret: &[u8],
) -> Result<[u8; 32], DataError> {
    if ml_kem_shared_secret.len() != crate::pq::sizes::ML_KEM_768_SHARED_SECRET_LEN {
        return Err(DataError::EnvelopeMalformed {
            reason: format!(
                "ML-KEM-768 shared secret length mismatch: expected {}, got {}",
                crate::pq::sizes::ML_KEM_768_SHARED_SECRET_LEN,
                ml_kem_shared_secret.len()
            ),
        });
    }
    if x25519_shared_secret.len() != crate::pq::sizes::X25519_SHARED_SECRET_LEN {
        return Err(DataError::EnvelopeMalformed {
            reason: format!(
                "X25519 shared secret length mismatch: expected {}, got {}",
                crate::pq::sizes::X25519_SHARED_SECRET_LEN,
                x25519_shared_secret.len()
            ),
        });
    }

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ml_kem_shared_secret);
    ikm[32..].copy_from_slice(x25519_shared_secret);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; crate::pq::sizes::HKDF_SHA256_OUTPUT_LEN];
    hk.expand(HYBRID_KDF_INFO, &mut output)
        .map_err(|_| DataError::EncryptionFailed {
            reason: "HKDF-SHA-256 hybrid combiner expansion failed".to_string(),
        })?;

    Ok(output)
}

pub(crate) fn bind_combiner_id_to_aad(aad: &mut Vec<u8>, combiner_id: u8) {
    aad.extend_from_slice(format!(";combiner=0x{combiner_id:02x}").as_bytes());
}

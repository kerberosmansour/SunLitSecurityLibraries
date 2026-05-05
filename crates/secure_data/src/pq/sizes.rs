// Fixed-size constants for the hybrid X25519 + ML-KEM-768 KEM and the
// HKDF-SHA-256 combiner.
//
// These values come from:
// - FIPS 203 (ML-KEM specification, 2024) for `ML_KEM_768_*` lengths.
// - RFC 7748 (Curve25519 / X25519) for `X25519_SHARE_LEN`.
// - RFC 5869 (HKDF) and RFC 6234 (SHA-256) for `HKDF_SHA256_OUTPUT_LEN`.
//
// Encoded as `const usize` so they can be used in array sizes, slice
// bounds, and BDD assertions on a non-PQ build (no dependency required).

/// ML-KEM-768 ciphertext length in bytes (FIPS 203).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

/// ML-KEM-768 public key length in bytes (FIPS 203).
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;

/// ML-KEM-768 shared secret length in bytes (FIPS 203, post-decapsulation).
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// X25519 public-key share length in bytes (RFC 7748).
pub const X25519_SHARE_LEN: usize = 32;

/// X25519 shared secret length in bytes (RFC 7748).
pub const X25519_SHARED_SECRET_LEN: usize = 32;

/// HKDF-SHA-256 output length in bytes (RFC 5869 + RFC 6234), used as the
/// data-key wrap-key length for hybrid envelopes.
pub const HKDF_SHA256_OUTPUT_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes (NIST SP 800-38D), used to wrap the
/// data key in hybrid envelopes — identical to the classical `Aes256Gcm`
/// path.
pub const AES_256_GCM_NONCE_LEN: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: every constant is non-zero. Catches accidental literal
    /// zeros from a future copy-paste.
    #[test]
    fn every_size_constant_is_non_zero() {
        assert_ne!(ML_KEM_768_CIPHERTEXT_LEN, 0);
        assert_ne!(ML_KEM_768_PUBLIC_KEY_LEN, 0);
        assert_ne!(ML_KEM_768_SHARED_SECRET_LEN, 0);
        assert_ne!(X25519_SHARE_LEN, 0);
        assert_ne!(X25519_SHARED_SECRET_LEN, 0);
        assert_ne!(HKDF_SHA256_OUTPUT_LEN, 0);
        assert_ne!(AES_256_GCM_NONCE_LEN, 0);
    }

    /// FIPS 203 fixes ML-KEM-768 ciphertext at 1088 bytes; if the constant
    /// drifts, downstream wire-format consumers break.
    #[test]
    fn ml_kem_768_ciphertext_is_1088_bytes_per_fips_203() {
        assert_eq!(ML_KEM_768_CIPHERTEXT_LEN, 1088);
    }

    /// HKDF-SHA-256 output is 32 bytes (one SHA-256 block); this is the
    /// data-key wrap-key length we feed to AES-256-GCM.
    #[test]
    fn hkdf_sha256_output_is_32_bytes() {
        assert_eq!(HKDF_SHA256_OUTPUT_LEN, 32);
    }

    /// X25519 share and ML-KEM-768 shared secret share the 32-byte length;
    /// the hybrid combiner concats them then HKDFs to 32 bytes.
    #[test]
    fn shared_secret_lengths_align_for_concat_combiner() {
        assert_eq!(ML_KEM_768_SHARED_SECRET_LEN, 32);
        assert_eq!(X25519_SHARED_SECRET_LEN, 32);
        assert_eq!(HKDF_SHA256_OUTPUT_LEN, 32);
    }
}

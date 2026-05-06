// Post-quantum primitives for secure_data.
//
// M1 reserves the public surface (size constants, the
// CryptoAlgorithm::HybridX25519MlKem768 enum variant, the EncryptionEnvelope
// `combiner_id` wire-format field) and the migration plan. M2 adds the
// hybrid X25519 + ML-KEM-768 KEM implementation behind the `pq` feature flag.
//
// See docs/slo/design/pq-migration-plan.md for the wire-format design,
// hybrid-construction rationale, FIPS-track posture, and the version-policy
// strategy across builds with and without `--features pq`.

/// Fixed-size constants for the hybrid X25519 + ML-KEM-768 KEM and the
/// HKDF-SHA-256 combiner. Exposed as a public, always-available surface so
/// downstream consumers can reference the wire-format dimensions even on
/// builds without `--features pq`.
pub mod sizes;

/// Combiner identifier for envelopes produced by the M2 hybrid KEM
/// (X25519 || ML-KEM-768 → HKDF-SHA-256). M1 reserves the value;
/// `EncryptionEnvelope::combiner_id == Some(COMBINER_ID_X25519_ML_KEM_768)`
/// means the envelope is a v2 hybrid envelope and decrypt requires the
/// `pq` feature.
pub const COMBINER_ID_X25519_ML_KEM_768: u8 = 0x01;

/// Reserved-future combiner identifier. Values in the range `[0x80, 0xFE]`
/// are reserved for future combiner schemes (e.g., a CFRG QSF combiner or
/// X-Wing). `0xFF` is permanently reserved as a "must-fail-closed" sentinel
/// — an envelope carrying `Some(0xFF)` must return
/// [`crate::error::DataError::AlgorithmRejectedByPolicy`] without attempting
/// any cryptographic operation.
pub const COMBINER_ID_RESERVED_FUTURE_MIN: u8 = 0x80;

/// Permanently-reserved fail-closed sentinel. See
/// [`COMBINER_ID_RESERVED_FUTURE_MIN`].
pub const COMBINER_ID_FAIL_CLOSED: u8 = 0xFF;

/// Returns `true` if `id` is a recognised combiner identifier as of M1.
///
/// As of M1, only `0x01` (X25519 + ML-KEM-768 / HKDF-SHA-256) is recognised.
/// All other values are either reserved for future combiners or the
/// fail-closed sentinel.
#[must_use]
pub fn is_recognised_combiner(id: u8) -> bool {
    id == COMBINER_ID_X25519_ML_KEM_768
}

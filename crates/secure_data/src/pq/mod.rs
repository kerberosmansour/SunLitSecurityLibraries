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

/// HKDF-SHA-256 combiner implementation for the M2 hybrid KEM.
#[cfg(feature = "pq")]
pub mod combiner;

/// Hybrid X25519 + ML-KEM-768 KEM implementation.
#[cfg(feature = "pq")]
pub mod kem;

#[cfg(feature = "pq")]
pub use kem::{hybrid_decapsulate, hybrid_encapsulate, HybridEncapsulation};

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

/// Returns the runtime FIPS posture of the PQ path on this build.
///
/// - `None` — the `pq` feature is not enabled; the question does not apply.
/// - `Some("pending_cmvp")` — the `pq` feature is enabled. As of 2026-05,
///   no CMVP cert covers ML-KEM-768 in any Rust-callable cryptographic
///   module; the PQ path is honestly labelled as validation-pending,
///   regardless of whether the `fips` feature is also enabled.
/// - `Some("validated")` — the `pq-aws-lc` feature (or successor) selects
///   a CMVP-validated PQ implementation. This branch does not exist as
///   of M4; it is reserved for the future runbook that promotes the
///   FIPS-track posture per `docs/slo/design/pq-migration-plan.md` §5.
///
/// Auditors / SBOM consumers can call this function (or grep for its
/// returned literal in compiled binaries) to verify the honest label is
/// in place. The CI lint `scripts/lint-fips-pq-claims.sh` enforces the
/// project's documentation posture; this function enforces the runtime
/// posture.
///
/// # Examples
///
/// ```
/// use secure_data::pq::fips_status;
///
/// match fips_status() {
///     None => { /* PQ path not built in */ }
///     Some("pending_cmvp") => { /* PQ enabled; FIPS pending CMVP */ }
///     Some(_other) => { /* future "validated" / etc. */ }
/// }
/// ```
#[must_use]
pub fn fips_status() -> Option<&'static str> {
    #[cfg(feature = "pq")]
    {
        Some("pending_cmvp")
    }
    #[cfg(not(feature = "pq"))]
    {
        None
    }
}

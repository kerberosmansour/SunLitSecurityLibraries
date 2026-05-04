//! Data classification levels.
//!
//! Variants are ordered from least to most sensitive, enabling comparison-based
//! redaction logic. Mitigates THREAT-I-01 and THREAT-E-01 (data exposure).

use serde::{Deserialize, Serialize};

/// The sensitivity level of a piece of data.
///
/// Variants are ordered from least sensitive (`Public`) to most sensitive (`Credentials`).
/// Use `<` / `>` comparisons to enforce redaction thresholds.
///
/// # Examples
///
/// ```
/// use security_core::classification::DataClassification;
///
/// // Variants are ordered for comparison-based redaction logic.
/// assert!(DataClassification::Public < DataClassification::PII);
/// assert!(DataClassification::Credentials > DataClassification::Secret);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DataClassification {
    /// Publicly shareable data with no confidentiality requirements.
    Public = 0,
    /// Internal data not intended for public disclosure.
    Internal = 1,
    /// Confidential business data.
    Confidential = 2,
    /// Personally Identifiable Information (PII).
    PII = 3,
    /// Data subject to regulatory requirements (e.g., HIPAA, GDPR).
    Regulated = 4,
    /// Highly sensitive secrets (keys, tokens, passwords).
    Secret = 5,
    /// Authentication credentials — the most sensitive classification.
    Credentials = 6,
}

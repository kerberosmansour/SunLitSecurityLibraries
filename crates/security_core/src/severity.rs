//! Security event severity levels.
//!
//! Ordered from least (`Info`) to most severe (`Critical`). Mitigates THREAT-D-01.

use serde::{Deserialize, Serialize};

/// The severity of a security event or finding.
///
/// Variants are ordered from least to most severe.
///
/// # Examples
///
/// ```
/// use security_core::severity::SecuritySeverity;
///
/// assert!(SecuritySeverity::Critical > SecuritySeverity::Info);
/// assert!(SecuritySeverity::Medium < SecuritySeverity::High);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecuritySeverity {
    /// Informational — no immediate action required.
    Info = 0,
    /// Low severity — monitor but no urgent action.
    Low = 1,
    /// Medium severity — investigate.
    Medium = 2,
    /// High severity — escalate promptly.
    High = 3,
    /// Critical severity — immediate response required.
    Critical = 4,
}

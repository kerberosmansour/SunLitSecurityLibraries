//! Privacy-specific error types.

use std::fmt;

/// Errors returned by the `secure_privacy` crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrivacyError {
    /// A regex pattern failed to compile.
    InvalidPattern(String),
    /// The pseudonymization salt was empty.
    EmptySalt,
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "invalid PII pattern: {msg}"),
            Self::EmptySalt => write!(f, "pseudonymization salt must not be empty"),
        }
    }
}

impl std::error::Error for PrivacyError {}

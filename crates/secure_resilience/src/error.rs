//! Error types for the `secure_resilience` crate.

use std::fmt;

/// Errors that can occur during resilience operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResilienceError {
    /// An invalid signal was provided.
    InvalidSignal(String),
    /// An integrity check failed to initialize.
    InvalidIntegrityConfig(String),
    /// An internal invariant was violated (e.g., a poisoned mutex).
    /// Used by the circuit-breaker for non-recoverable internal errors.
    Internal(String),
}

impl fmt::Display for ResilienceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignal(msg) => write!(f, "invalid signal: {msg}"),
            Self::InvalidIntegrityConfig(msg) => write!(f, "invalid integrity config: {msg}"),
            Self::Internal(msg) => write!(f, "internal resilience error: {msg}"),
        }
    }
}

impl std::error::Error for ResilienceError {}

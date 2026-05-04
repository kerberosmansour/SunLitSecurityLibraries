//! Redaction trait and display wrapper for sensitive values.
//!
//! Use [`RedactedDisplay`] to prevent sensitive strings from appearing in logs or error messages.
//! Mitigates THREAT-I-02 (credential exposure in logs).

use std::fmt;

mod sealed {
    /// Sealing trait — prevents external implementations of [`super::Redact`].
    pub trait Sealed {}
}

/// A trait for types that can produce a redacted display representation.
///
/// This trait is sealed — external crates cannot implement it.
pub trait Redact: sealed::Sealed {
    /// Returns a redacted string representation of the value.
    fn redacted(&self) -> String;
}

/// A wrapper that always displays its contents as `[REDACTED]`.
///
/// # Examples
///
/// ```
/// use security_core::redact::RedactedDisplay;
///
/// let secret = RedactedDisplay::new("my-api-key");
/// // Display and Debug are both redacted.
/// assert_eq!(format!("{}", secret), "[REDACTED]");
/// // The original value is still accessible.
/// assert_eq!(*secret.inner(), "my-api-key");
/// ```
pub struct RedactedDisplay<T: fmt::Display> {
    value: T,
}

impl<T: fmt::Display> RedactedDisplay<T> {
    /// Wraps `value` so that formatting it always produces `[REDACTED]`.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Returns the original value. Use with caution — not for display.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.value
    }
}

impl<T: fmt::Display> sealed::Sealed for RedactedDisplay<T> {}

impl<T: fmt::Display> Redact for RedactedDisplay<T> {
    fn redacted(&self) -> String {
        "[REDACTED]".to_string()
    }
}

impl<T: fmt::Display> fmt::Display for RedactedDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T: fmt::Display + fmt::Debug> fmt::Debug for RedactedDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedDisplay(REDACTED)")
    }
}

//! Error classification — retryability, alerting, security signals.
//!
//! Every `AppError` variant maps to exactly one `ErrorClassification`.

use crate::kind::AppError;

/// Operational classification of an error.
///
/// This type is `#[non_exhaustive]` to allow additional flags in future milestones
/// without breaking downstream match expressions.
///
/// # Examples
///
/// ```
/// use secure_errors::classify::ErrorClassification;
/// use secure_errors::kind::AppError;
///
/// let cls = ErrorClassification::for_error(&AppError::Forbidden { policy: "admin_only" });
/// assert!(cls.is_security_signal());
/// assert!(cls.is_alertable());
/// assert!(!cls.is_retryable());
/// ```
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct ErrorClassification {
    retryable: bool,
    alertable: bool,
    security_signal: bool,
    user_fixable: bool,
}

impl ErrorClassification {
    /// Returns the classification for the given `AppError`.
    pub fn for_error(err: &AppError) -> Self {
        match err {
            AppError::Validation { .. } | AppError::NotFound | AppError::Conflict => Self {
                retryable: false,
                alertable: false,
                security_signal: false,
                user_fixable: true,
            },
            AppError::Forbidden { .. } | AppError::Crypto => Self {
                retryable: false,
                alertable: true,
                security_signal: true,
                user_fixable: false,
            },
            AppError::Dependency { .. } => Self {
                retryable: true,
                alertable: true,
                security_signal: false,
                user_fixable: false,
            },
            AppError::Internal => Self {
                retryable: false,
                alertable: true,
                security_signal: false,
                user_fixable: false,
            },
            AppError::RateLimit { .. } => Self {
                retryable: true,
                alertable: false,
                security_signal: false,
                user_fixable: true,
            },
        }
    }

    /// Returns `true` if the operation may succeed on a subsequent attempt.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Returns `true` if this error should trigger an operational alert.
    #[must_use]
    pub const fn is_alertable(&self) -> bool {
        self.alertable
    }

    /// Returns `true` if this error represents a potential security incident.
    #[must_use]
    pub const fn is_security_signal(&self) -> bool {
        self.security_signal
    }

    /// Returns `true` if the caller can fix this error without operator intervention.
    #[must_use]
    pub const fn is_user_fixable(&self) -> bool {
        self.user_fixable
    }
}

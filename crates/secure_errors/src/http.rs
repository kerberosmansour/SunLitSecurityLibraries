//! Centralized HTTP mapping — `AppError` → `PublicError` + HTTP status.
//!
//! This is the **only** place that decides what HTTP status and public body
//! an internal error produces. No ad hoc JSON construction is permitted elsewhere.

use crate::{kind::AppError, public::PublicError};

/// Stable public error-code identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicErrorCode {
    InvalidRequest,
    Forbidden,
    NotFound,
    Conflict,
    TemporarilyUnavailable,
    InternalError,
    RateLimited,
}

impl PublicErrorCode {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InternalError => "internal_error",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[must_use]
pub(crate) fn public_error_code_for(err: &AppError) -> PublicErrorCode {
    match err {
        AppError::Validation { .. } => PublicErrorCode::InvalidRequest,
        AppError::Forbidden { .. } => PublicErrorCode::Forbidden,
        AppError::NotFound => PublicErrorCode::NotFound,
        AppError::Conflict => PublicErrorCode::Conflict,
        AppError::Dependency { .. } => PublicErrorCode::TemporarilyUnavailable,
        AppError::Crypto | AppError::Internal => PublicErrorCode::InternalError,
        AppError::RateLimit { .. } => PublicErrorCode::RateLimited,
    }
}

/// Maps an `AppError` to an HTTP status code and a safe `PublicError` response body.
///
/// This function is the single source of truth for all error-to-HTTP mappings.
/// It guarantees that no internal details (SQL, hostnames, backtraces) appear in
/// the returned `PublicError`.
///
/// # Examples
///
/// ```
/// use secure_errors::http::into_response_parts;
/// use secure_errors::kind::AppError;
///
/// let (status, body) = into_response_parts(&AppError::NotFound);
/// assert_eq!(status, 404);
/// assert_eq!(body.code, "not_found");
/// ```
pub fn into_response_parts(err: &AppError) -> (u16, PublicError) {
    let code = public_error_code_for(err).as_str();

    match err {
        AppError::Validation { .. } => (
            400,
            PublicError::new(code, "The request contains invalid data.", None),
        ),
        AppError::Forbidden { .. } => (403, PublicError::new(code, "Access denied.", None)),
        AppError::NotFound => (
            404,
            PublicError::new(code, "The requested resource was not found.", None),
        ),
        AppError::Conflict => (
            409,
            PublicError::new(code, "The request conflicts with the current state.", None),
        ),
        AppError::Dependency { .. } => (
            503,
            PublicError::new(code, "A required service is temporarily unavailable.", None),
        ),
        AppError::Crypto | AppError::Internal => (
            500,
            PublicError::new(code, "An internal error occurred.", None),
        ),
        AppError::RateLimit { .. } => (
            429,
            PublicError::new(code, "Too many requests. Please retry later.", None),
        ),
    }
}

/// Returns the `Retry-After` value in seconds if the error is `RateLimit` with a configured value.
///
/// # Examples
///
/// ```
/// use secure_errors::http::retry_after_seconds;
/// use secure_errors::kind::AppError;
///
/// let err = AppError::RateLimit { retry_after_seconds: Some(30) };
/// assert_eq!(retry_after_seconds(&err), Some(30));
///
/// let err = AppError::NotFound;
/// assert_eq!(retry_after_seconds(&err), None);
/// ```
#[must_use]
pub fn retry_after_seconds(err: &AppError) -> Option<u64> {
    match err {
        AppError::RateLimit {
            retry_after_seconds,
        } => *retry_after_seconds,
        _ => None,
    }
}

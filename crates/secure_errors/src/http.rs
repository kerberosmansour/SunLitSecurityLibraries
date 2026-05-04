//! Centralized HTTP mapping — `AppError` → `PublicError` + HTTP status.
//!
//! This is the **only** place that decides what HTTP status and public body
//! an internal error produces. No ad hoc JSON construction is permitted elsewhere.

use crate::{kind::AppError, public::PublicError};

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
    match err {
        AppError::Validation { .. } => (
            400,
            PublicError::new(
                "invalid_request",
                "The request contains invalid data.",
                None,
            ),
        ),
        AppError::Forbidden { .. } => (403, PublicError::new("forbidden", "Access denied.", None)),
        AppError::NotFound => (
            404,
            PublicError::new("not_found", "The requested resource was not found.", None),
        ),
        AppError::Conflict => (
            409,
            PublicError::new(
                "conflict",
                "The request conflicts with the current state.",
                None,
            ),
        ),
        AppError::Dependency { .. } => (
            503,
            PublicError::new(
                "temporarily_unavailable",
                "A required service is temporarily unavailable.",
                None,
            ),
        ),
        AppError::Crypto | AppError::Internal => (
            500,
            PublicError::new("internal_error", "An internal error occurred.", None),
        ),
        AppError::RateLimit { .. } => (
            429,
            PublicError::new(
                "rate_limited",
                "Too many requests. Please retry later.",
                None,
            ),
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

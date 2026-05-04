//! Internal error taxonomy.
//!
//! `AppError` is the only error type used inside the crate boundary. It must never
//! be serialized to HTTP responses directly — use `PublicError` via `http::into_response_parts`.

use thiserror::Error;

/// The set of internal application errors.
///
/// **Important**: This enum is `#[non_exhaustive]`. Match arms must always include
/// a wildcard arm to be forward-compatible.
///
/// Internal details (e.g. SQL text, hostnames, backtrace) may be attached to
/// `ErrorReport` but must **never** appear in `PublicError`.
///
/// # Examples
///
/// ```
/// use secure_errors::kind::AppError;
///
/// let err = AppError::Validation { code: "email_invalid" };
/// assert_eq!(err.to_string(), "validation error: email_invalid");
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    /// A request failed input validation.
    #[error("validation error: {code}")]
    Validation {
        /// Internal validation code — must not appear in public responses.
        code: &'static str,
    },

    /// Access was denied by a policy rule.
    #[error("forbidden by policy: {policy}")]
    Forbidden {
        /// The policy that denied access — must not appear in public responses.
        policy: &'static str,
    },

    /// The requested resource does not exist.
    #[error("not found")]
    NotFound,

    /// A resource conflict prevented the operation (e.g., duplicate key).
    #[error("conflict")]
    Conflict,

    /// A downstream dependency failed.
    #[error("dependency '{dep}' unavailable")]
    Dependency {
        /// The dependency name — must not appear in public responses.
        dep: &'static str,
    },

    /// A cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto,

    /// An unclassified internal error.
    #[error("internal error")]
    Internal,

    /// The caller has exceeded a rate limit.
    #[error("rate limit exceeded")]
    RateLimit {
        /// Optional number of seconds after which the client may retry.
        retry_after_seconds: Option<u64>,
    },
}

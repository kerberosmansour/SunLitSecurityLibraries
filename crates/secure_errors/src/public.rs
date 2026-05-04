//! The public-facing error type serialized into HTTP responses.
//!
//! `PublicError` is the **only** struct that may be serialized to HTTP responses.
//! It contains no internal details — only a stable error code, a user-facing message,
//! and an optional request identifier for correlation.

use std::borrow::Cow;

use serde::Serialize;

use security_core::types::RequestId;

/// A safe, client-visible error payload.
///
/// This struct is serializable but not deserializable: it is responses-only.
///
/// Fields:
/// - `code` — a stable machine-readable error code (e.g. `"not_found"`)
/// - `message` — a human-readable message safe for client consumption
/// - `request_id` — optional request correlation id (echo'd back to caller)
///
/// # Examples
///
/// ```
/// use secure_errors::public::PublicError;
///
/// let err = PublicError::new("not_found", "The resource was not found.", None);
/// assert_eq!(err.code, "not_found");
/// ```
#[must_use]
#[derive(Debug, Serialize)]
pub struct PublicError {
    /// Stable machine-readable error code.
    pub code: &'static str,
    /// Human-readable message safe for client consumption.
    pub message: Cow<'static, str>,
    /// Optional request correlation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

impl PublicError {
    /// Creates a new [`PublicError`].
    pub fn new(
        code: &'static str,
        message: impl Into<Cow<'static, str>>,
        request_id: Option<RequestId>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            request_id,
        }
    }
}

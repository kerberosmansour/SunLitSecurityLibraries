//! CRLF injection prevention for HTTP header values.

use crate::{
    attack_signal::{BoundaryViolation, ViolationKind},
    error::BoundaryRejection,
};

/// Validates a string intended for use as an HTTP header value.
///
/// Rejects any value containing `\r` (CR) or `\n` (LF), which could be used
/// for HTTP response splitting / CRLF injection attacks.
///
/// Returns the original string unchanged if it is safe, or [`BoundaryRejection::InvalidHeaderValue`]
/// if it contains control characters.
///
/// # Errors
///
/// Returns [`BoundaryRejection::InvalidHeaderValue`] when the value contains
/// `\r` or `\n`.
///
/// # Examples
///
/// ```
/// use secure_boundary::header_sanitize::sanitize_header_value;
///
/// assert!(sanitize_header_value("safe-value").is_ok());
/// assert!(sanitize_header_value("evil\r\ninjection").is_err());
/// ```
pub fn sanitize_header_value(value: &str) -> Result<String, BoundaryRejection> {
    if value.contains('\r') || value.contains('\n') {
        BoundaryViolation::new(ViolationKind::SyntaxViolation, "crlf_injection").emit();
        return Err(BoundaryRejection::InvalidHeaderValue);
    }
    Ok(value.to_owned())
}

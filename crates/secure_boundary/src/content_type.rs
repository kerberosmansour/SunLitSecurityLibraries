//! Allowlist-based Content-Type checking.

use mime::Mime;

/// Checks whether a `Content-Type` header value is in the provided allowlist.
///
/// # Errors
/// - `"content_type_missing"` — the header value was absent.
/// - `"content_type_invalid"` — the header value could not be parsed as a MIME type.
/// - `"content_type_not_allowed"` — the MIME type is not present in `allowlist`.
pub fn check_content_type(
    content_type: Option<&str>,
    allowlist: &[&str],
) -> Result<(), &'static str> {
    let ct = content_type.ok_or("content_type_missing")?;
    let mime: Mime = ct.parse().map_err(|_| "content_type_invalid")?;
    let essence = format!("{}/{}", mime.type_(), mime.subtype());
    if allowlist.iter().any(|allowed| *allowed == essence) {
        Ok(())
    } else {
        Err("content_type_not_allowed")
    }
}

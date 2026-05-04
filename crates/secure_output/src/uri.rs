//! URI scheme sanitiser.

/// Error type for URI scheme validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DangerousUriScheme {
    /// The scheme that was rejected.
    pub scheme: String,
}

impl std::fmt::Display for DangerousUriScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dangerous URI scheme rejected: {}", self.scheme)
    }
}

impl std::error::Error for DangerousUriScheme {}

/// Blocked URI schemes (case-insensitive).
const BLOCKED_SCHEMES: &[&str] = &["javascript", "data", "vbscript", "file", "blob"];

/// Validates that `uri` does not use a dangerous scheme.
///
/// Allowed: `https`, `http`, `mailto`, relative URIs (no scheme), and empty strings.
/// Blocked: `javascript:`, `data:`, `vbscript:`, `file:`, `blob:` (and case variants).
///
/// # Errors
///
/// Returns [`DangerousUriScheme`] when the URI uses a blocked scheme.
///
/// # Examples
///
/// ```
/// use secure_output::uri::sanitize_uri_scheme;
///
/// assert!(sanitize_uri_scheme("https://example.com").is_ok());
/// assert!(sanitize_uri_scheme("javascript:alert(1)").is_err());
/// ```
pub fn sanitize_uri_scheme(uri: &str) -> Result<(), DangerousUriScheme> {
    // Relative URIs and empty strings have no scheme — always safe.
    if uri.is_empty() || uri.starts_with('/') || uri.starts_with('#') || uri.starts_with('?') {
        return Ok(());
    }

    // Extract scheme: everything before the first ':'.
    if let Some(colon_pos) = uri.find(':') {
        let scheme = &uri[..colon_pos];
        // Schemes must be purely ASCII alpha (plus digits/+/-/. after first char per RFC 3986).
        // If the extracted "scheme" contains a slash, it's a relative-path — no scheme.
        if scheme.contains('/') {
            return Ok(());
        }
        let scheme_lower = scheme.to_ascii_lowercase();
        if BLOCKED_SCHEMES.contains(&scheme_lower.as_str()) {
            return Err(DangerousUriScheme {
                scheme: scheme_lower,
            });
        }
    }

    Ok(())
}

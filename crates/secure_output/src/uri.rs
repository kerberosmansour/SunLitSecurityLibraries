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

/// Schemes approved for browser `href`/`src` use by this validator.
const ALLOWED_SCHEMES: &[&str] = &["http", "https", "mailto"];

fn rejected(scheme: &str) -> DangerousUriScheme {
    DangerousUriScheme {
        scheme: scheme.to_owned(),
    }
}

/// Validates that `uri` does not use a dangerous scheme.
///
/// Allowed: `https`, `http`, `mailto`, well-formed relative references, and empty
/// strings. Every other explicit scheme and ambiguous browser syntax is rejected.
///
/// This validates URI syntax only. Encode the accepted value for its output
/// context (for example with `HtmlEncoder` before placing it in an HTML
/// attribute).
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
    // Browsers discard or reinterpret these characters during URL and HTML
    // parsing. Reject them before scheme inspection so the validated bytes are
    // the bytes a downstream parser receives.
    if uri.chars().any(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, '\\' | '"' | '\'' | '`' | '<' | '>')
    }) {
        return Err(rejected("invalid"));
    }

    if uri.is_empty() {
        return Ok(());
    }

    // Network-path references inherit the document's scheme and can cross
    // origins. Root-relative, query-only and fragment-only references remain
    // valid after the syntax checks above.
    if uri.starts_with("//") {
        return Err(rejected("network-path"));
    }
    if uri.starts_with('/') || uri.starts_with('#') || uri.starts_with('?') {
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
        let valid_scheme = scheme.chars().enumerate().all(|(index, c)| {
            c.is_ascii_alphabetic() || (index > 0 && matches!(c, '0'..='9' | '+' | '-' | '.'))
        });
        if !valid_scheme {
            return Err(rejected("invalid"));
        }
        let scheme_lower = scheme.to_ascii_lowercase();
        if !ALLOWED_SCHEMES.contains(&scheme_lower.as_str()) {
            return Err(rejected(&scheme_lower));
        }
    }

    Ok(())
}

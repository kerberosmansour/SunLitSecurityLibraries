//! HTML sanitization for accepting user-provided rich text safely (OWASP C3).
//!
//! Wraps the [`ammonia`] crate with secure defaults.  Use [`sanitize_html`] for
//! quick sanitization with the default allowlist, or build a [`SanitizeConfig`]
//! to customise which tags and attributes are permitted.
//!
//! # Why sanitization, not encoding?
//!
//! Output encoding (e.g. `secure_output::html::encode`) converts *all* HTML
//! characters to entities — suitable when no HTML should render.  Sanitization
//! keeps a *safe subset* of HTML intact (bold, italic, links, etc.) while
//! stripping dangerous elements (scripts, event handlers, `javascript:` URIs).
//! This is the correct control for WYSIWYG editors and user-authored HTML.
//!
//! # Examples
//!
//! ```
//! use secure_boundary::sanitize::{sanitize_html, SanitizeConfig};
//!
//! // Default sanitization — safe tags preserved, scripts removed
//! let safe = sanitize_html("<p>Hello</p><script>alert(1)</script>");
//! assert_eq!(safe, "<p>Hello</p>");
//!
//! // Custom allow-list — only <b> and <i>
//! let config = SanitizeConfig::new().allowed_tags(&["b", "i"]);
//! let safe = config.sanitize("<p>Hello <b>bold</b></p>");
//! assert!(safe.contains("<b>bold</b>"));
//! assert!(!safe.contains("<p>"));
//! ```

use std::collections::HashSet;

/// Sanitizes HTML using secure defaults.
///
/// Strips dangerous elements (scripts, event handlers, `javascript:` URIs)
/// while preserving a safe subset of HTML tags and attributes as defined by
/// [`ammonia::Builder::default`].
///
/// This is the primary convenience API — use it for typical WYSIWYG input.
///
/// # Examples
///
/// ```
/// use secure_boundary::sanitize::sanitize_html;
///
/// let safe = sanitize_html("<p>Hello</p><script>alert(1)</script>");
/// assert_eq!(safe, "<p>Hello</p>");
/// ```
///
/// # Errors
///
/// This function is infallible — invalid HTML is cleaned, never rejected.
#[must_use]
pub fn sanitize_html(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    ammonia::clean(input)
}

/// Configuration for HTML sanitization with a custom tag/attribute allowlist.
///
/// Build via [`SanitizeConfig::new`] and chain builder methods.
///
/// # Examples
///
/// ```
/// use secure_boundary::sanitize::SanitizeConfig;
///
/// let config = SanitizeConfig::new().allowed_tags(&["b", "i", "em"]);
/// let safe = config.sanitize("<p>Hello <b>bold</b></p>");
/// assert!(safe.contains("<b>bold</b>"));
/// assert!(!safe.contains("<p>"));
/// ```
#[derive(Clone, Debug)]
pub struct SanitizeConfig {
    tags: Option<HashSet<String>>,
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SanitizeConfig {
    /// Creates a new [`SanitizeConfig`] with default (ammonia) settings.
    #[must_use]
    pub fn new() -> Self {
        Self { tags: None }
    }

    /// Restricts the set of allowed HTML tags.
    ///
    /// Only the listed tags will be preserved; all others are stripped.
    /// Tag names are case-insensitive.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().allowed_tags(&["b", "i"]);
    /// let safe = config.sanitize("<div><b>bold</b></div>");
    /// assert!(safe.contains("<b>bold</b>"));
    /// assert!(!safe.contains("<div>"));
    /// ```
    #[must_use]
    pub fn allowed_tags(mut self, tags: &[&str]) -> Self {
        self.tags = Some(tags.iter().map(|t| t.to_lowercase()).collect());
        self
    }

    /// Sanitizes `input` using this configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().allowed_tags(&["em"]);
    /// let safe = config.sanitize("<p><em>hi</em></p>");
    /// assert_eq!(safe, "<em>hi</em>");
    /// ```
    #[must_use]
    pub fn sanitize(&self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }
        match &self.tags {
            Some(tags) => {
                let mut builder = ammonia::Builder::default();
                let tag_refs: HashSet<&str> = tags.iter().map(String::as_str).collect();
                builder.tags(tag_refs);
                builder.clean(input).to_string()
            }
            None => ammonia::clean(input),
        }
    }
}

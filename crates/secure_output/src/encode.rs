//! Output encoder trait.

use std::borrow::Cow;

/// Trait for encoding output values for safe rendering in a target context.
///
/// Implementors should return `Cow::Borrowed` when no encoding is necessary
/// (zero-allocation fast path for already-safe strings).
///
/// This trait is intentionally **open** — consumers can add custom encodings.
///
/// # Examples
///
/// ```
/// use secure_output::encode::OutputEncoder;
/// use secure_output::HtmlEncoder;
/// use std::borrow::Cow;
///
/// let encoder = HtmlEncoder;
/// let safe: Cow<str> = encoder.encode("<b>");
/// assert_eq!(safe, "&lt;b&gt;");
/// ```
pub trait OutputEncoder {
    /// Encodes `input` for safe output in the target context.
    ///
    /// Returns a [`Cow<str>`] to allow zero-copy passthrough for safe strings.
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str>;
}

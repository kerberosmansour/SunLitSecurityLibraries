//! HTML context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe HTML rendering.
///
/// Encodes `<`, `>`, `&`, `"`, `'`, and `/` to their HTML entity equivalents.
/// Returns [`Cow::Borrowed`] when the input contains no characters needing encoding
/// (zero-allocation fast path). Strips null bytes (`\0`).
///
/// # Examples
///
/// ```
/// use secure_output::html;
///
/// let safe = html::encode("<script>alert(1)</script>");
/// assert_eq!(safe, "&lt;script&gt;alert(1)&lt;&#x2F;script&gt;");
///
/// // Already-safe strings are zero-copy.
/// let safe = html::encode("hello");
/// assert_eq!(safe, "hello");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct HtmlEncoder;

fn needs_html_encoding(c: char) -> bool {
    matches!(c, '<' | '>' | '&' | '"' | '\'' | '/' | '\0')
}

impl OutputEncoder for HtmlEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.chars().any(needs_html_encoding) {
            return Cow::Borrowed(input);
        }
        let mut out = String::with_capacity(input.len() + 16);
        for c in input.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#x27;"),
                '/' => out.push_str("&#x2F;"),
                '\0' => {} // strip null bytes
                _ => out.push(c),
            }
        }
        Cow::Owned(out)
    }
}

/// Convenience free function for HTML encoding.
///
/// Equivalent to `HtmlEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::html;
///
/// assert_eq!(html::encode("<b>hi</b>"), "&lt;b&gt;hi&lt;&#x2F;b&gt;");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    HtmlEncoder.encode(input)
}

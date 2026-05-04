//! CSS context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe embedding in CSS contexts.
///
/// Any character that is not an ASCII alphanumeric, hyphen, or underscore
/// is escaped using CSS unicode-escape notation (`\XXXXXX`). Null bytes are stripped.
/// Returns [`Cow::Borrowed`] when the input needs no encoding (pure alphanumeric/safe).
///
/// # Examples
///
/// ```
/// use secure_output::css;
///
/// let safe = css::encode("expression(alert(1))");
/// assert!(safe.contains("\\")); // parentheses are escaped
///
/// let safe = css::encode("safe-name_123");
/// assert_eq!(safe, "safe-name_123");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct CssEncoder;

fn needs_css_encoding(c: char) -> bool {
    !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_')
}

impl OutputEncoder for CssEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.chars().any(needs_css_encoding) {
            return Cow::Borrowed(input);
        }
        let mut out = String::with_capacity(input.len() * 4);
        for c in input.chars() {
            if c == '\0' {
                // strip null bytes
            } else if needs_css_encoding(c) {
                // CSS unicode escape: \XXXXXX (6 hex digits)
                let code = c as u32;
                out.push_str(&format!("\\{code:06x}"));
            } else {
                out.push(c);
            }
        }
        Cow::Owned(out)
    }
}

/// Convenience free function for CSS context encoding.
///
/// Equivalent to `CssEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::css;
///
/// let safe = css::encode("normal");
/// assert_eq!(safe, "normal");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    CssEncoder.encode(input)
}

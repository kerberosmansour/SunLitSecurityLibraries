//! XML context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe embedding in XML text content and attribute values.
///
/// Encodes `<`, `>`, `&`, `"`, and `'` to their XML entity equivalents.
/// Strips null bytes (`\0`). Returns [`Cow::Borrowed`] for strings that need
/// no encoding (zero-allocation fast path).
///
/// # Examples
///
/// ```
/// use secure_output::xml;
///
/// let safe = xml::encode("<hello>&world</hello>");
/// assert_eq!(safe, "&lt;hello&gt;&amp;world&lt;/hello&gt;");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct XmlEncoder;

fn needs_xml_encoding(c: char) -> bool {
    matches!(c, '<' | '>' | '&' | '"' | '\'' | '\0')
}

impl OutputEncoder for XmlEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.chars().any(needs_xml_encoding) {
            return Cow::Borrowed(input);
        }
        let mut out = String::with_capacity(input.len() + 16);
        for c in input.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                '\0' => {} // strip null bytes
                _ => out.push(c),
            }
        }
        Cow::Owned(out)
    }
}

/// Convenience free function for XML encoding.
///
/// Equivalent to `XmlEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::xml;
///
/// assert_eq!(xml::encode("a & b"), "a &amp; b");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    XmlEncoder.encode(input)
}

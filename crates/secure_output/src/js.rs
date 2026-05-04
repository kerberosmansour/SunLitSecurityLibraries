//! JavaScript string context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe embedding inside JavaScript string literals.
///
/// Escapes: `\`, `'`, `"`, `\n`, `\r`, U+2028 (line separator),
/// U+2029 (paragraph separator). Strips null bytes (`\0`).
/// Returns [`Cow::Borrowed`] when the input needs no encoding.
///
/// # Examples
///
/// ```
/// use secure_output::js;
///
/// let safe = js::encode("hello\nworld");
/// assert_eq!(safe, "hello\\nworld");
///
/// let safe = js::encode("it's \"fine\"");
/// assert_eq!(safe, "it\\'s \\\"fine\\\"");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct JsStringEncoder;

fn needs_js_encoding(c: char) -> bool {
    matches!(
        c,
        '\\' | '\'' | '"' | '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\0'
    )
}

impl OutputEncoder for JsStringEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.chars().any(needs_js_encoding) {
            return Cow::Borrowed(input);
        }
        let mut out = String::with_capacity(input.len() + 16);
        for c in input.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\'' => out.push_str("\\'"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\u{2028}' => out.push_str("\\u2028"),
                '\u{2029}' => out.push_str("\\u2029"),
                '\0' => {} // strip null bytes
                _ => out.push(c),
            }
        }
        Cow::Owned(out)
    }
}

/// Convenience free function for JavaScript string encoding.
///
/// Equivalent to `JsStringEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::js;
///
/// assert_eq!(js::encode("line\nbreak"), "line\\nbreak");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    JsStringEncoder.encode(input)
}

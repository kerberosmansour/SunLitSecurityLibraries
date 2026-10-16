//! JavaScript string context encoders.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for JavaScript string literals outside HTML raw-text.
///
/// Escapes: `\`, `'`, `"`, `\n`, `\r`, U+2028 (line separator),
/// U+2029 (paragraph separator). Strips null bytes (`\0`).
/// Returns [`Cow::Borrowed`] when the input needs no encoding.
///
/// This encoder does not protect an HTML `<script>` raw-text boundary. Use
/// [`InlineScriptStringEncoder`] when the JavaScript string is embedded in an
/// HTML script element.
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

fn needs_inline_script_encoding(c: char) -> bool {
    needs_js_encoding(c) || matches!(c, '<' | '>' | '&')
}

fn encode_javascript_string(input: &str, inline_script: bool) -> Cow<'_, str> {
    let needs_encoding = if inline_script {
        needs_inline_script_encoding
    } else {
        needs_js_encoding
    };

    if !input.chars().any(needs_encoding) {
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
            '<' if inline_script => out.push_str("\\u003C"),
            '>' if inline_script => out.push_str("\\u003E"),
            '&' if inline_script => out.push_str("\\u0026"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

impl OutputEncoder for JsStringEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        encode_javascript_string(input, false)
    }
}

/// Encodes a JavaScript string literal inside an HTML `<script>` element.
///
/// In addition to JavaScript string-literal escaping, this encoder represents
/// `<`, `>` and `&` as JavaScript Unicode escapes. The HTML tokenizer therefore
/// cannot interpret attacker text as a script end tag or other raw-text markup.
/// Strips null bytes (`\0`) and returns [`Cow::Borrowed`] when no encoding is
/// required.
///
/// This type encodes a string value. It does not serialize arbitrary values as
/// JSON, supply surrounding quotes, or install a Content Security Policy.
///
/// # Examples
///
/// ```
/// use secure_output::{InlineScriptStringEncoder, OutputEncoder};
///
/// let safe = InlineScriptStringEncoder.encode("</script><script>marker()</script>");
/// assert_eq!(
///     safe,
///     r"\u003C/script\u003E\u003Cscript\u003Emarker()\u003C/script\u003E"
/// );
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct InlineScriptStringEncoder;

impl OutputEncoder for InlineScriptStringEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        encode_javascript_string(input, true)
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

/// Convenience function for a JavaScript string inside an HTML script element.
///
/// Equivalent to `InlineScriptStringEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::js;
///
/// assert_eq!(js::encode_inline_script("<tag>"), r"\u003Ctag\u003E");
/// ```
#[must_use]
pub fn encode_inline_script(input: &str) -> Cow<'_, str> {
    InlineScriptStringEncoder.encode(input)
}

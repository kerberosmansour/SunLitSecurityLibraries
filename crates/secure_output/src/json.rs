//! JSON context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes an already serialized JSON document for embedding in HTML.
///
/// Replaces `</` with `<\/` to prevent `</script>` injection when JSON is
/// embedded directly in HTML `<script>` blocks. Strips null bytes (`\0`).
///
/// This encoder does not serialize an arbitrary string or validate JSON grammar.
/// Establish one complete JSON document with a serializer before applying this
/// HTML-boundary transformation.
///
/// Returns [`Cow::Borrowed`] when the input needs no encoding.
///
/// # Examples
///
/// ```
/// use secure_output::json;
///
/// let serialized = r#"{"name":"</script>"}"#;
/// let safe = json::encode(serialized);
/// assert_eq!(safe, r#"{"name":"<\/script>"}"#);
///
/// let safe = json::encode("safe value");
/// assert_eq!(safe, "safe value");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonEncoder;

impl OutputEncoder for JsonEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.contains("</") && !input.contains('\0') {
            return Cow::Borrowed(input);
        }
        let no_nulls: String = input.chars().filter(|&c| c != '\0').collect();
        let result = no_nulls.replace("</", "<\\/");
        Cow::Owned(result)
    }
}

/// Convenience function for already serialized JSON embedded in HTML.
///
/// Equivalent to `JsonEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::json;
///
/// let serialized = r#"{"name":"</script>"}"#;
/// assert_eq!(json::encode(serialized), r#"{"name":"<\/script>"}"#);
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    JsonEncoder.encode(input)
}

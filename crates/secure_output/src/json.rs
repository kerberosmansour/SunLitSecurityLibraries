//! JSON context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe inclusion in JSON values embedded in HTML.
///
/// Replaces `</` with `<\/` to prevent `</script>` injection when JSON is
/// embedded directly in HTML `<script>` blocks. Strips null bytes (`\0`).
///
/// Returns [`Cow::Borrowed`] when the input needs no encoding.
///
/// # Examples
///
/// ```
/// use secure_output::json;
///
/// let safe = json::encode("</script>");
/// assert_eq!(safe, "<\\/script>");
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

/// Convenience free function for JSON-in-HTML encoding.
///
/// Equivalent to `JsonEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::json;
///
/// assert_eq!(json::encode("</script>"), "<\\/script>");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    JsonEncoder.encode(input)
}

//! Log-injection sanitization helpers.

/// Sanitizes a string for safe emission to a text-based log sink.
///
/// - Replaces `\n` (0x0A) with the two-char literal `\n`.
/// - Replaces `\r` (0x0D) with the two-char literal `\r`.
/// - Replaces all other ASCII control characters (0x00–0x1F) with U+FFFD.
///
/// # Examples
///
/// ```
/// use security_events::sanitize::sanitize_for_text_sink;
///
/// let safe = sanitize_for_text_sink("event\ninjection\r");
/// assert_eq!(safe, "event\\ninjection\\r");
/// ```
#[must_use]
pub fn sanitize_for_text_sink(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            c if (c as u32) < 0x20 => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

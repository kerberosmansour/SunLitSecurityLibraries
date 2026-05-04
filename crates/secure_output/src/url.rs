//! URL context encoder.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe inclusion in URLs (percent-encoding per RFC 3986).
///
/// Only unreserved characters (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`) are
/// passed through unchanged. All other bytes are percent-encoded with uppercase
/// hex digits. Null bytes are stripped (not percent-encoded as `%00`).
///
/// Returns [`Cow::Borrowed`] when the input contains only unreserved characters.
///
/// # Examples
///
/// ```
/// use secure_output::url;
///
/// let safe = url::encode("hello world");
/// assert_eq!(safe, "hello%20world");
///
/// let safe = url::encode("safe-value_123");
/// assert_eq!(safe, "safe-value_123");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct UrlEncoder;

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

impl OutputEncoder for UrlEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let needs = input.bytes().any(|b| !is_unreserved(b));
        if !needs {
            return Cow::Borrowed(input);
        }
        let mut out = String::with_capacity(input.len() * 2);
        for b in input.bytes() {
            if b == 0 {
                // strip null bytes
                continue;
            }
            if is_unreserved(b) {
                out.push(b as char);
            } else {
                let hi = char::from_digit(u32::from(b >> 4), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase();
                let lo = char::from_digit(u32::from(b & 0xF), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase();
                out.push('%');
                out.push(hi);
                out.push(lo);
            }
        }
        Cow::Owned(out)
    }
}

/// Convenience free function for URL percent-encoding.
///
/// Equivalent to `UrlEncoder.encode(input)`.
///
/// # Examples
///
/// ```
/// use secure_output::url;
///
/// assert_eq!(url::encode("a b"), "a%20b");
/// ```
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    UrlEncoder.encode(input)
}

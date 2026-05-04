//! LDAP output encoders for DN (RFC 4514) and filter (RFC 4515) contexts.
//!
//! Provides two encoders:
//! - [`LdapDnEncoder`] — escapes characters special in LDAP Distinguished Names
//! - [`LdapFilterEncoder`] — hex-escapes characters special in LDAP search filters
//!
//! Both implement the [`OutputEncoder`] trait for generic contexts, but the
//! **primary API is convenience free functions**: [`encode_dn()`] and [`encode_filter()`].
//!
//! # LDAP DN encoding (RFC 4514)
//!
//! The following characters are backslash-escaped: `,`, `+`, `"`, `\`, `<`, `>`, `;`, `=`, `#`
//! (when leading). Leading and trailing spaces are escaped. Null bytes are hex-escaped as `\00`.
//!
//! # LDAP filter encoding (RFC 4515)
//!
//! The following characters are hex-escaped: `*`, `(`, `)`, `\`, NUL (`\x00`).

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe use in LDAP Distinguished Name components (RFC 4514).
///
/// Escapes the special characters `,`, `+`, `"`, `\`, `<`, `>`, `;`, and `=`.
/// Leading `#` and leading/trailing spaces are also escaped. Null bytes are
/// hex-escaped as `\00`.
///
/// Returns [`Cow::Borrowed`] when the input needs no encoding (zero-allocation
/// fast path).
///
/// # Examples
///
/// ```
/// use secure_output::ldap::LdapDnEncoder;
/// use secure_output::encode::OutputEncoder;
///
/// let encoder = LdapDnEncoder;
/// assert_eq!(encoder.encode("John Smith"), "John Smith");
/// assert_eq!(encoder.encode("a+b,c=d"), "a\\+b\\,c\\=d");
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[must_use]
pub struct LdapDnEncoder;

/// Characters that must be backslash-escaped in DN attribute values per RFC 4514 §2.4.
fn is_dn_special(c: char) -> bool {
    matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' | '\0')
}

/// Returns `true` if the input requires any DN encoding.
fn needs_dn_encoding(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    let first = input.as_bytes()[0];
    let last = input.as_bytes()[input.len() - 1];
    if first == b' ' || first == b'#' || last == b' ' {
        return true;
    }
    input.chars().any(is_dn_special)
}

fn encode_dn_inner(input: &str) -> String {
    let len = input.len();
    let mut out = String::with_capacity(len + 16);
    for (i, c) in input.char_indices() {
        match c {
            '\0' => out.push_str("\\00"),
            _ if is_dn_special(c) => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => {
                out.push('\\');
                out.push('#');
            }
            ' ' if i == 0 || i == len - 1 => {
                out.push('\\');
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

impl OutputEncoder for LdapDnEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !needs_dn_encoding(input) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(encode_dn_inner(input))
    }
}

/// Encodes a string for safe use in an LDAP Distinguished Name component (RFC 4514).
///
/// This is the primary convenience API. It delegates to [`LdapDnEncoder`] but
/// does not require constructing an encoder instance.
///
/// # Examples
///
/// ```
/// use secure_output::ldap::encode_dn;
///
/// assert_eq!(encode_dn("John Smith"), "John Smith");
/// assert_eq!(encode_dn("a+b,c=d"), "a\\+b\\,c\\=d");
/// assert_eq!(encode_dn(" admin "), "\\ admin\\ ");
/// ```
///
/// # Errors
///
/// This function is infallible — it always returns a valid encoded string.
#[must_use]
pub fn encode_dn(input: &str) -> Cow<'_, str> {
    LdapDnEncoder.encode(input)
}

// ──────────────────────────────────────────────
// LDAP Filter Encoder (RFC 4515)
// ──────────────────────────────────────────────

/// Encodes strings for safe use in LDAP search filter assertions (RFC 4515).
///
/// Hex-escapes the characters `*`, `(`, `)`, `\`, and NUL (`\x00`) using the
/// `\XX` notation defined in RFC 4515 §3.
///
/// Returns [`Cow::Borrowed`] when the input needs no encoding.
///
/// # Examples
///
/// ```
/// use secure_output::ldap::LdapFilterEncoder;
/// use secure_output::encode::OutputEncoder;
///
/// let encoder = LdapFilterEncoder;
/// assert_eq!(encoder.encode("john"), "john");
/// assert_eq!(encoder.encode("user*admin"), "user\\2aadmin");
/// assert_eq!(encoder.encode("(admin)"), "\\28admin\\29");
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[must_use]
pub struct LdapFilterEncoder;

/// Characters that must be hex-escaped in LDAP filter values per RFC 4515 §3.
fn is_filter_special(c: char) -> bool {
    matches!(c, '*' | '(' | ')' | '\\' | '\0')
}

fn encode_filter_inner(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for c in input.chars() {
        if is_filter_special(c) {
            // Hex-escape as \XX (two lowercase hex digits of the byte value)
            for byte in c.to_string().as_bytes() {
                out.push_str(&format!("\\{byte:02x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl OutputEncoder for LdapFilterEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if !input.chars().any(is_filter_special) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(encode_filter_inner(input))
    }
}

/// Encodes a string for safe use in an LDAP search filter assertion (RFC 4515).
///
/// This is the primary convenience API. It delegates to [`LdapFilterEncoder`]
/// but does not require constructing an encoder instance.
///
/// # Examples
///
/// ```
/// use secure_output::ldap::encode_filter;
///
/// assert_eq!(encode_filter("john"), "john");
/// assert_eq!(encode_filter("user*admin"), "user\\2aadmin");
/// assert_eq!(encode_filter("(admin)"), "\\28admin\\29");
/// ```
///
/// # Errors
///
/// This function is infallible — it always returns a valid encoded string.
#[must_use]
pub fn encode_filter(input: &str) -> Cow<'_, str> {
    LdapFilterEncoder.encode(input)
}

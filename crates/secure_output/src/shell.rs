//! OS shell context encoder.
//!
//! Provides [`ShellEncoder`] for escaping strings intended for use as arguments
//! in POSIX shell contexts, and the convenience free function [`encode()`].
//!
//! The encoding strategy is single-quoting: the input is wrapped in single
//! quotes (`'...'`), and any embedded single quotes are escaped as `'\''`
//! (end quote, escaped literal quote, restart quote). This is the safest
//! POSIX shell quoting mechanism — inside single quotes, no metacharacters
//! are interpreted.
//!
//! Null bytes are stripped because they cannot appear in POSIX shell arguments.
//!
//! Empty input returns an empty string (not `''`), because encoding an
//! absent value should produce an absent value.
//!
//! # Security note
//!
//! Output encoding for shell contexts is a defense-in-depth measure. Where
//! possible, prefer passing arguments via `std::process::Command` argument
//! arrays rather than interpolating into shell strings.

use std::borrow::Cow;

use crate::encode::OutputEncoder;

/// Encodes strings for safe embedding as arguments in POSIX shell commands.
///
/// Uses single-quoting to prevent interpretation of all shell metacharacters
/// (`;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `<`, `>`, `!`, `~`, `{`, `}`,
/// `[`, `]`, `*`, `?`, `#`, `\n`, `\r`, `\\`, `"`, spaces, tabs, etc.).
///
/// The only character that needs special handling inside single quotes is
/// the single quote itself, which is escaped as `'\''`.
///
/// Returns [`Cow::Borrowed`] when the input consists entirely of shell-safe
/// characters (alphanumeric, `-`, `_`, `.`, `/`, `:`, `@`).
///
/// # Examples
///
/// ```
/// use secure_output::shell::ShellEncoder;
/// use secure_output::encode::OutputEncoder;
///
/// let encoder = ShellEncoder;
/// assert_eq!(encoder.encode("backup-2024"), "backup-2024");
/// assert_eq!(encoder.encode("file; rm -rf /"), "'file; rm -rf /'");
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[must_use]
pub struct ShellEncoder;

/// Characters that are safe in a POSIX shell argument without quoting.
fn is_shell_safe(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '/' | ':' | '@')
}

fn encode_shell_inner(input: &str) -> String {
    // Strip null bytes first
    let cleaned: String = input.chars().filter(|&c| c != '\0').collect();
    if cleaned.is_empty() {
        return String::new();
    }
    // If all safe after null stripping, return as-is
    if cleaned.chars().all(is_shell_safe) {
        return cleaned;
    }
    // Single-quote the entire string, escaping embedded single quotes
    let mut out = String::with_capacity(cleaned.len() + 4);
    out.push('\'');
    for c in cleaned.chars() {
        if c == '\'' {
            // End current quote, add escaped literal quote, restart quote
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

impl OutputEncoder for ShellEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if input.is_empty() {
            return Cow::Borrowed(input);
        }
        // Fast path: no null bytes and all safe chars
        if !input.contains('\0') && input.chars().all(is_shell_safe) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(encode_shell_inner(input))
    }
}

/// Encodes a string for safe use as a POSIX shell argument.
///
/// This is the primary convenience API. It delegates to [`ShellEncoder`] but
/// does not require constructing an encoder instance.
///
/// # Examples
///
/// ```
/// use secure_output::shell::encode;
///
/// assert_eq!(encode("backup-2024"), "backup-2024");
/// assert_eq!(encode("file; rm -rf /"), "'file; rm -rf /'");
/// assert_eq!(encode("it's"), "'it'\\''s'");
/// ```
///
/// # Errors
///
/// This function is infallible — it always returns a valid encoded string.
///
/// # Security note
///
/// Prefer `std::process::Command` argument arrays over shell string interpolation
/// where possible. Use this encoder as defense-in-depth when shell invocation is
/// unavoidable.
#[must_use]
pub fn encode(input: &str) -> Cow<'_, str> {
    ShellEncoder.encode(input)
}

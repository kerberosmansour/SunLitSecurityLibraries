//! Input normalization: Unicode NFC, whitespace trimming, email case normalization.

use unicode_normalization::UnicodeNormalization;

/// Normalizes a string to Unicode NFC (Canonical Decomposition, followed by Canonical Composition).
///
/// Ensures consistent representation of composed vs decomposed Unicode characters,
/// preventing normalization-based injection attacks.
///
/// # Examples
///
/// ```
/// use secure_boundary::normalize::to_nfc;
///
/// // Composed and decomposed forms are normalised to the same output.
/// let result = to_nfc("caf\u{00e9}"); // 'é' precomposed
/// assert_eq!(result, "café");
/// ```
#[must_use]
pub fn to_nfc(input: &str) -> String {
    input.nfc().collect()
}

/// Trims leading and trailing ASCII whitespace from a string.
///
/// # Examples
///
/// ```
/// use secure_boundary::normalize::trim_whitespace;
///
/// assert_eq!(trim_whitespace("  hello  "), "hello");
/// ```
#[must_use]
pub fn trim_whitespace(input: &str) -> String {
    input.trim().to_owned()
}

/// Normalizes an email address: trims whitespace and lowercases the domain portion.
///
/// Per RFC 5321, only the domain portion is case-insensitive. The local part
/// (before `@`) is preserved as-is.
///
/// # Examples
///
/// ```
/// use secure_boundary::normalize::normalize_email;
///
/// assert_eq!(normalize_email("Alice@EXAMPLE.COM"), "Alice@example.com");
/// ```
#[must_use]
pub fn normalize_email(input: &str) -> String {
    let trimmed = input.trim();
    if let Some(at_pos) = trimmed.rfind('@') {
        let local = &trimmed[..at_pos];
        let domain = &trimmed[at_pos + 1..];
        format!("{}@{}", local, domain.to_lowercase())
    } else {
        trimmed.to_owned()
    }
}

/// Applies all normalizations: Unicode NFC, whitespace trimming, and optional email normalization.
///
/// If `is_email` is `true`, also applies [`normalize_email`] to lowercase the domain.
///
/// # Examples
///
/// ```
/// use secure_boundary::normalize::normalize;
///
/// let result = normalize("  hello  ", false);
/// assert_eq!(result, "hello");
///
/// let email = normalize("  User@EXAMPLE.COM  ", true);
/// assert_eq!(email, "User@example.com");
/// ```
#[must_use]
pub fn normalize(input: &str, is_email: bool) -> String {
    let nfc = to_nfc(input);
    let trimmed = nfc.trim().to_owned();
    if is_email {
        normalize_email(&trimmed)
    } else {
        trimmed
    }
}

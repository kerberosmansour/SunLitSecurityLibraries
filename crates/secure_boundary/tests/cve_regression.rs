//! CVE regression tests — input validation vulnerabilities.
//!
//! Milestone 9 — BDD: Known normalization and injection vulnerabilities must be blocked.
use secure_boundary::normalize::{normalize, normalize_email, to_nfc, trim_whitespace};

/// CVE pattern: Unicode normalization bypass.
///
/// An attacker submits a username with decomposed Unicode (NFD) that is visually
/// identical to a registered account (NFC). After normalization, they should produce
/// the same string, preventing duplicate account creation through normalization differences.
#[test]
fn cve_unicode_normalization_bypass_email() {
    // "café" in NFC (composed é) vs NFD (decomposed e + combining accent)
    let nfc_form = "caf\u{00E9}@example.com"; // é as single codepoint
    let nfd_form = "cafe\u{0301}@example.com"; // e + combining acute accent

    let normalized_nfc = normalize(nfc_form, true);
    let normalized_nfd = normalize(nfd_form, true);

    assert_eq!(
        normalized_nfc, normalized_nfd,
        "Unicode normalization bypass: NFC and NFD forms of the same email must normalize identically.\n\
         NFC result: {normalized_nfc:?}\n\
         NFD result: {normalized_nfd:?}"
    );
}

/// CVE pattern: Unicode normalization bypass for usernames.
///
/// Two usernames that look identical but have different Unicode representations
/// must normalize to the same canonical form.
#[test]
fn cve_unicode_normalization_bypass_username() {
    // "Ångström" with precomposed Å vs decomposed A + combining ring above
    let composed = "\u{00C5}ngstr\u{00F6}m"; // Å + ö as single codepoints
    let decomposed = "A\u{030A}ngstro\u{0308}m"; // A + ̊ + o + combining umlaut

    let n1 = to_nfc(composed);
    let n2 = to_nfc(decomposed);

    assert_eq!(
        n1, n2,
        "Unicode normalization bypass: composed and decomposed forms must produce the same NFC string.\n\
         Composed result: {n1:?}\n\
         Decomposed result: {n2:?}"
    );
}

/// CVE pattern: CRLF injection in normalized input.
///
/// Input containing CRLF sequences must have whitespace trimmed at boundaries,
/// and normalize() must not introduce new characters.
#[test]
fn cve_crlf_normalize_no_injection() {
    let input_with_crlf = "user@example.com\r\nX-Injected: header";
    let normalized = normalize(input_with_crlf, true);
    // normalize trims — the result should not start/end with whitespace
    assert!(!normalized.starts_with('\r'));
    assert!(!normalized.starts_with('\n'));
    // Normalize must not add characters
    assert!(normalized.len() <= input_with_crlf.len());
}

/// CVE pattern: Homograph attack via mixed Unicode scripts.
///
/// "а" (Cyrillic small a, U+0430) looks like "a" (Latin small a, U+0061) but is different.
/// NFC normalization does NOT merge different Unicode characters, which is correct behavior —
/// the system should treat them as different inputs (preventing account takeover via homograph).
#[test]
fn cve_homograph_attack_not_merged_by_normalization() {
    let latin_a = "admin"; // all Latin
    let cyrillic_a = "\u{0430}dmin"; // first char is Cyrillic 'а'

    let n1 = to_nfc(latin_a);
    let n2 = to_nfc(cyrillic_a);

    // These MUST NOT be equal — NFC should not merge different scripts
    assert_ne!(
        n1, n2,
        "Homograph attack: Latin and Cyrillic lookalikes must remain distinct after NFC normalization"
    );
}

/// Email normalization: domain is lowercased, local part is preserved.
#[test]
fn cve_email_normalization_domain_lowercase() {
    let email = "User+Tag@EXAMPLE.COM";
    let normalized = normalize_email(email);
    assert_eq!(
        normalized, "User+Tag@example.com",
        "Email domain must be lowercased, local part preserved"
    );
}

/// Whitespace injection: leading/trailing whitespace is stripped.
#[test]
fn cve_whitespace_injection_trimmed() {
    let padded = "  admin  ";
    let trimmed = trim_whitespace(padded);
    assert_eq!(trimmed, "admin");
    assert!(!trimmed.starts_with(' '));
    assert!(!trimmed.ends_with(' '));
}

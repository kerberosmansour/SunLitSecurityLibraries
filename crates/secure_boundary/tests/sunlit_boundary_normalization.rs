use secure_boundary::normalize::{normalize, normalize_email, to_nfc, trim_whitespace};

#[test]
fn test_nfc_normalization() {
    // é as decomposed (U+0065 U+0301) vs composed (U+00E9)
    let decomposed = "e\u{0301}"; // decomposed é
    let composed = "\u{00E9}"; // precomposed é
    let result = to_nfc(decomposed);
    assert_eq!(
        result, composed,
        "decomposed é should normalize to composed é"
    );
}

#[test]
fn test_whitespace_trimming() {
    let result = trim_whitespace("  Alice  ");
    assert_eq!(result, "Alice");
}

#[test]
fn test_whitespace_trimming_no_change() {
    let result = trim_whitespace("Alice");
    assert_eq!(result, "Alice");
}

#[test]
fn test_email_domain_lowercased() {
    let result = normalize_email("Alice@Example.COM");
    assert_eq!(result, "Alice@example.com");
}

#[test]
fn test_email_local_part_preserved() {
    // local part case is preserved per RFC 5321
    let result = normalize_email("Alice+Tag@EXAMPLE.COM");
    assert_eq!(result, "Alice+Tag@example.com");
}

#[test]
fn test_normalize_plain_string() {
    let result = normalize("  Alice  ", false);
    assert_eq!(result, "Alice");
}

#[test]
fn test_normalize_email_combined() {
    let result = normalize("  Alice@Example.COM  ", true);
    assert_eq!(result, "Alice@example.com");
}

#[test]
fn test_normalize_nfc_and_trim() {
    // decomposed é with surrounding whitespace
    let input = "  e\u{0301}  ";
    let result = normalize(input, false);
    assert_eq!(result, "\u{00E9}");
}

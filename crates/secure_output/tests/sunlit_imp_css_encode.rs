//! BDD scenarios: CssEncoder (M12)

use secure_output::CssEncoder;
use secure_output::OutputEncoder;
use std::borrow::Cow;

// Scenario: Alphanumeric unchanged (zero-copy)
#[test]
fn css_alphanumeric_unchanged() {
    let enc = CssEncoder;
    let result = enc.encode("red");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "expected Cow::Borrowed for pure alphanumeric input"
    );
    assert_eq!(result, "red");
}

// Scenario: Parentheses escaped
#[test]
fn css_parentheses_escaped() {
    let enc = CssEncoder;
    let result = enc.encode("expression(alert(1))");
    // Must not contain literal parentheses in the output
    assert!(
        !result.contains('('),
        "parentheses must be escaped: {result}"
    );
    assert!(
        !result.contains(')'),
        "parentheses must be escaped: {result}"
    );
}

// Scenario: Backslash escaped
#[test]
fn css_backslash_escaped() {
    let enc = CssEncoder;
    let result = enc.encode("a\\b");
    // The backslash must be escaped in CSS
    assert!(
        !result.contains("a\\b") || result.starts_with("a\\00"),
        "backslash must be escaped: {result}"
    );
    // Ensure the output contains the CSS unicode escape or doubled backslash
    assert!(
        result.contains("005c") || result.contains("\\\\"),
        "expected CSS escape for backslash: {result}"
    );
}

// Scenario: Null bytes stripped
#[test]
fn css_null_bytes_stripped() {
    let enc = CssEncoder;
    let result = enc.encode("color\0red");
    assert!(!result.contains('\0'));
}

// Scenario: Numbers remain unchanged
#[test]
fn css_numbers_unchanged() {
    let enc = CssEncoder;
    let result = enc.encode("123");
    assert!(matches!(result, Cow::Borrowed(_)));
    assert_eq!(result, "123");
}

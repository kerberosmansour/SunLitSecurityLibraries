//! BDD scenarios: JsStringEncoder (M12)

use secure_output::JsStringEncoder;
use secure_output::OutputEncoder;
use std::borrow::Cow;

// Scenario: Single quotes escaped
#[test]
fn js_single_quote_escaped() {
    let enc = JsStringEncoder;
    let result = enc.encode("it's a test");
    assert_eq!(result, r"it\'s a test");
}

// Scenario: Backslash escaped
#[test]
fn js_backslash_escaped() {
    let enc = JsStringEncoder;
    let result = enc.encode(r"path\to");
    assert_eq!(result, r"path\\to");
}

// Scenario: Newlines escaped
#[test]
fn js_newlines_escaped() {
    let enc = JsStringEncoder;
    let result = enc.encode("line1\nline2");
    assert_eq!(result, r"line1\nline2");
}

// Scenario: Carriage return escaped
#[test]
fn js_carriage_return_escaped() {
    let enc = JsStringEncoder;
    let result = enc.encode("line1\rline2");
    assert_eq!(result, r"line1\rline2");
}

// Scenario: Unicode line separator escaped (U+2028)
#[test]
fn js_unicode_line_separator_escaped() {
    let enc = JsStringEncoder;
    let input = "before\u{2028}after";
    let result = enc.encode(input);
    assert!(
        result.contains("\\u2028"),
        "expected \\u2028 in {:?}",
        result
    );
    assert!(!result.contains('\u{2028}'));
}

// Scenario: Unicode paragraph separator escaped (U+2029)
#[test]
fn js_unicode_paragraph_separator_escaped() {
    let enc = JsStringEncoder;
    let input = "before\u{2029}after";
    let result = enc.encode(input);
    assert!(
        result.contains("\\u2029"),
        "expected \\u2029 in {:?}",
        result
    );
    assert!(!result.contains('\u{2029}'));
}

// Scenario: Safe string zero-copy
#[test]
fn js_safe_string_zero_copy() {
    let enc = JsStringEncoder;
    let result = enc.encode("hello");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "expected Cow::Borrowed for safe input"
    );
}

// Scenario: Null bytes stripped
#[test]
fn js_null_bytes_stripped() {
    let enc = JsStringEncoder;
    let result = enc.encode("a\0b");
    assert!(!result.contains('\0'));
    assert_eq!(result, "ab");
}

// Scenario: Double quotes escaped
#[test]
fn js_double_quote_escaped() {
    let enc = JsStringEncoder;
    let result = enc.encode("say \"hello\"");
    assert_eq!(result, r#"say \"hello\""#);
}

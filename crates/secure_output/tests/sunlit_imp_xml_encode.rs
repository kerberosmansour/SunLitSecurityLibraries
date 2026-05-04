//! BDD scenarios: XmlEncoder (M12)

use secure_output::OutputEncoder;
use secure_output::XmlEncoder;
use std::borrow::Cow;

// Scenario: Angle brackets encoded
#[test]
fn xml_angle_brackets_encoded() {
    let enc = XmlEncoder;
    let result = enc.encode("<tag>");
    assert_eq!(result, "&lt;tag&gt;");
}

// Scenario: Ampersand encoded
#[test]
fn xml_ampersand_encoded() {
    let enc = XmlEncoder;
    let result = enc.encode("a&b");
    assert_eq!(result, "a&amp;b");
}

// Scenario: Double quotes encoded for attributes
#[test]
fn xml_double_quotes_encoded() {
    let enc = XmlEncoder;
    let result = enc.encode("\"value\"");
    assert_eq!(result, "&quot;value&quot;");
}

// Scenario: Single quotes encoded
#[test]
fn xml_single_quotes_encoded() {
    let enc = XmlEncoder;
    let result = enc.encode("it's");
    assert_eq!(result, "it&apos;s");
}

// Scenario: Safe string zero-copy
#[test]
fn xml_safe_string_zero_copy() {
    let enc = XmlEncoder;
    let result = enc.encode("hello world");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "expected Cow::Borrowed for safe input"
    );
}

// Scenario: Null bytes stripped
#[test]
fn xml_null_bytes_stripped() {
    let enc = XmlEncoder;
    let result = enc.encode("a\0b");
    assert!(!result.contains('\0'));
}

// Scenario: Combined dangerous chars
#[test]
fn xml_combined_dangerous_chars() {
    let enc = XmlEncoder;
    let result = enc.encode("<script>alert('xss')</script>");
    assert_eq!(
        result,
        "&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;"
    );
}

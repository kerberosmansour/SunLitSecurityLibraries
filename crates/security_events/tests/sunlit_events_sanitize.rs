//! BDD tests for log injection sanitization.

use security_events::sanitize::sanitize_for_text_sink;

#[test]
fn test_newline_sanitized() {
    let input = "foo\nbar";
    let output = sanitize_for_text_sink(input);
    assert!(!output.contains('\n'), "Should not contain literal newline");
    assert!(output.contains(r"\n"), "Should contain escaped newline");
}

#[test]
fn test_control_chars_stripped() {
    // 0x01 is a control char
    let input = "foo\x01bar";
    let output = sanitize_for_text_sink(input);
    assert!(!output.contains('\x01'), "Control char should be replaced");
    assert!(
        output.contains('\u{FFFD}'),
        "Should contain replacement char"
    );
}

#[test]
fn test_carriage_return_normalized() {
    let input = "foo\r\nbar";
    let output = sanitize_for_text_sink(input);
    assert!(!output.contains('\r'), "Should not contain literal CR");
    assert!(!output.contains('\n'), "Should not contain literal LF");
    assert!(output.contains(r"\r"), "Should contain escaped CR");
    assert!(output.contains(r"\n"), "Should contain escaped LF");
}

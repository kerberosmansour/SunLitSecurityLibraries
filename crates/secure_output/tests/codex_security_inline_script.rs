use secure_output::{InlineScriptStringEncoder, JsonEncoder, OutputEncoder};
use std::borrow::Cow;

#[test]
fn inline_script_string_rejects_html_raw_text_breakout_bytes() {
    let encoder = InlineScriptStringEncoder;

    for payload in [
        "</script><script>marker()</script>",
        "</ScRiPt><img src=x onerror=marker()>",
        "<!--</script>",
        "x & y > z < marker",
    ] {
        let encoded = encoder.encode(payload);
        assert!(
            !encoded.contains('<'),
            "literal '<' remained in {encoded:?}"
        );
        assert!(
            !encoded.contains('>'),
            "literal '>' remained in {encoded:?}"
        );
        assert!(
            !encoded.contains('&'),
            "literal '&' remained in {encoded:?}"
        );
    }

    assert_eq!(encoder.encode("</script>"), r"\u003C/script\u003E");
}

#[test]
fn inline_script_string_preserves_javascript_lexical_escaping() {
    let encoder = InlineScriptStringEncoder;
    let encoded = encoder.encode("'\"\\\n\r\u{2028}\u{2029}\0");

    assert_eq!(encoded, "\\'\\\"\\\\\\n\\r\\u2028\\u2029");
    assert!(!encoded.contains('\0'));
}

#[test]
fn inline_script_safe_text_remains_zero_copy() {
    let encoded = InlineScriptStringEncoder.encode("plain_identifier_123");
    assert!(matches!(encoded, Cow::Borrowed(_)));
}

#[test]
fn serialized_json_is_encoded_only_after_grammar_is_established() {
    // This is one complete JSON document produced before the HTML-boundary step.
    let serialized = r#"{"name":"</script><script>marker()</script>","expression":"alert(1)"}"#;
    let encoded = JsonEncoder.encode(serialized);

    assert!(!encoded.to_ascii_lowercase().contains("</script"));
    assert!(encoded.starts_with('{'));
    assert!(encoded.ends_with('}'));
    assert!(encoded.contains(r#""expression":"alert(1)""#));
}

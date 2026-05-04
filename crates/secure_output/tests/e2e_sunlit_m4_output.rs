use secure_output::{HtmlEncoder, JsonEncoder, OutputEncoder, UrlEncoder};

#[test]
fn test_json_encoding_prevents_injection() {
    let enc = JsonEncoder;
    let malicious = "</script><script>alert('xss')</script>";
    let encoded = enc.encode(malicious);
    assert!(
        !encoded.contains("</script>"),
        "raw </script> should not appear in encoded output"
    );
}

#[test]
fn test_html_encoding_prevents_xss() {
    let enc = HtmlEncoder;
    let xss = "<img src=x onerror=alert(1)>";
    let encoded = enc.encode(xss);
    assert!(
        !encoded.contains('<'),
        "raw < should not appear in HTML-encoded output"
    );
    assert!(
        !encoded.contains('>'),
        "raw > should not appear in HTML-encoded output"
    );
}

#[test]
fn test_url_encoding_roundtrip() {
    let enc = UrlEncoder;
    let input = "user name@domain.com";
    let encoded = enc.encode(input);
    assert_eq!(encoded, "user%20name%40domain.com");
}

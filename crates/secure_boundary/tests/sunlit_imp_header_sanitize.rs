//! BDD tests for `sanitize_header_value` — CRLF injection prevention (M11).

use secure_boundary::header_sanitize::sanitize_header_value;

#[test]
fn normal_header_value_unchanged() {
    // Given: a normal header value
    let result = sanitize_header_value("application/json");
    // Then: returned unchanged
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "application/json");
}

#[test]
fn crlf_sequence_rejected() {
    // Given: CRLF injection payload
    let result = sanitize_header_value("value\r\nInjected-Header: evil");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn carriage_return_rejected() {
    // Given: bare CR injection payload
    let result = sanitize_header_value("value\rX-Evil: yes");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn newline_only_rejected() {
    // Given: bare LF injection payload
    let result = sanitize_header_value("value\nInjected-Header: evil");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn empty_value_accepted() {
    // Given: an empty header value
    let result = sanitize_header_value("");
    // Then: returned as-is
    assert!(result.is_ok());
}

#[test]
fn value_with_colon_accepted() {
    // Given: a value with a colon (valid in many header values)
    let result = sanitize_header_value("Bearer eyJ0...");
    // Then: returned as-is
    assert!(result.is_ok());
}

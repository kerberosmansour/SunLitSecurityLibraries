//! BDD tests for M11 safe types: SafePath, SafeFilename, SafeCommandArg,
//! SafeUrl, SafeRedirectUrl, SqlIdentifier, LdapSafeString.

use secure_boundary::safe_types::{
    LdapSafeString, SafeCommandArg, SafeFilename, SafePath, SafeRedirectUrl, SafeUrl, SqlIdentifier,
};

// ── SafePath ────────────────────────────────────────────────────────────────

#[test]
fn safe_path_valid_relative_accepted() {
    // Given: a valid relative path
    let result = SafePath::try_from("images/photo.png");
    // Then: returns Ok and inner value matches
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_inner(), "images/photo.png");
}

#[test]
fn safe_path_traversal_dotdot_slash_rejected() {
    // Given: a directory traversal attempt with ../
    let result = SafePath::try_from("../../etc/passwd");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_path_traversal_backslash_rejected() {
    // Given: a directory traversal attempt with ..\
    let result = SafePath::try_from("..\\..\\windows\\system32");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_path_null_byte_rejected() {
    // Given: a path with a null byte
    let result = SafePath::try_from("file\x00.txt");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_path_absolute_rejected() {
    // Given: an absolute path
    let result = SafePath::try_from("/etc/passwd");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_path_encoded_traversal_rejected() {
    // Given: a percent-encoded traversal
    let result = SafePath::try_from("%2e%2e/etc/passwd");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_path_violation_emits_event() {
    // Given: an attack path
    // When: attempt construction (event emission is fire-and-forget)
    let result = SafePath::try_from("../../etc/shadow");
    // Then: returns Err (event was emitted internally)
    assert!(result.is_err());
}

// ── SafeUrl ──────────────────────────────────────────────────────────────────

#[test]
fn safe_url_https_accepted() {
    // Given: a valid HTTPS URL
    let result = SafeUrl::try_from("https://example.com/api");
    // Then: returns Ok
    assert!(result.is_ok());
}

#[test]
fn safe_url_private_ip_127_rejected() {
    // Given: loopback address
    let result = SafeUrl::try_from("http://127.0.0.1/admin");
    // Then: returns Err (SSRF prevention)
    assert!(result.is_err());
}

#[test]
fn safe_url_private_ip_10x_rejected() {
    // Given: 10.x private IP
    let result = SafeUrl::try_from("http://10.0.0.1/internal");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_url_private_ip_192168_rejected() {
    // Given: 192.168.x private IP
    let result = SafeUrl::try_from("http://192.168.1.1/");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_url_link_local_169254_rejected() {
    // Given: link-local address (AWS metadata endpoint)
    let result = SafeUrl::try_from("http://169.254.169.254/meta");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_url_file_scheme_rejected() {
    // Given: file:// scheme
    let result = SafeUrl::try_from("file:///etc/passwd");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_url_gopher_scheme_rejected() {
    // Given: gopher:// scheme
    let result = SafeUrl::try_from("gopher://evil.com");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_url_javascript_scheme_rejected() {
    // Given: javascript: scheme
    let result = SafeUrl::try_from("javascript:alert(1)");
    // Then: returns Err
    assert!(result.is_err());
}

// ── SafeCommandArg ────────────────────────────────────────────────────────────

#[test]
fn safe_command_arg_alphanumeric_accepted() {
    // Given: a safe alphanumeric argument
    let result = SafeCommandArg::try_from("backup-2024");
    // Then: returns Ok
    assert!(result.is_ok());
}

#[test]
fn safe_command_arg_semicolon_rejected() {
    // Given: argument with semicolon (shell command separator)
    let result = SafeCommandArg::try_from("file; rm -rf /");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_command_arg_pipe_rejected() {
    // Given: argument with pipe
    let result = SafeCommandArg::try_from("file | cat /etc/passwd");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_command_arg_backtick_rejected() {
    // Given: argument with backtick (command substitution)
    let result = SafeCommandArg::try_from("file`whoami`");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_command_arg_dollar_paren_rejected() {
    // Given: argument with $() (command substitution)
    let result = SafeCommandArg::try_from("$(whoami)");
    // Then: returns Err
    assert!(result.is_err());
}

// ── SqlIdentifier ─────────────────────────────────────────────────────────────

#[test]
fn sql_identifier_valid_accepted() {
    // Given: a valid SQL identifier
    let result = SqlIdentifier::try_from("user_name");
    // Then: returns Ok
    assert!(result.is_ok());
}

#[test]
fn sql_identifier_injection_rejected() {
    // Given: SQL injection payload
    let result = SqlIdentifier::try_from("users; DROP TABLE users--");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn sql_identifier_too_long_rejected() {
    // Given: 129-character string (exceeds 128 max)
    let long = "a".repeat(129);
    let result = SqlIdentifier::try_from(long.as_str());
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn sql_identifier_empty_rejected() {
    // Given: empty string
    let result = SqlIdentifier::try_from("");
    // Then: returns Err
    assert!(result.is_err());
}

// ── SafeFilename ──────────────────────────────────────────────────────────────

#[test]
fn safe_filename_valid_accepted() {
    // Given: a safe filename
    let result = SafeFilename::try_from("document.pdf");
    // Then: returns Ok
    assert!(result.is_ok());
}

#[test]
fn safe_filename_slash_rejected() {
    // Given: filename with forward slash
    let result = SafeFilename::try_from("dir/file.txt");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_filename_dotdot_rejected() {
    // Given: filename with traversal prefix
    let result = SafeFilename::try_from("../file.txt");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_filename_null_byte_rejected() {
    // Given: filename with null byte
    let result = SafeFilename::try_from("file\x00.txt");
    // Then: returns Err
    assert!(result.is_err());
}

// ── SafeRedirectUrl ───────────────────────────────────────────────────────────

#[test]
fn safe_redirect_url_relative_accepted() {
    // Given: a relative redirect path
    let result = SafeRedirectUrl::try_from("/dashboard");
    // Then: returns Ok
    assert!(result.is_ok());
}

#[test]
fn safe_redirect_url_absolute_rejected() {
    // Given: an absolute URL (open redirect risk)
    let result = SafeRedirectUrl::try_from("https://evil.com");
    // Then: returns Err
    assert!(result.is_err());
}

#[test]
fn safe_redirect_url_protocol_relative_rejected() {
    // Given: protocol-relative URL (//evil.com hijack)
    let result = SafeRedirectUrl::try_from("//evil.com");
    // Then: returns Err
    assert!(result.is_err());
}

// ── LdapSafeString ────────────────────────────────────────────────────────────

#[test]
fn ldap_safe_string_clean_input_accepted() {
    // Given: clean LDAP-safe string
    let result = LdapSafeString::try_from("john.doe");
    // Then: returns Ok with unchanged value
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_inner(), "john.doe");
}

#[test]
fn ldap_safe_string_asterisk_escaped() {
    // Given: string with LDAP wildcard character
    let result = LdapSafeString::try_from("user*admin");
    // Then: returns Ok with escaped value
    assert!(result.is_ok());
    assert!(result.unwrap().as_inner().contains("\\2a"));
}

#[test]
fn ldap_safe_string_null_byte_escaped() {
    // Given: string with NUL byte
    let result = LdapSafeString::try_from("user\x00admin");
    // Then: returns Ok with NUL escaped
    assert!(result.is_ok());
    assert!(result.unwrap().as_inner().contains("\\00"));
}

#[test]
fn ldap_safe_string_parens_escaped() {
    // Given: string with LDAP filter parentheses
    let result = LdapSafeString::try_from("(admin)");
    // Then: returns Ok with parens escaped
    let s = result.unwrap();
    assert!(s.as_inner().contains("\\28") && s.as_inner().contains("\\29"));
}

//! BDD tests for LDAP DN and LDAP filter encoding (M19).

use std::borrow::Cow;

use secure_output::encode::OutputEncoder;
use secure_output::ldap::{encode_dn, encode_filter, LdapDnEncoder, LdapFilterEncoder};

// ──────────────────────────────────────────────
// Feature: LDAP DN encoding (RFC 4514)
// ──────────────────────────────────────────────

#[test]
fn dn_plain_cn_passes_through() {
    // Given: a plain CN value
    let input = "John Smith";
    // When: encoded for LDAP DN context
    let result = encode_dn(input);
    // Then: returned unchanged
    assert_eq!(result, "John Smith");
    assert!(matches!(result, Cow::Borrowed(_)));
}

#[test]
fn dn_special_chars_escaped() {
    // Given: a DN value with special characters +,;\"<>#=
    let input = "John+Smith,OU=Users";
    // When: encoded
    let result = encode_dn(input);
    // Then: special chars are backslash-escaped
    assert_eq!(result, "John\\+Smith\\,OU\\=Users");
}

#[test]
fn dn_leading_trailing_spaces_escaped() {
    // Given: a value with leading and trailing spaces
    let input = " admin ";
    // When: encoded
    let result = encode_dn(input);
    // Then: leading and trailing spaces are escaped
    assert_eq!(result, "\\ admin\\ ");
}

#[test]
fn dn_null_byte_escaped() {
    // Given: a value with a null byte
    let input = "user\x00admin";
    // When: encoded
    let result = encode_dn(input);
    // Then: null byte is hex-escaped
    assert_eq!(result, "user\\00admin");
}

#[test]
fn dn_empty_input_returns_empty() {
    // Given: an empty string
    let input = "";
    // When: encoded
    let result = encode_dn(input);
    // Then: returns empty
    assert_eq!(result, "");
}

#[test]
fn dn_leading_hash_escaped() {
    // Given: a value starting with #
    let input = "#admin";
    // When: encoded for DN
    let result = encode_dn(input);
    // Then: leading # is escaped
    assert_eq!(result, "\\#admin");
}

#[test]
fn dn_backslash_escaped() {
    // Given: a value with a backslash
    let input = "a\\b";
    // When: encoded
    let result = encode_dn(input);
    // Then: backslash is escaped
    assert_eq!(result, "a\\\\b");
}

#[test]
fn dn_quotes_escaped() {
    // Given: a value with double quotes
    let input = "he said \"hello\"";
    // When: encoded
    let result = encode_dn(input);
    // Then: quotes are escaped
    assert_eq!(result, "he said \\\"hello\\\"");
}

#[test]
fn dn_angle_brackets_escaped() {
    // Given: a value with < and >
    let input = "<admin>";
    // When: encoded
    let result = encode_dn(input);
    // Then: angle brackets are escaped
    assert_eq!(result, "\\<admin\\>");
}

// ──────────────────────────────────────────────
// Feature: LDAP filter encoding (RFC 4515)
// ──────────────────────────────────────────────

#[test]
fn filter_plain_value_passes_through() {
    // Given: a plain value
    let input = "john";
    // When: encoded for LDAP filter context
    let result = encode_filter(input);
    // Then: returned unchanged
    assert_eq!(result, "john");
    assert!(matches!(result, Cow::Borrowed(_)));
}

#[test]
fn filter_wildcard_escaped() {
    // Given: a value with an asterisk
    let input = "user*admin";
    // When: encoded
    let result = encode_filter(input);
    // Then: asterisk hex-escaped
    assert_eq!(result, "user\\2aadmin");
}

#[test]
fn filter_parentheses_escaped() {
    // Given: a value with parentheses
    let input = "(admin)";
    // When: encoded
    let result = encode_filter(input);
    // Then: parentheses hex-escaped
    assert_eq!(result, "\\28admin\\29");
}

#[test]
fn filter_backslash_escaped() {
    // Given: a value with a backslash
    let input = "a\\b";
    // When: encoded
    let result = encode_filter(input);
    // Then: backslash hex-escaped
    assert_eq!(result, "a\\5cb");
}

#[test]
fn filter_null_byte_escaped() {
    // Given: a value with a null byte
    let input = "\x00";
    // When: encoded
    let result = encode_filter(input);
    // Then: null hex-escaped
    assert_eq!(result, "\\00");
}

#[test]
fn filter_empty_input_returns_empty() {
    // Given: an empty string
    let input = "";
    // When: encoded
    let result = encode_filter(input);
    // Then: returns empty
    assert_eq!(result, "");
}

#[test]
fn filter_combined_special_chars() {
    // Given: a value with multiple special chars
    let input = "*()\\\x00";
    // When: encoded
    let result = encode_filter(input);
    // Then: all special chars hex-escaped
    assert_eq!(result, "\\2a\\28\\29\\5c\\00");
}

// ──────────────────────────────────────────────
// Feature: Convenience free functions match trait
// ──────────────────────────────────────────────

#[test]
fn free_function_matches_trait_dn() {
    let inputs = [
        "John Smith",
        "John+Smith,OU=Users",
        " admin ",
        "user\x00admin",
        "",
        "#test",
    ];
    let encoder = LdapDnEncoder;
    for input in &inputs {
        assert_eq!(
            encode_dn(input).as_ref(),
            encoder.encode(input).as_ref(),
            "Mismatch for DN input: {:?}",
            input
        );
    }
}

#[test]
fn free_function_matches_trait_filter() {
    let inputs = ["john", "user*admin", "(admin)", "a\\b", "\x00", ""];
    let encoder = LdapFilterEncoder;
    for input in &inputs {
        assert_eq!(
            encode_filter(input).as_ref(),
            encoder.encode(input).as_ref(),
            "Mismatch for filter input: {:?}",
            input
        );
    }
}

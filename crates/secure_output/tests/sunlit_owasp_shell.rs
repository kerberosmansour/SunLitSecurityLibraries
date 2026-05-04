//! BDD tests for OS shell encoding (M19).

use std::borrow::Cow;

use secure_output::encode::OutputEncoder;
use secure_output::shell::{encode, ShellEncoder};

/// Helper: asserts the result is single-quoted (safe shell argument).
fn assert_single_quoted(result: &str, label: &str) {
    assert!(
        result.starts_with('\'') && result.ends_with('\''),
        "{label}: expected single-quoted output, got: {result}"
    );
}

// ──────────────────────────────────────────────
// Feature: OS shell encoding
// ──────────────────────────────────────────────

#[test]
fn shell_alphanumeric_passes_through() {
    // Given: an alphanumeric string with hyphens
    let input = "backup-2024";
    // When: encoded for shell context
    let result = encode(input);
    // Then: returned unchanged
    assert_eq!(result, "backup-2024");
    assert!(matches!(result, Cow::Borrowed(_)));
}

#[test]
fn shell_semicolon_escaped() {
    // Given: a value with a semicolon for command injection
    let input = "file; rm -rf /";
    // When: encoded
    let result = encode(input);
    // Then: entire input is single-quoted so semicolon cannot be interpreted
    assert_single_quoted(&result, "semicolon");
    assert_eq!(result, "'file; rm -rf /'");
}

#[test]
fn shell_pipe_escaped() {
    // Given: a value with a pipe
    let input = "file | cat /etc/passwd";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted, pipe neutralized
    assert_single_quoted(&result, "pipe");
}

#[test]
fn shell_backtick_escaped() {
    // Given: a value with backticks
    let input = "file`id`";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted, backtick neutralized
    assert_single_quoted(&result, "backtick");
}

#[test]
fn shell_dollar_sign_escaped() {
    // Given: a value with dollar sign (variable injection)
    let input = "$HOME";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted, dollar neutralized
    assert_single_quoted(&result, "dollar");
}

#[test]
fn shell_newline_escaped() {
    // Given: a value with a newline
    let input = "file\nid";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted — newlines are safe inside single quotes
    assert_single_quoted(&result, "newline");
}

#[test]
fn shell_empty_input_returns_empty() {
    // Given: an empty string
    let input = "";
    // When: encoded
    let result = encode(input);
    // Then: returns empty
    assert_eq!(result, "");
}

#[test]
fn shell_null_byte_stripped() {
    // Given: a value with a null byte
    let input = "file\x00name";
    // When: encoded
    let result = encode(input);
    // Then: null byte is stripped
    assert!(!result.contains('\x00'));
    // The result should contain "filename" without null
    assert!(result.contains("filename"));
}

#[test]
fn shell_ampersand_escaped() {
    // Given: a value with & for background command injection
    let input = "file & id";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted, ampersand neutralized
    assert_single_quoted(&result, "ampersand");
}

#[test]
fn shell_parentheses_escaped() {
    // Given: a value with parentheses for subshell injection
    let input = "$(id)";
    // When: encoded
    let result = encode(input);
    // Then: single-quoted, subshell neutralized
    assert_single_quoted(&result, "parens");
}

#[test]
fn shell_single_quote_escaped() {
    // Given: a value that contains a single quote
    let input = "it's";
    // When: encoded
    let result = encode(input);
    // Then: single quotes in input are escaped as '\'' pattern
    assert_eq!(result, "'it'\\''s'");
}

// ──────────────────────────────────────────────
// Feature: Convenience free function matches trait
// ──────────────────────────────────────────────

#[test]
fn free_function_matches_trait_shell() {
    let inputs = [
        "backup-2024",
        "file; rm -rf /",
        "file | cat /etc/passwd",
        "file`id`",
        "$HOME",
        "file\nid",
        "",
    ];
    let encoder = ShellEncoder;
    for input in &inputs {
        assert_eq!(
            encode(input).as_ref(),
            encoder.encode(input).as_ref(),
            "Mismatch for shell input: {:?}",
            input
        );
    }
}

use secure_output::sanitize_uri_scheme;

#[test]
fn rejects_browser_ignored_controls_before_or_inside_executable_schemes() {
    for value in [
        "\tjavascript:alert(1)",
        "\njavascript:alert(1)",
        " javaScript:alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "\u{0000}javascript:alert(1)",
        "\u{007f}javascript:alert(1)",
    ] {
        assert!(
            sanitize_uri_scheme(value).is_err(),
            "browser-normalized executable URI must be rejected: {value:?}"
        );
    }
}

#[test]
fn rejects_attribute_breakout_and_ambiguous_relative_references() {
    for value in [
        "relative\" onmouseover=\"alert(1)",
        "relative' onmouseover='alert(1)",
        "relative`onmouseover=alert(1)",
        "relative<svg/onload=alert(1)>",
        "//evil.example/path",
        "\\\\evil.example/path",
        "/\\evil.example/path",
        "custom:payload",
    ] {
        assert!(
            sanitize_uri_scheme(value).is_err(),
            "ambiguous or attribute-breaking URI must be rejected: {value:?}"
        );
    }
}

#[test]
fn preserves_explicit_safe_schemes_and_well_formed_relative_references() {
    for value in [
        "https://example.com/path?q=1#fragment",
        "http://example.com/",
        "mailto:user@example.com",
        "/relative/path",
        "relative/path",
        "?query=value",
        "#fragment",
        "",
    ] {
        assert!(
            sanitize_uri_scheme(value).is_ok(),
            "documented safe URI must remain accepted: {value:?}"
        );
    }
}

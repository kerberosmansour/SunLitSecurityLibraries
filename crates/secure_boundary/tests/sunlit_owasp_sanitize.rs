//! BDD tests for HTML sanitization (M18).
//!
//! Covers: safe HTML passthrough, XSS prevention, style injection, empty input,
//! configurable allow-list.

#[cfg(feature = "html-sanitize")]
mod sanitize_tests {
    use secure_boundary::sanitize::{sanitize_html, SanitizeConfig};

    // ===================================================================
    // Feature: HTML sanitization
    // ===================================================================

    #[test]
    fn clean_html_passes_through() {
        // Given: safe HTML
        // When: sanitize_html()
        // Then: Returns same HTML
        let input = "<p>Hello <strong>world</strong></p>";
        let output = sanitize_html(input);
        assert_eq!(output, input);
    }

    #[test]
    fn script_tags_removed() {
        // Given: HTML with script tag (XSS)
        // When: sanitize_html()
        // Then: Script tag removed, safe content preserved
        let input = "<p>Hello</p><script>alert(1)</script>";
        let output = sanitize_html(input);
        assert!(
            !output.contains("<script"),
            "script tag not removed: {output}"
        );
        assert!(
            output.contains("<p>Hello</p>"),
            "safe content lost: {output}"
        );
    }

    #[test]
    fn event_handlers_removed() {
        // Given: HTML with event handler (XSS)
        // When: sanitize_html()
        // Then: onerror attribute removed
        let input = r#"<img src="x" onerror="alert(1)">"#;
        let output = sanitize_html(input);
        assert!(
            !output.contains("onerror"),
            "event handler not removed: {output}"
        );
    }

    #[test]
    fn style_injection_removed() {
        // Given: HTML with style injection
        // When: sanitize_html()
        // Then: Dangerous style attribute removed or sanitized
        let input = r#"<div style="background:url(javascript:alert(1))">text</div>"#;
        let output = sanitize_html(input);
        assert!(
            !output.contains("javascript:"),
            "javascript: URI not removed: {output}"
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        // Given: empty input
        // When: sanitize_html()
        // Then: Returns empty string
        let output = sanitize_html("");
        assert_eq!(output, "");
    }

    #[test]
    fn allowed_tags_configurable() {
        // Given: Custom allow list with only <b>, <i>
        // When: sanitize_html() with config
        // Then: Only those tags preserved; <p> stripped
        let config = SanitizeConfig::new().allowed_tags(&["b", "i"]);
        let input = "<p>Hello <b>bold</b> and <i>italic</i></p>";
        let output = config.sanitize(input);
        assert!(output.contains("<b>bold</b>"), "b tag lost: {output}");
        assert!(output.contains("<i>italic</i>"), "i tag lost: {output}");
        assert!(!output.contains("<p>"), "p tag not stripped: {output}");
    }

    #[test]
    fn nested_xss_in_attributes() {
        // Given: nested XSS via data URIs and unusual attributes
        let input = r#"<a href="javascript:alert(1)">click</a>"#;
        let output = sanitize_html(input);
        assert!(
            !output.contains("javascript:"),
            "javascript: URI not removed: {output}"
        );
    }

    #[test]
    fn preserves_safe_links() {
        // Given: a legitimate HTTPS link
        let input = r#"<a href="https://example.com">Link</a>"#;
        let output = sanitize_html(input);
        assert!(
            output.contains("https://example.com"),
            "safe link lost: {output}"
        );
    }
}

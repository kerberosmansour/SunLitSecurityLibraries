//! Property tests — output encoding invariants.
//!
//! Milestone 9 — BDD: HTML encode safety.
use proptest::prelude::*;
use secure_output::encode::OutputEncoder;
use secure_output::html::HtmlEncoder;

proptest! {
    /// HTML-encoded output never contains raw dangerous characters
    #[test]
    fn prop_html_encode_no_raw_special_chars(s in ".*") {
        let enc = HtmlEncoder;
        let encoded = enc.encode(&s);
        prop_assert!(!encoded.contains('<'), "raw '<' found in: {encoded}");
        prop_assert!(!encoded.contains('>'), "raw '>' found in: {encoded}");
        prop_assert!(!encoded.contains('"'), "raw '\"' found in: {encoded}");
        prop_assert!(!encoded.contains('\''), "raw '\\'' found in: {encoded}");
    }

    /// HTML encode never panics on arbitrary input
    #[test]
    fn prop_html_encode_no_panic(s in ".*") {
        let enc = HtmlEncoder;
        let _ = enc.encode(&s);
    }

    /// HTML encoded output never contains a literal <script tag (XSS protection)
    #[test]
    fn prop_html_encode_no_script_tag(s in ".*") {
        let enc = HtmlEncoder;
        let encoded = enc.encode(&s);
        let lower = encoded.to_lowercase();
        prop_assert!(!lower.contains("<script"), "script tag found in: {encoded}");
    }
}

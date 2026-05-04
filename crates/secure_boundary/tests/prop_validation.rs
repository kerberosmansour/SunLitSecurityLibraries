//! Property tests — validation invariants for secure_boundary.
//!
//! Milestone 9 — BDD: Validation idempotency property.
use proptest::prelude::*;
use secure_boundary::normalize::{normalize, to_nfc, trim_whitespace};

proptest! {
    /// NFC normalization is idempotent: to_nfc(to_nfc(x)) == to_nfc(x)
    #[test]
    fn prop_nfc_normalization_idempotent(s in ".*") {
        let once = to_nfc(&s);
        let twice = to_nfc(&once);
        prop_assert_eq!(once, twice);
    }

    /// normalize never panics on arbitrary input
    #[test]
    fn prop_normalize_no_panic(s in ".*") {
        let _ = normalize(&s, false);
        let _ = normalize(&s, true);
    }

    /// trim_whitespace result is never longer than input
    #[test]
    fn prop_trim_no_chars_added(s in ".*") {
        let trimmed = trim_whitespace(&s);
        prop_assert!(trimmed.len() <= s.len());
    }
}

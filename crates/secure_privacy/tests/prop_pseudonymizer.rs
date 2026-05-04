//! Property tests — pseudonymizer and PII classifier invariants for secure_privacy.
//!
//! Milestone 9 — BDD: Privacy control safety properties.
use proptest::prelude::*;
use secure_privacy::{PiiClassification, PiiClassifier, Pseudonymizer};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Same input + same salt always produces the same pseudonym (deterministic).
    #[test]
    fn prop_pseudonymize_deterministic(input in ".*", salt in proptest::collection::vec(1u8..=255, 1..32)) {
        let p = Pseudonymizer::new(&salt).unwrap();
        let result1 = p.pseudonymize(&input);
        let result2 = p.pseudonymize(&input);
        prop_assert_eq!(
            result1, result2,
            "Same input and salt must produce identical pseudonyms",
        );
    }

    /// Pseudonymized output cannot produce the original input via simple reversal tests.
    /// The output is a hex-encoded HMAC-SHA256 — it should never equal the input.
    #[test]
    fn prop_pseudonymize_not_reversible(
        input in "[a-zA-Z0-9]{1,50}",
        salt in proptest::collection::vec(1u8..=255, 1..32),
    ) {
        let p = Pseudonymizer::new(&salt).unwrap();
        let result = p.pseudonymize(&input);
        let value = result.value.clone();
        // The pseudonymized value should not equal the input
        prop_assert_ne!(
            value, input,
            "Pseudonym must not equal the original input",
        );
        // The hex output is always 64 chars (SHA-256 = 32 bytes = 64 hex chars)
        let value2 = result.value;
        prop_assert_eq!(
            value2.len(), 64,
            "HMAC-SHA256 output should always be 64 hex characters",
        );
    }

    /// Different salts produce different pseudonyms for the same input.
    #[test]
    fn prop_different_salts_different_output(input in "[a-zA-Z0-9]{1,50}") {
        let p1 = Pseudonymizer::new(b"salt_one").unwrap();
        let p2 = Pseudonymizer::new(b"salt_two").unwrap();
        let r1 = p1.pseudonymize(&input);
        let r2 = p2.pseudonymize(&input);
        prop_assert_ne!(
            r1, r2,
            "Different salts must produce different pseudonyms",
        );
    }

    /// PiiClassifier::classify never panics on arbitrary input.
    #[test]
    fn prop_classify_no_panic(input in ".*") {
        let classifier = PiiClassifier::new();
        let _ = classifier.classify(&input);
    }

    /// Known email patterns are always classified as Email.
    #[test]
    fn prop_classify_emails(
        local in "[a-z]{1,10}",
        domain in "[a-z]{1,10}\\.[a-z]{2,4}",
    ) {
        let email = format!("{local}@{domain}");
        let classifier = PiiClassifier::new();
        let result = classifier.classify(&email);
        prop_assert_eq!(
            result,
            PiiClassification::Email,
            "Email pattern should be classified as Email",
        );
    }
}

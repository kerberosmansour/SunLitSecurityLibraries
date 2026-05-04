//! PII discovery and classification engine.
//!
//! Provides regex-based pattern matching to identify personally identifiable
//! information (PII) in arbitrary text fields — email addresses, phone numbers,
//! IP addresses, device identifiers (IMEI), and custom patterns.

use crate::error::PrivacyError;
use regex::Regex;
use serde::Serialize;

/// Classification result for a scanned data field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum PiiClassification {
    /// An email address was detected.
    Email,
    /// A phone number was detected.
    PhoneNumber,
    /// An IP address (v4 or v6) was detected.
    IpAddress,
    /// A device identifier (e.g. IMEI) was detected.
    DeviceIdentifier,
    /// A custom pattern was matched.
    Custom(String),
    /// No PII was detected.
    None,
}

/// A compiled custom PII pattern.
struct CustomPattern {
    name: String,
    regex: Regex,
}

/// Regex-based PII classifier.
///
/// Scans input strings against built-in patterns (email, phone, IP, IMEI)
/// and optional custom patterns. Returns the first matching classification.
pub struct PiiClassifier {
    email_re: Regex,
    phone_re: Regex,
    ipv4_re: Regex,
    imei_re: Regex,
    custom_patterns: Vec<CustomPattern>,
}

impl PiiClassifier {
    /// Creates a new classifier with built-in PII patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            email_re: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            phone_re: Regex::new(r"\+\d[\d\s\-]{6,}\d").unwrap(),
            ipv4_re: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            imei_re: Regex::new(r"\b\d{15}\b").unwrap(),
            custom_patterns: Vec::new(),
        }
    }

    /// Adds a custom PII pattern with a name and regex string.
    ///
    /// # Errors
    ///
    /// Returns `PrivacyError::InvalidPattern` if the regex fails to compile.
    pub fn add_custom_pattern(&mut self, name: &str, pattern: &str) -> Result<(), PrivacyError> {
        let regex = Regex::new(pattern).map_err(|e| PrivacyError::InvalidPattern(e.to_string()))?;
        self.custom_patterns.push(CustomPattern {
            name: name.to_string(),
            regex,
        });
        Ok(())
    }

    /// Classifies an input string, returning the first matching PII category.
    ///
    /// Checks built-in patterns (email, IMEI, phone, IP) in order, then custom
    /// patterns. Returns `PiiClassification::None` if no pattern matches.
    #[must_use]
    pub fn classify(&self, input: &str) -> PiiClassification {
        if self.email_re.is_match(input) {
            return PiiClassification::Email;
        }
        if self.imei_re.is_match(input) {
            return PiiClassification::DeviceIdentifier;
        }
        if self.phone_re.is_match(input) {
            return PiiClassification::PhoneNumber;
        }
        if self.ipv4_re.is_match(input) {
            return PiiClassification::IpAddress;
        }
        for custom in &self.custom_patterns {
            if custom.regex.is_match(input) {
                return PiiClassification::Custom(custom.name.clone());
            }
        }
        PiiClassification::None
    }
}

impl Default for PiiClassifier {
    fn default() -> Self {
        Self::new()
    }
}

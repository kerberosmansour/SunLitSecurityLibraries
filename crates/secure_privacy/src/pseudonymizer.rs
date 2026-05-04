//! HMAC-based data pseudonymization.
//!
//! Produces deterministic, non-reversible pseudonyms for identifiers using
//! HMAC-SHA256 keyed with a caller-provided salt. The same input + salt always
//! produces the same pseudonym, but different salts produce different pseudonyms.

use crate::error::PrivacyError;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A pseudonymized (non-reversible) representation of an identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PseudonymizedValue {
    /// The hex-encoded HMAC-SHA256 output.
    pub value: String,
}

/// HMAC-based pseudonymizer for identifiers.
///
/// Uses HMAC-SHA256 keyed with the provided salt. Deterministic: the same
/// input and salt always produce the same pseudonym.
pub struct Pseudonymizer {
    salt: Vec<u8>,
}

impl Pseudonymizer {
    /// Creates a new pseudonymizer with the given salt.
    ///
    /// # Errors
    ///
    /// Returns `PrivacyError::EmptySalt` if the salt is empty.
    pub fn new(salt: &[u8]) -> Result<Self, PrivacyError> {
        if salt.is_empty() {
            return Err(PrivacyError::EmptySalt);
        }
        Ok(Self {
            salt: salt.to_vec(),
        })
    }

    /// Pseudonymizes a single identifier.
    #[must_use]
    pub fn pseudonymize(&self, input: &str) -> PseudonymizedValue {
        let mut mac = HmacSha256::new_from_slice(&self.salt).expect("HMAC accepts any key length");
        mac.update(input.as_bytes());
        let result = mac.finalize();
        let hex_str = hex::encode(result.into_bytes());
        PseudonymizedValue { value: hex_str }
    }

    /// Pseudonymizes a batch of identifiers.
    #[must_use]
    pub fn pseudonymize_batch(&self, inputs: &[&str]) -> Vec<PseudonymizedValue> {
        inputs
            .iter()
            .map(|input| self.pseudonymize(input))
            .collect()
    }
}

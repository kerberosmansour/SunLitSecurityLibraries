//! Certificate pinning validation — SPKI hash comparison.

use crate::error::NetworkSecurityError;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// A set of SHA-256 SPKI (Subject Public Key Info) pin hashes.
#[derive(Clone, Debug)]
pub struct PinSet {
    pins: Vec<[u8; 32]>,
}

impl PinSet {
    /// Creates an empty pin set.
    #[must_use]
    pub fn new() -> Self {
        Self { pins: Vec::new() }
    }

    /// Creates a pin set from hex-encoded SHA-256 hashes.
    ///
    /// # Errors
    ///
    /// Returns `NetworkSecurityError::CertificateParseError` if a hex string is invalid.
    pub fn from_hex_hashes(hashes: &[&str]) -> Result<Self, NetworkSecurityError> {
        let mut pins = Vec::with_capacity(hashes.len());
        for hex_str in hashes {
            let bytes =
                hex_to_bytes(hex_str).map_err(|e| NetworkSecurityError::CertificateParseError {
                    detail: format!("invalid hex pin hash: {e}"),
                })?;
            if bytes.len() != 32 {
                return Err(NetworkSecurityError::CertificateParseError {
                    detail: format!("pin hash must be 32 bytes, got {}", bytes.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            pins.push(arr);
        }
        Ok(Self { pins })
    }

    /// Adds a raw 32-byte SHA-256 pin hash.
    pub fn add_pin(&mut self, hash: [u8; 32]) {
        self.pins.push(hash);
    }

    /// Returns `true` if no pins are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Returns the number of pins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Checks whether the given SPKI hash matches any pin.
    #[must_use]
    pub fn matches(&self, spki_hash: &[u8; 32]) -> bool {
        self.pins.iter().any(|pin| pin == spki_hash)
    }
}

impl Default for PinSet {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of certificate pin validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertPinResult {
    /// The certificate matched a configured pin.
    Valid,
    /// The certificate SPKI hash did not match any configured pin.
    PinMismatch,
    /// No pins were configured — validation was skipped (warning).
    NoPinsConfigured,
    /// The certificate has expired.
    Expired,
}

/// Validates certificate chains against pinned SPKI hashes.
#[derive(Clone, Debug)]
pub struct CertPinValidator {
    pin_set: PinSet,
    check_expiry: bool,
}

impl CertPinValidator {
    /// Creates a new validator with the given pin set.
    #[must_use]
    pub fn new(pin_set: PinSet) -> Self {
        Self {
            pin_set,
            check_expiry: false,
        }
    }

    /// Enables certificate expiry checking.
    #[must_use]
    pub fn with_expiry_check(mut self, check: bool) -> Self {
        self.check_expiry = check;
        self
    }

    /// Validates a DER-encoded certificate against the pin set.
    pub fn validate_der(&self, cert_der: &[u8]) -> CertPinResult {
        self.validate_der_at(cert_der, ::time::OffsetDateTime::now_utc())
    }

    /// Validates a DER-encoded certificate against the pin set at a specific point in time.
    pub fn validate_der_at(&self, cert_der: &[u8], now: ::time::OffsetDateTime) -> CertPinResult {
        if self.pin_set.is_empty() {
            return CertPinResult::NoPinsConfigured;
        }

        let cert = match X509Certificate::from_der(cert_der) {
            Ok((_, cert)) => cert,
            Err(_) => return CertPinResult::PinMismatch,
        };

        if self.check_expiry {
            let validity = cert.validity();
            let not_after_unix = validity.not_after.timestamp();
            let now_unix = now.unix_timestamp();
            if now_unix > not_after_unix {
                return CertPinResult::Expired;
            }
        }

        let spki_bytes = cert.public_key().raw;
        let spki_hash = Sha256::digest(spki_bytes);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&spki_hash);

        if self.pin_set.matches(&hash_arr) {
            CertPinResult::Valid
        } else {
            CertPinResult::PinMismatch
        }
    }

    /// Validates a DER-encoded certificate chain (leaf first).
    /// Returns `Valid` if the leaf certificate matches a pin.
    pub fn validate_chain(&self, chain: &[&[u8]]) -> CertPinResult {
        if let Some(leaf) = chain.first() {
            self.validate_der(leaf)
        } else {
            CertPinResult::PinMismatch
        }
    }

    /// Validates and emits a security event on failure.
    pub fn validate_der_and_emit(&self, cert_der: &[u8], sink: &dyn SecuritySink) -> CertPinResult {
        self.validate_der_at_and_emit(cert_der, ::time::OffsetDateTime::now_utc(), sink)
    }

    /// Validates at a specific time and emits a security event on failure.
    pub fn validate_der_at_and_emit(
        &self,
        cert_der: &[u8],
        now: ::time::OffsetDateTime,
        sink: &dyn SecuritySink,
    ) -> CertPinResult {
        let result = self.validate_der_at(cert_der, now);
        match &result {
            CertPinResult::PinMismatch => {
                let mut event = SecurityEvent::new(
                    EventKind::CertPinFailure,
                    SecuritySeverity::Critical,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some("cert_pin_mismatch");
                sink.write_event(&event);
            }
            CertPinResult::Expired => {
                let mut event = SecurityEvent::new(
                    EventKind::CertPinFailure,
                    SecuritySeverity::High,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some("cert_expired");
                sink.write_event(&event);
            }
            CertPinResult::Valid | CertPinResult::NoPinsConfigured => {}
        }
        result
    }

    /// Computes the SHA-256 SPKI hash of a DER-encoded certificate.
    ///
    /// # Errors
    ///
    /// Returns `NetworkSecurityError::CertificateParseError` if the DER is invalid.
    pub fn spki_hash(cert_der: &[u8]) -> Result<[u8; 32], NetworkSecurityError> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            NetworkSecurityError::CertificateParseError {
                detail: format!("failed to parse certificate: {e}"),
            }
        })?;
        let spki_bytes = cert.public_key().raw;
        let hash = Sha256::digest(spki_bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Ok(arr)
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pin_set_is_empty() {
        let ps = PinSet::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn pin_set_add_and_match() {
        let mut ps = PinSet::new();
        let hash = [0xABu8; 32];
        ps.add_pin(hash);
        assert!(ps.matches(&hash));
        assert!(!ps.matches(&[0xCDu8; 32]));
    }
}

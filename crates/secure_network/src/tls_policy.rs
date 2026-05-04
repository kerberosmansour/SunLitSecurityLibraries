//! TLS policy enforcement — version and cipher suite validation.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use serde::Serialize;

/// Supported TLS protocol versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TlsVersion {
    /// SSL 3.0 (insecure, always rejected).
    Ssl3,
    /// TLS 1.0 (deprecated).
    Tls10,
    /// TLS 1.1 (deprecated).
    Tls11,
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

/// Known cipher suite identifiers for policy enforcement.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum CipherSuite {
    /// AES-128-GCM with SHA-256.
    Aes128Gcm,
    /// AES-256-GCM with SHA-384.
    Aes256Gcm,
    /// ChaCha20-Poly1305 with SHA-256.
    Chacha20Poly1305,
    /// AES-128-CBC (legacy, may be disallowed).
    Aes128Cbc,
    /// AES-256-CBC (legacy, may be disallowed).
    Aes256Cbc,
    /// RC4 (insecure).
    Rc4,
    /// DES / 3DES (insecure).
    Des,
    /// NULL cipher (no encryption).
    Null,
    /// An unrecognized cipher suite identified by name.
    Other(String),
}

/// The result of TLS policy validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsValidationResult {
    /// The connection parameters satisfy the policy.
    Allow,
    /// The connection parameters violate the policy.
    Deny {
        /// Why the connection was denied.
        reason: TlsDenyReason,
    },
}

/// Reason a TLS connection was denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsDenyReason {
    /// The TLS version is below the minimum.
    TlsVersion {
        /// The minimum acceptable version.
        minimum: TlsVersion,
        /// The version that was presented.
        actual: TlsVersion,
    },
    /// A weak or disallowed cipher suite was used.
    WeakCipher {
        /// The cipher that was rejected.
        cipher: CipherSuite,
    },
}

/// A TLS policy that enforces minimum version and cipher allowlists.
#[derive(Clone, Debug)]
pub struct TlsPolicy {
    min_version: TlsVersion,
    allowed_ciphers: Option<Vec<CipherSuite>>,
}

impl TlsPolicy {
    /// Creates a new TLS policy with the given minimum version.
    #[must_use]
    pub fn new(min_version: TlsVersion) -> Self {
        Self {
            min_version,
            allowed_ciphers: None,
        }
    }

    /// Restricts the policy to only the specified cipher suites.
    #[must_use]
    pub fn with_allowed_ciphers(mut self, ciphers: Vec<CipherSuite>) -> Self {
        self.allowed_ciphers = Some(ciphers);
        self
    }

    /// Validates a connection's TLS version and cipher suite against this policy.
    pub fn validate(&self, version: TlsVersion, cipher: &CipherSuite) -> TlsValidationResult {
        if version < self.min_version {
            return TlsValidationResult::Deny {
                reason: TlsDenyReason::TlsVersion {
                    minimum: self.min_version,
                    actual: version,
                },
            };
        }

        if Self::is_known_weak(cipher) {
            return TlsValidationResult::Deny {
                reason: TlsDenyReason::WeakCipher {
                    cipher: cipher.clone(),
                },
            };
        }

        if let Some(ref allowed) = self.allowed_ciphers {
            if !allowed.contains(cipher) {
                return TlsValidationResult::Deny {
                    reason: TlsDenyReason::WeakCipher {
                        cipher: cipher.clone(),
                    },
                };
            }
        }

        TlsValidationResult::Allow
    }

    /// Validates and emits a security event on violation.
    pub fn validate_and_emit(
        &self,
        version: TlsVersion,
        cipher: &CipherSuite,
        sink: &dyn SecuritySink,
    ) -> TlsValidationResult {
        let result = self.validate(version, cipher);
        if let TlsValidationResult::Deny { ref reason } = result {
            let mut event = SecurityEvent::new(
                EventKind::TlsViolation,
                SecuritySeverity::High,
                EventOutcome::Blocked,
            );
            event.reason_code = Some(match reason {
                TlsDenyReason::TlsVersion { .. } => "tls_version_too_low",
                TlsDenyReason::WeakCipher { .. } => "weak_cipher_suite",
            });
            sink.write_event(&event);
        }
        result
    }

    fn is_known_weak(cipher: &CipherSuite) -> bool {
        matches!(
            cipher,
            CipherSuite::Rc4 | CipherSuite::Des | CipherSuite::Null
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_ordering() {
        assert!(TlsVersion::Ssl3 < TlsVersion::Tls10);
        assert!(TlsVersion::Tls10 < TlsVersion::Tls11);
        assert!(TlsVersion::Tls11 < TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }
}

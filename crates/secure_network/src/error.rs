//! Network security error types.

use std::fmt;

/// Errors produced by the `secure_network` crate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkSecurityError {
    /// The TLS version is below the minimum required.
    TlsVersionTooLow {
        /// The minimum acceptable version.
        minimum: super::tls_policy::TlsVersion,
        /// The version that was presented.
        actual: super::tls_policy::TlsVersion,
    },
    /// A weak or disallowed cipher suite was used.
    WeakCipher {
        /// Description of the cipher.
        cipher: String,
    },
    /// A certificate pin did not match any configured pin.
    PinMismatch,
    /// The certificate has expired.
    CertificateExpired,
    /// No pins were configured (warning, not hard error).
    NoPinsConfigured,
    /// Cleartext traffic was detected.
    CleartextDetected {
        /// The URL or scheme that triggered the detection.
        url: String,
    },
    /// An insecure URI scheme was used.
    InsecureScheme {
        /// The scheme that was detected.
        scheme: String,
    },
    /// Failed to parse a certificate.
    CertificateParseError {
        /// Description of the parse error.
        detail: String,
    },
}

impl fmt::Display for NetworkSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsVersionTooLow { minimum, actual } => {
                write!(f, "TLS version {actual:?} is below minimum {minimum:?}")
            }
            Self::WeakCipher { cipher } => write!(f, "weak cipher suite: {cipher}"),
            Self::PinMismatch => write!(f, "certificate pin mismatch"),
            Self::CertificateExpired => write!(f, "certificate has expired"),
            Self::NoPinsConfigured => write!(f, "no certificate pins configured"),
            Self::CleartextDetected { url } => write!(f, "cleartext traffic detected: {url}"),
            Self::InsecureScheme { scheme } => write!(f, "insecure URI scheme: {scheme}"),
            Self::CertificateParseError { detail } => {
                write!(f, "certificate parse error: {detail}")
            }
        }
    }
}

impl std::error::Error for NetworkSecurityError {}

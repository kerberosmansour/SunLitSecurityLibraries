#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_network` — TLS configuration validation, certificate pinning, and cleartext detection
//! for OWASP MASVS-NETWORK-1 and MASVS-NETWORK-2.
//!
//! All types are pure Rust policy objects and validators — they do not perform TLS handshakes.
//! The consuming application provides raw certificate chains and TLS parameters; this crate
//! provides the validation logic.

pub mod cert_pin;
pub mod cleartext;
pub mod error;
pub mod mtls;
pub mod tls_policy;

pub use cert_pin::{CertPinResult, CertPinValidator, PinSet};
pub use cleartext::{CleartextDetector, CleartextResult};
pub use error::NetworkSecurityError;
pub use mtls::{
    MtlsClientIdentity, MtlsClientIdentityStatus, MtlsRevocationLookup, NoMtlsRevocations,
};
pub use tls_policy::{CipherSuite, TlsPolicy, TlsValidationResult, TlsVersion};

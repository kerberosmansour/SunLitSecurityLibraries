#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_privacy` — Data minimization and privacy controls for OWASP MASVS-PRIVACY.
//!
//! This crate provides PII discovery/classification, data pseudonymization,
//! consent tracking abstractions, and data retention policy enforcement.
//! It is a pure policy engine — the consuming application implements storage
//! and UI; this crate provides the state machine, validation, and classification logic.

pub mod classifier;
pub mod consent;
pub mod error;
pub mod pseudonymizer;
pub mod retention;

pub use classifier::{PiiClassification, PiiClassifier};
pub use consent::{ConsentDecision, ConsentPolicy, ConsentPurpose, ConsentState};
pub use error::PrivacyError;
pub use pseudonymizer::{PseudonymizedValue, Pseudonymizer};
pub use retention::{RetentionPolicy, RetentionStatus};

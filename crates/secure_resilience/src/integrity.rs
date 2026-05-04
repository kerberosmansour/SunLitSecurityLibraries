//! App integrity verification — signature, store, and resource integrity checks.
//!
//! These types validate that the app binary, its signing certificate, installation source,
//! and bundled resources have not been tampered with (MASWE-0105, MASWE-0106, MASWE-0107).

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use serde::Serialize;
use std::collections::HashMap;

/// The result of an integrity check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum IntegrityResult {
    /// The integrity check passed — no tampering detected.
    Valid,
    /// The app binary or resources have been modified.
    Tampered,
    /// The app was not installed from an official store.
    SideLoaded,
}

/// An integrity check configuration.
///
/// Supports three modes: signature hash comparison, store origin verification,
/// and resource hash verification. Each mode is constructed with a dedicated
/// constructor.
#[derive(Clone, Debug)]
pub struct IntegrityCheck {
    mode: IntegrityMode,
}

/// Integrity check result with details about mismatched resources.
#[derive(Clone, Debug)]
pub struct IntegrityCheckResult {
    /// The overall result.
    pub result: IntegrityResult,
    /// Details about any mismatches found.
    pub details: Vec<String>,
}

#[derive(Clone, Debug)]
enum IntegrityMode {
    Signature {
        expected_hash: String,
    },
    StoreVerification {
        allowed_stores: Vec<String>,
    },
    ResourceIntegrity {
        expected_hashes: HashMap<String, String>,
    },
}

impl IntegrityCheck {
    /// Create a signature-based integrity check.
    ///
    /// Compares the app's signing certificate hash against the expected value.
    pub fn new_signature(expected_hash: &str) -> Self {
        Self {
            mode: IntegrityMode::Signature {
                expected_hash: expected_hash.to_string(),
            },
        }
    }

    /// Create a store verification check.
    ///
    /// Verifies the app was installed from one of the allowed store package names.
    pub fn new_store_verification(allowed_stores: Vec<String>) -> Self {
        Self {
            mode: IntegrityMode::StoreVerification { allowed_stores },
        }
    }

    /// Create a resource integrity check.
    ///
    /// Verifies that bundled resources match their expected hashes.
    pub fn new_resource_integrity() -> Self {
        Self {
            mode: IntegrityMode::ResourceIntegrity {
                expected_hashes: HashMap::new(),
            },
        }
    }

    /// Add an expected resource hash for resource integrity mode.
    pub fn add_resource_hash(&mut self, resource_path: &str, expected_hash: &str) {
        if let IntegrityMode::ResourceIntegrity { expected_hashes } = &mut self.mode {
            expected_hashes.insert(resource_path.to_string(), expected_hash.to_string());
        }
    }

    /// Verify a signature hash against the expected value.
    pub fn verify(&self, actual_hash: &str) -> IntegrityResult {
        match &self.mode {
            IntegrityMode::Signature { expected_hash } => {
                if actual_hash == expected_hash {
                    IntegrityResult::Valid
                } else {
                    IntegrityResult::Tampered
                }
            }
            _ => IntegrityResult::Valid,
        }
    }

    /// Verify a signature hash and emit a security event on mismatch.
    pub fn verify_with_events(
        &self,
        actual_hash: &str,
        sink: &impl SecuritySink,
    ) -> IntegrityResult {
        let result = self.verify(actual_hash);
        if result == IntegrityResult::Tampered {
            let mut event = SecurityEvent::new(
                EventKind::IntegrityViolation,
                SecuritySeverity::Critical,
                EventOutcome::Blocked,
            );
            event.resource = Some("app_signature".to_string());
            sink.write_event(&event);
        }
        result
    }

    /// Verify the app's installation store against the allowed stores list.
    pub fn verify_store(&self, actual_store: &str) -> IntegrityResult {
        match &self.mode {
            IntegrityMode::StoreVerification { allowed_stores } => {
                if allowed_stores.iter().any(|s| s == actual_store) {
                    IntegrityResult::Valid
                } else {
                    IntegrityResult::SideLoaded
                }
            }
            _ => IntegrityResult::Valid,
        }
    }

    /// Verify the installation store and emit a security event on sideloading.
    pub fn verify_store_with_events(
        &self,
        actual_store: &str,
        sink: &impl SecuritySink,
    ) -> IntegrityResult {
        let result = self.verify_store(actual_store);
        if result == IntegrityResult::SideLoaded {
            let mut event = SecurityEvent::new(
                EventKind::IntegrityViolation,
                SecuritySeverity::High,
                EventOutcome::Blocked,
            );
            event.resource = Some(format!("store:{actual_store}"));
            sink.write_event(&event);
        }
        result
    }

    /// Verify resource hashes against expected values.
    pub fn verify_resources(&self, actual_hashes: &HashMap<String, String>) -> IntegrityResult {
        match &self.mode {
            IntegrityMode::ResourceIntegrity { expected_hashes } => {
                for (path, expected) in expected_hashes {
                    match actual_hashes.get(path) {
                        Some(actual) if actual == expected => {}
                        _ => return IntegrityResult::Tampered,
                    }
                }
                IntegrityResult::Valid
            }
            _ => IntegrityResult::Valid,
        }
    }

    /// Verify resource hashes and emit a security event on tampering.
    pub fn verify_resources_with_events(
        &self,
        actual_hashes: &HashMap<String, String>,
        sink: &impl SecuritySink,
    ) -> IntegrityResult {
        let result = self.verify_resources(actual_hashes);
        if result == IntegrityResult::Tampered {
            let mut event = SecurityEvent::new(
                EventKind::IntegrityViolation,
                SecuritySeverity::Critical,
                EventOutcome::Blocked,
            );
            event.resource = Some("resource_integrity".to_string());
            sink.write_event(&event);
        }
        result
    }
}

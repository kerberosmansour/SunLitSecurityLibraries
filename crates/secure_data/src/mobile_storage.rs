//! Mobile storage extensions for MASVS-STORAGE-1.
//!
//! Provides:
//! - `SensitiveBuffer` — a zeroize-on-drop, zeroize-on-wipe byte buffer for
//!   transient sensitive data (biometric templates, PIN entries, etc.).
//! - `BackupExclusion` — metadata marker for backup exclusion (secure by default).
//! - `MobileStoragePolicy` — policy type enforcing encryption and hardware keystore
//!   requirements based on data classification.
//!
//! All types are feature-gated behind `mobile-storage` and are pure Rust policy
//! objects — no platform-specific code or `unsafe` blocks.

use security_core::classification::DataClassification;
use security_events::event::SecurityEvent;
use security_events::kind::EventKind;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// A sensitive byte buffer that zeroes memory on drop and supports explicit wipe.
///
/// - Implements `Zeroize` and `Drop` to clear memory automatically.
/// - `Debug` and `Display` output `[REDACTED]` — never leaks contents.
/// - Optional TTL for bounded-lifetime buffers.
///
/// # Examples
///
/// ```
/// use secure_data::mobile_storage::SensitiveBuffer;
///
/// let mut buf = SensitiveBuffer::new(vec![0x42; 16]);
/// assert_eq!(buf.expose().len(), 16);
/// buf.wipe();
/// assert!(buf.expose().iter().all(|&b| b == 0));
/// ```
pub struct SensitiveBuffer {
    inner: Vec<u8>,
    created_at: Instant,
    ttl: Option<Duration>,
}

impl SensitiveBuffer {
    /// Creates a new `SensitiveBuffer` wrapping the given bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: data,
            created_at: Instant::now(),
            ttl: None,
        }
    }

    /// Creates a new `SensitiveBuffer` with a maximum time-to-live.
    ///
    /// After `ttl` elapses, [`is_expired`](Self::is_expired) returns `true`.
    #[must_use]
    pub fn with_ttl(data: Vec<u8>, ttl: Duration) -> Self {
        Self {
            inner: data,
            created_at: Instant::now(),
            ttl: Some(ttl),
        }
    }

    /// Exposes the underlying bytes. Use only where strictly necessary.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Explicitly zeroes the buffer contents.
    pub fn wipe(&mut self) {
        self.inner.zeroize();
    }

    /// Returns `true` if the buffer's TTL has expired.
    ///
    /// Buffers without a TTL never expire.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => self.created_at.elapsed() >= ttl,
            None => false,
        }
    }
}

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for SensitiveBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SensitiveBuffer([REDACTED] {} bytes)", self.inner.len())
    }
}

impl std::fmt::Display for SensitiveBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Backup exclusion metadata for mobile data items.
///
/// Defaults to [`Exclude`](BackupExclusion::Exclude) (secure by default, per MASWE-0004).
///
/// # Examples
///
/// ```
/// use secure_data::mobile_storage::BackupExclusion;
///
/// let policy = BackupExclusion::default();
/// assert!(policy.should_exclude_from_backup());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BackupExclusion {
    /// Data must be excluded from device backups.
    #[default]
    Exclude,
    /// Data may be included in device backups.
    Allow,
}

impl BackupExclusion {
    /// Returns `true` if this data item should be excluded from device backups.
    #[must_use]
    pub fn should_exclude_from_backup(&self) -> bool {
        matches!(self, Self::Exclude)
    }
}

/// Mobile storage policy enforcing encryption and hardware keystore requirements.
///
/// Policy requirements are derived from the data's [`DataClassification`]:
/// - `Public` / `Internal`: no encryption or hardware required.
/// - `Confidential` / `PII` / `Regulated`: encryption required.
/// - `Secret` / `Credentials`: encryption + hardware keystore required.
///
/// # Examples
///
/// ```
/// use secure_data::mobile_storage::MobileStoragePolicy;
/// use security_core::classification::DataClassification;
///
/// let policy = MobileStoragePolicy::encrypted(DataClassification::Confidential);
/// assert!(policy.requires_encryption());
/// assert!(!policy.requires_hardware_keystore());
/// ```
#[derive(Clone, Debug)]
pub struct MobileStoragePolicy {
    classification: DataClassification,
    require_encryption: bool,
    require_hardware_keystore: bool,
}

impl MobileStoragePolicy {
    /// Creates a policy that requires encryption for the given classification.
    #[must_use]
    pub fn encrypted(classification: DataClassification) -> Self {
        Self {
            classification,
            require_encryption: true,
            require_hardware_keystore: false,
        }
    }

    /// Creates a policy that requires both encryption and hardware keystore.
    #[must_use]
    pub fn hardware_backed(classification: DataClassification) -> Self {
        Self {
            classification,
            require_encryption: true,
            require_hardware_keystore: true,
        }
    }

    /// Auto-selects an appropriate policy based on data classification.
    ///
    /// - `Public` / `Internal`: no requirements.
    /// - `Confidential` / `PII` / `Regulated`: encryption required.
    /// - `Secret` / `Credentials`: encryption + hardware keystore required.
    #[must_use]
    pub fn for_classification(classification: DataClassification) -> Self {
        match classification {
            DataClassification::Public | DataClassification::Internal => Self {
                classification,
                require_encryption: false,
                require_hardware_keystore: false,
            },
            DataClassification::Confidential
            | DataClassification::PII
            | DataClassification::Regulated => Self {
                classification,
                require_encryption: true,
                require_hardware_keystore: false,
            },
            DataClassification::Secret | DataClassification::Credentials => Self {
                classification,
                require_encryption: true,
                require_hardware_keystore: true,
            },
            _ => Self {
                classification,
                require_encryption: true,
                require_hardware_keystore: false,
            },
        }
    }

    /// Returns `true` if the policy requires encrypted storage.
    #[must_use]
    pub fn requires_encryption(&self) -> bool {
        self.require_encryption
    }

    /// Returns `true` if the policy requires a hardware-backed keystore.
    #[must_use]
    pub fn requires_hardware_keystore(&self) -> bool {
        self.require_hardware_keystore
    }

    /// Returns the data classification this policy applies to.
    #[must_use]
    pub fn classification(&self) -> DataClassification {
        self.classification
    }

    /// Checks whether the given storage state complies with this policy.
    ///
    /// Returns a list of [`SecurityEvent`] violations. An empty list means compliant.
    ///
    /// # Arguments
    ///
    /// - `is_encrypted`: whether the storage is encrypted.
    /// - `has_hardware_keystore`: whether a hardware keystore is in use.
    #[must_use]
    pub fn check_compliance(
        &self,
        is_encrypted: bool,
        has_hardware_keystore: bool,
    ) -> Vec<SecurityEvent> {
        use security_core::severity::SecuritySeverity;
        use security_events::event::EventOutcome;

        let mut violations = Vec::new();

        if self.require_encryption && !is_encrypted {
            let mut event = SecurityEvent::new(
                EventKind::StoragePolicyViolation,
                SecuritySeverity::High,
                EventOutcome::Failure,
            );
            event.resource = Some(format!(
                "encryption required for {:?} data but storage is not encrypted",
                self.classification
            ));
            violations.push(event);
        }

        if self.require_hardware_keystore && !has_hardware_keystore {
            let mut event = SecurityEvent::new(
                EventKind::StoragePolicyViolation,
                SecuritySeverity::High,
                EventOutcome::Failure,
            );
            event.resource = Some(format!(
                "hardware keystore required for {:?} data but not available",
                self.classification
            ));
            violations.push(event);
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_buffer_debug_redacted() {
        let buf = SensitiveBuffer::new(vec![1, 2, 3]);
        assert!(format!("{:?}", buf).contains("[REDACTED]"));
    }

    #[test]
    fn backup_exclusion_default_is_exclude() {
        assert!(BackupExclusion::default().should_exclude_from_backup());
    }

    #[test]
    fn mobile_storage_policy_public_relaxed() {
        let p = MobileStoragePolicy::for_classification(DataClassification::Public);
        assert!(!p.requires_encryption());
        assert!(!p.requires_hardware_keystore());
    }

    #[test]
    fn mobile_storage_policy_credentials_strict() {
        let p = MobileStoragePolicy::for_classification(DataClassification::Credentials);
        assert!(p.requires_encryption());
        assert!(p.requires_hardware_keystore());
    }
}

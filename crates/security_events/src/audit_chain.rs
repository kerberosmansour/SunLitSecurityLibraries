//! Tamper-evident hash-linked audit chain (OWASP C9).
//!
//! Each entry contains the SHA-256 hash of `(previous_entry_hash_hex || event_json)`.
//! The first entry hashes `("" || event_json)` — the empty-string prefix.
//! Calling `verify()` recomputes all hashes and checks chain consistency.

use crate::event::SecurityEvent;
use hex;
use sha2::{Digest, Sha256};

/// A single entry in the audit chain.
#[derive(Debug, Clone)]
pub struct ChainedAuditEntry {
    /// The security event stored in this entry.
    pub event: SecurityEvent,
    /// The SHA-256 hash of this entry (hex-encoded).
    pub hash: String,
    /// The hash of the previous entry, or `None` for the genesis entry.
    pub previous_hash: Option<String>,
}

/// A tamper-evident, SHA-256 hash-linked audit event chain.
///
/// Each entry's hash covers the previous entry's hash and the current event's
/// JSON serialization, making the chain resistant to retroactive modification.
///
/// # Example
/// ```rust
/// use security_events::audit_chain::AuditChain;
/// use security_events::event::{SecurityEvent, EventOutcome};
/// use security_events::kind::EventKind;
/// use security_core::severity::SecuritySeverity;
///
/// let mut chain = AuditChain::new();
/// let event = SecurityEvent::new(EventKind::AdminAction, SecuritySeverity::Info, EventOutcome::Success);
/// chain.append(event);
/// assert!(chain.verify());
/// ```
#[derive(Debug, Default)]
pub struct AuditChain {
    entries: Vec<ChainedAuditEntry>,
}

impl AuditChain {
    /// Creates a new empty audit chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a security event to the chain.
    ///
    /// Computes `hash = SHA256(previous_hash_hex_bytes || event_json_bytes)`.
    pub fn append(&mut self, event: SecurityEvent) {
        let previous_hash = self.entries.last().map(|e| e.hash.clone());
        let hash = compute_entry_hash(previous_hash.as_deref(), &event);
        self.entries.push(ChainedAuditEntry {
            event,
            hash,
            previous_hash,
        });
    }

    /// Returns a slice of all entries in the chain.
    #[must_use]
    pub fn entries(&self) -> &[ChainedAuditEntry] {
        &self.entries
    }

    /// Returns the number of entries in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the chain has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verifies the integrity of the chain by recomputing all hashes.
    ///
    /// Returns `true` if all hashes are consistent, `false` if any tampering is detected.
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut prev_hash: Option<&str> = None;
        for entry in &self.entries {
            // Check previous_hash pointer
            match (&entry.previous_hash, prev_hash) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => return false,
            }
            // Recompute and compare
            let expected = compute_entry_hash(prev_hash, &entry.event);
            if expected != entry.hash {
                return false;
            }
            prev_hash = Some(&entry.hash);
        }
        true
    }
}

/// Computes `SHA256(previous_hash_hex || event_json)`.
fn compute_entry_hash(previous_hash: Option<&str>, event: &SecurityEvent) -> String {
    let event_json = serde_json::to_string(event).unwrap_or_default();
    let mut hasher = Sha256::new();
    if let Some(prev) = previous_hash {
        hasher.update(prev.as_bytes());
    }
    hasher.update(event_json.as_bytes());
    hex::encode(hasher.finalize())
}

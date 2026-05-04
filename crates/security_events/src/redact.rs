//! Classification-driven redaction engine.

use crate::event::{EventValue, SecurityEvent};
use security_core::classification::DataClassification;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The action to apply to a data value during redaction.
///
/// # Examples
///
/// ```
/// use security_events::redact::RedactionStrategy;
///
/// let strategy = RedactionStrategy::Redact;
/// assert_ne!(strategy, RedactionStrategy::Allow);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RedactionStrategy {
    /// Emit the value unchanged.
    Allow,
    /// Replace the value with `"[REDACTED]"`.
    Redact,
    /// Replace the value with `"SHA256:<hex>"`.
    Hash,
    /// Remove the label from the event entirely.
    Drop,
    /// Pseudonymize the value (currently a no-op, treated as Allow).
    Pseudonymize,
}

/// Maps [`DataClassification`] levels to [`RedactionStrategy`] actions.
///
/// # Examples
///
/// ```
/// use security_events::redact::RedactionPolicy;
/// use security_events::redact::RedactionStrategy;
/// use security_core::classification::DataClassification;
///
/// let policy = RedactionPolicy::default();
/// assert_eq!(policy.strategy_for(DataClassification::Public), RedactionStrategy::Allow);
/// assert_eq!(policy.strategy_for(DataClassification::PII), RedactionStrategy::Hash);
/// ```
#[derive(Clone, Debug)]
pub struct RedactionPolicy {
    /// Strategy for Public data.
    pub public: RedactionStrategy,
    /// Strategy for Internal data.
    pub internal: RedactionStrategy,
    /// Strategy for Confidential data.
    pub confidential: RedactionStrategy,
    /// Strategy for PII data.
    pub pii: RedactionStrategy,
    /// Strategy for Regulated data.
    pub regulated: RedactionStrategy,
    /// Strategy for Secret data.
    pub secret: RedactionStrategy,
    /// Strategy for Credentials data.
    pub credentials: RedactionStrategy,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            public: RedactionStrategy::Allow,
            internal: RedactionStrategy::Allow,
            confidential: RedactionStrategy::Redact,
            pii: RedactionStrategy::Hash,
            regulated: RedactionStrategy::Hash,
            secret: RedactionStrategy::Redact,
            credentials: RedactionStrategy::Drop,
        }
    }
}

impl RedactionPolicy {
    /// Returns the [`RedactionStrategy`] for the given [`DataClassification`].
    #[must_use]
    pub fn strategy_for(&self, classification: DataClassification) -> RedactionStrategy {
        match classification {
            DataClassification::Public => self.public,
            DataClassification::Internal => self.internal,
            DataClassification::Confidential => self.confidential,
            DataClassification::PII => self.pii,
            DataClassification::Regulated => self.regulated,
            DataClassification::Secret => self.secret,
            DataClassification::Credentials => self.credentials,
            _ => RedactionStrategy::Redact,
        }
    }
}

/// Applies a [`RedactionPolicy`] to [`SecurityEvent`] labels before emission.
///
/// # Examples
///
/// ```
/// use security_events::redact::{RedactionEngine, RedactionPolicy};
///
/// let engine = RedactionEngine::with_default_policy();
/// // Use engine.process_event(event) to apply redaction to event labels.
/// ```
#[derive(Clone, Debug)]
pub struct RedactionEngine {
    /// The policy controlling how each classification level is handled.
    pub policy: RedactionPolicy,
}

impl RedactionEngine {
    /// Creates a new [`RedactionEngine`] with the given policy.
    #[must_use]
    pub fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Creates a new [`RedactionEngine`] using the default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self {
            policy: RedactionPolicy::default(),
        }
    }

    /// Processes a [`SecurityEvent`], applying the redaction policy to all labels.
    ///
    /// - `Drop` removes the label entirely.
    /// - `Redact` replaces the value with `"[REDACTED]"`.
    /// - `Hash` replaces the value with `"SHA256:<hex>"`.
    /// - `Allow` / `Pseudonymize` leave the value unchanged.
    #[must_use]
    pub fn process_event(&self, mut event: SecurityEvent) -> SecurityEvent {
        let mut new_labels = BTreeMap::new();
        for (key, value) in event.labels {
            match value {
                EventValue::Classified {
                    value: v,
                    classification,
                } => {
                    let strategy = self.policy.strategy_for(classification);
                    match strategy {
                        RedactionStrategy::Drop => {}
                        RedactionStrategy::Redact => {
                            new_labels.insert(
                                key,
                                EventValue::Classified {
                                    value: "[REDACTED]".to_string(),
                                    classification,
                                },
                            );
                        }
                        RedactionStrategy::Hash => {
                            let mut hasher = Sha256::new();
                            hasher.update(v.as_bytes());
                            let hash = hex::encode(hasher.finalize());
                            new_labels.insert(
                                key,
                                EventValue::Classified {
                                    value: format!("SHA256:{hash}"),
                                    classification,
                                },
                            );
                        }
                        RedactionStrategy::Allow | RedactionStrategy::Pseudonymize => {
                            new_labels.insert(
                                key,
                                EventValue::Classified {
                                    value: v,
                                    classification,
                                },
                            );
                        }
                    }
                }
            }
        }
        event.labels = new_labels;
        event
    }
}

//! Consent tracking state machine and policy enforcement.
//!
//! Provides the state machine and validation logic for consent management.
//! The consuming application is responsible for storage and UI; this module
//! provides purpose-scoped consent validation and state transitions.

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use serde::Serialize;

/// A purpose for which consent may be granted (e.g., "analytics", "marketing").
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ConsentPurpose(pub String);

impl ConsentPurpose {
    /// Creates a new consent purpose.
    #[must_use]
    pub fn new(purpose: &str) -> Self {
        Self(purpose.to_string())
    }
}

/// The current state of consent for a given purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum ConsentState {
    /// Consent has been explicitly granted.
    Granted,
    /// Consent has been explicitly denied.
    Denied,
    /// Consent was previously granted but has been withdrawn.
    Withdrawn,
    /// Consent has not yet been collected for this purpose.
    NotCollected,
}

/// The result of a consent check — whether data processing is allowed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum ConsentDecision {
    /// Processing is allowed.
    Allowed,
    /// Processing is denied (consent explicitly denied).
    Denied,
    /// Consent has not yet been collected (deny by default).
    NotCollected,
    /// Consent was previously granted but has been withdrawn.
    Withdrawn,
    /// The requested processing purpose does not match the consented purpose.
    PurposeMismatch,
}

/// A consent policy that tracks state for a specific purpose and validates
/// processing requests against that state.
pub struct ConsentPolicy {
    purpose: ConsentPurpose,
    state: ConsentState,
}

impl ConsentPolicy {
    /// Creates a new consent policy for the given purpose with no consent collected.
    #[must_use]
    pub fn new(purpose: ConsentPurpose) -> Self {
        Self {
            purpose,
            state: ConsentState::NotCollected,
        }
    }

    /// Returns the current consent state.
    #[must_use]
    pub fn state(&self) -> ConsentState {
        self.state
    }

    /// Returns the purpose this policy governs.
    #[must_use]
    pub fn purpose(&self) -> &ConsentPurpose {
        &self.purpose
    }

    /// Records that consent has been granted.
    pub fn grant(&mut self) {
        self.state = ConsentState::Granted;
    }

    /// Records that consent has been denied.
    pub fn deny(&mut self) {
        self.state = ConsentState::Denied;
    }

    /// Withdraws previously granted consent.
    pub fn withdraw(&mut self) {
        self.state = ConsentState::Withdrawn;
    }

    /// Checks whether data processing is allowed for the given purpose.
    ///
    /// If consent is not granted, emits a `ConsentViolation` security event
    /// to the provided sink.
    pub fn check_consent(
        &self,
        requested_purpose: &ConsentPurpose,
        sink: &dyn SecuritySink,
    ) -> ConsentDecision {
        // Purpose mismatch check
        if *requested_purpose != self.purpose {
            let mut event = SecurityEvent::new(
                EventKind::ConsentViolation,
                SecuritySeverity::High,
                EventOutcome::Blocked,
            );
            event.labels.insert(
                "consented_purpose".to_string(),
                EventValue::Classified {
                    value: self.purpose.0.clone(),
                    classification: DataClassification::Internal,
                },
            );
            event.labels.insert(
                "requested_purpose".to_string(),
                EventValue::Classified {
                    value: requested_purpose.0.clone(),
                    classification: DataClassification::Internal,
                },
            );
            event.labels.insert(
                "reason".to_string(),
                EventValue::Classified {
                    value: "purpose_mismatch".to_string(),
                    classification: DataClassification::Internal,
                },
            );
            sink.write_event(&event);
            return ConsentDecision::PurposeMismatch;
        }

        match self.state {
            ConsentState::Granted => ConsentDecision::Allowed,
            ConsentState::Denied => {
                self.emit_consent_event(sink, "consent_denied");
                ConsentDecision::Denied
            }
            ConsentState::NotCollected => {
                self.emit_consent_event(sink, "consent_not_collected");
                ConsentDecision::NotCollected
            }
            ConsentState::Withdrawn => {
                self.emit_consent_event(sink, "consent_withdrawn");
                ConsentDecision::Withdrawn
            }
        }
    }

    fn emit_consent_event(&self, sink: &dyn SecuritySink, reason: &str) {
        let mut event = SecurityEvent::new(
            EventKind::ConsentViolation,
            SecuritySeverity::Medium,
            EventOutcome::Blocked,
        );
        event.labels.insert(
            "purpose".to_string(),
            EventValue::Classified {
                value: self.purpose.0.clone(),
                classification: DataClassification::Internal,
            },
        );
        event.labels.insert(
            "reason".to_string(),
            EventValue::Classified {
                value: reason.to_string(),
                classification: DataClassification::Internal,
            },
        );
        sink.write_event(&event);
    }
}

//! Step-up authentication policy enforcement.
//!
//! Provides policy evaluation for determining whether a sensitive operation
//! requires re-authentication (step-up), satisfying MASVS-AUTH-3/MASWE-0029.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use std::time::Duration;

/// The result of evaluating a step-up authentication policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepUpDecision {
    /// The operation requires re-authentication before proceeding.
    Required,
    /// The user's authentication is fresh enough; no step-up needed.
    NotRequired,
}

/// Policy governing when step-up authentication is required for an operation.
///
/// Step-up authentication forces re-verification before sensitive operations
/// (e.g., money transfers, account deletion) even if the user has a valid session.
#[derive(Clone, Debug)]
pub struct StepUpPolicy {
    operation: String,
    /// Maximum allowed age of the last authentication. If the user's last
    /// authentication is older than this, step-up is required.
    /// `None` means step-up is always required regardless of auth freshness.
    max_auth_age: Option<Duration>,
}

impl StepUpPolicy {
    /// Create a step-up policy for an operation with a time-based threshold.
    ///
    /// If the user's last authentication is older than `max_auth_age`, step-up
    /// is required.
    #[must_use]
    pub fn new(operation: impl Into<String>, max_auth_age: Duration) -> Self {
        Self {
            operation: operation.into(),
            max_auth_age: Some(max_auth_age),
        }
    }

    /// Create a step-up policy that always requires re-authentication.
    ///
    /// Used for critical operations like account deletion where no auth
    /// freshness is sufficient.
    #[must_use]
    pub fn always(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            max_auth_age: None,
        }
    }

    /// Returns the operation name this policy applies to.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Evaluate whether step-up authentication is required.
    ///
    /// `last_auth_age` is how long ago the user last authenticated.
    #[must_use]
    pub fn evaluate(&self, last_auth_age: Duration) -> StepUpDecision {
        match self.max_auth_age {
            None => StepUpDecision::Required,
            Some(max_age) => {
                if last_auth_age > max_age {
                    StepUpDecision::Required
                } else {
                    StepUpDecision::NotRequired
                }
            }
        }
    }

    /// Evaluate and return security events if step-up is required.
    ///
    /// Returns a list of security events. Empty if step-up is not required.
    #[must_use]
    pub fn evaluate_with_events(&self, last_auth_age: Duration) -> Vec<SecurityEvent> {
        let decision = self.evaluate(last_auth_age);
        match decision {
            StepUpDecision::NotRequired => vec![],
            StepUpDecision::Required => {
                let mut event = SecurityEvent::new(
                    EventKind::StepUpAuthFailure,
                    SecuritySeverity::High,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some("step_up_required");
                event.resource = Some(self.operation.clone());
                vec![event]
            }
        }
    }
}

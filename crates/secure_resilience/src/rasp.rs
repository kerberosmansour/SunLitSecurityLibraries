//! RASP (Runtime Application Self-Protection) policy engine.
//!
//! Evaluates environment detection signals against configurable policies and returns
//! response decisions (Allow, Warn, Block, Degrade). The engine also maintains an
//! aggregate threat level from all processed signals.

use crate::environment::{Confidence, EnvironmentSignal, ThreatLevel};
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use serde::Serialize;
use std::sync::atomic::{AtomicU32, Ordering};

/// The configured response action for a signal type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum ResponseAction {
    /// Allow the operation to proceed without restriction.
    Allow,
    /// Warn but allow the operation to continue.
    Warn,
    /// Block the operation entirely.
    Block,
    /// Degrade functionality — remove sensitive capabilities.
    Degrade,
}

/// The RASP engine's decision after evaluating a signal against policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RaspDecision {
    /// The operation is allowed to proceed.
    Allow,
    /// The operation is allowed but a warning was issued.
    Warn {
        /// The signal category that triggered the warning.
        signal_category: String,
    },
    /// The operation is blocked.
    Block {
        /// The signal category that triggered the block.
        signal_category: String,
    },
    /// Functionality is degraded — sensitive capabilities removed.
    Degrade {
        /// List of capabilities that were removed.
        capabilities_removed: Vec<String>,
    },
}

/// Configurable RASP policy defining response actions for each signal type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RaspPolicy {
    /// Response when root/jailbreak is detected.
    pub root_response: ResponseAction,
    /// Response when an emulator is detected.
    pub emulator_response: ResponseAction,
    /// Response when a debugger is detected.
    pub debugger_response: ResponseAction,
    /// Response for unknown/custom signals.
    pub unknown_response: ResponseAction,
}

impl Default for RaspPolicy {
    /// Default policy: warn on all known signals, allow unknowns.
    /// This is secure but not disruptive — appropriate for initial deployment.
    fn default() -> Self {
        Self {
            root_response: ResponseAction::Warn,
            emulator_response: ResponseAction::Warn,
            debugger_response: ResponseAction::Warn,
            unknown_response: ResponseAction::Allow,
        }
    }
}

impl RaspPolicy {
    /// Create a fully permissive policy — all signals result in Allow.
    /// Useful for development/testing environments.
    pub fn permissive() -> Self {
        Self {
            root_response: ResponseAction::Allow,
            emulator_response: ResponseAction::Allow,
            debugger_response: ResponseAction::Allow,
            unknown_response: ResponseAction::Allow,
        }
    }

    /// Returns the configured response action for the given signal.
    fn action_for(&self, signal: &EnvironmentSignal) -> ResponseAction {
        match signal {
            EnvironmentSignal::RootDetected { .. } => self.root_response,
            EnvironmentSignal::EmulatorDetected { .. } => self.emulator_response,
            EnvironmentSignal::DebuggerAttached { .. } => self.debugger_response,
            EnvironmentSignal::Unknown { .. } => self.unknown_response,
        }
    }
}

/// The RASP engine processes environment signals and returns policy-driven decisions.
///
/// It maintains an internal threat score that accumulates as signals are processed,
/// enabling progressive threat level escalation.
pub struct RaspEngine {
    policy: RaspPolicy,
    threat_score: AtomicU32,
}

impl RaspEngine {
    /// Create a new RASP engine with the given policy.
    pub fn new(policy: RaspPolicy) -> Self {
        Self {
            policy,
            threat_score: AtomicU32::new(0),
        }
    }

    /// Process an environment signal, emit a security event, and return a decision.
    pub fn process_signal(
        &self,
        signal: &EnvironmentSignal,
        sink: &impl SecuritySink,
    ) -> RaspDecision {
        // Update threat score
        let weight = self.compute_weighted_score(signal);
        if weight > 0 {
            self.threat_score.fetch_add(weight, Ordering::Relaxed);
        }

        // Emit security event
        let severity = self.severity_for(signal);
        let action = self.policy.action_for(signal);
        let outcome = match action {
            ResponseAction::Allow => EventOutcome::Success,
            ResponseAction::Warn => EventOutcome::Success,
            ResponseAction::Block => EventOutcome::Blocked,
            ResponseAction::Degrade => EventOutcome::Success,
        };

        let mut event = SecurityEvent::new(EventKind::EnvironmentThreat, severity, outcome);
        event.resource = Some(signal.category().to_string());
        event.labels.insert(
            "evidence".to_string(),
            EventValue::Classified {
                value: signal.evidence().to_string(),
                classification: DataClassification::Internal,
            },
        );
        if let Some(confidence) = signal.confidence() {
            event.labels.insert(
                "confidence".to_string(),
                EventValue::Classified {
                    value: format!("{confidence:?}"),
                    classification: DataClassification::Internal,
                },
            );
        }
        sink.write_event(&event);

        // Return decision
        self.action_to_decision(action, signal)
    }

    /// Returns the current aggregate threat level.
    pub fn threat_level(&self) -> ThreatLevel {
        ThreatLevel::from_score(self.threat_score.load(Ordering::Relaxed))
    }

    /// Compute a weighted score for a signal based on its base weight and confidence.
    fn compute_weighted_score(&self, signal: &EnvironmentSignal) -> u32 {
        let base = signal.base_threat_weight();
        let multiplier = match signal.confidence() {
            Some(Confidence::High) => 100,
            Some(Confidence::Medium) => 60,
            Some(Confidence::Low) => 30,
            None => 0,
        };
        base * multiplier / 100
    }

    /// Map signal to security severity.
    fn severity_for(&self, signal: &EnvironmentSignal) -> SecuritySeverity {
        match signal {
            EnvironmentSignal::DebuggerAttached {
                confidence: Confidence::High,
                ..
            } => SecuritySeverity::Critical,
            EnvironmentSignal::DebuggerAttached { .. } => SecuritySeverity::High,
            EnvironmentSignal::RootDetected {
                confidence: Confidence::High,
                ..
            } => SecuritySeverity::High,
            EnvironmentSignal::RootDetected { .. } => SecuritySeverity::Medium,
            EnvironmentSignal::EmulatorDetected { .. } => SecuritySeverity::Medium,
            EnvironmentSignal::Unknown { .. } => SecuritySeverity::Low,
        }
    }

    /// Convert a response action + signal into a RaspDecision.
    fn action_to_decision(
        &self,
        action: ResponseAction,
        signal: &EnvironmentSignal,
    ) -> RaspDecision {
        match action {
            ResponseAction::Allow => RaspDecision::Allow,
            ResponseAction::Warn => RaspDecision::Warn {
                signal_category: signal.category().to_string(),
            },
            ResponseAction::Block => RaspDecision::Block {
                signal_category: signal.category().to_string(),
            },
            ResponseAction::Degrade => RaspDecision::Degrade {
                capabilities_removed: self.degraded_capabilities(signal),
            },
        }
    }

    /// Returns the list of capabilities to remove for a degraded response.
    fn degraded_capabilities(&self, signal: &EnvironmentSignal) -> Vec<String> {
        match signal {
            EnvironmentSignal::RootDetected { .. } => {
                vec!["secure_storage".to_string(), "biometric_auth".to_string()]
            }
            EnvironmentSignal::EmulatorDetected { .. } => vec![
                "payment_processing".to_string(),
                "sensitive_data_display".to_string(),
            ],
            EnvironmentSignal::DebuggerAttached { .. } => {
                vec!["all_sensitive_operations".to_string()]
            }
            EnvironmentSignal::Unknown { .. } => vec!["unknown_capability".to_string()],
        }
    }
}

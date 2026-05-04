//! BDD acceptance tests for RASP policy engine (Milestone 5).

use secure_resilience::environment::*;
use secure_resilience::rasp::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

// --- Feature: RASP Policy Engine ---

/// Scenario: Warn policy on root detection
/// Given `RaspPolicy` with `root_response: Warn`
/// When Root signal received
/// Then `RaspDecision::Warn` returned
#[test]
fn given_warn_policy_when_root_detected_then_warn_decision() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy {
        root_response: ResponseAction::Warn,
        ..RaspPolicy::default()
    };
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Warn { .. }));
}

/// Scenario: Block policy on debugger
/// Given `RaspPolicy` with `debugger_response: Block`
/// When Debugger signal received
/// Then `RaspDecision::Block` returned
#[test]
fn given_block_policy_when_debugger_detected_then_block_decision() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy {
        debugger_response: ResponseAction::Block,
        ..RaspPolicy::default()
    };
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::DebuggerAttached {
        confidence: Confidence::High,
        evidence: "frida".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Block { .. }));
}

/// Scenario: Degrade policy on emulator
/// Given `RaspPolicy` with `emulator_response: Degrade`
/// When Emulator signal received
/// Then `RaspDecision::Degrade { capabilities_removed }` returned
#[test]
fn given_degrade_policy_when_emulator_detected_then_degrade_decision() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy {
        emulator_response: ResponseAction::Degrade,
        ..RaspPolicy::default()
    };
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::EmulatorDetected {
        confidence: Confidence::Medium,
        evidence: "goldfish".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    match decision {
        RaspDecision::Degrade {
            capabilities_removed,
        } => {
            assert!(!capabilities_removed.is_empty());
        }
        _ => panic!("Expected Degrade decision, got {decision:?}"),
    }
}

/// Scenario: Allow policy (permissive mode)
/// Given `RaspPolicy::permissive()`
/// When Any signal received
/// Then `RaspDecision::Allow` with informational event
#[test]
fn given_permissive_policy_when_any_signal_then_allow_with_event() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::permissive();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Allow));

    // Informational event still emitted
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::EnvironmentThreat);
}

/// Scenario: Default policy is warn
/// Given `RaspPolicy::default()`
/// When Root detected
/// Then `RaspDecision::Warn` (secure but not disruptive default)
#[test]
fn given_default_policy_when_root_detected_then_warn() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Warn { .. }));
}

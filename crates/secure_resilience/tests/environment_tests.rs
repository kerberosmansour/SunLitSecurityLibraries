//! BDD acceptance tests for environment signal processing (Milestone 5).

use secure_resilience::environment::*;
use secure_resilience::rasp::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

// --- Feature: Environment Signal Processing ---

/// Scenario: Root detection signal processed
/// Given `EnvironmentSignal::RootDetected` with high confidence
/// When Signal processed by `RaspEngine`
/// Then `ThreatLevel` updated, security event emitted
#[test]
fn given_root_detected_high_confidence_when_processed_then_threat_updated_and_event_emitted() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary found".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);

    // Default policy warns on root
    assert!(matches!(decision, RaspDecision::Warn { .. }));

    // Security event emitted
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::EnvironmentThreat);

    // Threat level updated
    let threat_level = engine.threat_level();
    assert!(threat_level > ThreatLevel::None);
}

/// Scenario: Emulator detected
/// Given `EnvironmentSignal::EmulatorDetected` with medium confidence
/// When Signal processed
/// Then `ThreatLevel` updated appropriately
#[test]
fn given_emulator_detected_medium_confidence_when_processed_then_threat_updated() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::EmulatorDetected {
        confidence: Confidence::Medium,
        evidence: "emulator properties detected".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Warn { .. }));

    let threat_level = engine.threat_level();
    assert!(threat_level > ThreatLevel::None);
}

/// Scenario: Debugger attached
/// Given `EnvironmentSignal::DebuggerAttached` with high confidence
/// When Signal processed
/// Then Highest priority threat, immediate response recommended
#[test]
fn given_debugger_attached_high_confidence_when_processed_then_highest_threat() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::DebuggerAttached {
        confidence: Confidence::High,
        evidence: "ptrace attached".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Warn { .. }));

    let threat_level = engine.threat_level();
    assert_eq!(threat_level, ThreatLevel::Critical);
}

/// Scenario: Multiple signals aggregate
/// Given Root + emulator + debugger signals
/// When All processed
/// Then `ThreatLevel` reflects combined risk
#[test]
fn given_multiple_signals_when_all_processed_then_threat_reflects_combined_risk() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let root = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary".to_string(),
    };
    let emulator = EnvironmentSignal::EmulatorDetected {
        confidence: Confidence::Medium,
        evidence: "goldfish".to_string(),
    };
    let debugger = EnvironmentSignal::DebuggerAttached {
        confidence: Confidence::High,
        evidence: "frida".to_string(),
    };

    engine.process_signal(&root, &sink);
    engine.process_signal(&emulator, &sink);
    engine.process_signal(&debugger, &sink);

    let threat_level = engine.threat_level();
    assert_eq!(threat_level, ThreatLevel::Critical);

    // All signals emitted events
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|e| e.kind == EventKind::EnvironmentThreat));
}

/// Scenario: Unknown signal type handled
/// Given `EnvironmentSignal::Unknown`
/// When Signal processed
/// Then Logged but does not trigger response
#[test]
fn given_unknown_signal_when_processed_then_logged_no_threat_change() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy::default();
    let engine = RaspEngine::new(policy);

    let signal = EnvironmentSignal::Unknown {
        label: "custom_check".to_string(),
        evidence: "some unknown signal".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Allow));

    // Event is still emitted for observability
    let events = sink.events();
    assert_eq!(events.len(), 1);

    // Threat level unchanged
    let threat_level = engine.threat_level();
    assert_eq!(threat_level, ThreatLevel::None);
}

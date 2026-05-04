//! E2E runtime validation tests for Milestone 5 — secure_resilience.
//!
//! These tests prove end-to-end integration of environment detection,
//! RASP policy evaluation, integrity verification, and security event emission.

use secure_resilience::environment::*;
use secure_resilience::integrity::*;
use secure_resilience::rasp::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

/// E2E: Full RASP pipeline — multiple environment signals trigger correct decisions and events.
#[test]
fn test_rasp_pipeline_processes_multiple_signals_with_events() {
    let sink = InMemorySink::new();
    let policy = RaspPolicy {
        root_response: ResponseAction::Warn,
        emulator_response: ResponseAction::Degrade,
        debugger_response: ResponseAction::Block,
        ..RaspPolicy::default()
    };
    let engine = RaspEngine::new(policy);

    // Root → Warn
    let root = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary found".to_string(),
    };
    let d1 = engine.process_signal(&root, &sink);
    assert!(matches!(d1, RaspDecision::Warn { .. }));

    // Emulator → Degrade
    let emu = EnvironmentSignal::EmulatorDetected {
        confidence: Confidence::Medium,
        evidence: "goldfish".to_string(),
    };
    let d2 = engine.process_signal(&emu, &sink);
    assert!(matches!(d2, RaspDecision::Degrade { .. }));

    // Debugger → Block
    let dbg = EnvironmentSignal::DebuggerAttached {
        confidence: Confidence::High,
        evidence: "frida server".to_string(),
    };
    let d3 = engine.process_signal(&dbg, &sink);
    assert!(matches!(d3, RaspDecision::Block { .. }));

    // Verify all events emitted
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|e| e.kind == EventKind::EnvironmentThreat));

    // Verify threat level escalated to Critical
    assert_eq!(engine.threat_level(), ThreatLevel::Critical);
}

/// E2E: Integrity check pipeline — signature verification with event emission.
#[test]
fn test_integrity_pipeline_signature_verification() {
    let sink = InMemorySink::new();
    let expected = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let check = IntegrityCheck::new_signature(expected);

    // Valid signature — no events
    let result = check.verify_with_events(expected, &sink);
    assert_eq!(result, IntegrityResult::Valid);
    assert!(sink.events().is_empty());

    // Tampered signature — event emitted
    let result = check.verify_with_events("tampered", &sink);
    assert_eq!(result, IntegrityResult::Tampered);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::IntegrityViolation);
}

/// E2E: Resource integrity pipeline — multiple resources checked with event emission.
#[test]
fn test_integrity_pipeline_resource_verification() {
    let sink = InMemorySink::new();
    let mut check = IntegrityCheck::new_resource_integrity();
    check.add_resource_hash("app.js", "hash1");
    check.add_resource_hash("config.xml", "hash2");

    let mut actual = std::collections::HashMap::new();
    actual.insert("app.js".to_string(), "hash1".to_string());
    actual.insert("config.xml".to_string(), "wrong".to_string());

    let result = check.verify_resources_with_events(&actual, &sink);
    assert_eq!(result, IntegrityResult::Tampered);
    assert_eq!(sink.events().len(), 1);
    assert_eq!(sink.events()[0].kind, EventKind::IntegrityViolation);
}

/// E2E: Permissive RASP policy allows everything but still emits events.
#[test]
fn test_permissive_policy_allows_with_observability() {
    let sink = InMemorySink::new();
    let engine = RaspEngine::new(RaspPolicy::permissive());

    let signals = vec![
        EnvironmentSignal::RootDetected {
            confidence: Confidence::High,
            evidence: "su".to_string(),
        },
        EnvironmentSignal::DebuggerAttached {
            confidence: Confidence::High,
            evidence: "gdb".to_string(),
        },
    ];

    for signal in &signals {
        let decision = engine.process_signal(signal, &sink);
        assert!(matches!(decision, RaspDecision::Allow));
    }

    // Events still emitted for monitoring
    assert_eq!(sink.events().len(), 2);
}

/// E2E: Store verification pipeline.
#[test]
fn test_store_verification_pipeline() {
    let sink = InMemorySink::new();
    let stores = vec!["com.android.vending".to_string()];
    let check = IntegrityCheck::new_store_verification(stores);

    // Official store — valid
    let r1 = check.verify_store_with_events("com.android.vending", &sink);
    assert_eq!(r1, IntegrityResult::Valid);
    assert!(sink.events().is_empty());

    // Unknown store — sideloaded
    let r2 = check.verify_store_with_events("com.shady.store", &sink);
    assert_eq!(r2, IntegrityResult::SideLoaded);
    assert_eq!(sink.events().len(), 1);
}

/// E2E: Threat level progression through signal accumulation.
#[test]
fn test_threat_level_progression() {
    let sink = InMemorySink::new();
    let engine = RaspEngine::new(RaspPolicy::default());

    assert_eq!(engine.threat_level(), ThreatLevel::None);

    // Low-confidence emulator → Low threat
    engine.process_signal(
        &EnvironmentSignal::EmulatorDetected {
            confidence: Confidence::Low,
            evidence: "heuristic".to_string(),
        },
        &sink,
    );
    assert_eq!(engine.threat_level(), ThreatLevel::Low);

    // High-confidence root → escalates to High
    engine.process_signal(
        &EnvironmentSignal::RootDetected {
            confidence: Confidence::High,
            evidence: "su".to_string(),
        },
        &sink,
    );
    assert!(engine.threat_level() >= ThreatLevel::High);

    // High-confidence debugger → escalates to Critical
    engine.process_signal(
        &EnvironmentSignal::DebuggerAttached {
            confidence: Confidence::High,
            evidence: "frida".to_string(),
        },
        &sink,
    );
    assert_eq!(engine.threat_level(), ThreatLevel::Critical);
}

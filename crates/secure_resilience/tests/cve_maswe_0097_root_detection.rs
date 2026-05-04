//! CVE regression tests — MASWE-0097: Root/jailbreak detection signal processing.
//!
//! Milestone 9 — BDD: Root detection signals are processed correctly by RASP engine.
use secure_resilience::{
    Confidence, EnvironmentSignal, RaspDecision, RaspEngine, RaspPolicy, ResponseAction,
    ThreatLevel,
};
use security_events::sink::InMemorySink;

/// MASWE-0097: Root detection with high confidence produces Block when policy says Block.
#[test]
fn maswe_0097_root_high_confidence_block() {
    let policy = RaspPolicy {
        root_response: ResponseAction::Block,
        emulator_response: ResponseAction::Warn,
        debugger_response: ResponseAction::Block,
        unknown_response: ResponseAction::Allow,
    };
    let engine = RaspEngine::new(policy);
    let sink = InMemorySink::new();

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su binary found at /system/xbin/su".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    match decision {
        RaspDecision::Block { signal_category } => {
            assert_eq!(signal_category, "root_detected");
        }
        other => panic!("Expected Block, got: {other:?}"),
    }

    // Should have emitted a security event
    assert_eq!(sink.events().len(), 1);
}

/// MASWE-0097: Root detection with low confidence still processed.
#[test]
fn maswe_0097_root_low_confidence_warn() {
    let engine = RaspEngine::new(RaspPolicy::default());
    let sink = InMemorySink::new();

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::Low,
        evidence: "suspicious property detected".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    match decision {
        RaspDecision::Warn { signal_category } => {
            assert_eq!(signal_category, "root_detected");
        }
        other => panic!("Expected Warn (default policy), got: {other:?}"),
    }
}

/// MASWE-0097: Emulator detection signal processing.
#[test]
fn maswe_0097_emulator_detection() {
    let engine = RaspEngine::new(RaspPolicy::default());
    let sink = InMemorySink::new();

    let signal = EnvironmentSignal::EmulatorDetected {
        confidence: Confidence::High,
        evidence: "goldfish hardware detected".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(
        matches!(decision, RaspDecision::Warn { .. }),
        "Default policy warns on emulator: {decision:?}"
    );
}

/// MASWE-0097: Debugger attachment is highest threat.
#[test]
fn maswe_0097_debugger_highest_threat() {
    let policy = RaspPolicy {
        root_response: ResponseAction::Warn,
        emulator_response: ResponseAction::Warn,
        debugger_response: ResponseAction::Block,
        unknown_response: ResponseAction::Allow,
    };
    let engine = RaspEngine::new(policy);
    let sink = InMemorySink::new();

    let signal = EnvironmentSignal::DebuggerAttached {
        confidence: Confidence::High,
        evidence: "ptrace detected".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    assert!(matches!(decision, RaspDecision::Block { .. }));
}

/// MASWE-0097: Threat level escalates with multiple signals.
#[test]
fn maswe_0097_threat_level_escalation() {
    let engine = RaspEngine::new(RaspPolicy::default());
    let sink = InMemorySink::new();

    assert_eq!(engine.threat_level(), ThreatLevel::None);

    engine.process_signal(
        &EnvironmentSignal::RootDetected {
            confidence: Confidence::High,
            evidence: "su found".to_string(),
        },
        &sink,
    );

    let level_after_root = engine.threat_level();
    assert!(
        level_after_root > ThreatLevel::None,
        "Threat level must increase after root detection"
    );

    engine.process_signal(
        &EnvironmentSignal::DebuggerAttached {
            confidence: Confidence::High,
            evidence: "frida detected".to_string(),
        },
        &sink,
    );

    let level_after_debugger = engine.threat_level();
    assert!(
        level_after_debugger >= level_after_root,
        "Threat level must not decrease after additional signal"
    );
}

/// MASWE-0097: Degrade response removes specific capabilities.
#[test]
fn maswe_0097_degrade_removes_capabilities() {
    let policy = RaspPolicy {
        root_response: ResponseAction::Degrade,
        emulator_response: ResponseAction::Degrade,
        debugger_response: ResponseAction::Degrade,
        unknown_response: ResponseAction::Allow,
    };
    let engine = RaspEngine::new(policy);
    let sink = InMemorySink::new();

    let signal = EnvironmentSignal::RootDetected {
        confidence: Confidence::High,
        evidence: "su found".to_string(),
    };

    let decision = engine.process_signal(&signal, &sink);
    match decision {
        RaspDecision::Degrade {
            capabilities_removed,
        } => {
            assert!(
                !capabilities_removed.is_empty(),
                "Degrade should remove at least one capability"
            );
        }
        other => panic!("Expected Degrade, got: {other:?}"),
    }
}

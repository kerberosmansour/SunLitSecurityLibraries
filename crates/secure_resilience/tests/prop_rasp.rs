//! Property tests — RASP engine invariants for secure_resilience.
//!
//! Milestone 9 — BDD: RASP decision consistency properties.
use proptest::prelude::*;
use secure_resilience::{
    Confidence, EnvironmentSignal, RaspDecision, RaspEngine, RaspPolicy, ResponseAction,
};
use security_events::sink::InMemorySink;

/// Helper: build a signal from indices.
fn signal_from_idx(idx: u8, confidence_idx: u8) -> EnvironmentSignal {
    let confidence = match confidence_idx % 3 {
        0 => Confidence::Low,
        1 => Confidence::Medium,
        _ => Confidence::High,
    };
    match idx % 4 {
        0 => EnvironmentSignal::RootDetected {
            confidence,
            evidence: "prop-test".to_string(),
        },
        1 => EnvironmentSignal::EmulatorDetected {
            confidence,
            evidence: "prop-test".to_string(),
        },
        2 => EnvironmentSignal::DebuggerAttached {
            confidence,
            evidence: "prop-test".to_string(),
        },
        _ => EnvironmentSignal::Unknown {
            label: "custom".to_string(),
            evidence: "prop-test".to_string(),
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// After a Block decision, the engine's threat level never decreases.
    /// The RASP engine accumulates threat score — it only goes up.
    #[test]
    fn prop_rasp_block_stops_processing(
        signal_idx in 0u8..4,
        confidence_idx in 0u8..3,
    ) {
        let policy = RaspPolicy {
            root_response: ResponseAction::Block,
            emulator_response: ResponseAction::Block,
            debugger_response: ResponseAction::Block,
            unknown_response: ResponseAction::Block,
        };
        let engine = RaspEngine::new(policy);
        let sink = InMemorySink::new();
        let signal = signal_from_idx(signal_idx, confidence_idx);

        let decision = engine.process_signal(&signal, &sink);
        let threat_after_first = engine.threat_level();

        // Process another signal
        let second_signal = signal_from_idx((signal_idx + 1) % 4, confidence_idx);
        let _ = engine.process_signal(&second_signal, &sink);
        let threat_after_second = engine.threat_level();

        // Block policy should produce Block decisions for known signals
        if signal_idx % 4 != 3 {
            // Known signals (not Unknown)
            match decision {
                RaspDecision::Block { .. } => {}
                _ => prop_assert!(false, "Expected Block, got: {decision:?}"),
            }
        }

        // Threat level should never decrease
        prop_assert!(
            threat_after_second >= threat_after_first,
            "Threat level decreased: {threat_after_first:?} -> {threat_after_second:?}",
        );
    }

    /// Permissive policy always returns Allow.
    #[test]
    fn prop_rasp_permissive_always_allows(
        signal_idx in 0u8..4,
        confidence_idx in 0u8..3,
    ) {
        let engine = RaspEngine::new(RaspPolicy::permissive());
        let sink = InMemorySink::new();
        let signal = signal_from_idx(signal_idx, confidence_idx);
        let decision = engine.process_signal(&signal, &sink);
        prop_assert_eq!(
            decision,
            RaspDecision::Allow,
            "Permissive policy should always Allow",
        );
    }

    /// process_signal never panics on any signal/confidence combination.
    #[test]
    fn prop_rasp_process_no_panic(
        signal_idx in 0u8..4,
        confidence_idx in 0u8..3,
        evidence in "[a-zA-Z0-9 ]{0,50}",
    ) {
        let engine = RaspEngine::new(RaspPolicy::default());
        let sink = InMemorySink::new();
        let confidence = match confidence_idx % 3 {
            0 => Confidence::Low,
            1 => Confidence::Medium,
            _ => Confidence::High,
        };
        let signal = match signal_idx % 4 {
            0 => EnvironmentSignal::RootDetected { confidence, evidence },
            1 => EnvironmentSignal::EmulatorDetected { confidence, evidence },
            2 => EnvironmentSignal::DebuggerAttached { confidence, evidence },
            _ => EnvironmentSignal::Unknown { label: "custom".to_string(), evidence },
        };
        let _ = engine.process_signal(&signal, &sink);
    }
}

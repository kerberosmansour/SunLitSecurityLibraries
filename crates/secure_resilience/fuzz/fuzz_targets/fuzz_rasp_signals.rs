#![no_main]
//! Fuzz target: RaspEngine::process_signal never panics on arbitrary signal sequences.
use libfuzzer_sys::fuzz_target;
use secure_resilience::{Confidence, EnvironmentSignal, RaspEngine, RaspPolicy};
use security_events::sink::InMemorySink;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let engine = RaspEngine::new(RaspPolicy::default());
    let sink = InMemorySink::new();

    // Process multiple signals from the fuzz data
    for chunk in data.chunks(3) {
        if chunk.is_empty() {
            continue;
        }
        let confidence = match chunk[0] % 3 {
            0 => Confidence::Low,
            1 => Confidence::Medium,
            _ => Confidence::High,
        };
        let signal_type = if chunk.len() > 1 { chunk[1] } else { 0 };
        let evidence = if chunk.len() > 2 {
            format!("fuzz-{}", chunk[2])
        } else {
            "fuzz".to_string()
        };

        let signal = match signal_type % 4 {
            0 => EnvironmentSignal::RootDetected { confidence, evidence },
            1 => EnvironmentSignal::EmulatorDetected { confidence, evidence },
            2 => EnvironmentSignal::DebuggerAttached { confidence, evidence },
            _ => EnvironmentSignal::Unknown { label: "fuzz".to_string(), evidence },
        };

        let _ = engine.process_signal(&signal, &sink);
    }

    // Threat level should be queryable without panic
    let _ = engine.threat_level();
});

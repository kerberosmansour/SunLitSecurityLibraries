#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_resilience` — Anti-tampering and environment detection for OWASP MASVS-RESILIENCE.
//!
//! This crate provides environment detection signal types (root/jailbreak, emulator, debugger),
//! app integrity verification, and RASP (Runtime Application Self-Protection) signal aggregation.
//! It is a pure policy engine — the consuming application implements platform-specific detection
//! and feeds signals into this crate for policy evaluation.

pub mod environment;
pub mod error;
pub mod integrity;
pub mod rasp;

pub use environment::{Confidence, EnvironmentSignal, ThreatLevel};
pub use error::ResilienceError;
pub use integrity::{IntegrityCheck, IntegrityCheckResult, IntegrityResult};
pub use rasp::{RaspDecision, RaspEngine, RaspPolicy, ResponseAction};

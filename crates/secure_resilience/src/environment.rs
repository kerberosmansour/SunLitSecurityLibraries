//! Environment detection signal types for root/jailbreak, emulator, and debugger detection.
//!
//! These are pure data types — the consuming application implements actual detection
//! and constructs signals. This crate evaluates policy responses.

use serde::Serialize;

/// Confidence level of an environment detection signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Confidence {
    /// Low confidence — heuristic or indirect evidence.
    Low,
    /// Medium confidence — multiple indicators.
    Medium,
    /// High confidence — direct evidence.
    High,
}

/// An environment detection signal fed from the mobile application into the RASP engine.
///
/// The consuming application implements platform-specific detection (e.g., checking for
/// `su` binary, Magisk, Frida, emulator properties) and constructs these signals.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum EnvironmentSignal {
    /// Root or jailbreak detected (MASWE-0097).
    RootDetected {
        /// Confidence of the detection.
        confidence: Confidence,
        /// Human-readable evidence string (e.g., "su binary found at /system/xbin/su").
        evidence: String,
    },
    /// Emulator or virtualized environment detected (MASWE-0098, MASWE-0099).
    EmulatorDetected {
        /// Confidence of the detection.
        confidence: Confidence,
        /// Human-readable evidence string.
        evidence: String,
    },
    /// Debugger attached to the process (MASWE-0100).
    DebuggerAttached {
        /// Confidence of the detection.
        confidence: Confidence,
        /// Human-readable evidence string.
        evidence: String,
    },
    /// An unknown or custom signal type for extensibility.
    Unknown {
        /// Label identifying this custom signal.
        label: String,
        /// Human-readable evidence string.
        evidence: String,
    },
}

impl EnvironmentSignal {
    /// Returns the confidence level of this signal, or `None` for unknown signals.
    pub fn confidence(&self) -> Option<Confidence> {
        match self {
            Self::RootDetected { confidence, .. }
            | Self::EmulatorDetected { confidence, .. }
            | Self::DebuggerAttached { confidence, .. } => Some(*confidence),
            Self::Unknown { .. } => None,
        }
    }

    /// Returns the evidence string for this signal.
    pub fn evidence(&self) -> &str {
        match self {
            Self::RootDetected { evidence, .. }
            | Self::EmulatorDetected { evidence, .. }
            | Self::DebuggerAttached { evidence, .. }
            | Self::Unknown { evidence, .. } => evidence,
        }
    }

    /// Returns a human-readable category name for this signal.
    pub fn category(&self) -> &str {
        match self {
            Self::RootDetected { .. } => "root_detected",
            Self::EmulatorDetected { .. } => "emulator_detected",
            Self::DebuggerAttached { .. } => "debugger_attached",
            Self::Unknown { label, .. } => label,
        }
    }

    /// Returns the inherent threat weight for this signal type (0–100).
    ///
    /// Debugger signals carry the highest weight because they indicate
    /// active runtime analysis.
    pub(crate) fn base_threat_weight(&self) -> u32 {
        match self {
            Self::DebuggerAttached { .. } => 100,
            Self::RootDetected { .. } => 70,
            Self::EmulatorDetected { .. } => 40,
            Self::Unknown { .. } => 0,
        }
    }
}

/// Aggregate threat level computed from accumulated environment signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ThreatLevel {
    /// No threat detected.
    None,
    /// Low threat — minor or low-confidence signals.
    Low,
    /// Medium threat — multiple low-confidence or single medium-confidence signals.
    Medium,
    /// High threat — high-confidence root or emulator detection.
    High,
    /// Critical threat — debugger attached or combined high-confidence signals.
    Critical,
}

impl ThreatLevel {
    /// Compute threat level from an accumulated threat score.
    pub(crate) fn from_score(score: u32) -> Self {
        match score {
            0 => Self::None,
            1..=30 => Self::Low,
            31..=60 => Self::Medium,
            61..=99 => Self::High,
            _ => Self::Critical,
        }
    }
}

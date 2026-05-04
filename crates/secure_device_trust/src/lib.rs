#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_device_trust` — typed native-client device trust policy decisions.
//!
//! This crate models bootstrap identity, client type, platform, attestation
//! rollout mode, trust-tier decisions, and short-lived session certificate
//! lifecycle policy.

pub mod session;

pub use session::{
    CsrExtensionRequest, CsrRejectionReason, NoRevocations, RevocationChecker, RevocationHandle,
    SessionCertificateBundle, SessionCertificateError, SessionCertificateIssuer,
    SessionCertificatePolicy, SessionCertificateProfile, SessionCertificateRequest,
    SessionCertificateSigner, SessionCsrProfile, SessionExtendedKeyUsage, SessionSubjectAltName,
    SignedSessionCertificate,
};

use security_core::classification::DataClassification;
use serde::{Deserialize, Serialize};

/// Native client shape presenting device trust evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ClientType {
    /// Desktop client, including Tauri desktop apps.
    Desktop,
    /// Mobile client, including iOS/iPadOS and Android apps.
    Mobile,
    /// CI/conformance client.
    Ci,
}

/// Operating system or runtime platform for a native client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Platform {
    /// Apple macOS.
    MacOs,
    /// Apple iOS or iPadOS.
    Ios,
    /// Android.
    Android,
    /// Microsoft Windows.
    Windows,
    /// Linux desktop.
    Linux,
    /// CI-only test platform.
    Ci,
    /// Platform without supported attestation.
    Unsupported,
}

/// Backend-owned platform attestation rollout mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationMode {
    /// Certificate-only device trust.
    Off,
    /// Parse/record evidence but do not block absent unsupported evidence.
    Monitor,
    /// Require valid platform evidence for supported routes/platforms.
    Enforce,
}

/// Whether bootstrap identity is currently authorised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapStatus {
    /// Bootstrap identity is authorised.
    Authorised,
    /// Bootstrap identity has been revoked.
    Revoked,
}

/// Whether the bootstrap credential is per-install or a shared app credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapBinding {
    /// Per-install or per-device bootstrap identity.
    PerInstall,
    /// Shared application credential. Never sufficient for production trust.
    SharedApp,
}

/// Bootstrap certificate metadata needed by device trust policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapIdentity {
    /// Application identifier from the bootstrap certificate/profile.
    pub app_id: String,
    /// Redacted certificate subject.
    pub subject: String,
    /// Certificate fingerprint or stable bootstrap key identifier.
    pub fingerprint: String,
    /// Authorisation state.
    pub status: BootstrapStatus,
    /// Binding strength.
    pub binding: BootstrapBinding,
}

/// Normalised attestation evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAttestationEvidence {
    /// Provider such as `apple-app-attest`, `android-play-integrity`, or `windows-tpm`.
    pub provider: String,
    /// Server-issued challenge identifier.
    pub challenge_id: String,
    /// Redacted payload summary. Raw payloads must not be stored here.
    pub payload_summary: String,
    /// Freshness verdict.
    pub freshness: EvidenceFreshness,
}

/// Attestation freshness state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceFreshness {
    /// Evidence is fresh for the current challenge.
    Fresh,
    /// Evidence is stale or replayed.
    Stale,
    /// Platform cannot provide supported evidence.
    Unsupported,
}

/// Release channel for the requesting app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseChannel {
    /// Local developer profile.
    Dev,
    /// CI/conformance profile.
    Ci,
    /// Production profile.
    Production,
}

/// Device trust evaluation input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustRequest {
    /// Bootstrap identity metadata.
    pub bootstrap: BootstrapIdentity,
    /// Client type.
    pub client_type: ClientType,
    /// Platform.
    pub platform: Platform,
    /// Release channel.
    pub release_channel: ReleaseChannel,
    /// Backend-owned attestation mode.
    pub attestation_mode: AttestationMode,
    /// Optional platform attestation evidence.
    pub attestation: Option<DeviceAttestationEvidence>,
}

/// High-level device trust outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTrustOutcome {
    /// Fully trusted for high-trust routes.
    Trusted,
    /// Authenticated but lower trust; policy may deny sensitive routes.
    LowerTrust,
    /// Denied.
    Denied,
}

/// Trust tier assigned to a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustTier {
    /// No usable trust.
    None,
    /// Certificate-only or software-bound trust.
    SoftwareBound,
    /// Platform or hardware-backed trust.
    HardwareBacked,
}

/// Stable reason codes for trust decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeviceTrustReason {
    /// Bootstrap identity is authorised.
    BootstrapAuthorised,
    /// Bootstrap identity has been revoked.
    BootstrapRevoked,
    /// Shared app bootstrap credential was rejected.
    SharedBootstrapRejected,
    /// Platform attestation evidence is fresh.
    PlatformAttestationFresh,
    /// Attestation is unsupported for this platform/profile.
    AttestationUnsupported,
    /// Enforce mode requires fresh attestation.
    AttestationRequired,
}

/// Result of evaluating a device trust request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustDecision {
    outcome: DeviceTrustOutcome,
    tier: TrustTier,
    reasons: Vec<DeviceTrustReason>,
    audit_classification: DataClassification,
}

impl DeviceTrustDecision {
    /// Returns the high-level outcome.
    #[must_use]
    pub fn outcome(&self) -> DeviceTrustOutcome {
        self.outcome
    }

    /// Returns the assigned trust tier.
    #[must_use]
    pub fn tier(&self) -> TrustTier {
        self.tier
    }

    /// Returns stable reason codes.
    #[must_use]
    pub fn reasons(&self) -> &[DeviceTrustReason] {
        &self.reasons
    }

    /// Returns the audit data classification for this decision.
    #[must_use]
    pub fn audit_classification(&self) -> DataClassification {
        self.audit_classification
    }
}

/// Errors returned by policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceTrustError {
    /// Evidence metadata is malformed.
    MalformedEvidence {
        /// Field that failed validation.
        field: &'static str,
    },
}

impl std::fmt::Display for DeviceTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEvidence { field } => {
                write!(f, "malformed attestation evidence field: {field}")
            }
        }
    }
}

impl std::error::Error for DeviceTrustError {}

/// Device trust policy evaluator.
#[derive(Clone, Copy, Debug)]
pub struct DeviceTrustPolicy {
    production: bool,
}

impl DeviceTrustPolicy {
    /// Production policy profile.
    #[must_use]
    pub fn production() -> Self {
        Self { production: true }
    }

    /// Evaluates a request and returns a trust decision.
    pub fn evaluate(
        &self,
        request: &DeviceTrustRequest,
    ) -> Result<DeviceTrustDecision, DeviceTrustError> {
        if let Some(attestation) = &request.attestation {
            validate_attestation(attestation)?;
        }

        if request.bootstrap.status == BootstrapStatus::Revoked {
            return Ok(denied(DeviceTrustReason::BootstrapRevoked));
        }

        if self.production && request.bootstrap.binding == BootstrapBinding::SharedApp {
            return Ok(denied(DeviceTrustReason::SharedBootstrapRejected));
        }

        let mut reasons = vec![DeviceTrustReason::BootstrapAuthorised];
        let supported_platform = supports_platform_attestation(request.platform);

        match request.attestation_mode {
            AttestationMode::Off => Ok(lower_trust(reasons)),
            AttestationMode::Monitor => {
                if let Some(attestation) = &request.attestation {
                    if supported_platform && attestation.freshness == EvidenceFreshness::Fresh {
                        reasons.push(DeviceTrustReason::PlatformAttestationFresh);
                        return Ok(trusted(reasons));
                    }
                }
                if !supported_platform {
                    reasons.push(DeviceTrustReason::AttestationUnsupported);
                }
                Ok(lower_trust(reasons))
            }
            AttestationMode::Enforce => match &request.attestation {
                Some(attestation)
                    if supported_platform && attestation.freshness == EvidenceFreshness::Fresh =>
                {
                    reasons.push(DeviceTrustReason::PlatformAttestationFresh);
                    Ok(trusted(reasons))
                }
                Some(attestation) if attestation.freshness == EvidenceFreshness::Unsupported => {
                    reasons.push(DeviceTrustReason::AttestationUnsupported);
                    Ok(lower_trust(reasons))
                }
                _ => {
                    reasons.push(DeviceTrustReason::AttestationRequired);
                    Ok(DeviceTrustDecision {
                        outcome: DeviceTrustOutcome::Denied,
                        tier: TrustTier::None,
                        reasons,
                        audit_classification: DataClassification::Confidential,
                    })
                }
            },
        }
    }
}

fn trusted(reasons: Vec<DeviceTrustReason>) -> DeviceTrustDecision {
    DeviceTrustDecision {
        outcome: DeviceTrustOutcome::Trusted,
        tier: TrustTier::HardwareBacked,
        reasons,
        audit_classification: DataClassification::Confidential,
    }
}

fn lower_trust(reasons: Vec<DeviceTrustReason>) -> DeviceTrustDecision {
    DeviceTrustDecision {
        outcome: DeviceTrustOutcome::LowerTrust,
        tier: TrustTier::SoftwareBound,
        reasons,
        audit_classification: DataClassification::Confidential,
    }
}

fn denied(reason: DeviceTrustReason) -> DeviceTrustDecision {
    DeviceTrustDecision {
        outcome: DeviceTrustOutcome::Denied,
        tier: TrustTier::None,
        reasons: vec![reason],
        audit_classification: DataClassification::Confidential,
    }
}

fn supports_platform_attestation(platform: Platform) -> bool {
    matches!(
        platform,
        Platform::Ios | Platform::Android | Platform::Windows | Platform::MacOs
    )
}

fn validate_attestation(attestation: &DeviceAttestationEvidence) -> Result<(), DeviceTrustError> {
    validate_label("provider", &attestation.provider)?;
    validate_label("challenge_id", &attestation.challenge_id)?;
    if attestation.payload_summary.is_empty() || attestation.payload_summary.len() > 1024 {
        return Err(DeviceTrustError::MalformedEvidence {
            field: "payload_summary",
        });
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), DeviceTrustError> {
    if value.is_empty() || value.len() > 80 {
        return Err(DeviceTrustError::MalformedEvidence { field });
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(DeviceTrustError::MalformedEvidence { field });
    }
    Ok(())
}

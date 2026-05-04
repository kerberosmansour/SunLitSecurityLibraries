//! Security event kind classifications.

use serde::Serialize;

/// The kind/category of a security event.
///
/// # Examples
///
/// ```
/// use security_events::kind::EventKind;
///
/// let kind = EventKind::AuthnFailure;
/// assert_eq!(format!("{kind:?}"), "AuthnFailure");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EventKind {
    /// A boundary violation was detected.
    BoundaryViolation,
    /// An authentication failure occurred.
    AuthnFailure,
    /// An MFA-related event.
    MfaEvent,
    /// An authorization denial.
    AuthzDeny,
    /// An attempted cross-tenant resource access.
    CrossTenantAttempt,
    /// A secret was accessed.
    SecretAccess,
    /// A cryptographic key was rotated.
    KeyRotation,
    /// An administrative action was performed.
    AdminAction,
    /// A file upload anomaly was detected.
    FileUploadAnomaly,
    /// A deserialization anomaly was detected.
    DeserializationAnomaly,
    /// An error was escalated to a security event.
    ErrorEscalation,
    /// A rate limit block event.
    RateLimitBlock,
    /// An anti-automation trigger.
    AntiAutomation,
    /// A TLS policy violation was detected (weak version or cipher).
    TlsViolation,
    /// A certificate pin mismatch was detected.
    CertPinFailure,
    /// Cleartext (unencrypted) traffic was blocked.
    CleartextBlocked,
    /// A mobile storage policy violation was detected.
    StoragePolicyViolation,
    /// A biometric authentication failure was detected.
    BiometricAuthFailure,
    /// A step-up authentication failure was detected.
    StepUpAuthFailure,
    /// A mobile platform safety violation was detected (deep link, WebView, clipboard).
    PlatformSafetyViolation,
    /// An environment threat was detected (root/jailbreak, emulator, debugger).
    EnvironmentThreat,
    /// App integrity tampering was detected (signature mismatch, sideloading).
    IntegrityViolation,
    /// A privacy consent violation was detected (missing/denied/withdrawn consent).
    ConsentViolation,
    /// A data retention policy expiry was detected.
    RetentionExpiry,
}

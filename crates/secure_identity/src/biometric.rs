//! Biometric authentication result validation.
//!
//! Validates the *result* of platform biometric authentication (e.g., a signed
//! attestation or cryptographic proof), not the biometric data itself.
//! No biometric templates or raw sensor data should ever touch these types.
//!
//! Feature-gated behind `biometric`.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;

/// The biometric strength class per Android BiometricManager classification.
///
/// - `Class1`: Convenience (e.g., swipe patterns). Not suitable for sensitive ops.
/// - `Class2`: Weak biometric (e.g., face unlock without depth).
/// - `Class3`: Strong biometric (e.g., fingerprint, 3D face). Required for MASVS-AUTH-2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BiometricClass {
    /// Convenience-level (weakest). Not recommended for security-sensitive operations.
    Class1 = 1,
    /// Weak biometric. Acceptable for low-sensitivity operations.
    Class2 = 2,
    /// Strong biometric (fingerprint, 3D face). Required by MASTG-BEST-0031.
    Class3 = 3,
}

/// Cryptographic binding proof from the platform biometric API.
///
/// Represents a key bound to a specific biometric enrollment. If the enrollment
/// changes (e.g., new fingerprint added), the key should be invalidated
/// per MASTG-BEST-0037.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoBinding {
    /// Identifier for the cryptographic key used in the binding.
    pub key_id: String,
    /// Identifier for the biometric enrollment state when the key was created.
    pub enrollment_id: String,
}

/// The result of a platform biometric authentication attempt.
///
/// This is the input to the validation engine — it comes from the platform API
/// (Android BiometricPrompt, iOS LocalAuthentication) and is validated against
/// the configured policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiometricAuthResult {
    /// The biometric strength class reported by the platform.
    pub biometric_class: BiometricClass,
    /// Optional cryptographic binding proof (MASTG-BEST-0036).
    pub crypto_binding: Option<CryptoBinding>,
    /// Whether the authentication used a device credential fallback (PIN/pattern).
    pub device_credential_fallback: bool,
}

/// The reason a biometric authentication was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BiometricRejection {
    /// Biometric class is below the minimum required by policy.
    WeakBiometric,
    /// No cryptographic binding was provided but policy requires it.
    NoCryptoBinding,
    /// Biometric enrollment has changed since the key was created.
    EnrollmentChanged,
    /// Device credential fallback was used but policy does not allow it.
    DeviceCredentialNotAllowed,
}

/// The result of validating a biometric authentication attempt against policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BiometricValidation {
    /// The biometric authentication passed all policy checks.
    Accepted,
    /// The biometric authentication was rejected for the given reason.
    Rejected(BiometricRejection),
}

/// Policy for validating biometric authentication results.
///
/// Defaults enforce MASTG-BEST-0031 (strong biometrics), MASTG-BEST-0036
/// (cryptographic binding required), and MASTG-BEST-0038 (no device credential
/// fallback unless explicitly allowed).
#[derive(Clone, Debug)]
pub struct BiometricPolicy {
    /// Minimum biometric class required. Default: `Class3`.
    pub minimum_class: BiometricClass,
    /// Whether cryptographic binding is required. Default: `true`.
    pub require_crypto_binding: bool,
    /// Whether device credential fallback (PIN/pattern) is allowed. Default: `false`.
    pub allow_device_credential: bool,
}

impl Default for BiometricPolicy {
    fn default() -> Self {
        Self {
            minimum_class: BiometricClass::Class3,
            require_crypto_binding: true,
            allow_device_credential: false,
        }
    }
}

impl BiometricPolicy {
    /// Validate a biometric authentication result against this policy.
    ///
    /// `current_enrollment_id` is the current biometric enrollment state. If provided,
    /// it is compared against the enrollment ID in the crypto binding to detect
    /// enrollment changes (MASTG-BEST-0037).
    #[must_use]
    pub fn validate(
        &self,
        result: &BiometricAuthResult,
        current_enrollment_id: Option<&str>,
    ) -> BiometricValidation {
        // Check device credential fallback first
        if result.device_credential_fallback && !self.allow_device_credential {
            return BiometricValidation::Rejected(BiometricRejection::DeviceCredentialNotAllowed);
        }

        // Check biometric class meets minimum
        if result.biometric_class < self.minimum_class {
            return BiometricValidation::Rejected(BiometricRejection::WeakBiometric);
        }

        // Check cryptographic binding
        if self.require_crypto_binding {
            match &result.crypto_binding {
                None => {
                    return BiometricValidation::Rejected(BiometricRejection::NoCryptoBinding);
                }
                Some(binding) => {
                    // Check enrollment hasn't changed (MASTG-BEST-0037)
                    if let Some(current) = current_enrollment_id {
                        if binding.enrollment_id != current {
                            return BiometricValidation::Rejected(
                                BiometricRejection::EnrollmentChanged,
                            );
                        }
                    }
                }
            }
        }

        BiometricValidation::Accepted
    }

    /// Validate and return security events for any rejections.
    ///
    /// Returns a list of security events. Empty if validation passed.
    #[must_use]
    pub fn validate_with_events(
        &self,
        result: &BiometricAuthResult,
        current_enrollment_id: Option<&str>,
    ) -> Vec<SecurityEvent> {
        let validation = self.validate(result, current_enrollment_id);
        match validation {
            BiometricValidation::Accepted => vec![],
            BiometricValidation::Rejected(reason) => {
                let severity = match reason {
                    BiometricRejection::WeakBiometric => SecuritySeverity::High,
                    BiometricRejection::NoCryptoBinding => SecuritySeverity::High,
                    BiometricRejection::EnrollmentChanged => SecuritySeverity::Critical,
                    BiometricRejection::DeviceCredentialNotAllowed => SecuritySeverity::Medium,
                };
                let mut event = SecurityEvent::new(
                    EventKind::BiometricAuthFailure,
                    severity,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some(match reason {
                    BiometricRejection::WeakBiometric => "weak_biometric",
                    BiometricRejection::NoCryptoBinding => "no_crypto_binding",
                    BiometricRejection::EnrollmentChanged => "enrollment_changed",
                    BiometricRejection::DeviceCredentialNotAllowed => {
                        "device_credential_not_allowed"
                    }
                });
                vec![event]
            }
        }
    }
}

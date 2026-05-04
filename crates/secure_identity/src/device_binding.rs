//! Device credential binding types.
//!
//! Provides types for representing device-bound credential claims that tie
//! authentication to a specific hardware device, supporting MASVS-AUTH-2.

/// A claim that a credential is bound to a specific device.
///
/// Used to verify that authentication tokens or keys are tied to the
/// originating device and cannot be replayed from a different device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCredentialClaim {
    /// A unique identifier for the device (e.g., hardware attestation key ID).
    pub device_id: String,
    /// The type of device binding used.
    pub binding_type: DeviceBindingType,
    /// Whether the credential is backed by hardware security (TEE/SE).
    pub hardware_backed: bool,
}

/// The type of device binding mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceBindingType {
    /// Key stored in a hardware-backed keystore (Android Keystore, iOS Secure Enclave).
    HardwareKeystore,
    /// Key stored in software keystore (less secure, no TEE backing).
    SoftwareKeystore,
    /// Device attestation via platform API.
    PlatformAttestation,
}

impl DeviceCredentialClaim {
    /// Create a new hardware-backed device credential claim.
    #[must_use]
    pub fn hardware_backed(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            binding_type: DeviceBindingType::HardwareKeystore,
            hardware_backed: true,
        }
    }

    /// Create a new software-backed device credential claim.
    #[must_use]
    pub fn software_backed(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            binding_type: DeviceBindingType::SoftwareKeystore,
            hardware_backed: false,
        }
    }

    /// Returns true if the credential is backed by hardware security.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }
}

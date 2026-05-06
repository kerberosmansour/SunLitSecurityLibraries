# `secure_device_trust`

`secure_device_trust` evaluates native-client trust evidence before user
authentication. It is the production library surface for ZeroTrustAuth
conformance and other native-client access checks.

## Quick Start

```toml
[dependencies]
secure_device_trust = "0.1.2"
```

## What It Does

- Models bootstrap certificate metadata without accepting private key material.
- Requires callers to identify `ClientType`, `Platform`, `ReleaseChannel`, and
  backend-owned `AttestationMode`.
- Produces a typed `DeviceTrustDecision` with `DeviceTrustOutcome`,
  `TrustTier`, stable `DeviceTrustReason` codes, and audit classification.
- Treats unsupported platform attestation as a lower trust tier, not hardware
  trust.
- Rejects shared app bootstrap credentials in production policy.

## Minimal Example

```rust
use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus,
    ClientType, DeviceAttestationEvidence, DeviceTrustPolicy, DeviceTrustRequest,
    EvidenceFreshness, Platform, ReleaseChannel, TrustTier,
};

let request = DeviceTrustRequest {
    bootstrap: BootstrapIdentity {
        app_id: "sunlit-guardian-tauri".to_owned(),
        subject: "CN=sunlit-guardian-tauri,OU=bootstrap-app".to_owned(),
        fingerprint: "redacted-fingerprint".to_owned(),
        status: BootstrapStatus::Authorised,
        binding: BootstrapBinding::PerInstall,
    },
    client_type: ClientType::Desktop,
    platform: Platform::Ios,
    release_channel: ReleaseChannel::Production,
    attestation_mode: AttestationMode::Enforce,
    attestation: Some(DeviceAttestationEvidence {
        provider: "apple-app-attest".to_owned(),
        challenge_id: "challenge-1".to_owned(),
        payload_summary: "redacted-receipt-summary".to_owned(),
        freshness: EvidenceFreshness::Fresh,
    }),
};

let decision = DeviceTrustPolicy::production().evaluate(&request)?;
assert_eq!(decision.tier(), TrustTier::HardwareBacked);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Non-Goals In M1

- No session certificate issuance.
- No CSR parsing or CA signing.
- No raw platform attestation payload parsing.
- No framework adapter. Actix Web and other service integration comes through
  later adapter milestones.

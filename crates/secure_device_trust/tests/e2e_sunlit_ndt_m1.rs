use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus, ClientType,
    DeviceAttestationEvidence, DeviceTrustDecision, DeviceTrustError, DeviceTrustOutcome,
    DeviceTrustPolicy, DeviceTrustReason, DeviceTrustRequest, EvidenceFreshness, Platform,
    ReleaseChannel, TrustTier,
};
use security_core::classification::DataClassification;

fn authorised_bootstrap(binding: BootstrapBinding) -> BootstrapIdentity {
    BootstrapIdentity {
        app_id: "sunlit-guardian-tauri".to_owned(),
        subject: "CN=sunlit-guardian-tauri,OU=bootstrap-app".to_owned(),
        fingerprint: "bootstrap-fp".to_owned(),
        status: BootstrapStatus::Authorised,
        binding,
    }
}

fn fresh_evidence() -> DeviceAttestationEvidence {
    DeviceAttestationEvidence {
        provider: "apple-app-attest".to_owned(),
        challenge_id: "challenge-1".to_owned(),
        payload_summary: "redacted-app-attest-receipt".to_owned(),
        freshness: EvidenceFreshness::Fresh,
    }
}

fn request(
    binding: BootstrapBinding,
    platform: Platform,
    attestation_mode: AttestationMode,
    attestation: Option<DeviceAttestationEvidence>,
) -> DeviceTrustRequest {
    DeviceTrustRequest {
        bootstrap: authorised_bootstrap(binding),
        client_type: ClientType::Desktop,
        platform,
        release_channel: ReleaseChannel::Production,
        attestation_mode,
        attestation,
    }
}

fn assert_reason(decision: &DeviceTrustDecision, reason: DeviceTrustReason) {
    assert!(
        decision.reasons().contains(&reason),
        "expected reason {reason:?}, got {:?}",
        decision.reasons()
    );
}

#[test]
fn happy_path_valid_platform_evidence_is_hardware_trusted() {
    let decision = DeviceTrustPolicy::production()
        .evaluate(&request(
            BootstrapBinding::PerInstall,
            Platform::Ios,
            AttestationMode::Enforce,
            Some(fresh_evidence()),
        ))
        .expect("fresh supported evidence should evaluate");

    assert_eq!(decision.outcome(), DeviceTrustOutcome::Trusted);
    assert_eq!(decision.tier(), TrustTier::HardwareBacked);
    assert_eq!(
        decision.audit_classification(),
        DataClassification::Confidential
    );
    assert_reason(&decision, DeviceTrustReason::BootstrapAuthorised);
    assert_reason(&decision, DeviceTrustReason::PlatformAttestationFresh);
}

#[test]
fn unsupported_platform_is_lower_trust_not_implicitly_hardware_trusted() {
    let decision = DeviceTrustPolicy::production()
        .evaluate(&request(
            BootstrapBinding::PerInstall,
            Platform::Unsupported,
            AttestationMode::Monitor,
            None,
        ))
        .expect("unsupported platform should still evaluate");

    assert_eq!(decision.outcome(), DeviceTrustOutcome::LowerTrust);
    assert_eq!(decision.tier(), TrustTier::SoftwareBound);
    assert_reason(&decision, DeviceTrustReason::AttestationUnsupported);
}

#[test]
fn malformed_attestation_is_safe_error_and_does_not_echo_payload() {
    let raw_payload = "evil-raw-attestation-payload";
    let err = DeviceTrustPolicy::production()
        .evaluate(&request(
            BootstrapBinding::PerInstall,
            Platform::Android,
            AttestationMode::Enforce,
            Some(DeviceAttestationEvidence {
                provider: String::new(),
                challenge_id: "challenge-1".to_owned(),
                payload_summary: raw_payload.to_owned(),
                freshness: EvidenceFreshness::Fresh,
            }),
        ))
        .expect_err("malformed evidence should be rejected");

    assert_eq!(
        err,
        DeviceTrustError::MalformedEvidence { field: "provider" }
    );
    assert!(
        !err.to_string().contains(raw_payload),
        "safe error must not echo raw attestation payload"
    );
}

#[test]
fn production_rejects_shared_app_bootstrap_identity() {
    let decision = DeviceTrustPolicy::production()
        .evaluate(&request(
            BootstrapBinding::SharedApp,
            Platform::Ios,
            AttestationMode::Enforce,
            Some(fresh_evidence()),
        ))
        .expect("shared app bootstrap should produce a denial decision");

    assert_eq!(decision.outcome(), DeviceTrustOutcome::Denied);
    assert_eq!(decision.tier(), TrustTier::None);
    assert_reason(&decision, DeviceTrustReason::SharedBootstrapRejected);
}

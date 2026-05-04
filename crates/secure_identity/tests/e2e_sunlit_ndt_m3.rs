//! BDD acceptance tests for native device trust passwordless binding.

use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus, ClientType,
    DeviceTrustPolicy, DeviceTrustRequest, Platform, ReleaseChannel,
};
use secure_identity::{
    PasskeySupport, PasswordlessChallengeRequest, PasswordlessChallengeService, PasswordlessError,
    PasswordlessMethod, PasswordlessProof, PasswordlessProofVerifier,
};
use secure_network::MtlsClientIdentity;
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct FixtureVerifier {
    identity: AuthenticatedIdentity,
}

impl FixtureVerifier {
    fn new(identity: AuthenticatedIdentity) -> Self {
        Self { identity }
    }
}

impl PasswordlessProofVerifier for FixtureVerifier {
    fn verify(
        &self,
        challenge: &secure_identity::PasswordlessChallenge,
        proof: &PasswordlessProof,
    ) -> Result<AuthenticatedIdentity, PasswordlessError> {
        if proof.challenge_id() != challenge.challenge_id() {
            return Err(PasswordlessError::ChallengeMismatch);
        }
        Ok(self.identity.clone())
    }
}

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: std::collections::HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

fn allowing_decision() -> secure_device_trust::DeviceTrustDecision {
    DeviceTrustPolicy::production()
        .evaluate(&DeviceTrustRequest {
            bootstrap: BootstrapIdentity {
                app_id: "com.sunlit.guardian".to_string(),
                subject: "CN=Sunlit Guardian".to_string(),
                fingerprint: "bootstrap-fingerprint".to_string(),
                status: BootstrapStatus::Authorised,
                binding: BootstrapBinding::PerInstall,
            },
            client_type: ClientType::Mobile,
            platform: Platform::Ios,
            release_channel: ReleaseChannel::Production,
            attestation_mode: AttestationMode::Off,
            attestation: None,
        })
        .expect("device trust decision should evaluate")
}

fn denied_decision() -> secure_device_trust::DeviceTrustDecision {
    DeviceTrustPolicy::production()
        .evaluate(&DeviceTrustRequest {
            bootstrap: BootstrapIdentity {
                app_id: "com.sunlit.guardian".to_string(),
                subject: "CN=Sunlit Guardian".to_string(),
                fingerprint: "revoked-bootstrap".to_string(),
                status: BootstrapStatus::Revoked,
                binding: BootstrapBinding::PerInstall,
            },
            client_type: ClientType::Mobile,
            platform: Platform::Ios,
            release_channel: ReleaseChannel::Production,
            attestation_mode: AttestationMode::Off,
            attestation: None,
        })
        .expect("device trust decision should evaluate")
}

fn mtls(serial: &str, fingerprint: &str) -> MtlsClientIdentity {
    let now = OffsetDateTime::now_utc();
    MtlsClientIdentity::new(
        serial,
        fingerprint,
        now - Duration::minutes(1),
        now + Duration::days(1),
        true,
    )
}

#[test]
fn happy_path_challenge_and_session_are_bound_to_session_certificate() {
    let now = OffsetDateTime::now_utc();
    let mtls = mtls("session-serial-1", "sha256:session-cert-1");
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));

    let challenge = service
        .request_challenge(
            Some(&mtls),
            &allowing_decision(),
            &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Supported),
            now,
        )
        .expect("challenge should be issued after valid session mTLS");

    assert_eq!(challenge.method(), PasswordlessMethod::Passkey);
    assert_eq!(
        challenge.device_binding().certificate_fingerprint(),
        mtls.fingerprint
    );

    let proof =
        PasswordlessProof::passkey(challenge.challenge_id(), "credential-1", "client-data-hash");
    let session = service
        .complete_challenge(&mtls, &challenge, &proof, 3600, now)
        .expect("passkey proof should complete into a device-bound session");

    assert!(session.is_bound_to(&mtls));
    assert_eq!(
        session.device_binding().certificate_fingerprint(),
        "sha256:session-cert-1"
    );
    assert!(!session.session_token().is_empty());
}

#[test]
fn replayed_passkey_result_from_different_mtls_certificate_is_rejected() {
    let now = OffsetDateTime::now_utc();
    let original_mtls = mtls("session-serial-1", "sha256:session-cert-1");
    let replay_mtls = mtls("session-serial-2", "sha256:session-cert-2");
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));

    let challenge = service
        .request_challenge(
            Some(&original_mtls),
            &allowing_decision(),
            &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Supported),
            now,
        )
        .expect("challenge should be issued");
    let proof =
        PasswordlessProof::passkey(challenge.challenge_id(), "credential-1", "client-data-hash");

    let result = service.complete_challenge(&replay_mtls, &challenge, &proof, 3600, now);

    assert!(matches!(
        result,
        Err(PasswordlessError::CertificateBindingMismatch)
    ));
}

#[test]
fn unsupported_passkey_falls_back_to_deep_link_still_bound_to_mtls() {
    let now = OffsetDateTime::now_utc();
    let mtls = mtls("session-serial-linux", "sha256:session-cert-linux");
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));

    let challenge = service
        .request_challenge(
            Some(&mtls),
            &allowing_decision(),
            &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Unsupported),
            now,
        )
        .expect("fallback challenge should be issued");

    assert_eq!(challenge.method(), PasswordlessMethod::DeepLink);
    assert_eq!(
        challenge.device_binding().certificate_fingerprint(),
        mtls.fingerprint
    );

    let proof = PasswordlessProof::deep_link(challenge.challenge_id(), "nonce-1", "signature-1");
    let session = service
        .complete_challenge(&mtls, &challenge, &proof, 3600, now)
        .expect("deep-link proof should complete into a device-bound session");

    assert!(session.is_bound_to(&mtls));
}

#[test]
fn browser_like_caller_without_certificate_is_rejected_before_challenge_generation() {
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));

    let result = service.request_challenge(
        None,
        &allowing_decision(),
        &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Supported),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PasswordlessError::MissingClientCertificate)
    ));
}

#[test]
fn denied_device_trust_cannot_request_passwordless_challenge() {
    let mtls = mtls("session-serial-denied", "sha256:session-cert-denied");
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));

    let result = service.request_challenge(
        Some(&mtls),
        &denied_decision(),
        &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Supported),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(result, Err(PasswordlessError::DeniedDeviceTrust)));
}

#[test]
fn debug_output_redacts_passwordless_proof_and_session_binding_material() {
    let now = OffsetDateTime::now_utc();
    let mtls = mtls("session-serial-redacted", "sha256:session-cert-redacted");
    let service = PasswordlessChallengeService::new(FixtureVerifier::new(identity()));
    let challenge = service
        .request_challenge(
            Some(&mtls),
            &allowing_decision(),
            &PasswordlessChallengeRequest::passkey_preferred(PasskeySupport::Supported),
            now,
        )
        .expect("challenge should be issued");
    let proof = PasswordlessProof::passkey(
        challenge.challenge_id(),
        "credential-sensitive",
        "client-data-sensitive",
    );
    let session = service
        .complete_challenge(&mtls, &challenge, &proof, 3600, now)
        .expect("proof should complete");

    let challenge_debug = format!("{challenge:?}");
    assert!(!challenge_debug.contains(challenge.challenge_id()));
    assert!(!challenge_debug.contains("sha256:session-cert-redacted"));

    let proof_debug = format!("{proof:?}");
    assert!(!proof_debug.contains("credential-sensitive"));
    assert!(!proof_debug.contains("client-data-sensitive"));

    let session_debug = format!("{session:?}");
    assert!(!session_debug.contains(session.session_token()));
    assert!(!session_debug.contains("session-serial-redacted"));
    assert!(!session_debug.contains("sha256:session-cert-redacted"));
}

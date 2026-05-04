use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus, ClientType,
    CsrExtensionRequest, CsrRejectionReason, DeviceTrustDecision, DeviceTrustError,
    DeviceTrustOutcome, DeviceTrustPolicy, DeviceTrustRequest, NoRevocations, Platform,
    ReleaseChannel, RevocationChecker, RevocationHandle, SessionCertificateBundle,
    SessionCertificateError, SessionCertificateIssuer, SessionCertificatePolicy,
    SessionCertificateProfile, SessionCertificateRequest, SessionCertificateSigner,
    SessionCsrProfile, SessionExtendedKeyUsage, SessionSubjectAltName, SignedSessionCertificate,
};
use secure_network::{MtlsClientIdentity, MtlsClientIdentityStatus, NoMtlsRevocations};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug)]
struct TestSigner;

impl SessionCertificateSigner for TestSigner {
    fn sign(
        &self,
        profile: &SessionCertificateProfile,
    ) -> Result<SignedSessionCertificate, SessionCertificateError> {
        Ok(SignedSessionCertificate {
            certificate_der: b"test-session-cert-der".to_vec(),
            ca_chain_der: vec![b"test-session-ca-der".to_vec()],
            serial: format!("serial-{}", profile.public_key_fingerprint),
            fingerprint: format!("fingerprint-{}", profile.public_key_fingerprint),
        })
    }
}

#[derive(Clone, Debug)]
struct RevokedHandle {
    handle: RevocationHandle,
}

impl RevocationChecker for RevokedHandle {
    fn is_revoked(&self, handle: &RevocationHandle) -> bool {
        &self.handle == handle
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_778_000_000).expect("valid fixture time")
}

fn authorised_bootstrap(status: BootstrapStatus) -> BootstrapIdentity {
    BootstrapIdentity {
        app_id: "sunlit-guardian-tauri".to_owned(),
        subject: "CN=sunlit-guardian-tauri,OU=bootstrap-app".to_owned(),
        fingerprint: "bootstrap-fp".to_owned(),
        status,
        binding: BootstrapBinding::PerInstall,
    }
}

fn trust_decision(status: BootstrapStatus) -> Result<DeviceTrustDecision, DeviceTrustError> {
    DeviceTrustPolicy::production().evaluate(&DeviceTrustRequest {
        bootstrap: authorised_bootstrap(status),
        client_type: ClientType::Desktop,
        platform: Platform::MacOs,
        release_channel: ReleaseChannel::Production,
        attestation_mode: AttestationMode::Off,
        attestation: None,
    })
}

fn valid_request(ttl: Duration) -> SessionCertificateRequest {
    SessionCertificateRequest {
        requested_ttl: ttl,
        csr: SessionCsrProfile {
            subject: "CN=sunlit-device-session".to_owned(),
            public_key_fingerprint: "spki-fp-1".to_owned(),
            requested_subject_alt_names: vec![
                SessionSubjectAltName::Uri("urn:sunlit:app:sunlit-guardian-tauri".to_owned()),
                SessionSubjectAltName::Uri("urn:sunlit:platform:macos".to_owned()),
                SessionSubjectAltName::Uri("urn:sunlit:client-type:desktop".to_owned()),
            ],
            requested_extensions: vec![CsrExtensionRequest::ClientAuth],
        },
    }
}

fn existing_bundle(
    refresh_after: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> SessionCertificateBundle {
    let profile = SessionCertificateProfile {
        subject: "CN=sunlit-device-session".to_owned(),
        public_key_fingerprint: "spki-fp-1".to_owned(),
        subject_alt_names: vec![SessionSubjectAltName::Uri(
            "urn:sunlit:app:sunlit-guardian-tauri".to_owned(),
        )],
        extended_key_usages: vec![SessionExtendedKeyUsage::ClientAuth],
        not_before: now() - Duration::minutes(10),
        not_after: expires_at,
    };

    SessionCertificateBundle {
        certificate_der: b"existing-cert".to_vec(),
        ca_chain_der: vec![b"ca".to_vec()],
        serial: "serial-spki-fp-1".to_owned(),
        fingerprint: "fingerprint-spki-fp-1".to_owned(),
        not_before: profile.not_before,
        expires_at,
        refresh_after,
        revocation_handle: RevocationHandle {
            serial: "serial-spki-fp-1".to_owned(),
            fingerprint: "fingerprint-spki-fp-1".to_owned(),
        },
        profile,
    }
}

#[test]
fn trusted_device_csr_issues_client_auth_session_cert_with_bounded_ttl() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let issued = issuer
        .issue(
            &valid_request(Duration::days(90)),
            &trust_decision(BootstrapStatus::Authorised).expect("decision"),
            now(),
        )
        .expect("trusted certificate-only device should receive session cert");

    assert_eq!(issued.expires_at, now() + Duration::days(30));
    assert_eq!(issued.refresh_after, issued.expires_at - Duration::days(7));
    assert_eq!(
        issued.profile.extended_key_usages,
        vec![SessionExtendedKeyUsage::ClientAuth]
    );
    assert!(
        issued.profile.subject_alt_names.iter().all(|san| {
            matches!(san, SessionSubjectAltName::Uri(value) if value.starts_with("urn:sunlit:"))
        }),
        "issuer must copy only allowed Sunlit URI SANs"
    );
    assert!(!issued.certificate_der.is_empty());
    assert_eq!(issued.revocation_handle.serial, issued.serial);
}

#[test]
fn csr_with_forbidden_extension_is_rejected_safely() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let mut request = valid_request(Duration::days(7));
    request
        .csr
        .requested_extensions
        .push(CsrExtensionRequest::ServerAuth);

    let err = issuer
        .issue(
            &request,
            &trust_decision(BootstrapStatus::Authorised).expect("decision"),
            now(),
        )
        .expect_err("serverAuth request must be rejected");

    assert_eq!(
        err,
        SessionCertificateError::InvalidCsr {
            reason: CsrRejectionReason::ForbiddenExtension
        }
    );
    assert!(
        !err.to_string().contains("serverAuth"),
        "safe error must not echo arbitrary CSR extension text"
    );
}

#[test]
fn csr_with_dns_subject_alt_name_is_rejected() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let mut request = valid_request(Duration::days(7));
    request
        .csr
        .requested_subject_alt_names
        .push(SessionSubjectAltName::DnsName(
            "api.sunlit.example".to_owned(),
        ));

    let err = issuer
        .issue(
            &request,
            &trust_decision(BootstrapStatus::Authorised).expect("decision"),
            now(),
        )
        .expect_err("DNS SANs are not allowed on native-client session certs");

    assert_eq!(
        err,
        SessionCertificateError::InvalidCsr {
            reason: CsrRejectionReason::ForbiddenSubjectAltName
        }
    );
}

#[test]
fn revoked_bootstrap_decision_cannot_refresh_session_cert() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let existing = existing_bundle(now() - Duration::minutes(1), now() + Duration::days(1));

    let err = issuer
        .refresh(
            &existing,
            &valid_request(Duration::days(7)),
            &trust_decision(BootstrapStatus::Revoked).expect("decision"),
            &NoRevocations,
            now(),
        )
        .expect_err("revoked bootstrap decision must block refresh");

    assert_eq!(err, SessionCertificateError::DeniedDeviceTrust);
}

#[test]
fn revoked_session_handle_cannot_refresh_session_cert() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let existing = existing_bundle(now() - Duration::minutes(1), now() + Duration::days(1));
    let revoked = RevokedHandle {
        handle: existing.revocation_handle.clone(),
    };

    let err = issuer
        .refresh(
            &existing,
            &valid_request(Duration::days(7)),
            &trust_decision(BootstrapStatus::Authorised).expect("decision"),
            &revoked,
            now(),
        )
        .expect_err("revoked session handle must block refresh");

    assert_eq!(err, SessionCertificateError::Revoked);
}

#[test]
fn expired_session_identity_is_rejected_by_mtls_validator() {
    let identity = MtlsClientIdentity::new(
        "serial-spki-fp-1",
        "fingerprint-spki-fp-1",
        now() - Duration::days(31),
        now() - Duration::minutes(1),
        true,
    );

    assert_eq!(
        identity.validate_at(now(), &NoMtlsRevocations),
        MtlsClientIdentityStatus::Expired
    );
}

#[test]
fn denied_device_trust_decision_never_issues_session_cert() {
    let issuer = SessionCertificateIssuer::new(SessionCertificatePolicy::production(), TestSigner);
    let denied = trust_decision(BootstrapStatus::Revoked).expect("decision");

    assert_eq!(denied.outcome(), DeviceTrustOutcome::Denied);
    assert_eq!(
        issuer
            .issue(&valid_request(Duration::days(7)), &denied, now())
            .expect_err("denied decision must not issue"),
        SessionCertificateError::DeniedDeviceTrust
    );
}

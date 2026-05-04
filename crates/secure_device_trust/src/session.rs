//! Session certificate lifecycle policy for native device trust.

use crate::{DeviceTrustDecision, DeviceTrustOutcome, TrustTier};
use time::{Duration, OffsetDateTime};

/// Requested subject alternative name for a session certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionSubjectAltName {
    /// URI SAN, normally under `urn:sunlit:*`.
    Uri(String),
    /// DNS SAN. Not allowed for native-client session certificates.
    DnsName(String),
    /// IP address SAN. Not allowed for native-client session certificates.
    IpAddress(String),
    /// Email SAN. Not allowed for native-client session certificates.
    Email(String),
}

/// CSR extension requested by the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrExtensionRequest {
    /// Client authentication EKU.
    ClientAuth,
    /// Server authentication EKU. Forbidden for native-client session certificates.
    ServerAuth,
    /// Code signing EKU. Forbidden for native-client session certificates.
    CodeSigning,
    /// Any other requested extension OID. Forbidden unless a future profile explicitly allows it.
    CustomOid(String),
}

/// Extended key usage placed on an issued session certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionExtendedKeyUsage {
    /// Client authentication only.
    ClientAuth,
}

/// Normalised certificate signing request profile after transport parsing.
///
/// This type intentionally excludes private key material. A service adapter may
/// parse DER/PEM CSRs before constructing it, but the policy layer only accepts
/// the public request facts it must authorise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCsrProfile {
    /// Redacted subject requested by the client.
    pub subject: String,
    /// Fingerprint of the public key in the CSR.
    pub public_key_fingerprint: String,
    /// Requested subject alternative names.
    pub requested_subject_alt_names: Vec<SessionSubjectAltName>,
    /// Requested certificate extensions.
    pub requested_extensions: Vec<CsrExtensionRequest>,
}

/// Request to issue or refresh a short-lived session certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCertificateRequest {
    /// Normalised CSR profile.
    pub csr: SessionCsrProfile,
    /// Requested certificate lifetime.
    pub requested_ttl: Duration,
}

/// Issuer policy for native-client session certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCertificatePolicy {
    /// Maximum certificate lifetime.
    pub max_ttl: Duration,
    /// How long before expiry refresh becomes allowed.
    pub refresh_window: Duration,
    /// Allowed URI SAN prefixes.
    pub allowed_uri_san_prefixes: Vec<String>,
}

impl SessionCertificatePolicy {
    /// Production-like policy profile for Sunlit native clients.
    #[must_use]
    pub fn production() -> Self {
        Self {
            max_ttl: Duration::days(30),
            refresh_window: Duration::days(7),
            allowed_uri_san_prefixes: vec!["urn:sunlit:".to_owned()],
        }
    }
}

/// Certificate profile handed to an external CA signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCertificateProfile {
    /// Redacted certificate subject.
    pub subject: String,
    /// Public key fingerprint from the CSR.
    pub public_key_fingerprint: String,
    /// Allowed subject alternative names copied into the certificate.
    pub subject_alt_names: Vec<SessionSubjectAltName>,
    /// Extended key usages copied into the certificate.
    pub extended_key_usages: Vec<SessionExtendedKeyUsage>,
    /// Certificate validity start.
    pub not_before: OffsetDateTime,
    /// Certificate expiry.
    pub not_after: OffsetDateTime,
}

/// Signed certificate material returned by a CA adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSessionCertificate {
    /// Leaf certificate bytes, normally DER.
    pub certificate_der: Vec<u8>,
    /// CA chain bytes, normally DER, leaf excluded.
    pub ca_chain_der: Vec<Vec<u8>>,
    /// Issued certificate serial.
    pub serial: String,
    /// Fingerprint of the issued certificate.
    pub fingerprint: String,
}

/// Revocation lookup handle for a session certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationHandle {
    /// Issued certificate serial.
    pub serial: String,
    /// Issued certificate fingerprint.
    pub fingerprint: String,
}

/// Issued session certificate bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCertificateBundle {
    /// Leaf certificate bytes, normally DER.
    pub certificate_der: Vec<u8>,
    /// CA chain bytes, normally DER, leaf excluded.
    pub ca_chain_der: Vec<Vec<u8>>,
    /// Issued certificate serial.
    pub serial: String,
    /// Fingerprint of the issued certificate.
    pub fingerprint: String,
    /// Certificate validity start.
    pub not_before: OffsetDateTime,
    /// Certificate expiry.
    pub expires_at: OffsetDateTime,
    /// Earliest safe refresh time.
    pub refresh_after: OffsetDateTime,
    /// Revocation lookup handle.
    pub revocation_handle: RevocationHandle,
    /// Profile authorised before signing.
    pub profile: SessionCertificateProfile,
}

/// CA adapter used by the session certificate issuer.
///
/// Production implementations should call managed CA/KMS/HSM services. The
/// policy layer does not accept filesystem signer paths or private keys.
pub trait SessionCertificateSigner {
    /// Signs a pre-validated certificate profile.
    fn sign(
        &self,
        profile: &SessionCertificateProfile,
    ) -> Result<SignedSessionCertificate, SessionCertificateError>;
}

/// Revocation checker for session certificate lifecycle decisions.
pub trait RevocationChecker {
    /// Returns true when the supplied revocation handle is revoked.
    fn is_revoked(&self, handle: &RevocationHandle) -> bool;
}

/// Revocation checker that treats every session certificate as active.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRevocations;

impl RevocationChecker for NoRevocations {
    fn is_revoked(&self, _handle: &RevocationHandle) -> bool {
        false
    }
}

/// CSR rejection reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsrRejectionReason {
    /// CSR did not request client authentication.
    MissingClientAuth,
    /// CSR requested a forbidden extension.
    ForbiddenExtension,
    /// CSR requested a forbidden subject alternative name.
    ForbiddenSubjectAltName,
    /// CSR omitted its public key fingerprint.
    EmptyPublicKeyFingerprint,
    /// CSR requested an invalid TTL.
    InvalidTtl,
}

/// Errors from session certificate issuance and refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionCertificateError {
    /// Device trust decision does not allow session certificate issuance.
    DeniedDeviceTrust,
    /// CSR profile failed policy validation.
    InvalidCsr {
        /// Safe structured reason.
        reason: CsrRejectionReason,
    },
    /// Existing session certificate is revoked.
    Revoked,
    /// Refresh was requested before the refresh window.
    RefreshTooEarly,
    /// Existing session certificate is expired.
    SessionExpired,
    /// CA adapter failed or rejected the pre-validated profile.
    SignerRejected,
}

impl std::fmt::Display for SessionCertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeniedDeviceTrust => write!(f, "device trust decision denied issuance"),
            Self::InvalidCsr { reason } => write!(f, "invalid session certificate CSR: {reason:?}"),
            Self::Revoked => write!(f, "session certificate is revoked"),
            Self::RefreshTooEarly => write!(f, "session certificate refresh requested too early"),
            Self::SessionExpired => write!(f, "session certificate is expired"),
            Self::SignerRejected => write!(f, "session certificate signer rejected profile"),
        }
    }
}

impl std::error::Error for SessionCertificateError {}

/// Issues and refreshes short-lived native-client session certificates.
#[derive(Clone, Debug)]
pub struct SessionCertificateIssuer<S> {
    policy: SessionCertificatePolicy,
    signer: S,
}

impl<S> SessionCertificateIssuer<S>
where
    S: SessionCertificateSigner,
{
    /// Creates a new issuer from an explicit policy and signer adapter.
    #[must_use]
    pub fn new(policy: SessionCertificatePolicy, signer: S) -> Self {
        Self { policy, signer }
    }

    /// Issues a new session certificate.
    pub fn issue(
        &self,
        request: &SessionCertificateRequest,
        decision: &DeviceTrustDecision,
        now: OffsetDateTime,
    ) -> Result<SessionCertificateBundle, SessionCertificateError> {
        if !device_decision_allows_session(decision) {
            return Err(SessionCertificateError::DeniedDeviceTrust);
        }

        self.validate_request(request)?;

        let ttl = request.requested_ttl.min(self.policy.max_ttl);
        let not_before = now;
        let not_after = now + ttl;
        let refresh_after = if ttl > self.policy.refresh_window {
            not_after - self.policy.refresh_window
        } else {
            now
        };
        let profile = SessionCertificateProfile {
            subject: request.csr.subject.clone(),
            public_key_fingerprint: request.csr.public_key_fingerprint.clone(),
            subject_alt_names: request.csr.requested_subject_alt_names.clone(),
            extended_key_usages: vec![SessionExtendedKeyUsage::ClientAuth],
            not_before,
            not_after,
        };

        let signed = self.signer.sign(&profile)?;
        if signed.certificate_der.is_empty()
            || signed.serial.is_empty()
            || signed.fingerprint.is_empty()
        {
            return Err(SessionCertificateError::SignerRejected);
        }

        Ok(SessionCertificateBundle {
            certificate_der: signed.certificate_der,
            ca_chain_der: signed.ca_chain_der,
            serial: signed.serial.clone(),
            fingerprint: signed.fingerprint.clone(),
            not_before,
            expires_at: not_after,
            refresh_after,
            revocation_handle: RevocationHandle {
                serial: signed.serial,
                fingerprint: signed.fingerprint,
            },
            profile,
        })
    }

    /// Refreshes an existing session certificate inside the refresh window.
    pub fn refresh(
        &self,
        existing: &SessionCertificateBundle,
        request: &SessionCertificateRequest,
        decision: &DeviceTrustDecision,
        revocation: &dyn RevocationChecker,
        now: OffsetDateTime,
    ) -> Result<SessionCertificateBundle, SessionCertificateError> {
        if !device_decision_allows_session(decision) {
            return Err(SessionCertificateError::DeniedDeviceTrust);
        }
        if revocation.is_revoked(&existing.revocation_handle) {
            return Err(SessionCertificateError::Revoked);
        }
        if now >= existing.expires_at {
            return Err(SessionCertificateError::SessionExpired);
        }
        if now < existing.refresh_after {
            return Err(SessionCertificateError::RefreshTooEarly);
        }

        self.issue(request, decision, now)
    }

    fn validate_request(
        &self,
        request: &SessionCertificateRequest,
    ) -> Result<(), SessionCertificateError> {
        if request.requested_ttl <= Duration::ZERO {
            return Err(invalid_csr(CsrRejectionReason::InvalidTtl));
        }

        if request.csr.public_key_fingerprint.trim().is_empty() {
            return Err(invalid_csr(CsrRejectionReason::EmptyPublicKeyFingerprint));
        }

        if request.csr.subject.trim().is_empty() || request.csr.subject.len() > 200 {
            return Err(invalid_csr(CsrRejectionReason::ForbiddenSubjectAltName));
        }

        if request
            .csr
            .requested_extensions
            .iter()
            .any(|extension| !matches!(extension, CsrExtensionRequest::ClientAuth))
        {
            return Err(invalid_csr(CsrRejectionReason::ForbiddenExtension));
        }

        if !request
            .csr
            .requested_extensions
            .iter()
            .any(|extension| matches!(extension, CsrExtensionRequest::ClientAuth))
        {
            return Err(invalid_csr(CsrRejectionReason::MissingClientAuth));
        }

        if request.csr.requested_subject_alt_names.is_empty()
            || !request
                .csr
                .requested_subject_alt_names
                .iter()
                .all(|san| self.san_is_allowed(san))
        {
            return Err(invalid_csr(CsrRejectionReason::ForbiddenSubjectAltName));
        }

        Ok(())
    }

    fn san_is_allowed(&self, san: &SessionSubjectAltName) -> bool {
        let SessionSubjectAltName::Uri(value) = san else {
            return false;
        };
        !value.is_empty()
            && value.len() <= 200
            && value.bytes().all(|b| b.is_ascii_graphic())
            && self
                .policy
                .allowed_uri_san_prefixes
                .iter()
                .any(|prefix| value.starts_with(prefix))
    }
}

fn invalid_csr(reason: CsrRejectionReason) -> SessionCertificateError {
    SessionCertificateError::InvalidCsr { reason }
}

pub(crate) fn device_decision_allows_session(decision: &DeviceTrustDecision) -> bool {
    decision.outcome() != DeviceTrustOutcome::Denied && decision.tier() > TrustTier::None
}

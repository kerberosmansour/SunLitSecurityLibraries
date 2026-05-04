//! Passwordless login APIs bound to native device trust.

use ring::rand::{SecureRandom, SystemRandom};
use secure_device_trust::{DeviceTrustDecision, DeviceTrustOutcome, TrustTier};
use secure_network::{MtlsClientIdentity, MtlsClientIdentityStatus, NoMtlsRevocations};
use security_core::{
    identity::AuthenticatedIdentity,
    types::{ActorId, TenantId},
};
use time::{Duration, OffsetDateTime};

/// Passwordless authentication method selected for a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordlessMethod {
    /// Platform passkey or WebAuthn credential.
    Passkey,
    /// Native-app deep-link proof fallback.
    DeepLink,
}

/// Whether the client platform can satisfy a passkey challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeySupport {
    /// The platform can complete passkey authentication.
    Supported,
    /// The platform cannot complete passkey authentication.
    Unsupported,
}

/// Request to issue a passwordless user-authentication challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordlessChallengeRequest {
    /// Preferred authentication method.
    pub preferred_method: PasswordlessMethod,
    /// Platform passkey support state reported by the native client capability probe.
    pub passkey_support: PasskeySupport,
    /// Optional redacted user hint used by the upstream identity adapter.
    pub user_hint: Option<String>,
}

impl std::fmt::Debug for PasswordlessChallengeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordlessChallengeRequest")
            .field("preferred_method", &self.preferred_method)
            .field("passkey_support", &self.passkey_support)
            .field("user_hint", &self.user_hint.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl PasswordlessChallengeRequest {
    /// Builds a passkey-first challenge request.
    #[must_use]
    pub fn passkey_preferred(passkey_support: PasskeySupport) -> Self {
        Self {
            preferred_method: PasswordlessMethod::Passkey,
            passkey_support,
            user_hint: None,
        }
    }

    /// Adds a redacted user hint.
    #[must_use]
    pub fn with_user_hint(mut self, user_hint: impl Into<String>) -> Self {
        self.user_hint = Some(user_hint.into());
        self
    }
}

/// Device-session binding copied into passwordless challenges and user sessions.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceSessionBinding {
    certificate_serial: String,
    certificate_fingerprint: String,
    trust_tier: TrustTier,
}

impl std::fmt::Debug for DeviceSessionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSessionBinding")
            .field("certificate_serial", &"<redacted>")
            .field("certificate_fingerprint", &"<redacted>")
            .field("trust_tier", &self.trust_tier)
            .finish()
    }
}

impl DeviceSessionBinding {
    /// Creates a device-session binding from a certificate identity and trust tier.
    #[must_use]
    pub fn new(
        certificate_serial: impl Into<String>,
        certificate_fingerprint: impl Into<String>,
        trust_tier: TrustTier,
    ) -> Self {
        Self {
            certificate_serial: certificate_serial.into(),
            certificate_fingerprint: certificate_fingerprint.into(),
            trust_tier,
        }
    }

    /// Returns the certificate serial bound to the challenge or session.
    #[must_use]
    pub fn certificate_serial(&self) -> &str {
        &self.certificate_serial
    }

    /// Returns the certificate fingerprint bound to the challenge or session.
    #[must_use]
    pub fn certificate_fingerprint(&self) -> &str {
        &self.certificate_fingerprint
    }

    /// Returns the trust tier authorised before user authentication.
    #[must_use]
    pub fn trust_tier(&self) -> TrustTier {
        self.trust_tier
    }

    /// Returns true when this binding matches the supplied mTLS identity.
    #[must_use]
    pub fn matches_mtls(&self, mtls: &MtlsClientIdentity) -> bool {
        self.certificate_serial == mtls.serial && self.certificate_fingerprint == mtls.fingerprint
    }
}

/// Passwordless challenge issued after device trust and session mTLS checks.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordlessChallenge {
    challenge_id: String,
    method: PasswordlessMethod,
    binding: DeviceSessionBinding,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl std::fmt::Debug for PasswordlessChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordlessChallenge")
            .field("challenge_id", &"<redacted>")
            .field("method", &self.method)
            .field("binding", &self.binding)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl PasswordlessChallenge {
    /// Creates a passwordless challenge.
    #[must_use]
    pub fn new(
        challenge_id: impl Into<String>,
        method: PasswordlessMethod,
        binding: DeviceSessionBinding,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            method,
            binding,
            issued_at,
            expires_at,
        }
    }

    /// Returns the challenge identifier supplied to the proof verifier.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Returns the selected passwordless method.
    #[must_use]
    pub fn method(&self) -> PasswordlessMethod {
        self.method
    }

    /// Returns the device-session binding.
    #[must_use]
    pub fn device_binding(&self) -> &DeviceSessionBinding {
        &self.binding
    }

    /// Returns the challenge issue time.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// Returns the challenge expiry time.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// Passwordless proof material from a native client.
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordlessProof {
    /// Passkey assertion proof.
    Passkey {
        /// Challenge identifier being answered.
        challenge_id: String,
        /// Redacted credential identifier.
        credential_id: String,
        /// Redacted client-data hash or verifier-owned proof reference.
        client_data_hash: String,
    },
    /// Deep-link proof fallback.
    DeepLink {
        /// Challenge identifier being answered.
        challenge_id: String,
        /// Server challenge nonce returned through the native deep-link flow.
        nonce: String,
        /// Signature or proof reference validated by the consuming adapter.
        signature: String,
    },
}

impl std::fmt::Debug for PasswordlessProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passkey { .. } => f
                .debug_struct("Passkey")
                .field("challenge_id", &"<redacted>")
                .field("credential_id", &"<redacted>")
                .field("client_data_hash", &"<redacted>")
                .finish(),
            Self::DeepLink { .. } => f
                .debug_struct("DeepLink")
                .field("challenge_id", &"<redacted>")
                .field("nonce", &"<redacted>")
                .field("signature", &"<redacted>")
                .finish(),
        }
    }
}

impl PasswordlessProof {
    /// Builds a passkey proof.
    #[must_use]
    pub fn passkey(
        challenge_id: impl Into<String>,
        credential_id: impl Into<String>,
        client_data_hash: impl Into<String>,
    ) -> Self {
        Self::Passkey {
            challenge_id: challenge_id.into(),
            credential_id: credential_id.into(),
            client_data_hash: client_data_hash.into(),
        }
    }

    /// Builds a deep-link proof.
    #[must_use]
    pub fn deep_link(
        challenge_id: impl Into<String>,
        nonce: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self::DeepLink {
            challenge_id: challenge_id.into(),
            nonce: nonce.into(),
            signature: signature.into(),
        }
    }

    /// Returns the challenge identifier answered by this proof.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        match self {
            Self::Passkey { challenge_id, .. } | Self::DeepLink { challenge_id, .. } => {
                challenge_id
            }
        }
    }

    /// Returns the proof method.
    #[must_use]
    pub fn method(&self) -> PasswordlessMethod {
        match self {
            Self::Passkey { .. } => PasswordlessMethod::Passkey,
            Self::DeepLink { .. } => PasswordlessMethod::DeepLink,
        }
    }
}

/// User session token bound to the authorised session certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundUserSession {
    session_token: String,
    actor_id: ActorId,
    tenant_id: Option<TenantId>,
    roles: Vec<String>,
    binding: DeviceSessionBinding,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl std::fmt::Debug for BoundUserSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundUserSession")
            .field("session_token", &"<redacted>")
            .field("actor_id", &"<redacted>")
            .field("tenant_id", &self.tenant_id.as_ref().map(|_| "<redacted>"))
            .field("roles", &self.roles)
            .field("binding", &self.binding)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl BoundUserSession {
    /// Creates a bound user session.
    #[must_use]
    pub fn new(
        session_token: impl Into<String>,
        identity: &AuthenticatedIdentity,
        binding: DeviceSessionBinding,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            session_token: session_token.into(),
            actor_id: identity.actor_id.clone(),
            tenant_id: identity.tenant_id.clone(),
            roles: identity.roles.clone(),
            binding,
            created_at,
            expires_at,
        }
    }

    /// Returns the opaque user session token.
    #[must_use]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// Returns the authenticated actor.
    #[must_use]
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// Returns the authenticated tenant, if present.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns the roles copied into this session.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns the device-session binding.
    #[must_use]
    pub fn device_binding(&self) -> &DeviceSessionBinding {
        &self.binding
    }

    /// Returns the session creation time.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the session expiry time.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Returns true when this session is presented with its original mTLS certificate.
    #[must_use]
    pub fn is_bound_to(&self, mtls: &MtlsClientIdentity) -> bool {
        self.binding.matches_mtls(mtls)
    }
}

/// Passwordless challenge or completion error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordlessError {
    /// The caller did not present a verified mTLS session certificate.
    MissingClientCertificate,
    /// Device trust did not allow user authentication.
    DeniedDeviceTrust,
    /// The challenge has expired.
    ChallengeExpired,
    /// The completion mTLS certificate does not match the challenge binding.
    CertificateBindingMismatch,
    /// The supplied proof answers a different challenge.
    ChallengeMismatch,
    /// The supplied proof uses the wrong authentication method.
    ChallengeMethodMismatch,
    /// The proof verifier rejected the proof.
    InvalidProof,
    /// The requested user session lifetime is invalid.
    InvalidSessionLifetime,
    /// The passwordless provider is temporarily unavailable.
    ProviderUnavailable,
}

impl std::fmt::Display for PasswordlessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClientCertificate => write!(f, "missing client certificate"),
            Self::DeniedDeviceTrust => write!(f, "device trust denied passwordless challenge"),
            Self::ChallengeExpired => write!(f, "passwordless challenge expired"),
            Self::CertificateBindingMismatch => {
                write!(f, "passwordless challenge certificate binding mismatch")
            }
            Self::ChallengeMismatch => write!(f, "passwordless proof answered another challenge"),
            Self::ChallengeMethodMismatch => write!(f, "passwordless proof method mismatch"),
            Self::InvalidProof => write!(f, "passwordless proof rejected"),
            Self::InvalidSessionLifetime => write!(f, "passwordless session lifetime invalid"),
            Self::ProviderUnavailable => write!(f, "passwordless provider unavailable"),
        }
    }
}

impl std::error::Error for PasswordlessError {}

impl From<PasswordlessError> for crate::IdentityError {
    fn from(error: PasswordlessError) -> Self {
        match error {
            PasswordlessError::ChallengeExpired => Self::TokenExpired,
            PasswordlessError::ProviderUnavailable => Self::ProviderUnavailable,
            _ => Self::InvalidCredentials,
        }
    }
}

/// Adapter trait for passkey or deep-link proof verification.
pub trait PasswordlessProofVerifier {
    /// Verifies proof material and returns the resolved authenticated identity.
    fn verify(
        &self,
        challenge: &PasswordlessChallenge,
        proof: &PasswordlessProof,
    ) -> Result<AuthenticatedIdentity, PasswordlessError>;
}

/// Issues passwordless challenges and completes device-bound user sessions.
#[derive(Clone)]
pub struct PasswordlessChallengeService<V> {
    verifier: V,
    challenge_ttl: Duration,
}

impl<V> PasswordlessChallengeService<V>
where
    V: PasswordlessProofVerifier,
{
    /// Creates a service with the default challenge lifetime.
    #[must_use]
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            challenge_ttl: Duration::minutes(5),
        }
    }

    /// Creates a service with an explicit challenge lifetime.
    #[must_use]
    pub fn with_challenge_ttl(mut self, challenge_ttl: Duration) -> Self {
        self.challenge_ttl = challenge_ttl;
        self
    }

    /// Issues a passwordless challenge after device trust and mTLS checks.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordlessError`] when client mTLS is absent, device trust
    /// denies authentication, or challenge generation is unavailable.
    pub fn request_challenge(
        &self,
        mtls: Option<&MtlsClientIdentity>,
        decision: &DeviceTrustDecision,
        request: &PasswordlessChallengeRequest,
        now: OffsetDateTime,
    ) -> Result<PasswordlessChallenge, PasswordlessError> {
        let mtls = mtls.ok_or(PasswordlessError::MissingClientCertificate)?;
        if mtls.serial.trim().is_empty()
            || mtls.fingerprint.trim().is_empty()
            || mtls.validate_at(now, &NoMtlsRevocations) != MtlsClientIdentityStatus::Valid
        {
            return Err(PasswordlessError::MissingClientCertificate);
        }
        if decision.outcome() == DeviceTrustOutcome::Denied || decision.tier() <= TrustTier::None {
            return Err(PasswordlessError::DeniedDeviceTrust);
        }

        let method = match (request.preferred_method, request.passkey_support) {
            (PasswordlessMethod::Passkey, PasskeySupport::Unsupported) => {
                PasswordlessMethod::DeepLink
            }
            (method, _) => method,
        };
        let binding = DeviceSessionBinding::new(
            mtls.serial.clone(),
            mtls.fingerprint.clone(),
            decision.tier(),
        );
        Ok(PasswordlessChallenge::new(
            generate_opaque_token("plc")?,
            method,
            binding,
            now,
            now + self.challenge_ttl,
        ))
    }

    /// Completes passwordless proof verification and returns a bound user session.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordlessError`] when challenge binding, challenge freshness,
    /// proof method, or proof verification fails.
    pub fn complete_challenge(
        &self,
        mtls: &MtlsClientIdentity,
        challenge: &PasswordlessChallenge,
        proof: &PasswordlessProof,
        session_lifetime_secs: u64,
        now: OffsetDateTime,
    ) -> Result<BoundUserSession, PasswordlessError> {
        if !challenge.device_binding().matches_mtls(mtls) {
            return Err(PasswordlessError::CertificateBindingMismatch);
        }
        if now >= challenge.expires_at() {
            return Err(PasswordlessError::ChallengeExpired);
        }
        if proof.challenge_id() != challenge.challenge_id() {
            return Err(PasswordlessError::ChallengeMismatch);
        }
        if proof.method() != challenge.method() {
            return Err(PasswordlessError::ChallengeMethodMismatch);
        }

        let lifetime_secs = i64::try_from(session_lifetime_secs)
            .map_err(|_| PasswordlessError::InvalidSessionLifetime)?;
        if lifetime_secs <= 0 {
            return Err(PasswordlessError::InvalidSessionLifetime);
        }

        let identity = self.verifier.verify(challenge, proof)?;
        let expires_at = now + Duration::seconds(lifetime_secs);
        Ok(BoundUserSession::new(
            generate_opaque_token("bus")?,
            &identity,
            challenge.device_binding().clone(),
            now,
            expires_at,
        ))
    }
}

fn generate_opaque_token(prefix: &str) -> Result<String, PasswordlessError> {
    let rng = SystemRandom::new();
    let mut bytes = [0_u8; 16];
    rng.fill(&mut bytes)
        .map_err(|_| PasswordlessError::ProviderUnavailable)?;
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{prefix}_{suffix}"))
}

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_identity` — Identity resolution and session management for SunLit Security Libraries.
//!
//! Provides JWT-based authentication, session management, and MFA support.

pub mod api_key;
pub mod auth_events;
pub mod authenticator;
#[cfg(feature = "biometric")]
pub mod biometric;
pub mod boot;
pub mod capability;
pub mod dev;
#[cfg(feature = "biometric")]
pub mod device_binding;
pub mod error;
pub mod jwks;
pub mod mfa;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod openssh;
pub mod passwordless;
pub mod session;
#[cfg(feature = "session-redis")]
pub mod session_redis;
#[cfg(feature = "biometric")]
pub mod step_up;
pub mod token;
pub mod totp;
#[cfg(feature = "jwks")]
pub mod workload;

pub use authenticator::{AuthenticationRequest, Authenticator, TokenKind};
pub use boot::{assert_no_dev_identity_in_production, ProductionModeViolation};
pub use capability::{
    CapabilityError, CapabilityIssuer, CapabilityRequest, CapabilitySigner, CapabilityVerifier,
    Expected, InMemoryReplayStore, Operation, ReplayStore, RsaCapabilitySigner, VerifiedCapability,
    MAX_TTL_SECONDS,
};
pub use error::IdentityError;
pub use openssh::{
    validate_openssh_public_key, validate_openssh_public_key_with_rsa_minimum_bits,
    OpenSshPublicKeyError, MAX_OPENSSH_PUBLIC_KEY_BASE64_BYTES,
    MAX_OPENSSH_PUBLIC_KEY_DECODED_BYTES, OPENSSH_RSA_MAX_MODULUS_BITS,
    OPENSSH_RSA_MIN_MODULUS_BITS,
};
pub use passwordless::{
    BoundUserSession, DeviceSessionBinding, PasskeySupport, PasswordlessChallenge,
    PasswordlessChallengeRequest, PasswordlessChallengeService, PasswordlessError,
    PasswordlessMethod, PasswordlessProof, PasswordlessProofVerifier,
};
pub use session::{InMemorySessionManager, Session, SessionManager};
pub use token::{
    AlgorithmConfig, AsymmetricTokenValidator, AsymmetricTokenValidatorConfig, TokenValidator,
    TokenValidatorConfig,
};
#[cfg(feature = "jwks")]
pub use workload::{
    KubernetesServiceAccountSubject, WorkloadIdentityError, WorkloadJwtValidator,
    MAX_WORKLOAD_JWT_BYTES, MAX_WORKLOAD_KEY_ID_BYTES,
};

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
pub mod dev;
#[cfg(feature = "biometric")]
pub mod device_binding;
pub mod error;
pub mod jwks;
pub mod mfa;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod passwordless;
pub mod session;
#[cfg(feature = "session-redis")]
pub mod session_redis;
#[cfg(feature = "biometric")]
pub mod step_up;
pub mod token;
pub mod totp;

pub use authenticator::{AuthenticationRequest, Authenticator, TokenKind};
pub use boot::{assert_no_dev_identity_in_production, ProductionModeViolation};
pub use error::IdentityError;
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

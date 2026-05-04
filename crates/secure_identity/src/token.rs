//! JWT token validation.

use std::collections::HashMap;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use security_core::identity::AuthenticatedIdentity;
use security_core::severity::SecuritySeverity;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::authenticator::{private, AuthenticationRequest};
use crate::error::IdentityError;

/// Configuration for the JWT token validator.
///
/// # Examples
///
/// ```
/// use secure_identity::token::TokenValidatorConfig;
///
/// let config = TokenValidatorConfig {
///     issuer: "https://auth.example.com".to_string(),
///     audience: "my-api".to_string(),
///     secret: b"my-hmac-secret".to_vec(),
/// };
/// ```
pub struct TokenValidatorConfig {
    /// The expected issuer claim (`iss`).
    pub issuer: String,
    /// The expected audience claim (`aud`).
    pub audience: String,
    /// The HMAC-SHA256 secret used to verify token signatures.
    pub secret: Vec<u8>,
}

/// Algorithm configuration for asymmetric JWT validation.
pub enum AlgorithmConfig {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RS256 {
        /// The RSA public key for signature verification.
        decoding_key: DecodingKey,
    },
    /// ECDSA using P-256 curve and SHA-256.
    ES256 {
        /// The EC public key for signature verification.
        decoding_key: DecodingKey,
    },
}

/// Configuration for asymmetric JWT validation.
pub struct AsymmetricTokenValidatorConfig {
    /// The expected issuer claim (`iss`).
    pub issuer: String,
    /// The expected audience claim (`aud`).
    pub audience: String,
    /// The algorithm and key material for signature verification.
    pub algorithm: AlgorithmConfig,
}

/// Validates JWTs signed with asymmetric algorithms (RS256, ES256).
///
/// # Examples
///
/// ```no_run
/// use secure_identity::token::{
///     AsymmetricTokenValidator, AsymmetricTokenValidatorConfig, AlgorithmConfig,
/// };
/// use jsonwebtoken::DecodingKey;
///
/// let pem = std::fs::read("public_key.pem").unwrap();
/// let validator = AsymmetricTokenValidator::new(AsymmetricTokenValidatorConfig {
///     issuer: "https://auth.example.com".to_string(),
///     audience: "my-api".to_string(),
///     algorithm: AlgorithmConfig::RS256 {
///         decoding_key: DecodingKey::from_rsa_pem(&pem).unwrap(),
///     },
/// });
/// ```
pub struct AsymmetricTokenValidator {
    config: AsymmetricTokenValidatorConfig,
}

impl AsymmetricTokenValidator {
    /// Creates a new [`AsymmetricTokenValidator`] with the given configuration.
    #[must_use]
    pub fn new(config: AsymmetricTokenValidatorConfig) -> Self {
        Self { config }
    }

    fn validate_jwt(&self, token: &str) -> Result<JwtClaims, IdentityError> {
        let (algorithm, key) = match &self.config.algorithm {
            AlgorithmConfig::RS256 { decoding_key } => (Algorithm::RS256, decoding_key),
            AlgorithmConfig::ES256 { decoding_key } => (Algorithm::ES256, decoding_key),
        };
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        decode::<JwtClaims>(token, key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => IdentityError::TokenExpired,
                    ErrorKind::InvalidIssuer | ErrorKind::InvalidAudience => {
                        IdentityError::InvalidCredentials
                    }
                    _ => IdentityError::TokenMalformed,
                }
            })
    }
}

impl private::Sealed for AsymmetricTokenValidator {}

impl crate::authenticator::Authenticator for AsymmetricTokenValidator {
    async fn authenticate(
        &self,
        request: &AuthenticationRequest,
    ) -> Result<AuthenticatedIdentity, IdentityError> {
        let claims = self.validate_jwt(&request.token).inspect_err(|_e| {
            emit_security_event(SecurityEvent::new(
                EventKind::AuthnFailure,
                SecuritySeverity::High,
                EventOutcome::Failure,
            ));
        })?;

        let actor_uuid: Uuid = claims.sub.parse().map_err(|_| {
            emit_security_event(SecurityEvent::new(
                EventKind::AuthnFailure,
                SecuritySeverity::High,
                EventOutcome::Failure,
            ));
            IdentityError::TokenMalformed
        })?;

        let tenant_id = claims
            .tenant
            .as_deref()
            .and_then(|t| t.parse::<Uuid>().ok())
            .map(security_core::types::TenantId::from);

        Ok(AuthenticatedIdentity {
            actor_id: security_core::types::ActorId::from(actor_uuid),
            tenant_id,
            roles: claims.roles,
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}

impl security_core::identity::IdentitySource for AsymmetricTokenValidator {
    async fn resolve(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, security_core::identity::IdentityResolutionError> {
        use crate::authenticator::{AuthenticationRequest, Authenticator, TokenKind};
        let request = AuthenticationRequest {
            token: token.to_owned(),
            token_kind: TokenKind::BearerJwt,
        };
        self.authenticate(&request).await.map_err(|e| match e {
            IdentityError::TokenExpired => {
                security_core::identity::IdentityResolutionError::Expired
            }
            IdentityError::ProviderUnavailable => {
                security_core::identity::IdentityResolutionError::ProviderUnavailable
            }
            _ => security_core::identity::IdentityResolutionError::InvalidToken,
        })
    }
}

/// JWT claims structure.
#[derive(serde::Serialize, serde::Deserialize)]
struct JwtClaims {
    sub: String,
    exp: u64,
    iat: u64,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// Validates JWTs and resolves them to [`AuthenticatedIdentity`].
///
/// Uses `jsonwebtoken` which internally uses `ring` for constant-time HMAC-SHA256 verification.
///
/// # Examples
///
/// ```
/// use secure_identity::token::{TokenValidator, TokenValidatorConfig};
///
/// let validator = TokenValidator::new(TokenValidatorConfig {
///     issuer: "https://auth.example.com".to_string(),
///     audience: "my-api".to_string(),
///     secret: b"my-hmac-secret".to_vec(),
/// });
/// ```
pub struct TokenValidator {
    config: TokenValidatorConfig,
}

impl TokenValidator {
    /// Creates a new [`TokenValidator`] with the given configuration.
    #[must_use]
    pub fn new(config: TokenValidatorConfig) -> Self {
        Self { config }
    }

    fn validate_jwt(&self, token: &str) -> Result<JwtClaims, IdentityError> {
        let key = DecodingKey::from_secret(&self.config.secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        decode::<JwtClaims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => IdentityError::TokenExpired,
                    ErrorKind::InvalidIssuer | ErrorKind::InvalidAudience => {
                        IdentityError::InvalidCredentials
                    }
                    _ => IdentityError::TokenMalformed,
                }
            })
    }
}

impl private::Sealed for TokenValidator {}

impl crate::authenticator::Authenticator for TokenValidator {
    async fn authenticate(
        &self,
        request: &AuthenticationRequest,
    ) -> Result<AuthenticatedIdentity, IdentityError> {
        let claims = self.validate_jwt(&request.token).inspect_err(|_e| {
            emit_security_event(SecurityEvent::new(
                EventKind::AuthnFailure,
                SecuritySeverity::High,
                EventOutcome::Failure,
            ));
        })?;

        let actor_uuid: Uuid = claims.sub.parse().map_err(|_| {
            emit_security_event(SecurityEvent::new(
                EventKind::AuthnFailure,
                SecuritySeverity::High,
                EventOutcome::Failure,
            ));
            IdentityError::TokenMalformed
        })?;

        let tenant_id = claims
            .tenant
            .as_deref()
            .and_then(|t| t.parse::<Uuid>().ok())
            .map(security_core::types::TenantId::from);

        Ok(AuthenticatedIdentity {
            actor_id: security_core::types::ActorId::from(actor_uuid),
            tenant_id,
            roles: claims.roles,
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}

impl security_core::identity::IdentitySource for TokenValidator {
    async fn resolve(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, security_core::identity::IdentityResolutionError> {
        use crate::authenticator::{AuthenticationRequest, Authenticator, TokenKind};
        let request = AuthenticationRequest {
            token: token.to_owned(),
            token_kind: TokenKind::BearerJwt,
        };
        self.authenticate(&request).await.map_err(|e| match e {
            IdentityError::TokenExpired => {
                security_core::identity::IdentityResolutionError::Expired
            }
            IdentityError::ProviderUnavailable => {
                security_core::identity::IdentityResolutionError::ProviderUnavailable
            }
            _ => security_core::identity::IdentityResolutionError::InvalidToken,
        })
    }
}

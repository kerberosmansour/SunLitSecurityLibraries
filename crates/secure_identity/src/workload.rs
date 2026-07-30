//! Projected Kubernetes workload JWT validation.
//!
//! This primitive authenticates one fact only: a projected token was signed by
//! the configured Kubernetes issuer for the exact configured audience and
//! names a canonical Kubernetes service account. It deliberately returns no
//! tenant, role, operation, or other authorization claim. Consumers must map
//! the returned subject to authority in their own deny-by-default registry.
//!
//! Remote key retrieval is available only through the crate's `jwks` feature.
//! The configured endpoint must be an exact HTTPS URL, redirects are refused,
//! response size and key count are bounded, and stale keys are never used after
//! a failed refresh.

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{
    AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use url::Url;

/// Maximum accepted protected JWT key identifier length, in bytes.
pub const MAX_WORKLOAD_KEY_ID_BYTES: usize = 256;

/// Maximum accepted projected workload JWT length, in bytes.
pub const MAX_WORKLOAD_JWT_BYTES: usize = 16 * 1024;

const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_JWKS_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const UNKNOWN_KEY_REFRESH_FLOOR: Duration = Duration::from_secs(5);
const JWKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_JWKS_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_ISSUER_BYTES: usize = 2048;
const MAX_AUDIENCE_BYTES: usize = 512;
const MAX_NAMESPACE_BYTES: usize = 63;
const MAX_SERVICE_ACCOUNT_BYTES: usize = 253;
const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";

/// A validated canonical Kubernetes service-account subject.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KubernetesServiceAccountSubject(String);

impl KubernetesServiceAccountSubject {
    /// Parses a canonical `system:serviceaccount:<namespace>:<serviceaccount>` subject.
    ///
    /// Namespace names are bounded DNS labels. Service-account names are
    /// bounded DNS subdomains, matching Kubernetes object-name constraints.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadIdentityError::InvalidSubject`] when the subject is
    /// not a bounded canonical Kubernetes service-account subject.
    pub fn parse(subject: &str) -> Result<Self, WorkloadIdentityError> {
        let remainder = subject
            .strip_prefix(SERVICE_ACCOUNT_PREFIX)
            .ok_or(WorkloadIdentityError::InvalidSubject)?;
        let mut parts = remainder.split(':');
        let namespace = parts.next().ok_or(WorkloadIdentityError::InvalidSubject)?;
        let service_account = parts.next().ok_or(WorkloadIdentityError::InvalidSubject)?;
        if parts.next().is_some()
            || !dns_label_is_valid(namespace, MAX_NAMESPACE_BYTES)
            || !dns_subdomain_is_valid(service_account, MAX_SERVICE_ACCOUNT_BYTES)
        {
            return Err(WorkloadIdentityError::InvalidSubject);
        }

        Ok(Self(subject.to_owned()))
    }

    /// Returns the canonical subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for KubernetesServiceAccountSubject {
    type Error = WorkloadIdentityError;

    fn try_from(subject: &str) -> Result<Self, Self::Error> {
        Self::parse(subject)
    }
}

impl std::fmt::Debug for KubernetesServiceAccountSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubernetesServiceAccountSubject(<redacted>)")
    }
}

/// Errors returned while configuring or validating projected workload JWTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkloadIdentityError {
    /// The validator configuration is empty, oversized, or otherwise invalid.
    InvalidConfiguration,
    /// The configured JWKS endpoint is not an exact HTTPS URL.
    InvalidJwksUrl,
    /// The JWT exceeds [`MAX_WORKLOAD_JWT_BYTES`].
    TokenTooLarge,
    /// The JWT is malformed.
    TokenMalformed,
    /// The protected JWT algorithm is not RS256.
    AlgorithmMismatch,
    /// The protected JWT has no `kid`.
    MissingKeyId,
    /// The protected JWT `kid` is empty, oversized, or malformed.
    InvalidKeyId,
    /// The protected JWT `kid` does not identify exactly one trusted key.
    UnknownKeyId,
    /// The JWKS could not be fetched or safely parsed.
    JwksUnavailable,
    /// The selected JWKS key is not explicitly an RS256 signing key.
    JwksAlgorithmMismatch,
    /// The JWT signature does not verify against the selected JWKS key.
    InvalidSignature,
    /// The JWT issuer is not the exact configured issuer.
    IssuerMismatch,
    /// The JWT audience is not the exact configured audience.
    AudienceMismatch,
    /// The JWT is expired.
    Expired,
    /// The JWT is not valid yet.
    NotYetValid,
    /// The JWT subject is not a bounded canonical Kubernetes service-account subject.
    InvalidSubject,
    /// The system clock is before the Unix epoch.
    ClockUnavailable,
}

impl std::fmt::Display for WorkloadIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid workload identity configuration",
            Self::InvalidJwksUrl => "invalid workload JWKS URL",
            Self::TokenTooLarge => "workload token too large",
            Self::TokenMalformed => "workload token malformed",
            Self::AlgorithmMismatch => "workload token algorithm mismatch",
            Self::MissingKeyId => "workload token has no key identifier",
            Self::InvalidKeyId => "workload token key identifier invalid",
            Self::UnknownKeyId => "workload token key identifier not trusted",
            Self::JwksUnavailable => "workload JWKS unavailable",
            Self::JwksAlgorithmMismatch => "workload JWKS algorithm mismatch",
            Self::InvalidSignature => "workload token signature invalid",
            Self::IssuerMismatch => "workload token issuer mismatch",
            Self::AudienceMismatch => "workload token audience mismatch",
            Self::Expired => "workload token expired",
            Self::NotYetValid => "workload token not yet valid",
            Self::InvalidSubject => "workload token subject invalid",
            Self::ClockUnavailable => "system clock unavailable",
        };
        f.write_str(message)
    }
}

impl std::error::Error for WorkloadIdentityError {}

#[derive(Clone)]
enum JwksSource {
    Remote {
        client: reqwest::Client,
        url: Url,
    },
    #[cfg(feature = "dev")]
    Static(JwkSet),
}

#[derive(Default)]
struct CachedJwks {
    key_set: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

/// Validates projected Kubernetes service-account JWTs against a pinned JWKS endpoint.
pub struct WorkloadJwtValidator {
    issuer: String,
    audience: String,
    cache_ttl: Duration,
    source: JwksSource,
    cache: RwLock<CachedJwks>,
    refresh: Mutex<()>,
}

impl std::fmt::Debug for WorkloadJwtValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadJwtValidator")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks", &"<redacted>")
            .finish()
    }
}

impl WorkloadJwtValidator {
    /// Creates a validator using a five-minute JWKS cache.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadIdentityError::InvalidJwksUrl`] unless `jwks_url` is
    /// an exact HTTPS URL, or [`WorkloadIdentityError::InvalidConfiguration`]
    /// when another configured value is invalid.
    pub fn new(
        jwks_url: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, WorkloadIdentityError> {
        Self::with_cache_ttl(jwks_url, issuer, audience, DEFAULT_JWKS_CACHE_TTL)
    }

    /// Creates a validator using an explicit bounded JWKS cache lifetime.
    ///
    /// A refresh failure never falls back to an expired key set. Unknown key
    /// identifiers trigger one immediate refresh to support safe key rotation.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadIdentityError::InvalidJwksUrl`] unless `jwks_url` is
    /// an exact HTTPS URL, or [`WorkloadIdentityError::InvalidConfiguration`]
    /// when another configured value is invalid.
    pub fn with_cache_ttl(
        jwks_url: &str,
        issuer: &str,
        audience: &str,
        cache_ttl: Duration,
    ) -> Result<Self, WorkloadIdentityError> {
        let url = validate_jwks_url(jwks_url)?;
        validate_configuration(issuer, audience, cache_ttl)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(JWKS_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| WorkloadIdentityError::InvalidConfiguration)?;

        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            cache_ttl,
            source: JwksSource::Remote { client, url },
            cache: RwLock::new(CachedJwks::default()),
            refresh: Mutex::new(()),
        })
    }

    /// Builds a validator with an in-memory JWKS document for tests.
    ///
    /// This bypasses HTTPS retrieval and is available only with the explicitly
    /// unsafe-for-production `dev` feature. The nominal URL is still validated
    /// so configuration tests exercise the same pinning contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the validator configuration or JWKS is invalid.
    #[cfg(feature = "dev")]
    pub fn from_static_jwks_for_tests(
        jwks_url: &str,
        issuer: &str,
        audience: &str,
        jwks_json: &str,
    ) -> Result<Self, WorkloadIdentityError> {
        validate_jwks_url(jwks_url)?;
        validate_configuration(issuer, audience, DEFAULT_JWKS_CACHE_TTL)?;
        let key_set = parse_jwks(jwks_json.as_bytes())?;
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            cache_ttl: DEFAULT_JWKS_CACHE_TTL,
            source: JwksSource::Static(key_set),
            cache: RwLock::new(CachedJwks::default()),
            refresh: Mutex::new(()),
        })
    }

    /// Verifies a projected workload JWT and returns only its bounded service-account subject.
    ///
    /// Protected `kid` selection happens before claims are trusted. RS256,
    /// signature, exact issuer, exact single audience, required `exp`/`nbf`,
    /// and the canonical subject shape are all independently checked.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadIdentityError`] on every configuration, key selection,
    /// signature, claim, time, or subject validation failure.
    pub async fn verify(
        &self,
        token: &str,
    ) -> Result<KubernetesServiceAccountSubject, WorkloadIdentityError> {
        if token.len() > MAX_WORKLOAD_JWT_BYTES {
            return Err(WorkloadIdentityError::TokenTooLarge);
        }

        let header = decode_header(token).map_err(|_| WorkloadIdentityError::TokenMalformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(WorkloadIdentityError::AlgorithmMismatch);
        }
        let key_id = header
            .kid
            .as_deref()
            .ok_or(WorkloadIdentityError::MissingKeyId)?;
        if !key_id_is_valid(key_id) {
            return Err(WorkloadIdentityError::InvalidKeyId);
        }

        let key = self.decoding_key(key_id).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.leeway = 0;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let claims = decode::<WorkloadClaims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(map_jwt_error)?;

        if claims.iss != self.issuer {
            return Err(WorkloadIdentityError::IssuerMismatch);
        }
        if !claims.aud.is_exact(&self.audience) {
            return Err(WorkloadIdentityError::AudienceMismatch);
        }

        let now = unix_now()?;
        if now >= claims.exp {
            return Err(WorkloadIdentityError::Expired);
        }
        if now < claims.nbf {
            return Err(WorkloadIdentityError::NotYetValid);
        }

        KubernetesServiceAccountSubject::parse(&claims.sub)
    }

    async fn decoding_key(&self, key_id: &str) -> Result<DecodingKey, WorkloadIdentityError> {
        let key_set = self.key_set(false).await?;
        match select_decoding_key(&key_set, key_id) {
            Ok(key) => Ok(key),
            Err(WorkloadIdentityError::UnknownKeyId) if self.is_remote() => {
                let refreshed = self.key_set(true).await?;
                select_decoding_key(&refreshed, key_id)
            }
            Err(error) => Err(error),
        }
    }

    async fn key_set(&self, force_refresh: bool) -> Result<JwkSet, WorkloadIdentityError> {
        #[cfg(feature = "dev")]
        if let JwksSource::Static(key_set) = &self.source {
            return Ok(key_set.clone());
        }

        if !force_refresh {
            if let Some(key_set) = self.cached_key_set(self.cache_ttl).await {
                return Ok(key_set);
            }
        }

        let _refresh_guard = self.refresh.lock().await;
        let reusable_age = if force_refresh {
            UNKNOWN_KEY_REFRESH_FLOOR
        } else {
            self.cache_ttl
        };
        if let Some(key_set) = self.cached_key_set(reusable_age).await {
            return Ok(key_set);
        }

        let key_set = match &self.source {
            JwksSource::Remote { client, url } => fetch_jwks(client, url).await?,
            #[cfg(feature = "dev")]
            JwksSource::Static(key_set) => key_set.clone(),
        };
        let mut cache = self.cache.write().await;
        cache.key_set = Some(key_set.clone());
        cache.fetched_at = Some(Instant::now());
        Ok(key_set)
    }

    async fn cached_key_set(&self, max_age: Duration) -> Option<JwkSet> {
        let cache = self.cache.read().await;
        match (&cache.key_set, cache.fetched_at) {
            (Some(key_set), Some(fetched_at)) if fetched_at.elapsed() < max_age => {
                Some(key_set.clone())
            }
            _ => None,
        }
    }

    fn is_remote(&self) -> bool {
        matches!(self.source, JwksSource::Remote { .. })
    }
}

#[derive(Deserialize)]
struct WorkloadClaims {
    sub: String,
    iss: String,
    aud: AudienceClaim,
    exp: u64,
    nbf: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn is_exact(&self, expected: &str) -> bool {
        match self {
            Self::One(actual) => actual == expected,
            Self::Many(actual) => actual.len() == 1 && actual[0] == expected,
        }
    }
}

fn validate_jwks_url(jwks_url: &str) -> Result<Url, WorkloadIdentityError> {
    let url = Url::parse(jwks_url).map_err(|_| WorkloadIdentityError::InvalidJwksUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(WorkloadIdentityError::InvalidJwksUrl);
    }
    Ok(url)
}

fn validate_configuration(
    issuer: &str,
    audience: &str,
    cache_ttl: Duration,
) -> Result<(), WorkloadIdentityError> {
    if !bounded_graphic_string(issuer, MAX_ISSUER_BYTES)
        || !bounded_graphic_string(audience, MAX_AUDIENCE_BYTES)
        || cache_ttl.is_zero()
        || cache_ttl > MAX_JWKS_CACHE_TTL
    {
        return Err(WorkloadIdentityError::InvalidConfiguration);
    }
    Ok(())
}

fn bounded_graphic_string(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn key_id_is_valid(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= MAX_WORKLOAD_KEY_ID_BYTES
        && key_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=' | b'@')
        })
}

fn dns_label_is_valid(label: &str, max_bytes: usize) -> bool {
    !label.is_empty()
        && label.len() <= max_bytes
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn dns_subdomain_is_valid(name: &str, max_bytes: usize) -> bool {
    !name.is_empty()
        && name.len() <= max_bytes
        && name
            .split('.')
            .all(|label| dns_label_is_valid(label, MAX_NAMESPACE_BYTES))
}

async fn fetch_jwks(
    client: &reqwest::Client,
    expected_url: &Url,
) -> Result<JwkSet, WorkloadIdentityError> {
    let mut response = client
        .get(expected_url.clone())
        .send()
        .await
        .map_err(|_| WorkloadIdentityError::JwksUnavailable)?;
    if response.url() != expected_url || !response.status().is_success() {
        return Err(WorkloadIdentityError::JwksUnavailable);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_DOCUMENT_BYTES as u64)
    {
        return Err(WorkloadIdentityError::JwksUnavailable);
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WorkloadIdentityError::JwksUnavailable)?
    {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or(WorkloadIdentityError::JwksUnavailable)?;
        if next_len > MAX_JWKS_DOCUMENT_BYTES {
            return Err(WorkloadIdentityError::JwksUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    parse_jwks(&body)
}

fn parse_jwks(document: &[u8]) -> Result<JwkSet, WorkloadIdentityError> {
    if document.is_empty() || document.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(WorkloadIdentityError::JwksUnavailable);
    }
    let key_set: JwkSet =
        serde_json::from_slice(document).map_err(|_| WorkloadIdentityError::JwksUnavailable)?;
    if key_set.keys.is_empty() || key_set.keys.len() > MAX_JWKS_KEYS {
        return Err(WorkloadIdentityError::JwksUnavailable);
    }
    Ok(key_set)
}

fn select_decoding_key(
    key_set: &JwkSet,
    key_id: &str,
) -> Result<DecodingKey, WorkloadIdentityError> {
    let mut matches = key_set
        .keys
        .iter()
        .filter(|jwk| jwk.common.key_id.as_deref() == Some(key_id));
    let jwk = matches.next().ok_or(WorkloadIdentityError::UnknownKeyId)?;
    if matches.next().is_some() {
        return Err(WorkloadIdentityError::UnknownKeyId);
    }
    validate_selected_jwk(jwk, key_id)?;
    DecodingKey::from_jwk(jwk).map_err(|_| WorkloadIdentityError::JwksUnavailable)
}

fn validate_selected_jwk(jwk: &Jwk, key_id: &str) -> Result<(), WorkloadIdentityError> {
    if jwk.common.key_algorithm != Some(KeyAlgorithm::RS256)
        || !matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        || matches!(
            jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        )
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                operations.is_empty()
                    || operations
                        .iter()
                        .any(|operation| !matches!(operation, KeyOperations::Verify))
            })
    {
        return Err(WorkloadIdentityError::JwksAlgorithmMismatch);
    }

    let AlgorithmParameters::RSA(parameters) = &jwk.algorithm else {
        return Err(WorkloadIdentityError::JwksAlgorithmMismatch);
    };
    crate::capability::CapabilityVerificationKey::from_rsa_components(
        key_id.to_owned(),
        &parameters.n,
        &parameters.e,
    )
    .map(|_| ())
    .map_err(|_| WorkloadIdentityError::JwksUnavailable)
}

fn map_jwt_error(error: jsonwebtoken::errors::Error) -> WorkloadIdentityError {
    use jsonwebtoken::errors::ErrorKind;

    match error.kind() {
        ErrorKind::InvalidSignature => WorkloadIdentityError::InvalidSignature,
        ErrorKind::InvalidIssuer => WorkloadIdentityError::IssuerMismatch,
        ErrorKind::InvalidAudience => WorkloadIdentityError::AudienceMismatch,
        ErrorKind::ExpiredSignature => WorkloadIdentityError::Expired,
        ErrorKind::ImmatureSignature => WorkloadIdentityError::NotYetValid,
        ErrorKind::InvalidAlgorithm | ErrorKind::MissingAlgorithm => {
            WorkloadIdentityError::AlgorithmMismatch
        }
        _ => WorkloadIdentityError::TokenMalformed,
    }
}

fn unix_now() -> Result<u64, WorkloadIdentityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WorkloadIdentityError::ClockUnavailable)
}

//! OIDC discovery and authorization URL helpers.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use openidconnect::core::CoreProviderMetadata;
use openidconnect::{CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge};
use tokio::sync::Mutex;

/// Normalized provider metadata used by SunLit integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderConfig {
    /// Issuer URL.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL if provided by discovery metadata.
    pub token_endpoint: Option<String>,
    /// JWK set endpoint URL.
    pub jwks_uri: String,
}

/// Authorization URL response with generated PKCE verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationUrl {
    /// Fully built authorization URL including PKCE parameters.
    pub authorization_url: String,
    /// Random CSRF token for state validation.
    pub csrf_token: String,
    /// Random nonce for ID token validation.
    pub nonce: String,
    /// PKCE code verifier to store and use during token exchange.
    pub code_verifier: String,
}

/// Errors returned by [`OidcClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcError {
    /// Issuer URL must be HTTPS (unless explicit test override is enabled).
    InsecureIssuer,
    /// Issuer URL is syntactically invalid.
    InvalidIssuer,
    /// OIDC discovery endpoint could not be reached or parsed.
    DiscoveryUnreachable,
    /// Discovery result issuer does not match requested issuer.
    IssuerMismatch,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureIssuer => write!(f, "insecure_issuer"),
            Self::InvalidIssuer => write!(f, "invalid_issuer"),
            Self::DiscoveryUnreachable => write!(f, "discovery_unreachable"),
            Self::IssuerMismatch => write!(f, "issuer_mismatch"),
        }
    }
}

impl std::error::Error for OidcError {}

#[derive(Debug, Clone)]
struct CachedMetadata {
    expires_at: Instant,
    config: OidcProviderConfig,
}

/// Thin OIDC wrapper backed by `openidconnect` discovery.
pub struct OidcClient {
    cache_ttl: Duration,
    allow_insecure_http: bool,
    cache: Mutex<HashMap<String, CachedMetadata>>,
}

impl OidcClient {
    /// Creates a new OIDC client with metadata cache TTL in seconds.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::oidc::OidcClient;
    ///
    /// let client = OidcClient::new(300);
    /// let _ = client;
    /// ```
    #[must_use]
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            allow_insecure_http: false,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Enables non-HTTPS issuer URLs for test-only scenarios.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::oidc::OidcClient;
    ///
    /// let client = OidcClient::new(60).with_insecure_http_allowed_for_tests();
    /// let _ = client;
    /// ```
    #[must_use]
    pub fn with_insecure_http_allowed_for_tests(mut self) -> Self {
        self.allow_insecure_http = true;
        self
    }

    /// Discovers OIDC provider metadata and caches it for the configured TTL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "oidc")] {
    /// use secure_identity::oidc::OidcClient;
    ///
    /// async fn run() -> Result<(), secure_identity::oidc::OidcError> {
    ///     let client = OidcClient::new(300);
    ///     let _metadata = client.discover("https://accounts.example.com").await?;
    ///     Ok(())
    /// }
    /// # }
    /// ```
    pub async fn discover(&self, issuer: &str) -> Result<OidcProviderConfig, OidcError> {
        if !self.allow_insecure_http && !issuer.starts_with("https://") {
            return Err(OidcError::InsecureIssuer);
        }

        if let Some(hit) = self.cache.lock().await.get(issuer).cloned() {
            if hit.expires_at > Instant::now() {
                return Ok(hit.config);
            }
        }

        let discovered = discover_provider(issuer, self.allow_insecure_http).await?;
        self.cache.lock().await.insert(
            issuer.to_string(),
            CachedMetadata {
                expires_at: Instant::now() + self.cache_ttl,
                config: discovered.clone(),
            },
        );
        Ok(discovered)
    }

    /// Builds an authorization URL and always includes PKCE challenge parameters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "oidc")] {
    /// use secure_identity::oidc::OidcClient;
    ///
    /// async fn run() -> Result<(), secure_identity::oidc::OidcError> {
    ///     let client = OidcClient::new(300);
    ///     let _auth = client
    ///         .auth_url(
    ///             "https://accounts.example.com",
    ///             "client-id",
    ///             "https://app.example.com/callback",
    ///         )
    ///         .await?;
    ///     Ok(())
    /// }
    /// # }
    /// ```
    pub async fn auth_url(
        &self,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<AuthorizationUrl, OidcError> {
        let metadata = self.discover(issuer).await?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf = CsrfToken::new_random();
        let nonce = Nonce::new_random();

        let mut url = url::Url::parse(&metadata.authorization_endpoint)
            .map_err(|_| OidcError::DiscoveryUnreachable)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", csrf.secret())
            .append_pair("nonce", nonce.secret())
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", "S256");

        Ok(AuthorizationUrl {
            authorization_url: url.into(),
            csrf_token: csrf.secret().to_string(),
            nonce: nonce.secret().to_string(),
            code_verifier: pkce_verifier.secret().to_string(),
        })
    }
}

async fn discover_provider(
    issuer: &str,
    allow_insecure_http: bool,
) -> Result<OidcProviderConfig, OidcError> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| OidcError::DiscoveryUnreachable)?;

    if issuer.starts_with("http://") {
        if !allow_insecure_http {
            return Err(OidcError::InsecureIssuer);
        }

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        let value = http_client
            .get(url)
            .send()
            .await
            .map_err(|_| OidcError::DiscoveryUnreachable)?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| OidcError::DiscoveryUnreachable)?;

        return provider_config_from_value(issuer, value);
    }

    let issuer_url = IssuerUrl::new(issuer.to_string()).map_err(|_| OidcError::InvalidIssuer)?;

    let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("issuer") && msg.contains("mismatch") {
                OidcError::IssuerMismatch
            } else {
                OidcError::DiscoveryUnreachable
            }
        })?;

    let value = serde_json::to_value(&metadata).map_err(|_| OidcError::DiscoveryUnreachable)?;
    provider_config_from_value(issuer, value)
}

fn provider_config_from_value(
    issuer: &str,
    value: serde_json::Value,
) -> Result<OidcProviderConfig, OidcError> {
    let discovered_issuer = value
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .ok_or(OidcError::DiscoveryUnreachable)?;

    if discovered_issuer != issuer {
        return Err(OidcError::IssuerMismatch);
    }

    let authorization_endpoint = value
        .get("authorization_endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or(OidcError::DiscoveryUnreachable)?;
    let jwks_uri = value
        .get("jwks_uri")
        .and_then(serde_json::Value::as_str)
        .ok_or(OidcError::DiscoveryUnreachable)?;
    let token_endpoint = value
        .get("token_endpoint")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    Ok(OidcProviderConfig {
        issuer: discovered_issuer.to_string(),
        authorization_endpoint: authorization_endpoint.to_string(),
        token_endpoint,
        jwks_uri: jwks_uri.to_string(),
    })
}

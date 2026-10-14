//! JWKS (JSON Web Key Set) key store with TTL-based caching.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use tokio::sync::{Mutex, RwLock};

use crate::error::IdentityError;

/// A cached JWKS key entry.
#[derive(Clone)]
struct CachedKey {
    /// The algorithm, e.g. "RS256", "ES256".
    alg: String,
    /// The decoding key for signature verification.
    decoding_key: DecodingKey,
}

/// Internal cache state.
struct CacheState {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
    /// Last refresh triggered specifically by an unknown `kid`.
    ///
    /// Recorded before remote I/O so attacker-chosen key IDs cannot amplify an
    /// upstream outage into one JWKS request per invalid bearer.
    last_unknown_key_refresh_attempt: Option<Instant>,
}

/// Unknown-key misses are the normal signal for an issuer signing-key rotation,
/// but they are also attacker-controlled JWT header input. Permit an immediate
/// rotation refresh, then globally rate-limit further miss-driven refreshes.
const UNKNOWN_KEY_REFRESH_FLOOR: Duration = Duration::from_secs(30);

enum CacheLookup {
    Hit(DecodingKey),
    FreshMiss,
    ExpiredOrEmpty,
}

/// A JWKS key store that fetches and caches public keys from a JWKS endpoint.
///
/// Keys are cached with a configurable TTL. When the cache expires, the next
/// lookup triggers a refresh. If the endpoint is unavailable but the cache is warm,
/// stale cached keys are used with a warning logged.
pub struct JwksKeyStore {
    url: String,
    ttl: Duration,
    allow_insecure_loopback: bool,
    cache: Arc<RwLock<CacheState>>,
    /// Single-flight guard for cache refreshes. Without this, a key rotation can
    /// make every concurrent request fetch the same JWKS document.
    refresh: Arc<Mutex<()>>,
}

impl JwksKeyStore {
    /// Creates a new [`JwksKeyStore`] with the given endpoint URL and cache TTL.
    #[must_use]
    pub fn new(url: &str, ttl: Duration) -> Self {
        Self {
            url: url.to_owned(),
            ttl,
            allow_insecure_loopback: false,
            cache: Arc::new(RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
                last_unknown_key_refresh_attempt: None,
            })),
            refresh: Arc::new(Mutex::new(())),
        }
    }

    /// Creates an explicitly insecure store for numeric loopback HTTP fixtures.
    /// Available only with `dev`; never use for production issuer keys.
    #[cfg(feature = "dev")]
    #[must_use]
    pub fn new_insecure_loopback_for_testing(url: &str, ttl: Duration) -> Self {
        let mut store = Self::new(url, ttl);
        store.allow_insecure_loopback = true;
        store
    }

    /// Fetches the JWKS from the configured endpoint and updates the cache.
    ///
    /// # Errors
    /// Returns `IdentityError::ProviderUnavailable` if the endpoint cannot be reached.
    pub async fn fetch(&self) -> Result<(), IdentityError> {
        let parsed = url::Url::parse(&self.url).map_err(|_| IdentityError::ProviderUnavailable)?;
        let insecure = self.allow_insecure_loopback
            && parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
        if (!insecure && parsed.scheme() != "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host_str().is_none()
            || parsed.fragment().is_some()
        {
            return Err(IdentityError::ProviderUnavailable);
        }
        let jwks = fetch_jwks_http(&self.url, insecure).await?;
        let keys = parse_jwks(&jwks)?;

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// Returns the [`DecodingKey`] for the given `kid`, fetching from the endpoint if
    /// the cache is expired or empty. A `kid` miss in an otherwise fresh cache forces
    /// one bounded refresh so issuer signing-key rotation does not reject newly issued
    /// tokens until the ordinary TTL expires.
    pub async fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        if let CacheLookup::Hit(key) = self.cache_lookup(kid).await {
            return Some(key);
        }

        // Serialize refreshes, then re-check: another request may have loaded the
        // rotated key while this request waited for the guard.
        let _refresh_guard = self.refresh.lock().await;
        let force_for_unknown_key = match self.cache_lookup(kid).await {
            CacheLookup::Hit(key) => return Some(key),
            CacheLookup::FreshMiss => true,
            CacheLookup::ExpiredOrEmpty => false,
        };

        if force_for_unknown_key {
            let mut cache = self.cache.write().await;
            if cache
                .last_unknown_key_refresh_attempt
                .is_some_and(|attempted_at| attempted_at.elapsed() < UNKNOWN_KEY_REFRESH_FLOOR)
            {
                return None;
            }
            // Consume the rate-limit window before remote I/O. A failed refresh is
            // still an attempt; otherwise an attacker can hammer an unavailable issuer.
            cache.last_unknown_key_refresh_attempt = Some(Instant::now());
        }

        if let Err(e) = self.fetch().await {
            tracing::warn!("JWKS refresh failed: {e}, using stale cache if available");
            // Fall back to stale cache
            let cache = self.cache.read().await;
            return cache.keys.get(kid).map(|k| k.decoding_key.clone());
        }

        let cache = self.cache.read().await;
        cache.keys.get(kid).map(|k| k.decoding_key.clone())
    }

    async fn cache_lookup(&self, kid: &str) -> CacheLookup {
        let cache = self.cache.read().await;
        match cache.fetched_at {
            Some(fetched_at) if fetched_at.elapsed() < self.ttl => cache
                .keys
                .get(kid)
                .map(|key| CacheLookup::Hit(key.decoding_key.clone()))
                .unwrap_or(CacheLookup::FreshMiss),
            _ => CacheLookup::ExpiredOrEmpty,
        }
    }

    /// Returns the algorithm string for the given `kid`, if cached.
    pub async fn get_algorithm(&self, kid: &str) -> Option<String> {
        let cache = self.cache.read().await;
        cache.keys.get(kid).map(|k| k.alg.clone())
    }

    /// Returns true if the cache has keys and is within TTL.
    pub async fn is_cache_valid(&self) -> bool {
        let cache = self.cache.read().await;
        if let Some(fetched_at) = cache.fetched_at {
            fetched_at.elapsed() < self.ttl && !cache.keys.is_empty()
        } else {
            false
        }
    }
}

/// JWKS JSON structures for parsing.
#[derive(serde::Deserialize)]
struct JwksDocument {
    keys: Vec<JwkKey>,
}

#[derive(serde::Deserialize)]
struct JwkKey {
    #[serde(default)]
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    crv: Option<String>,
}

/// Production JWKS fetch over **HTTPS** via reqwest (rustls-tls). Enabled by the `jwks` feature.
///
/// Only HTTPS is accepted for production stores. Redirects are disabled and the
/// response is capped at 1 MiB. Build with `jwks` for production key retrieval.
#[cfg(feature = "jwks")]
async fn fetch_jwks_http(url: &str, insecure: bool) -> Result<String, IdentityError> {
    let client = reqwest::Client::builder()
        .https_only(!insecure)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| IdentityError::ProviderUnavailable)?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| IdentityError::ProviderUnavailable)?;
    if !resp.status().is_success() {
        return Err(IdentityError::ProviderUnavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| IdentityError::ProviderUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > 1_048_576 {
            return Err(IdentityError::ProviderUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| IdentityError::ProviderUnavailable)
}

/// Bounded numeric-loopback HTTP transport for explicit `dev` fixtures.
/// Production stores fail closed without the `jwks` feature.
#[cfg(not(feature = "jwks"))]
async fn fetch_jwks_http(url: &str, insecure: bool) -> Result<String, IdentityError> {
    // Without `jwks`, production fetches fail closed. Only the explicit dev
    // constructor can reach this numeric-loopback fixture transport.
    if !insecure {
        return Err(IdentityError::ProviderUnavailable);
    }
    let parsed = url::Url::parse(url).map_err(|_| IdentityError::ProviderUnavailable)?;
    let host = parsed
        .host_str()
        .ok_or(IdentityError::ProviderUnavailable)?;
    let ip = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .map_err(|_| IdentityError::ProviderUnavailable)?;
    let addr = std::net::SocketAddr::new(ip, parsed.port().unwrap_or(80));
    tokio::time::timeout(Duration::from_secs(10), async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;
        let path = &parsed[url::Position::BeforePath..url::Position::AfterQuery];
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;
        let mut response = Vec::new();
        stream
            .take(1_048_577)
            .read_to_end(&mut response)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;
        if response.len() > 1_048_576 {
            return Err(IdentityError::ProviderUnavailable);
        }
        let response =
            String::from_utf8(response).map_err(|_| IdentityError::ProviderUnavailable)?;
        if !response.starts_with("HTTP/1.1 200 ") && !response.starts_with("HTTP/1.0 200 ") {
            return Err(IdentityError::ProviderUnavailable);
        }
        let body = response
            .find("\r\n\r\n")
            .map(|i| &response[i + 4..])
            .ok_or(IdentityError::ProviderUnavailable)?;
        Ok(body.to_owned())
    })
    .await
    .map_err(|_| IdentityError::ProviderUnavailable)?
}

/// Parses a JWKS JSON document into a map of kid → CachedKey.
fn parse_jwks(json: &str) -> Result<HashMap<String, CachedKey>, IdentityError> {
    let doc: JwksDocument =
        serde_json::from_str(json).map_err(|_| IdentityError::TokenMalformed)?;

    let mut keys = HashMap::new();
    for jwk in &doc.keys {
        let kid = match &jwk.kid {
            Some(k) => k.clone(),
            None => continue, // skip keys without kid
        };
        let alg = jwk.alg.clone().unwrap_or_default();

        let decoding_key = match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_deref().ok_or(IdentityError::TokenMalformed)?;
                let e = jwk.e.as_deref().ok_or(IdentityError::TokenMalformed)?;
                DecodingKey::from_rsa_components(n, e).map_err(|_| IdentityError::TokenMalformed)?
            }
            "EC" => {
                let x = jwk.x.as_deref().ok_or(IdentityError::TokenMalformed)?;
                let y = jwk.y.as_deref().ok_or(IdentityError::TokenMalformed)?;
                DecodingKey::from_ec_components(x, y).map_err(|_| IdentityError::TokenMalformed)?
            }
            _ => continue, // skip unknown key types
        };

        keys.insert(kid, CachedKey { alg, decoding_key });
    }

    Ok(keys)
}

#[cfg(all(test, feature = "jwks"))]
mod jwks_https_proof {
    use super::*;

    /// Regression proof for the HTTPS JWKS fetch. The feature-less stub plaintext-TCP'd to :443
    /// and read back TLS-handshake bytes (never JSON), so zero keys loaded and every OIDC/Cognito
    /// token failed validation. With the `jwks` feature this fetches the REAL live Cognito JWKS
    /// over HTTPS and confirms keys are parsed + cached. `#[ignore]` — makes a live network call.
    #[tokio::test]
    #[ignore = "network: hits the live Cognito JWKS endpoint"]
    async fn fetches_live_cognito_jwks_over_https() {
        let url =
            "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_a5ROqvMOW/.well-known/jwks.json";
        let store = JwksKeyStore::new(url, Duration::from_secs(3600));
        store
            .fetch()
            .await
            .expect("HTTPS JWKS fetch+parse must succeed with the `jwks` feature");
        assert!(
            store.is_cache_valid().await,
            "cache must hold parsed keys after a successful HTTPS fetch"
        );
    }
}

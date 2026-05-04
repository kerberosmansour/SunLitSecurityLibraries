//! JWKS (JSON Web Key Set) key store with TTL-based caching.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use tokio::sync::RwLock;

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
}

/// A JWKS key store that fetches and caches public keys from a JWKS endpoint.
///
/// Keys are cached with a configurable TTL. When the cache expires, the next
/// lookup triggers a refresh. If the endpoint is unavailable but the cache is warm,
/// stale cached keys are used with a warning logged.
pub struct JwksKeyStore {
    url: String,
    ttl: Duration,
    cache: Arc<RwLock<CacheState>>,
}

impl JwksKeyStore {
    /// Creates a new [`JwksKeyStore`] with the given endpoint URL and cache TTL.
    #[must_use]
    pub fn new(url: &str, ttl: Duration) -> Self {
        Self {
            url: url.to_owned(),
            ttl,
            cache: Arc::new(RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
            })),
        }
    }

    /// Fetches the JWKS from the configured endpoint and updates the cache.
    ///
    /// # Errors
    /// Returns `IdentityError::ProviderUnavailable` if the endpoint cannot be reached.
    pub async fn fetch(&self) -> Result<(), IdentityError> {
        let jwks = fetch_jwks_http(&self.url).await?;
        let keys = parse_jwks(&jwks)?;

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// Returns the [`DecodingKey`] for the given `kid`, fetching from the endpoint if
    /// the cache is expired or empty.
    pub async fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(fetched_at) = cache.fetched_at {
                if fetched_at.elapsed() < self.ttl {
                    return cache.keys.get(kid).map(|k| k.decoding_key.clone());
                }
            }
        }

        // Cache expired or empty — try to refresh
        if let Err(e) = self.fetch().await {
            tracing::warn!("JWKS refresh failed: {e}, using stale cache if available");
            // Fall back to stale cache
            let cache = self.cache.read().await;
            return cache.keys.get(kid).map(|k| k.decoding_key.clone());
        }

        let cache = self.cache.read().await;
        cache.keys.get(kid).map(|k| k.decoding_key.clone())
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

/// Fetches JWKS JSON from a URL using a simple HTTP GET.
async fn fetch_jwks_http(url: &str) -> Result<String, IdentityError> {
    // Use a simple TCP-based HTTP client to avoid requiring reqwest at compile time.
    // For production use with the `jwks` feature, this would use reqwest.
    // This implementation handles http:// URLs for testing and is intentionally simple.
    let url_parsed = url::Url::parse(url).map_err(|_| IdentityError::ProviderUnavailable)?;

    let host = url_parsed
        .host_str()
        .ok_or(IdentityError::ProviderUnavailable)?;
    let port = url_parsed.port().unwrap_or(match url_parsed.scheme() {
        "https" => 443,
        _ => 80,
    });
    let path = url_parsed.path();

    let addr = format!("{host}:{port}");
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|_| IdentityError::ProviderUnavailable)?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| IdentityError::ProviderUnavailable)?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|_| IdentityError::ProviderUnavailable)?;

    let response_str = String::from_utf8_lossy(&response);
    // Find body after \r\n\r\n
    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .ok_or(IdentityError::ProviderUnavailable)?;
    Ok(response_str[body_start..].to_string())
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

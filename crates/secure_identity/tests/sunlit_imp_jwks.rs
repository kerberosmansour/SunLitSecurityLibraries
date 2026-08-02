//! BDD tests for JWKS key store.

use std::io::{Read, Write};
use std::net::TcpListener;

use secure_identity::jwks::JwksKeyStore;

/// Start a mock HTTP server returning the given body for all requests.
fn start_mock_server(
    response_body: &str,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr").to_string();
    let body = response_body.to_owned();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming().take(10) {
            if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Ok(mut stream) = stream {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    });

    // Give the server thread a moment to start
    std::thread::sleep(std::time::Duration::from_millis(50));
    (addr, stop)
}

/// Start a mock endpoint whose response advances once per request, then holds
/// the final document. Returns a request counter so rotation and rate-limiting
/// behavior is observable without reaching a real identity provider.
fn start_sequence_mock_server(
    response_bodies: Vec<String>,
) -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    assert!(!response_bodies.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr").to_string();
    let request_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let request_count_clone = request_count.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming().take(10) {
            if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Ok(mut stream) = stream {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let index = request_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = &response_bodies[index.min(response_bodies.len() - 1)];
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(50));
    (addr, request_count, stop)
}

// Minimal JWKS document with one RSA key (modulus n, exponent e from the test RSA key)
// These are extracted from the test RSA public key used in sunlit_imp_asymmetric_jwt.rs
fn test_jwks_json() -> String {
    // RSA public key components extracted from the test PEM
    // Using base64url encoding
    r#"{
        "keys": [{
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "ty6bGXbajYywwukqPYf0W2AxQiCPiwuZfNRDFWyP6Ge4hyv-YI3KsTGCmd2tH97F13tujrkUvpSlrI0ouIxeAMw4AswldY-oKBef69Aod54jhhPcDumkbGlGneu5W0ibQUaA8-eAZfHDqNLNHtm7p1QXD1_yfn3VPtB2BsDu-fdMfEWTqroanul0xQjqFUYb9ksdae1_a9bBztRyPL6yZb6n7w5Ukewv6Wi3O7LYLcqqp4rIr37_wQn7xY-8otdwDk47P7qpGlye04zphp8q8INVo4ZossAjmxkQcl0mJqTSkXFA2XdtcC-qoMgCJZVQFAmY3QuO-DL-MFSVLnbxdw",
            "e": "AQAB"
        }]
    }"#.to_string()
}

fn test_jwks_json_with_kid(kid: &str) -> String {
    test_jwks_json().replace("test-key-1", kid)
}

// --- Feature: JWKS key store ---

#[tokio::test]
async fn scenario_fetch_keys_from_endpoint() {
    // Given: JWKS endpoint returns valid keys
    let jwks_json = test_jwks_json();
    let (addr, stop) = start_mock_server(&jwks_json);
    let url = format!("http://{addr}/.well-known/jwks.json");

    // When: JwksKeyStore::fetch(url)
    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    let result = store.fetch().await;

    // Then: keys cached
    assert!(result.is_ok(), "Should fetch JWKS keys: {:?}", result.err());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_cache_hit_avoids_refetch() {
    // Given: keys cached within TTL
    let jwks_json = test_jwks_json();
    let (addr, stop) = start_mock_server(&jwks_json);
    let url = format!("http://{addr}/.well-known/jwks.json");

    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    store.fetch().await.expect("first fetch");

    // When: get_key (should use cache)
    let result = store.get_key("test-key-1").await;

    // Then: returns cached key
    assert!(result.is_some(), "Should find cached key");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_endpoint_unavailable_cold_start() {
    // Given: JWKS endpoint down, cold start (port 1 won't connect)
    let url = "http://127.0.0.1:1/.well-known/jwks.json";

    // When: fetch
    let store = JwksKeyStore::new(url, std::time::Duration::from_secs(300));
    let result = store.fetch().await;

    // Then: error
    assert!(result.is_err(), "Should fail on unreachable endpoint");
}

#[tokio::test]
async fn scenario_unknown_kid_returns_none() {
    // Given: JWKS with known kid
    let jwks_json = test_jwks_json();
    let (addr, stop) = start_mock_server(&jwks_json);
    let url = format!("http://{addr}/.well-known/jwks.json");

    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    store.fetch().await.expect("fetch");

    // When: get_key with unknown kid
    let result = store.get_key("nonexistent-kid").await;

    // Then: None
    assert!(result.is_none(), "Unknown kid should return None");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_unknown_kid_forces_bounded_refresh_for_rotation() {
    // Given: the cache is fresh with the old issuer key, while the next JWKS
    // response contains the newly rotated key.
    let (addr, request_count, stop) = start_sequence_mock_server(vec![
        test_jwks_json_with_kid("old-key"),
        test_jwks_json_with_kid("rotated-key"),
    ]);
    let url = format!("http://{addr}/.well-known/jwks.json");
    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    assert!(store.get_key("old-key").await.is_some());

    // When: a token signed by the rotated key arrives before the five-minute
    // cache TTL expires.
    let rotated = store.get_key("rotated-key").await;

    // Then: the miss forces one refresh and the new token can validate now,
    // rather than receiving a false 401 until TTL expiry.
    assert!(
        rotated.is_some(),
        "rotated key must be loaded on a fresh-cache miss"
    );
    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one cold fetch plus one bounded rotation refresh"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_unknown_kid_refresh_is_globally_rate_limited() {
    // Given: a fresh cache that will never contain attacker-chosen key IDs.
    let (addr, request_count, stop) =
        start_sequence_mock_server(vec![test_jwks_json(), test_jwks_json()]);
    let url = format!("http://{addr}/.well-known/jwks.json");
    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    assert!(store.get_key("test-key-1").await.is_some());

    // The first miss may check for rotation; a second distinct hostile `kid`
    // must not amplify that into another upstream request.
    assert!(store.get_key("attacker-key-a").await.is_none());
    assert!(store.get_key("attacker-key-b").await.is_none());
    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "unknown-key refreshes must be globally rate-limited"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_cache_valid_after_fetch() {
    // Given: fresh fetch
    let jwks_json = test_jwks_json();
    let (addr, stop) = start_mock_server(&jwks_json);
    let url = format!("http://{addr}/.well-known/jwks.json");

    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    store.fetch().await.expect("fetch");

    // When: check cache validity
    let valid = store.is_cache_valid().await;

    // Then: valid
    assert!(valid, "Cache should be valid after fetch");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test]
async fn scenario_get_algorithm_returns_correct_alg() {
    // Given: JWKS with RS256 key
    let jwks_json = test_jwks_json();
    let (addr, stop) = start_mock_server(&jwks_json);
    let url = format!("http://{addr}/.well-known/jwks.json");

    let store = JwksKeyStore::new(&url, std::time::Duration::from_secs(300));
    store.fetch().await.expect("fetch");

    // When: get algorithm for known kid
    let alg = store.get_algorithm("test-key-1").await;

    // Then: RS256
    assert_eq!(alg.as_deref(), Some("RS256"));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

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

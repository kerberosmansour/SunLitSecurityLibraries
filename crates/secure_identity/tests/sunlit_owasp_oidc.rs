//! BDD tests for Milestone 24 OIDC support.

#![cfg(feature = "oidc")]

use secure_identity::oidc::{OidcClient, OidcError};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn discovery_body(issuer: &str) -> String {
    format!(
        "{{\"issuer\":\"{issuer}\",\"authorization_endpoint\":\"{issuer}/authorize\",\"token_endpoint\":\"{issuer}/token\",\"jwks_uri\":\"{issuer}/jwks\",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}}"
    )
}

async fn spawn_discovery_server(counter: Arc<AtomicUsize>, mismatch: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local addr");
    let issuer = format!("http://{addr}");
    let body = if mismatch {
        discovery_body("http://different-issuer")
    } else {
        discovery_body(&issuer)
    };

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    issuer
}

#[tokio::test]
async fn scenario_non_https_issuer_rejected_by_default() {
    let client = OidcClient::new(60);
    let err = client
        .discover("http://issuer.example")
        .await
        .expect_err("non-https issuer must be rejected");

    assert!(matches!(err, OidcError::InsecureIssuer));
}

#[tokio::test]
async fn scenario_discovery_document_fetched_and_cached() {
    let counter = Arc::new(AtomicUsize::new(0));
    let issuer = spawn_discovery_server(Arc::clone(&counter), false).await;

    let client = OidcClient::new(60).with_insecure_http_allowed_for_tests();
    let first = client.discover(&issuer).await.expect("first discovery");
    let second = client.discover(&issuer).await.expect("second discovery");

    assert_eq!(first.issuer, second.issuer);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "second call should be cache hit"
    );
}

#[tokio::test]
async fn scenario_issuer_mismatch_rejected() {
    let counter = Arc::new(AtomicUsize::new(0));
    let issuer = spawn_discovery_server(Arc::clone(&counter), true).await;

    let client = OidcClient::new(60).with_insecure_http_allowed_for_tests();
    let err = client
        .discover(&issuer)
        .await
        .expect_err("issuer mismatch should fail");

    assert!(matches!(err, OidcError::IssuerMismatch));
}

#[tokio::test]
async fn scenario_network_failure_handled() {
    let client = OidcClient::new(60).with_insecure_http_allowed_for_tests();
    let err = client
        .discover("http://127.0.0.1:9")
        .await
        .expect_err("unreachable discovery endpoint must fail");

    assert!(matches!(err, OidcError::DiscoveryUnreachable));
}

#[tokio::test]
async fn scenario_pkce_included_in_auth_url() {
    let counter = Arc::new(AtomicUsize::new(0));
    let issuer = spawn_discovery_server(Arc::clone(&counter), false).await;

    let client = OidcClient::new(60).with_insecure_http_allowed_for_tests();
    let auth = client
        .auth_url(&issuer, "sunlit-client", "https://app.example/callback")
        .await
        .expect("auth url should build");

    assert!(auth.authorization_url.contains("code_challenge="));
    assert!(auth.code_verifier.len() >= 43);
}

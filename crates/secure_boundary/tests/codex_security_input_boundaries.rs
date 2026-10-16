#![cfg(feature = "axum")]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode},
    routing::post,
    Extension, Router,
};
use futures_util::stream;
use secure_boundary::{
    extract::SecureJson,
    limits::RequestLimits,
    safe_types::SafeUrl,
    validate::{SecureValidate, ValidationContext},
    xml::SecureXml,
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Payload {
    value: String,
}

impl SecureValidate for Payload {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

fn counted_body(polls: Arc<AtomicUsize>) -> Body {
    let chunks = vec![Bytes::from_static(b"xxxx"); 128];
    let body_stream = stream::iter(chunks.into_iter().map(move |chunk| {
        polls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(chunk)
    }));
    Body::from_stream(body_stream)
}

async fn send_counted(path: &str, content_type: &str, xml: bool) -> (StatusCode, usize) {
    let polls = Arc::new(AtomicUsize::new(0));
    let app = if xml {
        Router::new().route(
            path,
            post(|payload: SecureXml<Payload>| async move { payload.into_inner().value }),
        )
    } else {
        Router::new().route(
            path,
            post(|payload: SecureJson<Payload>| async move { payload.into_inner().value }),
        )
    }
    .layer(Extension(RequestLimits::new().with_max_body_bytes(8)));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", content_type)
                .body(counted_body(Arc::clone(&polls)))
                .expect("request"),
        )
        .await
        .expect("router response");

    (response.status(), polls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn json_limit_stops_stream_before_collecting_the_complete_body() {
    let (status, polls) = send_counted("/json", "application/json", false).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        polls <= 3,
        "collector read past the limit plus one rejecting frame: {polls} chunks"
    );
}

#[tokio::test]
async fn xml_honors_request_limit_and_stops_stream_before_complete_collection() {
    let (status, polls) = send_counted("/xml", "application/xml", true).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        polls <= 3,
        "collector read past the limit plus one rejecting frame: {polls} chunks"
    );
}

#[test]
fn safe_url_rejects_numeric_and_backslash_parser_differentials() {
    for value in [
        "http://2130706433/",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://0x7f.0.0.1/",
        "http://127.0.0.1./",
        "http://127.0.0.1\\@example.com/",
        "http://example.com\\127.0.0.1/",
    ] {
        assert!(
            SafeUrl::try_from(value).is_err(),
            "client-normalized protected destination must be rejected: {value}"
        );
    }
}

#[test]
fn safe_url_rejects_credentials_and_fragments() {
    for value in [
        "https://user@example.com/path",
        "https://user:secret@example.com/path",
        "https://example.com/path#fragment",
    ] {
        assert!(SafeUrl::try_from(value).is_err(), "must reject {value}");
    }
}

#[test]
fn safe_url_returns_the_canonical_value_that_was_classified() {
    let safe = SafeUrl::try_from("HTTP://EXAMPLE.COM:80/a/../b").expect("public URL");
    assert_eq!(safe.as_inner(), "http://example.com/b");
}

#[test]
fn safe_url_reuses_the_policy_for_resolved_addresses() {
    assert!(SafeUrl::validate_resolved_ip("127.0.0.1".parse().expect("IP")).is_err());
    assert!(SafeUrl::validate_resolved_ip("169.254.169.254".parse().expect("IP")).is_err());
    assert!(SafeUrl::validate_resolved_ip("8.8.8.8".parse().expect("IP")).is_ok());
}

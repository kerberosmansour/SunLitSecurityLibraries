//! End-to-end runtime validation for sunlit-owasp Milestone 22.

use security_core::severity::SecuritySeverity;
use security_events::correlation::with_parent;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::hmac::HmacEventSigner;
use security_events::kind::EventKind;
use security_events::sink::{FileSink, InMemorySink, SecuritySink};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

fn unique_test_dir(prefix: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-tmp")
        .join(format!("{prefix}-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("test directory should be created");
    dir
}

#[test]
fn test_hmac_tamper_detected() {
    let signer = HmacEventSigner::new("runtime-key").expect("valid key should be accepted");
    let mut event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::Critical,
        EventOutcome::Blocked,
    );
    signer
        .sign_event(&mut event)
        .expect("signing should succeed");

    event.actor = Some("mallory@example.com".to_string());

    assert!(!signer
        .verify_event(&event)
        .expect("verification should complete"));
}

#[test]
fn test_file_sink_writes_events() {
    let log_dir = unique_test_dir("security-events-e2e");
    let log_path = log_dir.join("audit.jsonl");
    let sink = FileSink::new(&log_path).expect("file sink should be created");
    let event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );

    sink.try_write_event(&event).expect("write should succeed");

    let contents = fs::read_to_string(&log_path).expect("log file should exist");
    assert!(contents.contains("AdminAction"));

    let _ = fs::remove_dir_all(&log_dir);
}

#[test]
fn test_event_correlation_roundtrip() {
    let parent = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    let child = with_parent(
        SecurityEvent::new(
            EventKind::AuthzDeny,
            SecuritySeverity::High,
            EventOutcome::Blocked,
        ),
        parent.event_id,
    );

    assert_eq!(child.parent_event_id, Some(parent.event_id));
}

#[test]
fn test_existing_sinks_still_work() {
    let sink = InMemorySink::new();
    let event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Medium,
        EventOutcome::Failure,
    );

    sink.write_event(&event);

    assert_eq!(sink.events().len(), 1);
}

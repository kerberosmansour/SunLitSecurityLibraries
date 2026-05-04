//! BDD tests for the new file and batching sinks.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::{BatchingSink, FileSink, InMemorySink, SecuritySink};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn unique_test_dir(prefix: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-tmp")
        .join(format!("{prefix}-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("test directory should be created");
    dir
}

fn temp_log_path(prefix: &str) -> PathBuf {
    unique_test_dir(prefix).join("audit.jsonl")
}

#[test]
fn events_written_to_file() {
    // Given: a file sink pointing at a temp file
    let log_path = temp_log_path("security-events");
    let cleanup_dir = log_path
        .parent()
        .expect("temp log path should have a parent")
        .to_path_buf();
    let sink = FileSink::new(&log_path).expect("file sink should be created");
    let event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );

    // When: several events are written
    sink.try_write_event(&event)
        .expect("first write should succeed");
    sink.try_write_event(&event)
        .expect("second write should succeed");
    sink.try_write_event(&event)
        .expect("third write should succeed");

    // Then: the file contains one JSON event per line
    let contents = fs::read_to_string(&log_path).expect("log file should exist");
    assert_eq!(contents.lines().count(), 3);

    let _ = fs::remove_dir_all(cleanup_dir);
}

#[test]
fn file_rotates_on_size_limit() {
    // Given: a file sink with a tiny rotation threshold
    let log_path = temp_log_path("security-events-rotate");
    let cleanup_dir = log_path
        .parent()
        .expect("temp log path should have a parent")
        .to_path_buf();
    let sink = FileSink::with_rotation(&log_path, 200).expect("file sink should be created");
    let mut event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::High,
        EventOutcome::Blocked,
    );
    event.resource = Some("x".repeat(400));

    // When: enough data is written to exceed the limit
    sink.try_write_event(&event)
        .expect("first write should succeed");
    sink.try_write_event(&event)
        .expect("second write should succeed");

    // Then: a rotated log file exists beside the active file
    let parent = log_path.parent().expect("temp file should have a parent");
    let rotated_count = fs::read_dir(parent)
        .expect("directory should be readable")
        .filter_map(Result::ok)
        .count();
    assert!(rotated_count >= 2, "expected active + rotated log files");

    let _ = fs::remove_dir_all(cleanup_dir);
}

#[test]
fn directory_created_if_missing() {
    // Given: a nested path that does not exist yet
    let base_dir = unique_test_dir("security-events-dir");
    let log_path = base_dir.join("nested/audit.jsonl");

    // When: the file sink is created
    let sink = FileSink::new(&log_path).expect("missing directories should be created");
    sink.try_write_event(&SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    ))
    .expect("write should succeed");

    // Then: the directory hierarchy exists on disk
    assert!(log_path.exists());

    let _ = fs::remove_dir_all(base_dir);
}

#[test]
fn batching_sink_flushes_to_inner_sink() {
    // Given: a batching sink wrapped around an in-memory sink
    let inner = Arc::new(InMemorySink::new());
    let batcher = BatchingSink::new(inner.clone(), 2, Duration::from_millis(25));
    let first = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Medium,
        EventOutcome::Failure,
    );
    let second = SecurityEvent::new(
        EventKind::AuthzDeny,
        SecuritySeverity::Medium,
        EventOutcome::Blocked,
    );

    // When: events are queued and flushed
    batcher.write_event(&first);
    batcher.write_event(&second);
    batcher.flush().expect("flush should succeed");

    // Then: the inner sink receives the batched events
    assert_eq!(inner.events().len(), 2);
}

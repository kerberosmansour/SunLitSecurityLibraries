//! BDD acceptance tests for the panic boundary.
//!
//! Feature: Panic boundary
//! Proves that `PanicSafeLayer` catches panics and returns a safe 500 response
//! without crashing the process.

use secure_errors::panic::{catch_panic_to_safe_response, PanicSafeLayer};

// ---------------------------------------------------------------------------
// Scenario: Panic caught at boundary
// ---------------------------------------------------------------------------
#[test]
fn panic_caught_at_boundary() {
    let result = catch_panic_to_safe_response(|| {
        panic!("unexpected state");
    });
    let (status, body) = result;
    assert_eq!(status, 500);
    let json: serde_json::Value = serde_json::from_str(&body).expect("must be valid JSON");
    assert_eq!(json["code"], "internal_error");
    // Panic message must not appear in body
    assert!(
        !body.contains("unexpected state"),
        "panic message must not leak"
    );
}

// ---------------------------------------------------------------------------
// Scenario: Panic does not crash service — process still responds normally
// ---------------------------------------------------------------------------
#[test]
fn panic_does_not_crash_service() {
    // First call panics
    let _ = catch_panic_to_safe_response(|| {
        panic!("crash me");
    });
    // Second call succeeds normally — service survived
    let result = catch_panic_to_safe_response(|| {
        // normal processing
        "ok"
    });
    // No panic means result is Ok — but our helper returns (200, "ok") or similar.
    // We just verify the process is still alive and another call returns something.
    let (status, _body) = result;
    assert_eq!(
        status, 200,
        "service must still respond normally after a panic"
    );
}

// ---------------------------------------------------------------------------
// PanicSafeLayer satisfies Clone + Send + Sync
// ---------------------------------------------------------------------------
#[test]
fn panic_safe_layer_is_clone_send_sync() {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<PanicSafeLayer>();
}

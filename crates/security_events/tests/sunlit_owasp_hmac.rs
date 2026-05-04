//! BDD tests for OWASP-aligned HMAC signing and event correlation.

use security_core::severity::SecuritySeverity;
use security_events::correlation::{filter_by_parent, with_parent};
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::hmac::{HmacError, HmacEventSigner};
use security_events::kind::EventKind;

#[test]
fn event_signed_on_emit() {
    // Given: an unsigned event and a configured HMAC signer
    let mut event = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::High,
        EventOutcome::Success,
    );
    let signer =
        HmacEventSigner::new("milestone-22-key").expect("non-empty key should be accepted");

    // When: the event is signed
    let signature = signer
        .sign_event(&mut event)
        .expect("signing should succeed");

    // Then: the event carries an HMAC and verifies successfully
    assert_eq!(event.hmac.as_deref(), Some(signature.as_str()));
    assert!(signer
        .verify_event(&event)
        .expect("signed event should verify"));
}

#[test]
fn tampered_event_detected() {
    // Given: a signed event
    let mut event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Critical,
        EventOutcome::Failure,
    );
    event.actor = Some("alice@example.com".to_string());
    let signer =
        HmacEventSigner::new("milestone-22-key").expect("non-empty key should be accepted");
    signer
        .sign_event(&mut event)
        .expect("signing should succeed");

    // When: a field is modified after signing
    event.resource = Some("admin-panel".to_string());

    // Then: verification fails
    assert!(!signer
        .verify_event(&event)
        .expect("verification should complete"));
}

#[test]
fn unsigned_event_detected() {
    // Given: an unsigned event
    let event = SecurityEvent::new(
        EventKind::BoundaryViolation,
        SecuritySeverity::High,
        EventOutcome::Blocked,
    );
    let signer =
        HmacEventSigner::new("milestone-22-key").expect("non-empty key should be accepted");

    // When / Then: verification reports the missing signature
    assert!(matches!(
        signer.verify_event(&event),
        Err(HmacError::MissingHmac)
    ));
}

#[test]
fn empty_hmac_key_rejected() {
    // Given / When: constructing a signer with an empty key
    let result = HmacEventSigner::new("");

    // Then: it fails securely
    assert!(matches!(result, Err(HmacError::MissingHmacKey)));
}

#[test]
fn parent_event_linked_and_queryable() {
    // Given: a root event and two child events
    let parent = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    let child_a = with_parent(
        SecurityEvent::new(
            EventKind::AuthzDeny,
            SecuritySeverity::Medium,
            EventOutcome::Blocked,
        ),
        parent.event_id,
    );
    let child_b = with_parent(
        SecurityEvent::new(
            EventKind::CrossTenantAttempt,
            SecuritySeverity::Critical,
            EventOutcome::Blocked,
        ),
        parent.event_id,
    );

    // When: querying by the parent correlation id
    let events = vec![parent.clone(), child_a.clone(), child_b.clone()];
    let related = filter_by_parent(&events, parent.event_id);

    // Then: only the linked child events are returned
    assert_eq!(child_a.parent_event_id, Some(parent.event_id));
    assert_eq!(child_b.parent_event_id, Some(parent.event_id));
    assert_eq!(related.len(), 2);
}

#[test]
fn different_events_produce_different_hmacs() {
    // Given: two distinct events
    let mut first = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::Medium,
        EventOutcome::Failure,
    );
    let mut second = SecurityEvent::new(
        EventKind::AdminAction,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    let signer =
        HmacEventSigner::new("milestone-22-key").expect("non-empty key should be accepted");

    // When: both are signed
    let first_sig = signer
        .sign_event(&mut first)
        .expect("signing should succeed");
    let second_sig = signer
        .sign_event(&mut second)
        .expect("signing should succeed");

    // Then: the per-event HMACs differ
    assert_ne!(first_sig, second_sig);
}

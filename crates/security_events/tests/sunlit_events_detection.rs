//! BDD tests for the detection engine.

use security_core::severity::SecuritySeverity;
use security_events::detect::DetectionEngine;
use security_events::event::EventOutcome;
use security_events::kind::EventKind;

#[test]
fn test_detection_fires_on_threshold() {
    let engine = DetectionEngine::new(3, 60);
    let actor = "attacker@example.com";
    // First 3 should not fire (threshold is 3, so > 3 fires)
    for _ in 0..3 {
        let result = engine.record_authz_denied(actor);
        assert!(
            result.is_none(),
            "Should not fire before exceeding threshold"
        );
    }
    // 4th should exceed threshold
    let result = engine.record_authz_denied(actor);
    assert!(result.is_some(), "Should fire on exceeding threshold");
    let event = result.unwrap();
    assert_eq!(event.kind, EventKind::AuthzDeny);
    assert_eq!(event.severity, SecuritySeverity::Critical);
}

#[test]
fn test_below_threshold_no_escalation() {
    let engine = DetectionEngine::new(3, 60);
    let actor = "legit@example.com";
    let result1 = engine.record_authz_denied(actor);
    let result2 = engine.record_authz_denied(actor);
    assert!(result1.is_none());
    assert!(result2.is_none());
}

#[test]
fn test_cross_tenant_probe_detected() {
    let engine = DetectionEngine::new(10, 60);
    let event = engine.record_cross_tenant_probe("actor1", "tenant-a", "tenant-b");
    assert_eq!(event.kind, EventKind::CrossTenantAttempt);
    assert_eq!(event.severity, SecuritySeverity::Critical);
    assert_eq!(event.outcome, EventOutcome::Blocked);
}

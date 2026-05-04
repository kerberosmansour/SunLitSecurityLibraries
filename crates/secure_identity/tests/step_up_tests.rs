//! BDD tests for step-up authentication — Milestone 3 (MASVS-AUTH)
//!
//! Feature: Step-Up Authentication

#![cfg(feature = "biometric")]

use secure_identity::step_up::{StepUpDecision, StepUpPolicy};
use security_events::event::EventOutcome;
use security_events::kind::EventKind;
use std::time::Duration;

// ─── Feature: Step-Up Authentication ────────────────────────────────────────

/// Scenario: Sensitive operation requires step-up
/// Given StepUpPolicy for "transfer_funds"
/// When User last authenticated 10 min ago, threshold is 5 min
/// Then StepUpDecision::Required
#[test]
fn given_transfer_funds_when_auth_10min_ago_threshold_5min_then_step_up_required() {
    let policy = StepUpPolicy::new("transfer_funds", Duration::from_secs(300));
    let last_auth_age = Duration::from_secs(600); // 10 min ago

    let decision = policy.evaluate(last_auth_age);
    assert_eq!(decision, StepUpDecision::Required);
}

/// Scenario: Recent auth skips step-up
/// Given StepUpPolicy for "transfer_funds"
/// When User authenticated 1 min ago, threshold is 5 min
/// Then StepUpDecision::NotRequired
#[test]
fn given_transfer_funds_when_auth_1min_ago_threshold_5min_then_not_required() {
    let policy = StepUpPolicy::new("transfer_funds", Duration::from_secs(300));
    let last_auth_age = Duration::from_secs(60); // 1 min ago

    let decision = policy.evaluate(last_auth_age);
    assert_eq!(decision, StepUpDecision::NotRequired);
}

/// Scenario: Step-up always required for critical ops
/// Given StepUpPolicy::always() for "delete_account"
/// When Any auth freshness
/// Then StepUpDecision::Required
#[test]
fn given_always_policy_for_delete_account_when_any_auth_then_required() {
    let policy = StepUpPolicy::always("delete_account");

    // Even 0 seconds ago
    let decision = policy.evaluate(Duration::from_secs(0));
    assert_eq!(decision, StepUpDecision::Required);

    // Even 1 second ago
    let decision = policy.evaluate(Duration::from_secs(1));
    assert_eq!(decision, StepUpDecision::Required);
}

/// Scenario: Step-up failure emits security event
/// Given Step-up authentication fails
/// When Failure detected
/// Then SecurityEvent with EventKind::StepUpAuthFailure emitted
#[test]
fn given_step_up_failure_when_detected_then_security_event_emitted() {
    let policy = StepUpPolicy::new("transfer_funds", Duration::from_secs(300));
    let last_auth_age = Duration::from_secs(600); // stale auth

    let events = policy.evaluate_with_events(last_auth_age);
    assert!(!events.is_empty(), "Expected at least one security event");
    assert_eq!(events[0].kind, EventKind::StepUpAuthFailure);
    assert_eq!(events[0].outcome, EventOutcome::Blocked);
}

/// Scenario: Step-up not required does not emit events
#[test]
fn given_fresh_auth_when_step_up_not_required_then_no_events() {
    let policy = StepUpPolicy::new("transfer_funds", Duration::from_secs(300));
    let last_auth_age = Duration::from_secs(60); // fresh

    let events = policy.evaluate_with_events(last_auth_age);
    assert!(
        events.is_empty(),
        "No events expected when step-up is not required"
    );
}

/// Scenario: Edge case — auth age exactly equals threshold
#[test]
fn given_auth_age_equals_threshold_then_not_required() {
    let policy = StepUpPolicy::new("view_balance", Duration::from_secs(300));
    let last_auth_age = Duration::from_secs(300); // exactly at threshold

    let decision = policy.evaluate(last_auth_age);
    assert_eq!(decision, StepUpDecision::NotRequired);
}

/// Scenario: StepUpPolicy operation name accessible
#[test]
fn given_policy_then_operation_name_accessible() {
    let policy = StepUpPolicy::new("transfer_funds", Duration::from_secs(300));
    assert_eq!(policy.operation(), "transfer_funds");
}

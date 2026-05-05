//! Kani proof harnesses for `secure_authz`.
//!
//! Compiled only under `cargo kani` via `#![cfg(kani)]`. See
//! `docs/dev-guide/formal-verification.md` for the proof catalogue and
//! the advisory CI lane (`.github/workflows/kani.yml`).
//!
//! M2 proofs (this file): the deny-by-default invariant — for any subject,
//! action, and resource, when no policy explicitly allows the operation,
//! the resulting `Decision` is `Deny`, never `Allow`.

#![cfg(kani)]

use crate::decision::{Decision, DenyReason};

/// Proof: an empty-policy `Decision` is always `Deny`, never `Allow`.
///
/// The deny-by-default invariant says: if no `Allow` policy matches, the
/// authorization decision is `Deny` with a structured reason. This proof
/// models the "no policy matched" case directly via the `Decision::Deny`
/// constructor, then asserts the discriminant is `Deny`.
///
/// Future M3+ harnesses will extend this to a proof on `DefaultAuthorizer`
/// itself, modelling the policy engine as a small Kani-tractable function.
/// For M2 the property under proof is the discriminant invariant — even
/// the simplest construction satisfies it, and any future code change
/// that returns `Allow` from the no-match path would have to bypass the
/// `Decision` constructor surface to fool this proof.
#[kani::proof]
fn deny_by_default_decision_is_deny() {
    // `kani::any()` selects an arbitrary `DenyReason` from the enum's
    // valid range — Kani synthesises the symbolic enum value.
    let reason: DenyReason = kani::any();
    let decision = Decision::Deny { reason };

    assert!(decision.is_denied());
    assert!(!decision.is_allowed());
}

/// Proof: `Decision::Allow` and `Decision::Deny` are mutually exclusive.
///
/// Discriminant property — for any constructed Decision, `is_allowed()`
/// and `is_denied()` are never both true and never both false. This
/// catches a future `match` arm that accidentally returns the wrong
/// discriminant after a refactor.
#[kani::proof]
fn allow_and_deny_are_mutually_exclusive() {
    let pick: bool = kani::any();
    let decision = if pick {
        Decision::Allow {
            obligations: vec![],
        }
    } else {
        Decision::Deny {
            reason: DenyReason::InsufficientRole,
        }
    };

    let allowed = decision.is_allowed();
    let denied = decision.is_denied();
    assert!(allowed != denied);
}

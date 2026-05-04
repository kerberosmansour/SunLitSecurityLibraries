//! Test helpers — `MockAuthorizer` and subject fixtures.
use std::sync::{Arc, Mutex};

use crate::action::Action;
use crate::decision::{Decision, DenyReason};
use crate::enforcer::Authorizer;
use crate::resource::ResourceRef;
use crate::subject::Subject;

/// A mock authorizer that always returns a fixed decision.
///
/// Useful for unit tests that need to control authorization outcomes without
/// running a real policy engine.
///
/// # Examples
///
/// ```
/// use secure_authz::testkit::MockAuthorizer;
/// use secure_authz::decision::DenyReason;
///
/// let allow = MockAuthorizer::allow();
/// assert_eq!(allow.call_count(), 0);
///
/// let deny = MockAuthorizer::deny(DenyReason::InsufficientRole);
/// ```
#[derive(Clone)]
pub struct MockAuthorizer {
    decision: Decision,
    call_count: Arc<Mutex<usize>>,
}

impl MockAuthorizer {
    /// Creates a mock that always allows access.
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow {
                obligations: vec![],
            },
            call_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Creates a mock that always denies with the given reason.
    pub fn deny(reason: DenyReason) -> Self {
        Self {
            decision: Decision::Deny { reason },
            call_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Returns the number of times `authorize` was called.
    #[must_use]
    pub fn call_count(&self) -> usize {
        *self.call_count.lock().unwrap()
    }
}

impl Authorizer for MockAuthorizer {
    fn authorize<'a>(
        &'a self,
        _subject: &'a Subject,
        _action: &'a Action,
        _resource: &'a ResourceRef,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        let decision = self.decision.clone();
        let count = self.call_count.clone();
        Box::pin(async move {
            *count.lock().unwrap() += 1;
            decision
        })
    }
}

/// Creates a test [`crate::subject::Subject`] with the given actor_id and roles.
///
/// # Examples
///
/// ```
/// use secure_authz::testkit::test_subject;
///
/// let subject = test_subject("alice", &["admin", "editor"]);
/// assert_eq!(subject.actor_id, "alice");
/// assert_eq!(subject.roles.len(), 2);
/// ```
#[must_use]
pub fn test_subject(actor_id: &str, roles: &[&str]) -> Subject {
    Subject {
        actor_id: actor_id.to_owned(),
        tenant_id: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
        attributes: Default::default(),
    }
}

/// Creates a test [`crate::subject::Subject`] with an actor_id, tenant_id, and roles.
#[must_use]
pub fn test_subject_with_tenant(actor_id: &str, tenant_id: &str, roles: &[&str]) -> Subject {
    Subject {
        actor_id: actor_id.to_owned(),
        tenant_id: Some(tenant_id.to_owned()),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        attributes: Default::default(),
    }
}

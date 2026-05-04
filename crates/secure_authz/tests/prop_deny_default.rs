//! Property tests — deny-by-default invariant.
//!
//! Milestone 9 — BDD: No policy → always deny.
use proptest::prelude::*;
use secure_authz::{
    action::Action,
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    subject::Subject,
};
use smallvec::smallvec;
use std::sync::Arc;
use tokio::runtime::Runtime;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// With no policy, any non-empty subject+action+resource is always denied
    #[test]
    fn prop_no_policy_always_deny(
        actor in "[a-z]{3,10}",
        resource_kind in "[a-z]{3,10}",
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let engine = Arc::new(DefaultPolicyEngine::new_empty().await.unwrap());
            let authorizer = DefaultAuthorizer::new(engine);
            let subject = Subject {
                actor_id: actor,
                tenant_id: None,
                roles: smallvec!["viewer".to_string()],
                attributes: Default::default(),
            };
            let resource = ResourceRef::new(resource_kind);
            for action in [Action::Read, Action::Write, Action::Delete, Action::Create] {
                let decision = authorizer.authorize(&subject, &action, &resource).await;
                prop_assert!(decision.is_deny(), "expected deny with no policy, got: {decision:?}");
            }
            Ok(())
        })?;
    }
}

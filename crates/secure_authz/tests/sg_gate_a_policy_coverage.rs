//! BDD: `secure_authz::testing::assert_every_route_has_policy` — sg-gate-a M4 A5.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use secure_authz::action::Action;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use secure_authz::testing::{
    assert_every_route_has_policy, PolicyFixture, RouteDescriptor, UnmappedRoute,
};

/// An authorizer that returns Allow for a specified set of (resource-kind, action, role)
/// triples and Deny for everything else.
struct RuleAuthorizer {
    rules: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl RuleAuthorizer {
    fn new(rules: Vec<(&str, &str, &str)>) -> Self {
        let mapped = rules
            .into_iter()
            .map(|(r, a, role)| (r.to_owned(), a.to_owned(), role.to_owned()))
            .collect();
        Self {
            rules: Arc::new(Mutex::new(mapped)),
        }
    }
}

impl Authorizer for RuleAuthorizer {
    fn authorize<'a>(
        &'a self,
        subject: &'a Subject,
        action: &'a Action,
        resource: &'a ResourceRef,
    ) -> Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        let rules = self.rules.clone();
        let resource_kind = resource.kind.clone();
        let action_str = action.to_string();
        let roles = subject.roles.clone();
        Box::pin(async move {
            let rules = rules.lock().unwrap();
            for role in &roles {
                if rules
                    .iter()
                    .any(|(r, a, ro)| r == &resource_kind && a == &action_str && ro == role)
                {
                    return Decision::Allow {
                        obligations: vec![],
                    };
                }
            }
            Decision::Deny {
                reason: DenyReason::NoPolicyMatch,
            }
        })
    }
}

fn route(path: &str, action: Action, kind: &str) -> RouteDescriptor {
    RouteDescriptor {
        method: "GET".to_owned(),
        path: path.to_owned(),
        action,
        resource: ResourceRef::new(kind),
    }
}

fn fixture(role: &str) -> PolicyFixture {
    PolicyFixture {
        subject: Subject {
            actor_id: format!("fixture-{role}"),
            tenant_id: None,
            roles: smallvec::smallvec![role.to_owned()],
            attributes: Default::default(),
        },
    }
}

#[test]
fn all_routes_have_policy() {
    let authz = RuleAuthorizer::new(vec![("item", "read", "reader"), ("doc", "write", "editor")]);
    let routes = vec![
        route("/items", Action::Read, "item"),
        route("/docs", Action::Write, "doc"),
    ];
    let fixtures = vec![fixture("reader"), fixture("editor")];
    let result = assert_every_route_has_policy(&authz, &routes, &fixtures);
    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

#[test]
fn one_route_missing_policy() {
    let authz = RuleAuthorizer::new(vec![
        ("item", "read", "reader"),
        // no rule for ("doc", "write", _)
    ]);
    let routes = vec![
        route("/items", Action::Read, "item"),
        route("/docs", Action::Write, "doc"),
    ];
    let fixtures = vec![fixture("reader"), fixture("editor")];
    let errs = assert_every_route_has_policy(&authz, &routes, &fixtures).unwrap_err();
    assert_eq!(errs.len(), 1);
    let UnmappedRoute { route, .. } = &errs[0];
    assert_eq!(route.path, "/docs");
}

#[test]
fn all_routes_missing_policy() {
    let authz = RuleAuthorizer::new(vec![]);
    let routes = vec![
        route("/items", Action::Read, "item"),
        route("/docs", Action::Write, "doc"),
    ];
    let fixtures = vec![fixture("reader"), fixture("editor")];
    let errs = assert_every_route_has_policy(&authz, &routes, &fixtures).unwrap_err();
    assert_eq!(errs.len(), 2);
}

#[test]
fn no_fixtures_means_no_coverage() {
    // Edge case: zero fixtures means every route is unmapped.
    let authz = RuleAuthorizer::new(vec![("item", "read", "reader")]);
    let routes = vec![route("/items", Action::Read, "item")];
    let errs = assert_every_route_has_policy(&authz, &routes, &[]).unwrap_err();
    assert_eq!(errs.len(), 1);
}

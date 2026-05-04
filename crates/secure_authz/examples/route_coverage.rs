//! Minimal runnable demonstration of
//! `secure_authz::testing::assert_every_route_has_policy`.
//!
//! Build & run:
//!
//! ```sh
//! cargo run --example route_coverage -p secure_authz
//! ```
//!
//! The example defines a tiny catalogue of three routes, two fixtures
//! (reader, editor), and an authorizer configured with a deliberate
//! coverage gap. The helper identifies the unmapped route and prints a
//! diagnostic a CI pipeline can fail on.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use secure_authz::action::Action;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use secure_authz::testing::{assert_every_route_has_policy, PolicyFixture, RouteDescriptor};

struct RuleAuthorizer {
    rules: Arc<Mutex<Vec<(String, String, String)>>>,
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
        let roles: Vec<String> = subject.roles.iter().cloned().collect();
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

fn main() {
    let authz = RuleAuthorizer {
        rules: Arc::new(Mutex::new(vec![
            // Policy for /articles (read) — covered.
            ("article".to_owned(), "read".to_owned(), "reader".to_owned()),
            // Policy for /articles (write) — covered.
            (
                "article".to_owned(),
                "write".to_owned(),
                "editor".to_owned(),
            ),
            // Intentionally NO policy for /admin/users (delete) — uncovered gap.
        ])),
    };

    let routes = vec![
        RouteDescriptor {
            method: "GET".to_owned(),
            path: "/articles".to_owned(),
            action: Action::Read,
            resource: ResourceRef::new("article"),
        },
        RouteDescriptor {
            method: "POST".to_owned(),
            path: "/articles".to_owned(),
            action: Action::Write,
            resource: ResourceRef::new("article"),
        },
        RouteDescriptor {
            method: "DELETE".to_owned(),
            path: "/admin/users/{id}".to_owned(),
            action: Action::Delete,
            resource: ResourceRef::new("admin_user"),
        },
    ];

    let fixtures = vec![
        PolicyFixture {
            subject: Subject {
                actor_id: "fixture-reader".to_owned(),
                tenant_id: None,
                roles: smallvec::smallvec!["reader".to_owned()],
                attributes: Default::default(),
            },
        },
        PolicyFixture {
            subject: Subject {
                actor_id: "fixture-editor".to_owned(),
                tenant_id: None,
                roles: smallvec::smallvec!["editor".to_owned()],
                attributes: Default::default(),
            },
        },
    ];

    match assert_every_route_has_policy(&authz, &routes, &fixtures) {
        Ok(()) => {
            println!("all routes covered");
        }
        Err(unmapped) => {
            eprintln!(
                "\nroute-policy coverage failed for {} route(s):",
                unmapped.len()
            );
            for u in &unmapped {
                eprintln!(
                    "  - {} {} (action={}, resource={}): {}",
                    u.route.method, u.route.path, u.route.action, u.route.resource.kind, u.reason
                );
            }
            // In real CI this would be `std::process::exit(1)`.
            eprintln!("\nexiting 0 so the example runs to completion, but CI would fail here.");
        }
    }
}

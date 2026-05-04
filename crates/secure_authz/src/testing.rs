//! Testing helpers that let services assert authorization-coverage
//! invariants in their own CI. Intended to be consumed from test and
//! integration-test code in downstream services.
//!
//! The main entry point is [`assert_every_route_has_policy`] — hand it
//! your list of registered HTTP routes and a small set of fixture
//! subjects; it asserts that every (route, action, resource) triple
//! resolves to at least one `Decision::Allow` somewhere across the
//! fixtures. If a route denies for every fixture, that's almost always
//! because no policy was wired for it — a production-breaking
//! misconfiguration the helper surfaces in CI.

use crate::action::Action;
use crate::decision::Decision;
use crate::enforcer::Authorizer;
use crate::resource::ResourceRef;
use crate::subject::Subject;

/// Describes a single HTTP route the service exposes and the
/// (action, resource) the authz layer should evaluate for it.
#[derive(Clone, Debug)]
pub struct RouteDescriptor {
    /// The HTTP method (`"GET"`, `"POST"`, …) — free-form string so
    /// both axum and actix services can populate this the same way.
    pub method: String,
    /// The path (e.g. `"/articles/{id}"`).
    pub path: String,
    /// The [`Action`] the authz layer enforces for this route.
    pub action: Action,
    /// The [`ResourceRef`] the authz layer enforces for this route.
    pub resource: ResourceRef,
}

/// A subject fixture used during the coverage sweep.
#[derive(Clone, Debug)]
pub struct PolicyFixture {
    /// The [`Subject`] to probe policies with.
    pub subject: Subject,
}

/// A route that failed the coverage sweep — i.e. returned `Decision::Deny`
/// for every fixture subject. Downstream CI should treat this as a
/// likely missing-policy configuration bug.
#[derive(Clone, Debug)]
pub struct UnmappedRoute {
    /// The offending route descriptor.
    pub route: RouteDescriptor,
    /// A short, log-safe explanation.
    pub reason: String,
}

/// Asserts every route in `routes` resolves to `Decision::Allow` for at
/// least one of the `fixtures`. Routes denied for all fixtures are
/// returned as [`UnmappedRoute`]s.
///
/// The check is inherently conservative — a route denied for every
/// fixture MIGHT have a genuine policy that requires a subject shape
/// you didn't model in the fixtures. To reduce false positives, pass
/// fixtures covering every role/tenant pair you expect in production.
///
/// # Errors
///
/// Returns a non-empty `Vec<UnmappedRoute>` when at least one route
/// failed. The vector is in the same order as `routes`.
///
/// # Examples
///
/// ```
/// use secure_authz::action::Action;
/// use secure_authz::resource::ResourceRef;
/// use secure_authz::subject::Subject;
/// use secure_authz::testkit::MockAuthorizer;
/// use secure_authz::testing::{
///     assert_every_route_has_policy, PolicyFixture, RouteDescriptor,
/// };
///
/// let authz = MockAuthorizer::allow();
/// let routes = vec![RouteDescriptor {
///     method: "GET".to_owned(),
///     path: "/items".to_owned(),
///     action: Action::Read,
///     resource: ResourceRef::new("item"),
/// }];
/// let fixtures = vec![PolicyFixture {
///     subject: Subject {
///         actor_id: "fixture".to_owned(),
///         tenant_id: None,
///         roles: smallvec::smallvec!["reader".to_owned()],
///         attributes: Default::default(),
///     },
/// }];
/// assert!(assert_every_route_has_policy(&authz, &routes, &fixtures).is_ok());
/// ```
pub fn assert_every_route_has_policy<A: Authorizer + ?Sized>(
    authorizer: &A,
    routes: &[RouteDescriptor],
    fixtures: &[PolicyFixture],
) -> Result<(), Vec<UnmappedRoute>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime for route-coverage probe");

    let mut unmapped = Vec::new();

    for route in routes {
        let mut any_allow = false;
        for fixture in fixtures {
            let decision = runtime.block_on(authorizer.authorize(
                &fixture.subject,
                &route.action,
                &route.resource,
            ));
            if matches!(decision, Decision::Allow { .. }) {
                any_allow = true;
                break;
            }
        }
        if !any_allow {
            unmapped.push(UnmappedRoute {
                route: route.clone(),
                reason: if fixtures.is_empty() {
                    "no fixtures supplied".to_owned()
                } else {
                    "denied for every fixture — likely missing policy".to_owned()
                },
            });
        }
    }

    if unmapped.is_empty() {
        Ok(())
    } else {
        Err(unmapped)
    }
}

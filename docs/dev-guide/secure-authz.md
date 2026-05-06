# `secure_authz` — Developer Guide

> **OWASP C7**: Deny-by-default authorization with RBAC, closure-based ABAC, temporal permissions, tenant isolation, and axum middleware.

`secure_authz` provides a policy engine that denies all requests by default. Access is only granted when an explicit policy rule or configured ABAC guard allows it. It supports role-based access control (RBAC), closure-based ABAC, time-bounded permissions, tenant isolation, decision caching, bulk authorization, and integrates with axum as Tower middleware.

---

## Quick Start

```toml
[dependencies]
secure_authz = "0.1.2"
```

---

## Core Concept: Deny by Default

With no policies loaded, **every** authorization request is denied. This is the fundamental security property:

```rust
use secure_authz::{DefaultAuthorizer, DefaultPolicyEngine, Action, ResourceRef, Decision};
use secure_authz::testkit::test_subject;
use std::sync::Arc;

// Empty policy engine — no rules
let engine = DefaultPolicyEngine::new_empty().await.unwrap();
let authorizer = DefaultAuthorizer::new(Arc::new(engine));

let subject = test_subject("alice", &["admin"]);
let resource = ResourceRef::new("article");

// Even an "admin" is denied — no policy match
let decision = authorizer.authorize(&subject, &Action::Read, &resource).await;
assert!(decision.is_deny());
```

---

## Complete Authorization Flow

### 1. Define Policies

```rust
use secure_authz::DefaultPolicyEngine;

let engine = DefaultPolicyEngine::new_empty().await.unwrap();

// Add RBAC policies: (role, resource, action)
engine.add_policy("admin", "articles", "read").await.unwrap();
engine.add_policy("admin", "articles", "write").await.unwrap();
engine.add_policy("admin", "articles", "delete").await.unwrap();
engine.add_policy("editor", "articles", "read").await.unwrap();
engine.add_policy("editor", "articles", "write").await.unwrap();
engine.add_policy("viewer", "articles", "read").await.unwrap();

// Inspect loaded policies
let policies = engine.get_policies().await;
// [["admin", "articles", "read"], ["admin", "articles", "write"], ...]
```

### 2. Build the Authorizer

```rust
use secure_authz::{DefaultAuthorizer, DefaultPolicyEngine};
use secure_authz::cache::DecisionCache;
use std::sync::Arc;
use std::time::Duration;

let engine = Arc::new(engine);

// Option A: Default cache (1024 entries, 5-minute TTL)
let authorizer = DefaultAuthorizer::new(engine.clone());

// Option B: Custom cache size and TTL
let cache = Arc::new(DecisionCache::new(
    256,                          // max entries
    Duration::from_secs(120),     // 2-minute TTL
));
let authorizer = DefaultAuthorizer::with_cache(engine, cache);
```

### 3. Resolve Identity to Subject

The `SubjectResolver` bridges `AuthenticatedIdentity` (from any identity provider) to `Subject` (authorization's input):

```rust
use secure_authz::{DefaultSubjectResolver, SubjectResolver, Subject};
use security_core::identity::AuthenticatedIdentity;

// From any IdentitySource result:
let subject = DefaultSubjectResolver::resolve(&authenticated_identity);
// subject.actor_id == identity.actor_id.to_string()
// subject.roles == identity.roles
// subject.tenant_id == identity.tenant_id.map(|t| t.to_string())
```

### 4. Authorize

```rust
use secure_authz::{Action, ResourceRef, Decision, DenyReason};

let subject = DefaultSubjectResolver::resolve(&identity);
let resource = ResourceRef::new("articles").with_id("article-42");
let action = Action::Write;

let decision = authorizer.authorize(&subject, &action, &resource).await;

// Decision is #[must_use] — you cannot silently ignore it
match decision {
    Decision::Allow { obligations } => {
        if obligations.is_empty() {
            // Proceed with the operation
        } else {
            // Check that obligations are fulfilled (e.g., MFA required)
            for obligation in &obligations {
                println!("Must satisfy: {obligation}");
            }
        }
    }
    Decision::Deny { reason } => {
        match reason {
            DenyReason::NoPolicyMatch => { /* No rule matches */ }
            DenyReason::InsufficientRole => { /* Role doesn't grant access */ }
            DenyReason::TenantMismatch => { /* Cross-tenant access blocked */ }
            DenyReason::IncompleteContext => { /* Missing actor_id or similar */ }
            DenyReason::EngineError => { /* Policy engine failure — deny */ }
            DenyReason::OwnershipRequired => { /* Must own the resource */ }
            DenyReason::MissingResource => { /* No resource kind specified */ }
            _ => { /* Non-exhaustive — future variants */ }
        }
        // Return 403 to client
    }
}
```

---

## Actions

```rust
use secure_authz::Action;

// Built-in actions
let read = Action::Read;
let write = Action::Write;
let create = Action::Create;
let delete = Action::Delete;
let admin = Action::Admin;

// Custom actions
let publish = Action::Custom("publish".to_string());
let approve = Action::Custom("approve".to_string());

println!("{read}"); // "read" (lowercase Display)
```

---

## Resource References

`ResourceRef` describes what is being accessed:

```rust
use secure_authz::ResourceRef;

// Basic — just the resource kind
let resource = ResourceRef::new("articles");

// With specific resource ID
let resource = ResourceRef::new("articles").with_id("article-42");

// With tenant scope
let resource = ResourceRef::new("articles")
    .with_id("article-42")
    .with_tenant("tenant-acme");

// With owner (for ownership checks)
let resource = ResourceRef::new("articles")
    .with_id("article-42")
    .with_owner("user-123")
    .with_tenant("tenant-acme");
```

---

## Tenant Isolation

Cross-tenant access is blocked **before** policy evaluation, regardless of what policies are loaded:

```rust
use secure_authz::{DefaultAuthorizer, DefaultPolicyEngine, Action, ResourceRef, Decision};
use secure_authz::testkit::test_subject_with_tenant;
use std::sync::Arc;

let engine = DefaultPolicyEngine::new_empty().await.unwrap();
engine.add_policy("admin", "articles", "read").await.unwrap();
let authorizer = DefaultAuthorizer::new(Arc::new(engine));

// Same tenant — allowed (if policy matches)
let subject = test_subject_with_tenant("alice", "tenant-A", &["admin"]);
let resource = ResourceRef::new("articles").with_tenant("tenant-A");
let decision = authorizer.authorize(&subject, &Action::Read, &resource).await;
assert!(decision.is_allow());

// Cross-tenant — denied, even though alice is admin
let resource_b = ResourceRef::new("articles").with_tenant("tenant-B");
let decision = authorizer.authorize(&subject, &Action::Read, &resource_b).await;
assert!(decision.is_deny());
// reason == DenyReason::TenantMismatch
```

---

## ABAC Guards (Closure-Based)

Use `AttributeGuard` to compose lightweight attribute predicates with standard Rust combinators:

```rust
use secure_authz::{abac::AttributeGuard, Action, ResourceRef};

let guard = AttributeGuard::require_subject_attr("role", "admin")
    .and(AttributeGuard::require_subject_attr("department", "engineering"));

let authorizer = DefaultAuthorizer::new(engine.clone()).with_abac_guard(guard);

let mut subject = test_subject("alice", &[]);
subject.attributes.insert("role".into(), "admin".into());
subject.attributes.insert("department".into(), "engineering".into());

let decision = authorizer
    .authorize(&subject, &Action::Read, &ResourceRef::new("repo"))
    .await;
assert!(decision.is_allow());
```

Missing attributes fail closed and return `DenyReason::AttributeMismatch`.

---

## Temporal Permissions

Use `PermissionWindow` to enforce not-before / expiry windows at authorization time:

```rust
use secure_authz::{temporal::PermissionWindow, Action, ResourceRef};
use time::{Duration, OffsetDateTime};

let now = OffsetDateTime::now_utc();
let window = PermissionWindow::new()
    .starting_at(now - Duration::hours(1))
    .expiring_at(now + Duration::hours(1));

let mut subject = test_subject("alice", &["editor"]);
window.apply_to_subject(&mut subject).unwrap();

let authorizer = DefaultAuthorizer::new(engine)
    .with_time_source(move || now);

let decision = authorizer
    .authorize(&subject, &Action::Read, &ResourceRef::new("report"))
    .await;
assert!(decision.is_allow());
```

Expired windows return `DenyReason::PermissionExpired`.

---

## Ownership Checks

Use the ownership helpers for resource-level access control:

```rust
use secure_authz::ownership::{is_owner, is_same_tenant};
use secure_authz::{Subject, ResourceRef};

let subject = Subject {
    actor_id: "user-123".to_string(),
    tenant_id: Some("tenant-A".to_string()),
    roles: vec!["editor".into()].into(),
    attributes: Default::default(),
};

let resource = ResourceRef::new("articles")
    .with_owner("user-123")
    .with_tenant("tenant-A");

assert!(is_owner(&subject, &resource));       // user-123 owns this article
assert!(is_same_tenant(&subject, &resource)); // same tenant

let other_resource = ResourceRef::new("articles")
    .with_owner("user-456")
    .with_tenant("tenant-B");

assert!(!is_owner(&subject, &other_resource));       // different owner
assert!(!is_same_tenant(&subject, &other_resource)); // different tenant
```

---

## axum Middleware Integration

Protect entire route groups with `AuthzLayer`:

```rust
use axum::{routing::{get, post, delete}, Router, Extension};
use secure_authz::{
    DefaultAuthorizer, DefaultPolicyEngine,
    Action, ResourceRef, Decision,
    middleware::{AuthzLayer, ObligationFulfillment},
};
use security_core::identity::AuthenticatedIdentity;
use std::sync::Arc;

// Build authorizer
let engine = DefaultPolicyEngine::new_empty().await.unwrap();
engine.add_policy("admin", "articles", "read").await.unwrap();
engine.add_policy("admin", "articles", "create").await.unwrap();
engine.add_policy("admin", "articles", "delete").await.unwrap();
engine.add_policy("editor", "articles", "read").await.unwrap();
engine.add_policy("editor", "articles", "create").await.unwrap();
let authorizer = Arc::new(DefaultAuthorizer::new(Arc::new(engine)));

// Protect routes — each route gets its own action + resource
let app = Router::new()
    .route("/articles", get(list_articles))
    .layer(AuthzLayer::new(
        authorizer.clone(),
        Action::Read,
        ResourceRef::new("articles"),
    ));

let app = Router::new()
    .route("/articles", post(create_article))
    .layer(AuthzLayer::new(
        authorizer.clone(),
        Action::Create,
        ResourceRef::new("articles"),
    ));

// The middleware:
// 1. Extracts AuthenticatedIdentity from request extensions
// 2. Resolves to Subject via DefaultSubjectResolver
// 3. Calls authorizer.authorize()
// 4. Returns 403 on Deny (with no internal details)
// 5. Checks obligation fulfillment if obligations are non-empty
```

### Obligation Fulfillment

Policies can require additional conditions (e.g., MFA):

```rust
use secure_authz::middleware::ObligationFulfillment;

// In prior middleware, after MFA verification:
let fulfillment = ObligationFulfillment {
    fulfilled: vec!["mfa_verified".to_string()],
};
// Insert into request extensions before AuthzLayer runs
request.extensions_mut().insert(fulfillment);
```

---

## Decision Caching

The `DefaultAuthorizer` includes an LRU cache keyed by (actor, action, resource, policy_version, tenant):

```rust
use secure_authz::cache::DecisionCache;
use std::time::Duration;

let cache = DecisionCache::new(
    1024,                          // max entries before LRU eviction
    Duration::from_secs(300),      // TTL per entry
);

// Cache is automatically invalidated when policies change
// (policy_version is incremented on every add_policy call)
```

**Cache key includes `tenant_id`** to prevent cross-tenant cache poisoning.

For explicit key construction in tests and advanced integrations:

```rust
use secure_authz::{cache::CacheKey, Action, ResourceRef};

let key = CacheKey::for_request(&subject, &Action::Read, &ResourceRef::new("doc"), 42);
```

---

## Bulk Authorization

Use `authorize_bulk()` when processing many checks in one request path:

```rust
use secure_authz::{Action, ResourceRef};

let requests = vec![
    (test_subject("alice", &["editor"]), Action::Read, ResourceRef::new("report")),
    (test_subject("bob", &["viewer"]), Action::Read, ResourceRef::new("report")),
];

let decisions = authorizer.authorize_bulk(&requests).await;
assert_eq!(decisions.len(), 2);
```

---

## In-Handler Authorization

For fine-grained access control (e.g., checking ownership), call the authorizer directly in handlers:

```rust
use axum::{extract::Path, Extension, response::Response};
use secure_authz::{
    DefaultAuthorizer, DefaultSubjectResolver, SubjectResolver,
    Action, ResourceRef, Decision,
};
use security_core::identity::AuthenticatedIdentity;

async fn get_article(
    Extension(identity): Extension<AuthenticatedIdentity>,
    Extension(authorizer): Extension<Arc<DefaultAuthorizer<DefaultPolicyEngine>>>,
    Path(article_id): Path<String>,
) -> Response {
    let subject = DefaultSubjectResolver::resolve(&identity);

    // Build resource with tenant from the actual article record
    let article = db_find_article(&article_id).await;
    let resource = ResourceRef::new("articles")
        .with_id(&article_id)
        .with_tenant(&article.tenant_id)
        .with_owner(&article.author_id);

    let decision = authorizer.authorize(&subject, &Action::Read, &resource).await;
    if decision.is_deny() {
        return forbidden_response();
    }

    // Authorized — return the article
    json_response(&article)
}
```

---

## Testing

### `MockAuthorizer`

```rust
use secure_authz::testkit::{MockAuthorizer, test_subject, test_subject_with_tenant};
use secure_authz::{Action, ResourceRef, DenyReason};

// Always allow
let mock = MockAuthorizer::allow();
let decision = mock.authorize(&subject, &Action::Read, &resource).await;
assert!(decision.is_allow());
assert_eq!(mock.call_count(), 1);

// Always deny
let mock = MockAuthorizer::deny(DenyReason::InsufficientRole);
let decision = mock.authorize(&subject, &Action::Write, &resource).await;
assert!(decision.is_deny());
```

### Test Subject Builders

```rust
use secure_authz::testkit::{test_subject, test_subject_with_tenant};

let subject = test_subject("alice", &["admin", "editor"]);
// actor_id: "alice", roles: ["admin", "editor"], tenant: None

let subject = test_subject_with_tenant("bob", "tenant-acme", &["viewer"]);
// actor_id: "bob", roles: ["viewer"], tenant: Some("tenant-acme")
```

---

## Authorization Pipeline Internals

When `DefaultAuthorizer::authorize()` is called, this pipeline runs:

```
1. Validate subject     → empty actor_id?      → Deny(IncompleteContext)
2. Validate resource    → empty kind?           → Deny(MissingResource)
3. Tenant isolation     → is_same_tenant()?     → Deny(TenantMismatch)
4. Temporal checks      → invalid window?        → Deny(PermissionExpired / PermissionNotYetActive)
5. ABAC guard           → predicate false?       → Deny(AttributeMismatch)
6. Cache lookup         → hit + not expired?     → return cached Decision
7. Policy evaluation    → try actor_id, then each role → first match wins
8. Decision logging     → Deny events emitted via security_events
9. Cache insert         → store result for next request
```

**Every error in this pipeline results in `Deny`** — never `Allow`.

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `Action` | `action` | Read / Write / Delete / Create / Admin / Custom |
| `Decision` | `decision` | Allow (with obligations) / Deny (with reason) |
| `DenyReason` | `decision` | denial reasons including ABAC/temporal variants |
| `Subject` | `subject` | Authenticated principal |
| `ResourceRef` | `resource` | Resource descriptor with tenant/owner |
| `AttributeGuard` | `abac` | Composable closure-based ABAC predicates |
| `PermissionWindow` | `temporal` | Time-bounded permission metadata |
| `DefaultAuthorizer<P>` | `enforcer` | Main authorizer implementation |
| `Authorizer` | `enforcer` | Authorization trait |
| `DefaultPolicyEngine` | `policy` | Casbin-backed RBAC engine |
| `PolicyEngine` | `policy` | Sealed policy evaluation trait |
| `DecisionCache` | `cache` | Bounded LRU with TTL |
| `DefaultSubjectResolver` | `resolver` | Identity → Subject mapper |
| `SubjectResolver` | `resolver` | Subject resolution trait |
| `AuthzLayer<A>` | `middleware` | Tower/axum middleware |
| `ObligationFulfillment` | `middleware` | Obligation satisfaction marker |
| `MockAuthorizer` | `testkit` | Test double |
| `test_subject()` | `testkit` | Test subject builder |
| `test_subject_with_tenant()` | `testkit` | Test subject builder with tenant |
| `is_owner()` | `ownership` | Resource ownership check |
| `is_same_tenant()` | `ownership` | Tenant isolation check |
| `log_decision()` | `decision_log` | Emit decision security events |

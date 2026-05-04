# Attack Tree: Authorisation & Access Control

> **Crate:** `secure_authz` (Milestone M7 — OWASP C7)  
> **Supporting Crates:** `security_core` (M1), `secure_identity` (M6), `security_events` (M3)  
> **Related Threats:** THREAT-E-01, THREAT-E-02, THREAT-E-03, THREAT-R-01, THREAT-S-01  
> **Classification:** INTERNAL — Security Sensitive  
> **Version:** 1.0.0

---

## Introduction

This attack tree models all credible paths by which an attacker can **bypass, circumvent, or abuse** the authorisation and access control layer provided by `secure_authz`. The tree is rooted at the adversarial goal of gaining access to resources or operations beyond what is permitted.

Critical infrastructure context: authorisation bypass in energy control systems can enable arbitrary SCADA commands; in healthcare it can expose bulk patient data; in financial systems it can authorise fraudulent transactions; in government systems it can expose classified information.

**Deny-by-default guarantee:** `secure_authz` implements OWASP C7's deny-by-default principle — access is denied unless an explicit policy grants it. The attack tree therefore focuses on ways to break this guarantee.

**Node notation:**
- `[OR]` — any one child path achieves the parent goal
- `[AND]` — all child paths must succeed simultaneously
- `[LEAF]` — terminal attack action (no further decomposition)
- `(M)` — mitigating control from `secure_authz` or a peer crate
- `(R)` — residual risk requiring compensating control from consuming team

---

## Attack Tree

```
GOAL: Gain Unauthorised Access — Access a resource or perform an action not permitted
│
├── [OR] 1. Bypass the Authorisation Middleware Entirely (THREAT-E-01)
│   │
│   ├── [OR] 1.1 Route Not Protected by Middleware
│   │   │
│   │   ├── [LEAF] 1.1.1 New route added without attaching secure_authz middleware
│   │   │           Mitigations: (M) deny-by-default: if middleware is present but no
│   │   │                             policy is registered for a route, access is denied;
│   │   │                         (R) Consuming team must audit routes in CI (see RR-02)
│   │   │
│   │   ├── [LEAF] 1.1.2 Sub-router constructed that bypasses global middleware layer
│   │   │           Mitigations: (M) secure_reference_service demonstrates correct
│   │   │                             router construction with middleware applied universally;
│   │   │                         (R) Architecture review required for every new router
│   │   │
│   │   └── [LEAF] 1.1.3 Debug / health / metrics endpoint exposes sensitive data
│   │               Mitigations: (M) secure_authz provides policy types for internal endpoints;
│   │                             (R) All non-public endpoints must require authentication
│   │
│   ├── [LEAF] 1.2 Middleware Panics / Returns Permissive Default on Error
│   │           Mitigations: (M) secure_authz returns 403 on any evaluation error;
│   │                         (M) secure_errors propagates AuthorisationError as opaque 403;
│   │                         never returns 200 on policy evaluation failure
│   │
│   └── [AND] 1.3 Race Condition in Async Middleware Application
│       ├── [LEAF] 1.3.1 Request arrives during middleware initialisation window
│       └── [LEAF] 1.3.2 Tower layer ordering places authz after handler in async graph
│               Mitigations: (M) Layer ordering enforced and documented in secure_reference_service;
│                             (M) Integration tests verify layer ordering is correct
│
├── [OR] 2. Present Forged or Manipulated Credentials (THREAT-E-02)
│   │
│   ├── [OR] 2.1 Escalate Role via Token Claim Manipulation
│   │   │
│   │   ├── [LEAF] 2.1.1 Forge JWT with elevated role claim (alg:none or algorithm confusion)
│   │   │           Mitigations: (M) secure_identity validates token signature before
│   │   │                             secure_authz extracts claims;
│   │   │                         See identity.md attack tree for token forgery sub-tree
│   │   │
│   │   ├── [LEAF] 2.1.2 Modify role claim in opaque session token (no MAC verification)
│   │   │           Mitigations: (M) secure_identity MACs or signs all token material;
│   │   │                         opaque tokens verified server-side before claim extraction
│   │   │
│   │   └── [LEAF] 2.1.3 Inject additional role claims via HTTP header smuggling
│   │               Mitigations: (M) secure_boundary normalises headers;
│   │                             (M) secure_identity extracts claims only from verified token,
│   │                                 not from arbitrary HTTP headers
│   │
│   └── [OR] 2.2 Claim a Different Identity (Horizontal Privilege Escalation)
│       │
│       ├── [LEAF] 2.2.1 Replace sub/user_id claim with victim's identifier
│       │           Mitigations: (M) sub claim bound to signed token; cannot be altered;
│       │                         (M) secure_authz policy evaluates verified identity from
│       │                             IdentitySource trait, not raw request parameters
│       │
│       └── [LEAF] 2.2.2 Supply victim's user ID in path/body after authentication
│                   Mitigations: (M) secure_authz ABAC policies check resource ownership
│                                    attribute against authenticated identity;
│                                 (R) Consuming team must configure ownership ABAC policy
│
├── [OR] 3. Insecure Direct Object Reference (IDOR) (THREAT-E-03)
│   │
│   ├── [OR] 3.1 Enumerate Resource IDs
│   │   │
│   │   ├── [LEAF] 3.1.1 Sequential integer IDs: increment/decrement path parameter
│   │   │           Mitigations: (M) security_core provides typed ID wrappers using UUIDs;
│   │   │                         (M) secure_authz ownership policy rejects cross-user access
│   │   │
│   │   ├── [LEAF] 3.1.2 Predictable UUID v1/v3 IDs based on MAC address + timestamp
│   │   │           Mitigations: (M) security_core uses UUID v4 (cryptographically random);
│   │   │                         (M) Resource IDs logged in security_events for anomaly detection
│   │   │
│   │   └── [LEAF] 3.1.3 Brute-force resource IDs via automated scanning
│   │               Mitigations: (M) secure_boundary enforces request rate limits;
│   │                             (M) security_events raises alert on rapid 404/403 pattern
│   │
│   └── [AND] 3.2 Access Resource with Valid Role But Wrong Owner
│       ├── [LEAF] 3.2.1 User has valid role (e.g., medical_staff) but requests another user's record
│       └── [LEAF] 3.2.2 Policy only checks role, not ownership attribute
│               Mitigations: (M) secure_authz ABAC policy attributes include ResourceOwner;
│                             (M) Policy engine evaluates: role ∧ ownership ∧ data_classification;
│                             (R) Consuming team must define ResourceOwner attribute in policy
│
├── [OR] 4. Privilege Escalation via Policy Misconfiguration
│   │
│   ├── [LEAF] 4.1 Overly Permissive Wildcard Role in Policy Definition
│   │           Mitigations: (M) secure_authz provides policy linting at startup;
│   │                         (M) secure_reference_service shows minimal-privilege policy examples;
│   │                         (R) Security review of all policy definitions before production
│   │
│   ├── [AND] 4.2 Policy Evaluation Short-Circuits to Permit on Exception
│   │   ├── [LEAF] 4.2.1 Policy evaluator encounters unexpected claim type → panics
│   │   └── [LEAF] 4.2.2 Panic recovery returns default-permit instead of deny
│   │           Mitigations: (M) PolicyResult::Deny is the default; any evaluation error → Deny;
│   │                         (M) All policy evaluation errors logged as CRITICAL in security_events
│   │
│   ├── [LEAF] 4.3 Stale Policy Cache Evaluated Against Updated Claims
│   │           Mitigations: (M) Policy cache TTL configurable; cache invalidation on policy update;
│   │                         (M) Token claims always re-validated against current policy on each request
│   │
│   └── [AND] 4.4 Concurrent Policy Update Race Condition
│       ├── [LEAF] 4.4.1 Policy updated mid-request during high-concurrency window
│       └── [LEAF] 4.4.2 Old policy applied to request that should be denied by new policy
│               Mitigations: (M) Policy store uses atomic swap for updates (RwLock<Arc<Policy>>);
│                             (M) No policy version can be partially applied to a single request
│
├── [OR] 5. Exploit Missing Audit Trail to Perform Deniable Actions (THREAT-R-01)
│   │
│   ├── [LEAF] 5.1 Perform privileged action on unaudited endpoint
│   │           Mitigations: (M) secure_authz emits SecurityEvent for every access decision;
│   │                         (M) security_events records ALLOW and DENY with full context
│   │
│   └── [AND] 5.2 Tamper with audit records to erase access evidence
│       ├── [LEAF] 5.2.1 Obtain write access to audit log store
│       └── [LEAF] 5.2.2 Delete or modify records of unauthorised access
│               Mitigations: (M) security_events implements tamper-evident HMAC chaining;
│                             (R) WORM / append-only log storage outside library scope
│
└── [OR] 6. Multi-Tenant Isolation Bypass (Abuse Case AC-06)
    │
    ├── [LEAF] 6.1 Access another tenant's resources via unprotected route (see 1.1.1)
    │           Mitigations: (M) Tenant claim included in every ABAC policy evaluation;
    │                         (R) All routes must be registered through secure_authz
    │
    ├── [LEAF] 6.2 Manipulate tenant_id claim in JWT
    │           Mitigations: (M) tenant_id claim bound to signed token (see 2.1.x above)
    │
    └── [AND] 6.3 Cross-Tenant Data Leakage via Shared Cache
        ├── [LEAF] 6.3.1 Cache key does not include tenant_id
        └── [LEAF] 6.3.2 Tenant A's response served to Tenant B
                Mitigations: (M) secure_authz requires tenant isolation in resource keys;
                              (R) Consuming team must namespace all cache keys with tenant_id
```

---

## Policy Evaluation Decision Matrix

The `secure_authz` policy engine evaluates the following attributes for every request:

| Attribute | Source | Required | Notes |
|---|---|---|---|
| `identity.subject` | Verified JWT/mTLS `sub` claim | Yes | Cannot be supplied by caller |
| `identity.roles` | Verified JWT `roles`/`groups` claim | Yes | Whitelist of allowed role values |
| `identity.tenant_id` | Verified JWT `tenant_id` claim | In multi-tenant deployments | Scopes all resource access |
| `resource.owner` | Application-defined ABAC attribute | For resource-level checks | See THREAT-E-03 |
| `resource.classification` | `security_core::DataClassification` | For sensitive data | Blocks access below clearance |
| `action` | HTTP method + route pattern | Yes | Granular verb-level control |

Default outcome when any attribute is missing or evaluation fails: **DENY**.

---

## Mitigating Controls Summary

| Attack Path | Primary Control | Crate | Milestone |
|---|---|---|---|
| Unprotected route (1.1.x) | Deny-by-default; route audit | `secure_authz` | M7 |
| Token claim escalation (2.1.x) | Signed/verified claims only | `secure_identity` | M6 |
| IDOR enumeration (3.1.x) | UUID v4 typed IDs + ownership ABAC | `security_core`, `secure_authz` | M1/M7 |
| Policy misconfiguration (4.x) | Policy linting + deny-on-error | `secure_authz` | M7 |
| Missing audit trail (5.1) | Mandatory event on every decision | `security_events` | M3 |
| Multi-tenant bypass (6.x) | Tenant claim in all ABAC policies | `secure_authz` | M7 |

---

## Residual Risk Cross-Reference

| Attack Path | Residual Risk | See Threat Model |
|---|---|---|
| Unprotected route (1.1.x) | Consuming team must audit all routes | RR-02 |
| Ownership ABAC (3.2.x) | Consuming team must define ownership policy | RR-02 |
| WORM log storage (5.2.x) | Immutable log storage outside library scope | RR-01 |

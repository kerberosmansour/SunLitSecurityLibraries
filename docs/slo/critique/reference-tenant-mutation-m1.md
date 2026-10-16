# Reference-service tenant mutation M1 critique

## CEO pass

The change closes a concrete cross-tenant destructive path in a copyable example
without expanding into production identity, storage or deployment work. The
scope is proportionate to a medium-severity reference-service defect.

## Engineering pass

The simplest consistent design uses the existing Tokio store lock and existing
`ResourceRef` tenant/owner fields. A separate helper centralizes resource
construction. GET uses a read lock; PUT and DELETE use a write lock retained
through the async authorization decision and mutation. This intentionally
serializes item mutations while authorization runs. The reference service is
in-memory and loopback-only, so correctness takes priority over that bounded
contention; a production datastore would use a transaction or version check.

## Security pass

The stored record, never request data, supplies tenant and owner. Both mutation
tests verify preservation after denial, preventing a superficial response-only
fix. Reusing `DefaultAuthorizer` retains RBAC and makes its unconditional tenant
check authoritative. Missing items still fail without mutation. No new package,
unsafe code, cryptographic primitive, external network path or workflow
authority enters the change.

## Product pass

Same-tenant clients keep the existing methods, payloads and response shapes.
Cross-tenant behavior becomes consistently `403` for read, update and delete.
The README and changelog will state the authoritative-metadata rule and retain
the development-only warning.

## Decision

Proceed with M1 under the 10-path allow-list. Require two independent red tests,
the full locked workspace/static/supply-chain matrix, exact-head CI, verified
merge identity and an exact merged-main Codex Security rescan before closure.

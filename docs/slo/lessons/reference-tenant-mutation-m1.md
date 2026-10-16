# Reference-service tenant mutation M1 lessons

## What changed the design

The policy engine already had an unconditional cross-tenant deny, but the
mutation routes passed it a resource without tenant metadata. Security policy
cannot enforce context it never receives. The durable fix is to construct the
authorization resource from the authoritative stored record.

Checking the tenant after a write would prevent only the response, and loading
before authorization without preserving the snapshot would permit a time-of-
check/time-of-use gap. The existing Tokio lock provides a small, explicit
transaction boundary for this in-memory reference service.

## What worked

- Separate PUT and DELETE red tests captured both destructive transitions and
  their preservation requirements.
- Reusing `ResourceRef::with_tenant` and `with_owner` required no dependency or
  policy-engine change.
- A single `resource_for_item` helper keeps GET and both mutations aligned on the
  same resource identity and future owner-aware policy inputs.
- Verifying the stored representation after denial prevented a status-only fix.

## Reusable rule

Authorize the concrete resource that will be acted on. Derive tenant, owner and
other authority-bearing attributes from trusted storage, and keep the decision
and mutation in one transaction or versioned state transition.

## Follow-up

The reference service deliberately uses loopback development authentication and
an in-memory store. Production examples should demonstrate the same invariant
with trusted identity and datastore transactions. Other findings from the
whole-repository scan remain separate bounded milestones.

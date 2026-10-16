# Reference-service tenant mutation threat model

## Boundary and asset

The protected asset is each stored item's name, description, tenant binding and
existence. The caller supplies identity headers through explicitly development-
only middleware and supplies the route UUID and update body. The in-memory item
store is authoritative for tenant and owner metadata.

The service is loopback-only, but its routes are a copyable integration example.
The milestone therefore treats a valid administrator from another tenant as the
attacker and does not treat network binding or development authentication as a
substitute for object-level authorization.

## Abuse cases

| ID | Attacker action | Vulnerable transition | Required control |
|---|---|---|---|
| `tm-reference-tenant-1` | Tenant B administrator sends PUT for Tenant A's known item UUID | Generic `admin/items/write` succeeds on a tenant-less resource, then the shared item is overwritten | Load the item under the write lock, attach its tenant and owner to `ResourceRef`, deny before mutation |
| `tm-reference-tenant-2` | Tenant B administrator sends DELETE for Tenant A's known item UUID | Generic `admin/items/delete` succeeds on a tenant-less resource, then the shared item is removed | Authorize the stored item under the same write lock and remove only after allow |
| `tm-reference-tenant-3` | Concurrent operations change the item between lookup and mutation | Authorization applies to stale or different metadata | Keep the store lock from lookup through decision and mutation |

## Invariants

1. A stored tenant is always supplied to `DefaultAuthorizer`; a subject without
   that exact tenant receives `Decision::Deny` before write or removal.
2. The stored owner is supplied for future ownership/ABAC policy even though the
   current reference policy is role-based.
3. No attacker-controlled request field supplies the resource tenant or owner.
4. The lock-protected item used to construct the authorization resource is the
   same item that is returned, updated or removed.
5. Missing UUIDs return `404`; role and tenant denials return the existing `403`
   JSON shape and never disclose the item body.

## Residual limits

This repair does not make `DevAuth` production authentication, add durable
storage transactions, enforce owner-only mutation, hide UUID existence, or
turn the loopback reference binary into a production service. Downstream
services must derive identity from trusted authentication and preserve the same
authoritative resource-metadata rule at their storage boundary.

# High input boundaries M1 lessons

## What changed the implementation

The findings shared one root pattern: one parser or stage made a security
decision, then a later stage interpreted the same input differently. The URI
helper approved bytes that browsers normalize, the body extractor checked size
after collection, and SafeUrl classified a manual authority split before the
HTTP client reparsed the original string. The reliable repair was to make the
authoritative interpretation the value that crosses the boundary.

## What worked

- Red tests used the scan's exact witnesses before production edits. This kept
  the change tied to demonstrated dataflows rather than broad input rewriting.
- Axum's existing limited collector stops at `limit + 1` evidence and preserves
  transport-error distinction; sharing it prevents JSON/XML policy drift.
- The locked `url` parser eliminates a custom/downstream parser differential and
  provides a canonical value for callers.
- Treating copyable documentation as part of the XSS surface removed the raw
  interpolation example while preserving source compatibility.
- Dependency admission still added value with no new package identity: it proved
  the direct edge, checksum, publisher/source, lifecycle and complete graph were
  the intended already-reviewed packages.
- Feature-matrix testing caught configuration boundaries that an all-feature
  workspace run alone does not prove.

## Reusable rule

For an untrusted-input control, identify the parser, allocator or encoder that
actually has authority at the sink. Enforce the policy during that operation and
carry its canonical result forward. A pre-check followed by reparsing, a byte
limit checked after allocation, or validation without context encoding leaves a
second interpretation available to the attacker.

## Follow-up

The resolved-address helper intentionally stops short of owning DNS and socket
connection policy. A later bounded integration may expose a resolver/connector
that classifies every answer and pins the selected address. The remaining Codex
Security findings proceed in separate severity-ordered milestones so this fix
can be reviewed and rolled back independently.

## Merged-main scan lesson

A named blocklist can pass every original witness and still miss a newly relevant
special-purpose range. The merged-main scan caught exactly that with
`100.100.100.200`. For an outbound network boundary, the stronger invariant is
positive: accept ordinary public-unicast addresses and fail closed on shared,
local, documentation, benchmarking, reserved and transition ranges. The same
classifier must govern both typed URL hosts and every DNS answer.

The adjacent redirect finding reinforced the parser-authority rule. A leading
slash check is not an origin check when backslashes or encoded separators can be
normalized later. Resolve with the same URL model, verify the fixed origin, and
carry only its canonical relative serialization forward.

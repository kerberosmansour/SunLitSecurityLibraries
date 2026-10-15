# Semgrep MCP advisory M1 lessons

## What changed the plan

Package metadata showed that a direct MCP 1.30.0 update was impossible, but a
static dependency traversal initially suggested the unused server closure could
be removed. The real Linux scan disproved that assumption: Semgrep's common CLI
imports its MCP result models through metrics and state modules before command
dispatch. A dependency can be runtime-required even when the vulnerable feature
it implements is never invoked.

## What worked

- Candidate resolution and wheel inspection happened without executing package
  code, so the incompatible update failed before admission.
- The exact-head runtime gate caught the gap between metadata reachability and
  Python import reachability.
- Keeping OSV's original output intact made the final decision auditable. The
  receipt can record a review without changing what the scanner observed.
- Binding exceptions to lock path, ecosystem, package, version and advisory
  prevents a narrow decision from drifting onto another package or toolchain.
- Treating a stale exception as failure forces cleanup when upstream finally
  removes the advisory.

## Reusable rule

For security tools, do not prune an apparently optional dependency from package
metadata alone. Prove the exact production command in its intended operating
system and interpreter after complete OSV/provenance admission. When an upstream
exact constraint prevents a fix and the affected capability is demonstrably
unused, keep the finding visible and require a short, owned, reachability-based
exception with fail-closed expiry and identity drift tests.

## Follow-up

Before 2026-10-29, re-check the latest Semgrep release. Replace this record with
an admitted MCP 1.30.0-or-later graph as soon as Semgrep's metadata permits it.
Do not extend the date without repeating resolution, provenance, reachability,
OSV and exact-platform runtime review.

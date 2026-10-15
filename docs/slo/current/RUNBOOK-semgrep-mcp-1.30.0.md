# Semgrep MCP advisory bounded-exception runbook

## Milestone tracker

| Milestone | Title | Status | Notes |
|---|---|---|---|
| M1 | Enforce a bounded exception for Semgrep's resolver-locked MCP advisory | done (2026-10-15) | MCP 1.30.0 is fixed, but Semgrep 1.180.0 and 1.181.0 require MCP 1.29.0 exactly. Removing MCP also breaks the ordinary `semgrep scan` import path. See the [verification](../verify/semgrep-mcp-1.30.0.md), [lessons](../lessons/semgrep-mcp-1.30.0.md) and [completion record](../completion/semgrep-mcp-1.30.0.md). |

## Goal

Keep Semgrep's complete, resolver-consistent Python 3.11/Linux wheel graph while
making its remaining MCP 1.29.0 advisory explicit, visible and time-bounded.
GHSA-84m7-p3x7-pcfv / CVE-2026-59951 affects the stateful Streamable HTTP MCP
server. This repository invokes only `semgrep scan` and never starts or exposes
that server.

This is a temporary reachability disposition, not a claim that MCP 1.29.0 is
fixed. It expires on 2026-10-29 and must be replaced when upstream Semgrep admits
MCP 1.30.0 or later.

## Exact file allow-list

- `docs/slo/current/RUNBOOK-semgrep-mcp-1.30.0.md`
- `docs/slo/critique/semgrep-mcp-1.30.0.md`
- `docs/slo/verify/semgrep-mcp-1.30.0.md`
- `docs/slo/lessons/semgrep-mcp-1.30.0.md`
- `docs/slo/completion/semgrep-mcp-1.30.0.md`
- `tools/security-toolchains/semgrep/requirements.txt`
- `tools/security-toolchains/semgrep/exceptions.json`
- `tools/security-toolchains/README.md`
- `scripts/osv-dependency-gate.py`
- `scripts/test_osv_dependency_gate.py`
- `CHANGELOG.md`

Raw wheel, resolution, OSV, provenance and runtime evidence remains outside the
repository. No Cargo manifest/lock, workflow, library source, crate version or
release artifact may change.

## BDD acceptance scenarios

| ID | Scenario | Required result |
|---|---|---|
| BDD-M1-1 | Resolve MCP 1.30.0 against official Semgrep metadata without installing it. | Resolution fails closed because Semgrep requires `mcp==1.29.0`; no incompatible override is admitted. |
| BDD-M1-2 | Run the ordinary Semgrep scan from a graph with MCP and its presumed private closure removed. | The exact-head Linux job fails on Semgrep's unconditional common CLI imports, proving the removal-only profile is invalid. |
| BDD-M1-3 | Scan the restored, hash-pinned graph with the checksum-pinned official OSV scanner before installation. | All root and nested locks are inventoried, no `MAL-*` finding exists, and the raw report retains the exact MCP advisory and aliases. |
| BDD-M1-4 | Validate the toolchain exception manifest. | Only the exact lock path, PyPI ecosystem, package, version and advisory match passes; expiry, stale records, path/identity drift, malformed schema, duplicates and every malware identity fail closed. |
| BDD-M1-5 | Install the admitted graph in clean Python 3.11/Linux with hashes, binary-only wheels and no dependency resolution. | Installation succeeds and the repository's real `semgrep scan` completes; no MCP server is started or exposed. |
| BDD-M1-6 | Run repository admission tests and exact-head GitHub checks. | Governance, OSV, Semgrep, CodeQL, Rust/platform and supply-chain checks pass at the reviewed signed head. |

## Security invariants and exclusions

- PyPI is the only package source; source distributions and unverified hashes
  remain rejected.
- The candidate graph is scanned before installation. OSV covers known
  advisories and known malicious-package records; it does not prove absence of
  unknown malware.
- The original OSV JSON and summary keep the advisory. The exception is recorded
  separately in the receipt and cannot alter scanner output.
- Every vulnerable security-toolchain package requires exactly one matching,
  owned, unexpired, reachability-based record. Missing or stale records fail.
- A `MAL-*` primary ID or alias can never be excepted.
- The exception grants no repository, network, deployment or publication
  authority. The vulnerable MCP server path remains unused and unexposed.
- The three existing root Cargo findings keep their existing dispositions and
  are outside this milestone.

## Definition of done

- Every BDD row has recorded evidence and explicit limits.
- Verification and completion records are attached to AgentBus with hashes.
- The exact signed head passes GitHub CI and is merged only with a commit fence.
- Dependabot PR #146 is closed with the upstream resolver evidence only after the
  reviewed replacement merges.

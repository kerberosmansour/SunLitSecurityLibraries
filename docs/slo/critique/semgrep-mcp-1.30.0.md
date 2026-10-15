# Semgrep MCP advisory M1 critique

## CEO / scope pass

The repository needs a reliable source scanner. Semgrep 1.180.0 requires the
affected MCP release exactly, while the repository never operates an MCP server.
The smallest honest change keeps the working scanner graph and turns the known
advisory into a short-lived, machine-enforced exception. Updating unrelated
libraries, changing CI authority or publishing crates would expand the review
surface without resolving the upstream constraint.

## Engineering pass

The Dependabot substitution is not resolvable: both Semgrep 1.180.0 and 1.181.0
declare `mcp==1.29.0`. Forcing 1.30.0 contradicts the installed distribution
metadata. A removal-only 50-package profile also fails the real Linux scan:
Semgrep's common CLI imports `semgrep.mcp.models` through metrics/state modules,
which requires Pydantic and ultimately the MCP package even when the invoked
command is `semgrep scan`.

The requirements graph must therefore return byte-for-byte to the admitted
66-package baseline. The policy change belongs in the OSV gate and a dedicated
toolchain manifest, not in package resolution.

## Security pass

The exception must not suppress evidence. The official scanner's original JSON
and generated summary retain GHSA-84m7-p3x7-pcfv and CVE-2026-59951. The receipt
records the reviewed disposition separately. Validation binds the record to the
exact repository-relative lock path, ecosystem, package, version and advisory;
requires a named owner, canonical future date and reachability reason; rejects
extra schema; and fails when the finding disappears without record cleanup.

Every vulnerability in a security-toolchain lock requires exactly one matching
record, so deleting this manifest while leaving MCP 1.29.0 does not turn the
finding into a warning. A primary or alias `MAL-*` identity fails before matching
and cannot be excepted.

The reachability claim is narrow: the stateful Streamable HTTP MCP server is not
started or exposed. It does not certify the whole MCP package, Semgrep, or the
rest of the Python graph.

## Product / operations pass

The workflow already installs the hash-pinned graph with `--require-hashes`,
`--no-deps` and binary-only wheels after dependency admission. No workflow
authority change is required. The exception expires on 2026-10-29, providing a
short deadline to adopt an upstream Semgrep release compatible with MCP 1.30.0
or later. Exact-head Linux CI remains the runtime proof that the admitted graph
can scan this repository.

## Decision

Proceed with the eleven-file allow-list. Restore the complete resolver-consistent
Semgrep graph, add the exact expiring toolchain record, enforce it in the OSV
gate with mutation tests, and merge only after the raw advisory remains visible
and the real Linux scan passes.

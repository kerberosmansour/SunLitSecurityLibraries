# Semgrep MCP advisory M1 completion

## Delivered behavior

The Semgrep security toolchain remains resolver-consistent at MCP 1.29.0. Its
known denial-of-service advisory is visible in OSV output and governed by an
exact exception expiring on 2026-10-29. CI rejects missing, expired, overlong,
stale, malformed, ambiguous or identity-drifted records and rejects every
malware primary ID or alias.

The failed removal-only design was discarded. The final change adds no package,
changes no dependency version, starts no MCP server and grants no new workflow,
repository or publication authority.

## Verification summary

- Official OSV 2.7.0: 6 locks, 1,448 package occurrences, 4 visible
  vulnerabilities, 0 malware findings, exit 0.
- Dependency gate unit suite: 31 passed.
- Ubuntu/Python 3.11 Semgrep: 329 rules, 762 tracked targets, 0 findings.
- Exact implementation head `bf3a7f71850d4c0ac00a2dc3b25b24595e891a4a`:
  all CI, Semgrep, CodeQL and governance checks passed.
- Commit signature and DCO sign-off verified.

## Shipping handoff

PR #147 is the reviewed replacement. Merge only its exact final signed head
after the documentation-only closeout commit repeats required checks. After the
merge, close Dependabot PR #146 with the resolver conflict and replacement link.
No crate version or publication is required because this changes repository
security tooling and governance only.

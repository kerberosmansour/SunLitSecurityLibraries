# Repository agent instructions

<!-- dependency-admission-osv:v1 -->
## Dependency admission: OSV is required

Before introducing or updating a direct or transitive dependency, resolve the
candidate lockfile without lifecycle scripts or builds, then run the repository's
`python3 scripts/osv-dependency-gate.py`. Stage any new nested lockfiles so the gate
can discover them. Scan every resolved production/toolchain lockfile; fixture-only
vulnerable locks must remain isolated and must never be installed. Keep the exact
scan report, command, lockfile diff and disposition with the change.

A complete scan with no known malware is required before dependency installation with scripts,
building/testing the candidate, merge or publication. OSV queries known advisories
including known malicious-package reports; it does not detect all unknown malware
or prove package safety. Review publisher/source provenance, integrity checksums,
transitive changes, install scripts and unexpected network/native behavior too.
Use `--ignore-scripts` when inspecting npm candidates; do not run an unknown Cargo
build.rs/procedural macro before admission. Use official pinned/checksummed scanner
binaries, never a floating installer. No install/build credentials enter the scan.

Scanner/network/parsing failure is a failed admission check, not a clean result.
Never allow-list a known malicious package (`MAL-*` IDs or aliases); remove it and
investigate affected direct/transitive paths. Ordinary vulnerability findings are
non-blocking in the OSV gate, but remain in the full JSON report, summary and CI
warning. Review and remediate them; record exact versions, reachability, an owner
and a target date for deferred fixes. Do not describe report-only admission as a
vulnerability-free result. No scanner suppressions or severity filters. Preserve
cargo-vet audits, source/provenance checks and version holds; their independent
policies are unchanged.

Both Codex and Claude must follow this rule. Dependency changes use reviewed PRs;
scan jobs remain read-only and do not remediate or merge automatically.
<!-- /dependency-admission-osv:v1 -->

## Consumer integration skill

- [`sunlit-rust-security`](skills/sunlit-rust-security/SKILL.md) — published package selection and integration.
  See [consumer installation](docs/agents/integration.md); this index does not install the skill in other projects.

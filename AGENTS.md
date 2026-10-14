# Repository agent instructions

<!-- dependency-admission-osv:v1 -->
## Dependency admission: OSV is required

Before introducing or updating a direct or transitive dependency, resolve the
candidate lockfile without lifecycle scripts or builds, then run the repository's
`python3 scripts/osv-dependency-gate.py`. Stage any new nested lockfiles so the gate
can discover them. Scan every resolved production/toolchain lockfile; fixture-only
vulnerable locks must remain isolated and must never be installed. Keep the exact
scan report, command, lockfile diff and disposition with the change.

A successful scan is required before dependency installation with scripts,
building/testing the candidate, merge or publication. OSV queries known advisories
including known malicious-package reports; it does not detect all unknown malware
or prove package safety. Review publisher/source provenance, integrity checksums,
transitive changes, install scripts and unexpected network/native behavior too.
Use `--ignore-scripts` when inspecting npm candidates; do not run an unknown Cargo
build.rs/procedural macro before admission. Use official pinned/checksummed scanner
binaries, never a floating installer. No install/build credentials enter the scan.

Scanner/network/parsing failure is a failed admission check, not a clean result.
No blanket ignores or severity filters. Never allow-list a known malicious package
(`MAL-*`); remove it and investigate affected direct/transitive paths. A legitimate
unpatched vulnerability requires a documented exact-version, reachability, owner
and expiry exception enforced by CI. Preserve cargo-vet audits and version holds.

Both Codex and Claude must follow this rule. Dependency changes use reviewed PRs;
scan jobs remain read-only and do not remediate or merge automatically.
<!-- /dependency-admission-osv:v1 -->

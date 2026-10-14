# Dependency admission — SLO maintenance contract

Scope authorized 2026-10-14: make OSV mandatory for new/updated dependencies, CI and daily workflows, and standing Codex/Claude instructions. Preserve existing dependency audits; never bypass known malicious-package reports.

M1: a standard-library bootstrap for checksum-pinned official OSV 2.7.0, exact lockfile inventory, JSON and diagnostic evidence, fail-closed scan outcomes. Read-only reusable job precedes repository dependency execution; one scan shared by each build matrix. Daily SCA delegates directly, removing duplicate JS scanner installation/triage.
M2: validate negative boundaries, live inventory, workflow permissions/order and documentation; open and merge verified PRs. Rust additionally repairs four same-day rustls advisories with an exact reviewed delta.

| Contract | Constraint |
|---|---|
| Allow-list | scripts/osv-dependency-gate.py, scripts/test_osv_dependency_gate.py, scripts/check-maintenance-workflows.py; .github/workflows/osv-dependency-gate.yml; existing dependency-executing workflows; .gitignore; AGENTS.md; CLAUDE.md; README.md; docs/dev-guide/branch-protection.md; this contract. Rust additionally scripts/install-security-tool.py, scripts/run-security-tool.py, scripts/check-native-dependencies.py, scripts/test_install_security_tool.py, scripts/audit.sh, scripts/audit.ps1, sca-scope.json, scripts/locked-cargo.py, scripts/lock-kani-cargo.py, scripts/test_ci_integrations.py, tools/security-toolchains/semgrep/requirements.txt, tools/security-toolchains/README.md, tools/security-toolchains/recipes.json, tools/security-toolchains/cargo-audit/Cargo.lock, tools/security-toolchains/cargo-deny/Cargo.lock, tools/security-toolchains/cargo-vet/Cargo.lock, tools/security-toolchains/kani-verifier/Cargo.lock, docs/dev-guide/unsafe-budget.md, docs/dev-guide/formal-verification.md, Cargo.lock, supply-chain/audits.toml, CHANGELOG.md for the exact rustls repair. |
| Read-list | All changed workflows and root manifests/locks, existing scope and exception files, official OSV release metadata/SHA256SUMS/source documentation, existing workflow regressions. |
| Dependencies | No new project dependency; official scanner is a verified build tool. OSV version and six platform digests matched to official release metadata and published SHA256SUMS. |
| Compatibility | Existing test/check names retained. Read-only scans do not remediate, merge, execute install scripts or perform call analysis. Deliberate vulnerable fixture locks stay excluded and uninstalled. |
| Data classification | Internal: dependency inventory; no source code or credentials in scan requests. |
| Controls | OWASP C2 secure libraries: resolved direct/transitive graph admission; C5 validation: checksum/inventory/expiry boundaries; SSDF PW.4 identifier only. |
| Bounds/invariants | Binary <=64 MiB; HTTPS download timeout 60s; scan subprocess timeout 600s; CI 15min; mandatory nonempty complete inventory; zero write/OIDC credentials. |
| Abuse scenarios | Changed cached binary, symlink executable/lock, malicious waiver, partial/empty scan, findings paired with erroneous zero exit, scanner/network error cannot admit dependencies. |
| Exemplar/anti-exemplar | Reuse existing exact dependency trust guards; avoid npm bootstrap before scanning, floating installers, blanket ignores and autonomous privileged remediation. |
| Rollback | Gate removal restores unscanned admission and is unsuitable as a routine recovery; repair pinned scanner/network failures without weakening policy. |
| Refactor/AI | Direct workflow factoring only; no AI component. |
| Validation | Live scans; fifteen negative/ordering tests in each repo; existing workflow authority tests; YAML/governance/formatter checks; unchanged product tests where appropriate; Rust audit/deny/vet/all-feature tests. |
| Definition of done | Real scans complete; negative cases fail correctly; production jobs depend on scanner; reports survive failures; instructions/docs reflect known-malware limits; PR checks pass before merge. |

Initial evidence: Hulumi 630 resolved packages across two locks; Rust 1,382 across five root/toolchain Cargo locks (514 library packages). Both live OSV scans pass; Rust retains three explicit vulnerability dispositions enforced by the existing exact-version/expiry guard. All fifteen admission tests and existing maintenance-authority tests pass. Cargo.lock changes only rustls version/checksum; audited graph retained. Final CI evidence is recorded at PR closeout.

Security tool graphs: compatible source-tool refreshes scan clean before building.
Source archive SHA256 and VCS commits were verified in official repositories.
Cargo-vet audit evaluation code remains unchanged; its documented manifest-only
reqwest/indicatif overlay removes unpatched legacy transport and unmaintained
progress dependencies. The rebuilt verifier reports the same audited graph.
Known unpatched cargo-geiger dependencies prevent its optional inventory from
running; no advisory waiver was added. Required unsafe/native/SAST/Kani checks
remain. Full tool graph admission reports are retained; root library exceptions
cannot suppress tool findings.

Follow-up boundary evidence: native override checks examine process and Cargo-config
namespaces separately so a non-forced config cannot hide a process override;
Rust admission requires the guard. Tool execution selects its exact built binary,
verifies the installed digest against the admitted source/lock recipe and supplies
Cargo's required subcommand environment. Kani's Linux compiler bundle has an
independently verified official-release SHA256 before setup. No cargo-geiger
waiver and no floating npm package install remain.

CI repair evidence: the first real GitHub run passed all 21 protected CI checks,
including Linux/macOS/Windows and the feature matrix. Additional lanes exposed
unsupported Kani --locked arguments, unclassified nested locks, Semgrep's old
vulnerable Python graph and a Dastardly registry/report-permission failure.
Kani now wraps only its repository-owned verified SDK Cargo, adding --locked to
actual compilation/metadata calls without editing the shared SDK. Dastardly uses
an official digest-pinned image, bounded pull retries and a standard-library
report verifier with read-only GitHub permissions. Scope classification includes
all nested tool locks. Semgrep 1.180.0's 66 hash-pinned wheels were independently
matched to official PyPI version metadata and inspected for install hooks/path
traversal; none were found. Its complete graph scans clean, before installation.
No MCP server or JWT authentication service is activated by source scanning.
The final live Rust scan covers six locks / 1,448 resolved package occurrences.
OSV detects known advisories, including malware reports; wheel integrity and
provenance review do not establish absence of unknown malicious code.

Independent review follow-up: Cargo global flags and arguments after `--` could
bypass the initial wrapper; incomplete DAST XML could falsely pass. Both were
reproduced by failing tests, then repaired. The wrapper parses global option
values and checks locking flags only before the application argument separator.
The report requires a completed suite with explicit nonnegative counts. Pinned
Kani driver source confirms release setup/metadata/build selects
`kani_dir/toolchain/bin/cargo`, not the runner CARGO environment variable.
Real Kani/DAST GitHub execution remains required before merge. Host network
access for loopback DAST and mutable upstream Semgrep rules are disclosed tool
containment/reproducibility limits; no source or credentials are sent to a model.

Maintainer decision: remove the redundant example-service DAST workflow after
its anonymous registry data quota repeatedly prevented the image pull. The
unused newly introduced XML helper/tests were removed too; no passing DAST
result is claimed. The required-check entry is replaced by OSV admission, while
all other protections remain. Local DAST helpers are research-only. All14 Kani
harnesses genuinely executed and passed in run38594854285; Semgrep/scope pass.

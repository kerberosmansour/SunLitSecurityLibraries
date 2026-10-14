# Security maintenance — 2026-10-14

SLO v4 maintenance contract. Owner: repository maintainer. Branch: `maintenance/security-refresh-2026-10-14`.
The user authorized dependency updates, security remediation, documentation, publication, and evidence-backed admin merges.

## Scope and compatibility
Update the existing dependency set; add no new production packages merely for convenience.
Retain public APIs and wire formats unless fail-closed security enforcement requires a documented migration.
Public source and release metadata; credentials remain Restricted and never enter evidence.
No live cloud infrastructure changes or destructive cleanup. Rollback: revert the maintenance merge; consumers may pin a previous version, with its documented security limitations.
No AI runtime behavior introduced. Measurement: N/A — maintenance of existing capabilities.

## Tracker
| Milestone | Status | Definition of done |
|---|---|---|
| M1 — dependencies and CI | done | Fresh audits, existing build/tests, reduced duplication, no PR code executed with privileged credentials |
| M2 — library security findings | done | Each report checked against current source; confirmed defects have failing-then-passing regressions; remaining dispositions explicit |
| M3 — release preparation and documentation | done | Twelve coordinated library versions/references and declarations, inspected package lists and core publication dry run; actual merge/publication tracked below |

## M1 contract
Read first: root manifests/lockfiles, CI/auto-merge/SCA/release workflows, dependency-update PR diffs, latest failed CI logs, architecture and security docs.
Allowed changes: Cargo.toml; Cargo.lock; crates/*/Cargo.toml (explicit workspace members only); .github/workflows/ci.yml; .github/workflows/dependabot-automerge.yml; .github/workflows/sca-emergency.yml; .github/workflows/tla.yml; .github/workflows/kani.yml; .github/workflows/codeql.yml; .github/workflows/semgrep.yml; .github/workflows/native-device-trust-conformance.yml; .github/workflows/release-sign.yml; .github/dependabot.yml; deny.toml; supply-chain/config.toml; supply-chain/audits.toml; crates/secure_smoke_service/src/routes/authz.rs; crates/secure_smoke_service/tests/*; scripts/check-maintenance-workflows.py; this contract and maintenance verification/release docs.
Exemplar: existing checksum-pinned OSV installation and read-only CI checkouts.
Anti-exemplar: any privileged checkout of a dependency PR followed by install/build/test.
Controls: OWASP C2 Use Cryptography to Protect Data (artifact integrity); C6 Implement Digital Identity (separate CI authority); C10 Handle All Errors and Exceptions (fail closed).
Abuse scenario: a malicious dependency/action patch must require maintainer review and must never inherit a merge or release token during tests.
Bounds: presubmit checks use finite job timeouts; scheduled SCA once daily plus manual dispatch.
Forbidden shortcuts: skipping failing security gates, blanket advisory ignores, floating action tags, fake passing checks, `--no-verify`, or force pushes.
Refactoring: only behavior-preserving CI deduplication with coverage retained; library bugs belong in M2.
Static gates: cargo fmt, clippy, audit, deny, vet.

## Acceptance and evidence
| Scenario/check | Expected | Actual | Status |
|---|---|---|---|
| Baseline | Capture current failing state before fixes | Historical CI failures and failing-then-passing security regressions captured privately | pass |
| Supply chain | Known vulnerabilities remediated or explicitly assessed; lock integrity preserved | pending | pending |
| Privileged CI | Cannot execute arbitrary PR code or auto-merge an action update | pending | pending |
| Regressions | Existing security and compatibility tests pass | pending | pending |
| CI cost | Remove repeated work without removing required coverage | pending | pending |
| Release | Registry/package/signing checks and post-merge CI confirmed | pending | pending |

## Secure release contract
Bundles B/D as applicable: library abuse/unit tests, SCA, static gates; IaC uses generated-resource/policy tests.
No new deployed service; DAST applies only to an existing smoke service when its behavior changes.
Artifact SBOM/provenance required at release. Maintainer owns residual findings, with precise reason and review date.
Detected Work Ledger: Codex Security findings captured privately; every finding receives fix_now, accepted_risk, operator_action, or upstream_feedback with evidence before closure.

## M2 contract — Rust library boundaries
Read and change only: crates/secure_identity/src/jwks.rs; crates/secure_identity/tests/sunlit_imp_jwks.rs; crates/secure_data/src/pq/kem.rs; crates/secure_data/tests/pqd_m2_hybrid_kem.rs; crates/secure_resilience/src/circuit_breaker.rs; crates/secure_resilience/tests/fv_m4_circuit_breaker.rs; crates/secure_boundary/src/prompt_boundary.rs; crates/secure_boundary/tests/prompt_boundary.rs; crates/security_core/tests/no_unsafe_code.rs; crates/secure_errors/src/proofs.rs; crates/secure_data/src/proofs.rs; relevant crate README files and docs/dev-guide/{formal-verification,unsafe-budget,secure-boundary,secure-identity,secure-data}.md; README.md; CHANGELOG.md; ARCHITECTURE.md; declarations/cyclonedx-1.6-capabilities.json; this contract and verification reports.
Compatibility: retain default constructor signatures; HTTP JWKS fetches fail closed. Test HTTP requires explicit dev-only loopback opt-in. No secret bytes in Debug. Stale circuit calls cannot mutate a new generation or release another call's probe. All forbidden Unicode directional controls rejected.
Bounds: JWKS 10-second request cap and bounded response; deterministic channel-controlled concurrency tests. No new production dependencies.
Exemplars: workload.rs HTTPS transport validation; existing redacted secret Debug types and channel/barrier tests. No blanket test exception or disabled failure reporting.
Regression-first: plaintext JWKS rejection; derived-key Debug redaction; stale Closed completion while a probe is in flight; omitted Unicode bidi controls. Proof claims must name the actual harness/assumptions; no whole-system claim.
Verification: cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace --locked; feature suites for jwks+dev and pq; cargo audit; cargo deny; cargo vet; Kani/TLC only at verified tool versions and relevant bounds.

M2 allow-list refinement: crates/secure_smoke_service/src/main.rs — the regression found the binary root lacked compiler unsafe prohibition; fix this compiled target as authorized security maintenance. M1 supply-chain/imports.lock records refreshed existing upstream audit feeds.

M1 scope clarification (user-confirmed): fix all reported vulnerabilities; review pending updates in small batches while preserving the audited graph elsewhere. Full-lock refresh was discarded. Native dependency boundary refinement: .cargo/config.toml; scripts/check-native-dependencies.py; CI; native build notes in the release evidence. Independent review identified optional DES weakness and external-library discovery authority. No blanket crypto or cargo-vet approval follows from that review; legacy-DES/FIPS/SSL features outside the reviewed graph are blocked, repository builds force bundled AWS-LC, and target-specific discovery overrides fail CI.

M2 documentation refinement: crates/secure_data/src/{lib.rs,pq/mod.rs}, crate README, root README/ARCHITECTURE and secure-data guide. Source review found the `fips` feature does not route envelope AEAD to AWS-LC and the documented EnvelopeEncrypted.pq_fips_status field does not exist. Correct those claims without inventing a validated backend. The runtime fips_status function remains an implementation label, not certification evidence.

M2 concurrency variant: downstream panic in a HalfOpen probe left the reservation stuck. A failing catch_unwind regression now passes with a generation-bound RAII reservation; no stale call releases a later generation's probe. The abstract TLA model does not represent this unwind refinement; runtime regression evidence is recorded separately.

M1 review outcome: exact lru 0.18.3 includes the earlier pop panic-safety fix while excluding later retain APIs flagged by independent review. Redis's existing xxhash-rust transitive dependency is constrained to the reviewed 0.8.15 default-secret path; later generic SecretInput APIs are held. Native AWS-LC versions retain exact temporary cargo-vet exemptions rather than fabricated whole-vendor audits; expiry, feature/version scope, bundled source and trusted formatter are CI-gated. An unchanged smartstring 1.0.1 informational unmaintained warning is deferred until 2026-11-14 with the same exact-version/owner/expiry gate; no patched upstream version exists. Outdated lru/webpki advisory ignores are removed. Spin 0.9.8 is replaced with 0.9.9's focused Once double-drop repair.

## M3 release contract
Allowed changes: public library manifests and internal version requirements; root/package READMEs, CHANGELOG, architecture and development/component/release docs affected by verified behavior; capability declarations; release workflow guard and signing isolation; this contract and matching release tests. Services remain unpublished. No full Rust dependency refresh. Validate exact tagged main ancestry, coordinated versions, package manifests/file lists, relevant full suite and registry readiness. Publishing is sequential and immutable: verify existing registry state before retrying. No infrastructure apply or human security-certification claim.

M1 scope refinement: osv-scanner.toml and the exact-version maintenance exception manifest align the already accepted RSA public-verification advisory with all scanners. The old OSV expiry was 2026-09-01; revalidated source contains public verification only, RustSec still has no patched version, and the renewed scope expires 2026-11-14 under the CI guard. No blanket ignore is added.

M1 targeted AWS batch: parser 0.62.5→0.62.7, runtime-api 1.12.0→1.12.3, types 1.4.7→1.4.9, schema 0.1.0 required by the parser. The independent review found new schema/codec defects outside retained generated SDK paths; exact JSON/schema exceptions expire 2026-11-14, with pinned SDK/parser versions and review guard. No broad certification or malicious package claim. Public reports/updated guards are within the existing dependency, verification and documentation allow-list.

Final CI refinement within M1: optional-feature workspace tests run on Linux; middleware matrix retains all twelve protected names/feature combinations but uses cargo test alone (which compiles them), removing the redundant metadata check. Advisory Kani/TLC run on relevant changes plus weekly/manual, preserving the declared proof/model scope. TLC negative evidence must contain an invariant counterexample and missing model files fail.

## Final verification evidence — 2026-10-14
- Targeted dependency graph adds 27 registry package versions and removes 40 against the original lock. Other audited/policy-accepted versions are preserved; no full dependency refresh. Registry-origin/checksum records are maintained. cargo audit reports zero unaccepted vulnerabilities; cargo deny advisory/bans/licenses/sources pass; cargo vet --locked passes under explicit pre-existing baseline and narrowly described new exceptions; OSV reports zero unaccepted groups after exact, dated dispositions.
- Full workspace all-feature tests, all-target/all-feature Clippy (-D warnings), rustdoc (-D warnings), formatting and actionlint pass on the final graph. JWKS/dev, KEM, bidi and circuit-breaker generation/unwind regressions failed before their fixes and pass afterward. Native boundary self-tests (5), workflow authority tests (4), actual guard and offline fixture drill pass. Cross-OS behavior awaits GitHub matrix verification.
- Kani bounded public-error whitelist proof passed with unwind 64 and assertion-reach checks disabled (coverage limitation explicit); copy/length smoke proofs do not prove RNG uniqueness. CircuitBreaker/SessionStepUp hardened abstract TLC models passed and naive models produced counterexamples. Runtime generation/unwind safety is tested independently of those abstract models.
- Twelve manifest/package-list checks confirm the dependency publish order; security_core 0.2.0 passed cargo publish --dry-run --locked. Dependent dry runs occur immediately before upload after prerequisite 0.2.0 registry versions exist. Local dirty-tree allowance was used only for preparation; actual publication requires a clean tested release commit.
- Independent source review of changed application security paths found no further introduced Rust defect. Native/pointer and Smithy review limitations are preserved: unresolved new custom-secret/schema APIs are outside mapped application paths; no broad crypto/native/API certification is claimed. Vendor defect details remain private; no upstream disclosure message was sent.

## Post-ship closeout — required and still pending
Record GitHub checks, actual merge, twelve registry uploads/dry runs/checksums, v0.2.0 tag/signing artifacts, GitHub release and Codex Security closure after completion. Prepared artifacts are not published artifacts. This goal remains active until closeout. No cloud infrastructure was deployed.

## Residual ownership and lessons
Repository maintainer owns 2026-11-14 expiry for the two native crypto exceptions, two legacy-SDK-only Smithy exceptions, unchanged smartstring maintenance notice, RSA public verification and unused xxhash custom-secret advisory. CI guards enforce versions/features/expiry; downstream consumers must audit their own graph. Retain small dependency batches, validate OSV as well as RustSec, map actual callers before acceptance, and never convert a scoped exception into a fabricated audit. Release packaging is sequential, so verify registry state before retrying. Rollback is a reviewed revert/new immutable release; yanking cannot erase published contents.

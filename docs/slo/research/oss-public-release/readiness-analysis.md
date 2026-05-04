# SunLit Security Libraries — Public-Release Readiness Analysis

**Date:** 2026-04-25
**Author:** Conversation between repo owner (kerberosmansour / cherifmansour@gmail.com) and Claude Code
**Status:** Pre-research — feeds `/slo-research` then `/slo-plan`
**Scope:** What is required to take SunLit Security Libraries from internal/private to publicly released as a *mission-critical* open-source project.

> **Post-cleanup note (2026-05-01):** the P0 governance/legal scaffold
> identified here has now landed: `LICENSE`, `LICENSE-MIT`,
> `LICENSE-APACHE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`,
> `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `GOVERNANCE.md`, `MAINTAINERS.md`,
> `.github/CODEOWNERS`, issue templates, PR template, and Dependabot config.
> Crate manifests now declare `MIT OR Apache-2.0`. The snapshot below is kept
> as historical input to the public-release runbook.

---

## 1. Goal

Take the SunLit Security Libraries Rust workspace public on GitHub + crates.io with the security, supply-chain, governance, and trust posture appropriate for a library set marketed as **mission critical** (security primitives consumed by other people's production systems / critical infrastructure). The user explicitly asked about:

1. Software-supply-chain risk coverage
2. Additional CI/CD security controls

…plus the implicit broader question of "what else does primetime require." This document captures both.

## 2. Current state (snapshot as of 2026-04-25)

**Repository:** `github.com/kerberosmansour/SunLitSecurityLibraries` (currently private). Branch `main`.

**Workspace shape:** 13 crates under `crates/` — `security_core`, `security_events`, `secure_errors`, `secure_boundary`, `secure_authz`, `secure_data`, `secure_output`, `secure_identity`, `secure_network`, `secure_resilience`, `secure_privacy`, `secure_reference_service`, `secure_smoke_service`. All currently at `version = 0.1.0`, `license = "MIT"`, `edition = "2021"`.

**What's already in place (strong foundation):**

- Threat model: [`THREAT_MODEL.md`](../../../../THREAT_MODEL.md) — STRIDE-based, mapped to NIST 800-53 / IEC 62443 / SOC 2.
- Architecture doc: [`ARCHITECTURE.md`](../../../../ARCHITECTURE.md).
- Detailed [`README.md`](../../../../README.md) documenting OWASP Proactive Controls coverage per crate.
- CI pipeline at [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml):
  - Multi-OS test matrix (ubuntu, macos, windows) with clippy `-D warnings`, fmt, doc.
  - `feature-matrix` job exercising `secure_boundary`/`secure_authz`/`secure_errors` across `axum`/`actix-web`/both/none.
  - `rustdoc-warnings` job (`RUSTDOCFLAGS: -D warnings`).
  - `supply-chain` job running `cargo audit`, `cargo deny check`, `cargo vet`.
- DAST workflow: [`dastardly.yml`](../../../../.github/workflows/dastardly.yml) targeting `secure_smoke_service`; ZAP remains as local-only tooling.
- Supply-chain config:
  - [`deny.toml`](../../../../deny.toml) — well-justified RUSTSEC ignores (5 entries, each with a written rationale tied to actual usage), license allowlist (MIT / Apache-2.0 / BSD-2/3 / ISC / Unicode / Zlib / CC0), license exceptions for unavoidable transitive deps (`r-efi` LGPL, `smartstring` MPL).
  - [`supply-chain/config.toml`](../../../../supply-chain/config.toml) — cargo-vet config with ~990 lines of exemptions (every transitive dep marked `safe-to-deploy` / `safe-to-run`).
  - [`supply-chain/imports.lock`](../../../../supply-chain/imports.lock) — vet imports lockfile present (good — means external audit imports are reproducible).
  - [`supply-chain/audits.toml`](../../../../supply-chain/audits.toml) — local audits.

**What's NOT in place (the gaps this initiative addresses):**

- No `LICENSE` file at repo root — manifests claim MIT but the legal text doesn't exist in-repo.
- No `SECURITY.md` (vuln disclosure policy / contact / SLA).
- No `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CODEOWNERS`, `GOVERNANCE.md`, issue/PR templates.
- README missing install snippet, MSRV, SemVer/stability statement.
- All crates at `0.1.0` — no public stability commitment.
- No Dependabot config (`.github/dependabot.yml`).
- No SBOM generation, no SLSA build provenance attestation, no artifact signing.
- GitHub Actions are pinned to mutable refs (`@v4`, `@v2`, `@stable`, **`@main`** for `PortSwigger/dastardly-github-action`).
- No top-level `permissions:` block in [`ci.yml`](../../../../.github/workflows/ci.yml) → workflows inherit broad GITHUB_TOKEN scopes.
- `cargo install cargo-audit cargo-deny cargo-vet` in CI installs unpinned latest at job time → supply-chain tooling itself is unpinned.
- No `--locked` flag on cargo invocations.
- No `actions/dependency-review-action` on PRs.
- No OpenSSF Scorecard workflow.
- No `step-security/harden-runner` (egress audit).
- No CodeQL / Semgrep / OSV-Scanner / gitleaks.
- No `cargo semver-checks` on PRs.
- No MSRV pinning (`rust-version = …`) and no MSRV CI job.
- No coverage measurement (`cargo-llvm-cov` or similar).
- No fuzzing — neither in-tree `cargo-fuzz` harnesses nor OSS-Fuzz integration, despite parsers in `secure_boundary` (HTML sanitizer, JSON limits), `secure_identity` (JWT/OIDC), `security_events` (regex sinks).
- No mutation testing (`cargo-mutants`).
- No release workflow / `release-plz` / cargo-release.
- No `cargo geiger` unsafe audit.
- No reproducible-build verification.
- No OpenSSF Best Practices Badge applied for.

## 3. Prioritized gap list

Items are tagged with priority (P0/P1/P2) and a rough effort estimate. P0 = blocker before going public; P1 = required for "mission critical" trust posture; P2 = ongoing-quality / 1.0 readiness.

### P0 — blockers before the repo is public

| # | Item | Effort |
|---|---|---|
| P0-1 | Add `LICENSE-MIT` and `LICENSE-APACHE` files at repo root (dual-license `MIT OR Apache-2.0`); update every crate manifest's `license` field to `"MIT OR Apache-2.0"`. Apache-2.0 supplies the explicit patent grant that MIT lacks — important for enterprise/critical-infra adopters. | 30 min |
| P0-2 | Write [`SECURITY.md`](../../../../SECURITY.md): private disclosure email + optional PGP, supported-versions table, response SLA, GHSA flow, scope statement. | 1 hr |
| P0-3 | Write [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md) with DCO sign-off requirement, dev setup, PR process, security-sensitive-path callouts. | 1 hr |
| P0-4 | Write [`CODE_OF_CONDUCT.md`](../../../../CODE_OF_CONDUCT.md) (Contributor Covenant 2.1) + enforcement contact. | 15 min |
| P0-5 | Write [`CHANGELOG.md`](../../../../CHANGELOG.md) seeded with current state in Keep-a-Changelog format. | 30 min |
| P0-6 | Add [`CODEOWNERS`](../../../../.github/CODEOWNERS) gating `crates/secure_*`, `.github/workflows/`, `deny.toml`, `supply-chain/` to required reviewers. | 15 min |
| P0-7 | Add issue + PR templates under `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md` (separate templates for `bug`, `feature`, `vuln→see SECURITY.md redirect`). | 30 min |
| P0-8 | README: add install snippet, MSRV statement, SemVer/stability section, link to SECURITY.md, badges (CI, license, crates.io once published, Scorecard). | 1 hr |

### P1 — supply-chain hardening (the user explicitly asked)

| # | Item | Effort |
|---|---|---|
| P1-1 | **Pin every GitHub Action to a full commit SHA** with semver tag in trailing comment. Critical: replace `PortSwigger/dastardly-github-action@main` (mutable branch) with SHA. Add `package-ecosystem: github-actions` to Dependabot to keep SHAs current. | 2 hrs |
| P1-2 | Add least-privilege `permissions:` blocks. `permissions: contents: read` at workflow root in [`ci.yml`](../../../../.github/workflows/ci.yml); elevate per-job (e.g., `id-token: write` only on the provenance job). | 1 hr |
| P1-3 | Add `--locked` to all cargo invocations (`cargo test --locked`, `cargo audit --locked`, `cargo build --locked`, etc.). | 30 min |
| P1-4 | Pin `cargo-audit` / `cargo-deny` / `cargo-vet` versions in CI. Use `taiki-e/install-action` (SHA-pinned) with explicit `--version`, or vendor pre-built binaries via cache. | 1 hr |
| P1-5 | Add [`.github/dependabot.yml`](../../../../.github/dependabot.yml) for `cargo` (workspace) + `github-actions` ecosystems; weekly cadence; security updates immediate. | 30 min |
| P1-6 | Generate **CycloneDX SBOM** per release using `cargo-cyclonedx` (or `syft`); attach as a release asset. | 2 hrs |
| P1-7 | Add **SLSA build provenance attestation** via `actions/attest-build-provenance@v2` (signed via GitHub's OIDC → Sigstore Fulcio). Targets SLSA Level 3. | 2 hrs |
| P1-8 | **Sign release artifacts with cosign keyless** (Sigstore via OIDC). Document `cosign verify-blob` instructions in README. | 2 hrs |
| P1-9 | Add `actions/dependency-review-action` on PRs to block introduction of vulnerable / disallowed-license deps before merge. | 30 min |
| P1-10 | Add **OpenSSF Scorecard** workflow (`.github/workflows/scorecard.yml`) running weekly + on push to default branch. Aim for ≥7. | 30 min |
| P1-11 | Add **`step-security/harden-runner`** to every workflow with `egress-policy: audit` initially → `block` after baseline established. Catches malicious deps phoning home during build. | 1 hr |
| P1-12 | Subscribe to cargo-vet imports from Mozilla / Google / Bytecode Alliance / Embark via `[imports]` in [`supply-chain/config.toml`](../../../../supply-chain/config.toml). Document a written burn-down target ("≤50 exemptions by 1.0"). | 2 hrs initial + ongoing |
| P1-13 | Add CI nag (cron or PR check) that fails if any RUSTSEC ignore in [`deny.toml`](../../../../deny.toml) has been in place > N days without a re-justification commit. | 1 hr |
| P1-14 | Apply to **OSS-Fuzz** for `secure_boundary` (HTML sanitizer, JSON limit parser), `secure_identity` (JWT/OIDC), and `security_events` (regex/redaction) parsers. Add minimal `cargo-fuzz` harnesses in-tree first. | 4-8 hrs |
| P1-15 | Reproducible-build verification: two-runner build → sha256 compare on workspace artifacts; flag drift in CI. | 2 hrs |

### P1 — additional CI/CD security controls

| # | Item | Effort |
|---|---|---|
| P1-16 | Add **CodeQL** (Rust public preview) and/or **Semgrep** with a Rust ruleset. | 1 hr |
| P1-17 | Add **OSV-Scanner** alongside `cargo audit` (broader source coverage: GHSA + OSV.dev, not just RUSTSEC). | 30 min |
| P1-18 | Add **gitleaks** secret scan to every PR. | 30 min |
| P1-19 | Add **`cargo semver-checks`** on PRs to catch breaking-change leaks before publish. | 1 hr |
| P1-20 | **Pin MSRV.** Add `rust-version = "1.NN"` to every crate manifest; add a CI job that runs on exactly that toolchain (in addition to `stable`). | 1 hr |
| P1-21 | **Branch protection rules** (configured via GitHub repo settings, documented in `docs/slo/research/oss-public-release/branch-protection.md`): required status checks (`test (ubuntu-latest)`, `feature-matrix`, `rustdoc-warnings`, `supply-chain`, `scorecard`, `codeql`); required reviews (≥1, codeowner-required); required signed commits; require linear history; disallow force-push; disallow deletion. | 1 hr |
| P1-22 | **GitHub repo settings**: enable secret scanning + push protection, Dependabot security updates, private vulnerability reporting (GHSA inbox), discussions (optional). | 30 min |
| P1-23 | **DAST gating policy**: confirm [`dastardly.yml`](../../../../.github/workflows/dastardly.yml) fails the build on High/Critical findings, not just upload artifacts; keep ZAP as an optional local OpenAPI-driven scan. | 1 hr |
| P1-24 | **Coverage gate**: wire `cargo-llvm-cov`; publish to codecov/coveralls; per-crate floor (e.g. 85%) for security-invariant crates. | 2 hrs |

### P2 — mission-critical / 1.0 readiness

| # | Item | Effort |
|---|---|---|
| P2-1 | **Cut a `1.0` release.** Lock public APIs across all 13 crates; document each crate's API stability commitment. Pre-1.0 SemVer is a non-starter for "mission critical" trust. | 1-2 weeks (API audit) |
| P2-2 | `cargo geiger` unsafe audit per crate; document unsafe-code policy; weekly miri run for crates that contain unsafe blocks; ASAN/UBSAN runs for FFI (`ring`, `aws-lc-rs`). | 4 hrs |
| P2-3 | Apply for **OpenSSF Best Practices Badge** ("passing" first; "silver" is the next bar). | 2 hrs |
| P2-4 | **Mutation testing** with `cargo-mutants` on security-critical crates; tests must catch invariant violations, not just code paths. | 4 hrs (initial), ongoing |
| P2-5 | **Property-based test inventory.** `proptest` is already a dep — make sure each named security invariant in [`THREAT_MODEL.md`](../../../../THREAT_MODEL.md) has a documented property test. | 1 day |
| P2-6 | Write [`GOVERNANCE.md`](../../../../GOVERNANCE.md) + [`MAINTAINERS.md`](../../../../MAINTAINERS.md). Solo-maintainer is fine — just say so. | 1 hr |
| P2-7 | **Release workflow** via `release-plz` or `cargo-release`. Move to **crates.io trusted publishing** (OIDC, no long-lived `CRATES_IO_TOKEN`) once stable; until then, store token in GitHub Environment with required-reviewer approval. | 4 hrs |
| P2-8 | **LTS / EOL policy** in writing — e.g., "1.x maintained for 18 months past 2.0 release." | 1 hr |
| P2-9 | Examples directory per crate showing safe usage; publish to `docs.rs` with feature flags fully documented. | 1 day |
| P2-10 | Threat-model continuity process — update [`THREAT_MODEL.md`](../../../../THREAT_MODEL.md) per release; PR template gate ("did this change the threat model?"). | 1 hr |

## 4. Open research questions (input to `/slo-research`)

The codebase cannot answer these — they're "current best practice in 2026" / external-system questions:

1. **Crates.io trusted publishing status** — As of 2026-04-25, is OIDC trusted publishing for crates.io GA, beta, or still proposed? If GA, mandate it and skip the long-lived-token interim. If not, define the interim posture.
2. **SLSA tier target** — Is SLSA Level 3 achievable end-to-end with `actions/attest-build-provenance@v2` for a multi-crate Rust workspace, or does Level 3 require the SLSA L3 reusable workflow framework and only Level 2 is reachable with attest-build-provenance alone?
3. **OSS-Fuzz onboarding** — Current acceptance criteria, expected onboarding turnaround, what an idiomatic Rust harness looks like for HTML sanitizer / JWT parser / regex sinks. Is the rust integration in OSS-Fuzz stable as of 2026?
4. **CodeQL Rust support** — Public-preview status today; gaps vs. C/C++/Java. If still preview-only, is `semgrep --config p/rust` (or `cargo-semgrep`) the better default?
5. **Sigstore / cosign keyless verification UX** — What's the verification command surface for a downstream consumer? Is the trust root still requiring `--certificate-identity` + `--certificate-oidc-issuer` flags, or has there been a UX simplification?
6. **`step-security/harden-runner` egress baseline** — How long does the audit-mode burn-in typically need before flipping to block-mode without false positives in a Rust-heavy CI? Does the action currently support GitHub-hosted runners on macOS / Windows, or Linux-only?
7. **`actions/dependency-review-action` Cargo support** — Confirm Cargo lockfile parsing is GA (was preview at one point); confirm policy file format for license + advisory blocks.
8. **OpenSSF Scorecard scoring quirks** — Which checks are flaky / known-low for a single-maintainer Rust repo? What's the realistic "stretch" score after this work (8? 9?)?
9. **Cargo-vet imports.lock from major orgs** — Confirm Mozilla / Google / Bytecode Alliance / Embark publish vet audit imports compatible with cargo-vet 0.10; document the exact `[imports]` URLs.
10. **`cargo semver-checks` accuracy** — Known false-positive rate; whether it handles `feature = …` gated APIs correctly (this workspace uses feature gates extensively).
11. **GHSA + RUSTSEC dual reporting** — Is the canonical workflow today still "report to RUSTSEC AND open GHSA" or has the Rust ecosystem unified on one?
12. **MSRV target** — What's the de-facto floor for security-library MSRV in 2026 (`1.74`? `1.78`?). Pick a defensible number with reasoning rather than "latest stable minus N."
13. **`secure_smoke_service` + ZAP/Dastardly fail thresholds** — Industry norms for fail-on-finding severity in DAST CI; whether the current configs already meet it (need to read the workflow YAML carefully).
14. **License-grant strategy** — Confirm `MIT OR Apache-2.0` is still the unambiguous Rust ecosystem default in 2026; or has there been movement (e.g., toward Apache-2.0 only with patent grant)?

## 5. Suggested SLO pipeline path

Given the system is already designed and most of the "what" is known, the recommended sequence is:

1. **`/slo-research`** — answer the 14 open questions in §4 → produces sourced dossier.
2. **Skip `/slo-architect`** — this is feature-addition to an already-designed workspace, not a new design.
3. **Skip `/slo-tla`** — no new concurrency or distributed-state surface introduced by hardening work.
4. **`/slo-plan`** — author the v3 runbook, **maximum 5 milestones** (per slo-plan's hard cap). Suggested split:
   - **M1: Legal + governance scaffolding** (P0-1 through P0-8) — LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG, CODEOWNERS, templates, README.
   - **M2: CI/CD hardening** (P1-1 through P1-5, P1-16, P1-17, P1-18, P1-19, P1-20, P1-22) — action SHA pinning, permissions blocks, `--locked`, tool pinning, Dependabot, CodeQL/OSV-Scanner/gitleaks/semver-checks, MSRV, repo settings.
   - **M3: Supply-chain provenance** (P1-6, P1-7, P1-8, P1-9, P1-10, P1-11, P1-15) — SBOM, build provenance, cosign signing, dependency-review, Scorecard, harden-runner, reproducible-build check.
   - **M4: Vet hygiene + fuzz** (P1-12, P1-13, P1-14, P2-2, P2-4, P2-5, P1-24) — cargo-vet imports + burn-down, RUSTSEC-ignore stale-check, OSS-Fuzz integration, cargo-geiger, mutation testing, property-test inventory, coverage gate.
   - **M5: 1.0 release readiness** (P2-1, P2-3, P2-6, P2-7, P2-8, P2-9, P2-10, P1-21, P1-23) — API stability audit + 1.0 cut, Best Practices Badge, GOVERNANCE/MAINTAINERS, release workflow, LTS policy, examples + docs.rs polish, threat-model continuity gate, branch protection, DAST gating policy.
5. **`/slo-critique`** — adversarial review (CEO, eng-lead, security; design pass auto-skipped — no UI).
6. **`/slo-execute Mn`** for each milestone, then **`/slo-verify`** then **`/slo-retro`**.
7. **`/slo-ship`** at the end of each milestone where appropriate.

## 6. Effort estimate (rough)

- **P0 (legal + governance):** ~5 hrs total → 1 day.
- **P1 (supply chain + CI/CD):** ~30 hrs total → 4-5 days for everything except OSS-Fuzz onboarding (which is calendar-blocked on the OSS-Fuzz team's response).
- **P2 (1.0 readiness):** 2-3 weeks, dominated by the API stability audit and 1.0 release.

**Total to "publicly announceable in good conscience":** P0 + P1 = ~5-6 days of focused work. P2 is the trail to "actually trustable for mission-critical."

## 7. Non-goals for this initiative

To keep scope honest:

- No new security features added to the libraries themselves — this is hardening *of the release process*, not the code.
- No threat-model rewrites — [`THREAT_MODEL.md`](../../../../THREAT_MODEL.md) stands as-is; we add a *continuity process* for it (P2-10), not a redo.
- No move off MIT/Apache-2.0 toward AGPL/BSL or similar — those are commercial-strategy decisions that should be made deliberately, not as part of a hardening sprint.
- No transfer to a foundation (CNCF, OpenSSF, Apache) — that's a year-long process out of scope here, though the hardening done here is a prerequisite if the user later wants to pursue it.
- No marketing/launch plan — release announcement timing/channels are the user's call once the technical bar is met.

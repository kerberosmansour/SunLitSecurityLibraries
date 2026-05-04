# Idea — Take SunLit Security Libraries Public as Mission-Critical OSS

**Slug:** `oss-public-release`
**Created:** 2026-04-25
**Status:** Pre-research — feeds `/slo-research` then `/slo-plan`
**Pointer:** Full readiness analysis in [`../research/oss-public-release/readiness-analysis.md`](../research/oss-public-release/readiness-analysis.md). This doc is the slo-research-shaped distillation.

> **Post-cleanup note (2026-05-01):** the initial legal/governance scaffold has
> now landed. The remaining public-release work is CI/CD hardening, provenance,
> release automation, vet/fuzz/coverage, and 1.0 readiness.

---

## Wedge

A 13-crate Rust security workspace (OWASP Proactive Controls C1/C4–C10, MASVS) is ready to be released publicly, but only ships meaningful trust if its supply-chain, CI/CD, and governance posture matches the "mission critical" framing — which means SLSA-grade provenance, signed artifacts, OSS-Fuzz coverage, and MIT-OR-Apache-2.0 dual licensing rather than just a tag and a README badge.

## Target user

Two audiences: (1) the repo maintainer (the user, solo) executing the hardening work over ~5–6 days, and (2) downstream consumers — Rust web-service authors targeting critical-infrastructure / regulated environments who will only adopt a security primitive if the supply-chain story is verifiable.

## Why this is non-trivial

The repository already has the *unique/novel* work done (threat model, deny.toml policy with justified ignores, cargo-vet integration, feature-matrix gates, DAST workflows). The remaining work is mostly mechanical hardening + governance scaffolding, but the *choice of which 2026-current tooling* to standardize on is non-obvious because the OSS supply-chain ecosystem changes faster than docs can keep up — e.g., crates.io trusted publishing, GitHub `actions/attest-build-provenance`, CodeQL Rust support, and cargo-vet imports availability all moved within the last 12–18 months.

## What "done" looks like

A 5-milestone runbook that takes the repo from "private with strong foundation" to "publicly announceable in good conscience as mission-critical OSS," with each milestone having an evidence log, BDD-shaped acceptance, and an explicit out-of-scope statement. Milestones are bounded by `/slo-plan`'s 5-max cap and split as:

1. **M1** — Legal + governance scaffolding (LICENSE files, SECURITY.md, CONTRIBUTING, COC, CHANGELOG, CODEOWNERS, templates, README polish).
2. **M2** — CI/CD hardening (action SHA pinning, `permissions:` blocks, `--locked`, tool pinning, Dependabot, SAST, MSRV, repo settings).
3. **M3** — Supply-chain provenance (SBOM, build-provenance attestations, cosign signing, dependency-review, Scorecard, harden-runner, reproducible-build check).
4. **M4** — Vet hygiene + fuzz + coverage (cargo-vet imports + burn-down, RUSTSEC-ignore stale-check, OSS-Fuzz integration, cargo-geiger, mutation testing, property-test inventory, coverage gate).
5. **M5** — 1.0 release readiness (API stability audit + 1.0 cut, OpenSSF Best Practices Badge, GOVERNANCE/MAINTAINERS, release workflow, LTS policy, examples + docs.rs polish, threat-model continuity gate, branch protection, DAST gating policy).

## Open questions for /slo-research

The codebase cannot answer these — they are "current best practice in 2026" / external-system questions. **Five highest-leverage** distilled from the 14 in the readiness analysis (full list preserved in §4 of [`../research/oss-public-release/readiness-analysis.md`](../research/oss-public-release/readiness-analysis.md)):

1. **crates.io trusted publishing — GA, beta, or proposed as of April 2026?** Drives M5 release-workflow design (OIDC vs. long-lived `CRATES_IO_TOKEN` interim). If GA, mandate it; if not, define the interim posture (GitHub Environment + required-reviewer gate). Look for: PSF/PEP-style trusted-publishing announcement on the crates.io blog or rust-lang RFC; status of any in-flight RFC; production usage by other security crates as exemplars.

2. **SLSA tier reachable with `actions/attest-build-provenance@v2` for a multi-crate Rust workspace.** Specifically: does it deliver Level 3 end-to-end on its own (signed by the GitHub OIDC issuer through Sigstore Fulcio + Rekor), or does Level 3 require the SLSA L3 reusable-workflow framework and `attest-build-provenance` alone tops out at Level 2? Drives M3 design and the "SLSA Level X" claim we put in the README. Look for: SLSA spec v1.0+ requirements text, GitHub blog posts on the action, SLSA Level 3 reference architectures for Rust/Cargo.

3. **OSS-Fuzz Rust onboarding — current acceptance criteria, expected turnaround, idiomatic harness shape for parsing crates.** Specifically for HTML sanitizer (`secure_boundary`), JWT/OIDC parser (`secure_identity`), and regex sinks (`security_events`). Drives M4 scope: do we add `cargo-fuzz` harnesses in-tree first and apply to OSS-Fuzz in parallel, or is the in-tree harness sufficient for the announcement and OSS-Fuzz onboarding becomes a post-1.0 deliverable? Look for: OSS-Fuzz `getting-started` for Rust as of 2026, recent Rust-project onboarding stories, fuzzing-by-coverage guidance.

4. **CodeQL Rust support status (GA / public preview / not started) vs. Semgrep + OSV-Scanner as the SAST default.** Drives M2 SAST tool choice. If CodeQL Rust is GA with reasonable rule coverage, prefer it (native GitHub integration, auto-uploads to the Security tab). If still preview-only or thin, default to `semgrep --config p/rust` plus `OSV-Scanner` and revisit. Look for: GitHub CodeQL release notes / supported-languages page, Semgrep's Rust ruleset coverage, OSV-Scanner GA status.

5. **License default for Rust security crates in 2026** — is `MIT OR Apache-2.0` still the unambiguous ecosystem default, or has the community moved (e.g., toward Apache-2.0-only with explicit patent grant, or toward something like BSL/SSPL for commercial-protection)? Drives M1 LICENSE-file content and every crate manifest's `license` field. **Also**: confirm cargo-vet imports availability from Mozilla, Google, Bytecode Alliance, and Embark Studios — do they currently publish vet audit feeds compatible with cargo-vet 0.10, and what are the canonical `[imports]` URLs? Drives M4 vet-imports configuration. Look for: Rust API guidelines / Cargo book licensing guidance, recent high-profile crate licensing choices, cargo-vet `imports` documentation and known publishers.

## Out of scope for research

- Marketing/launch plan, naming, branding.
- Choice of foundation (CNCF / OpenSSF / Apache) — the hardening enables this conversation but is not the conversation.
- Threat-model rewrites — `THREAT_MODEL.md` stands.
- Any new feature work in the libraries themselves.

## Constraints

- Solo maintainer.
- Private vulnerability disclosure must be wired up *before* announcement (chicken-and-egg if a researcher finds something pre-launch).
- All P0 + P1 work must land before public toggle; P2 work continues post-launch.
- Time budget: ~5–6 working days for P0 + P1; weeks for P2 + 1.0 cut.

## Success criteria

After research, `/slo-plan` can produce a runbook where every milestone's tool/process choices cite the dossier, no choice is "TBD," and the sequence is concretely executable by a solo maintainer in the stated time budget.

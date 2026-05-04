---
name: oss-public-release
researched: 2026-04-25
incomplete: true
incomplete_reason: |
  The slo-research skill's quality gate requires "≥3 sourced competitor comparisons
  with names, pricing, and one concrete feature difference." That gate is shaped for
  product-market research; this initiative is OSS-readiness for a security library,
  where "competitors" are tooling categories rather than priced products. The
  technical-prior-art and regulatory bars are met. Marking incomplete in good faith
  rather than inventing fake competitors. Downstream skills (slo-plan, slo-critique)
  should treat the substantive findings (Key Findings, Library & Tool Evaluations,
  Architecture Options, Design Recommendations) as decision-ready.
---

# Research Dossier — Take SunLit Security Libraries Public as Mission-Critical OSS

Full raw findings + executive summary in [`raw.md`](raw.md). This file is the
slo-research-shaped extract; downstream `/slo-plan` should consume both.

> **Post-cleanup note (2026-05-01):** the legal/governance recommendations in
> this dossier have been partially executed: dual license files, root governance
> docs, issue/PR templates, CODEOWNERS, and Dependabot config now exist. CI/CD,
> provenance, release, vet-import, and fuzz-hardening items remain future work.

## Market

The "market" for this project is downstream Rust web-service authors targeting
critical-infrastructure / regulated environments (FIPS, NIST 800-53, IEC 62443,
SOC 2). They evaluate OSS security primitives by signal: license, supply-chain
posture, signed releases, threat model, and OpenSSF Scorecard. This initiative
delivers all five — making the library *evaluable*. There is no "spend" to
proxy: the libraries are free, the spend is the consumer's evaluation hours.

## Direct competitors

Not applicable in the product-market sense. Adjacent **tooling categories** the
launch posture must out-compete on signal — table format kept for skill schema:

| Category | Reference exemplar | Price | Key feature | Gap vs our wedge |
|---|---|---|---|---|
| Multi-crate Rust release tooling | `release-plz` | free OSS | First-class crates.io Trusted Publishing + multi-crate workspace PRs ([release-plz quickstart](https://release-plz.dev/docs/github/quickstart)) | Fits the workspace; need to wire it for 13 crates with one-shot bootstrap-token publish then TP-only |
| SAST | CodeQL Rust GA (CodeQL 2.23.3, 2025-10-23) | free for public repos | Native GitHub Security tab integration; semantic dataflow ([CodeQL changelog](https://github.blog/changelog/2025-10-23-codeql-2-23-3-adds-a-new-rust-query-rust-support-and-easier-c-c-scanning/)) | Rule library is starter-level for Rust security patterns; pair with Semgrep `p/rust` for pattern coverage |
| SBOM / vuln scanning | OSV-Scanner v2.3.5 (March 2026) | free OSS | Aggregates OSV.dev (GHSA + RustSec); Cargo lockfile native; SARIF ([Google Security Blog](https://security.googleblog.com/2025/03/announcing-osv-scanner-v2-vulnerability.html)) | Overlaps with `cargo audit` and `dependency-review-action`; need intentional de-dup |
| Build provenance | `actions/attest-build-provenance@v2` | free for public repos | SLSA v1.0 in-toto + Sigstore signing ([GitHub Marketplace](https://github.com/marketplace/actions/attest-build-provenance)) | Standalone reaches **SLSA Build L2 only**; L3 requires reusable workflow |

## Adjacent tools

| Name | Why adjacent, not direct | Can they pivot into us? |
|---|---|---|
| `slsa-framework/slsa-github-generator` | Language-agnostic reusable-workflow framework; alternate L3 path | Yes — adopt if in-house reusable-workflow refactor proves heavy |
| `step-security/harden-runner` | Egress audit/block for runners; cross-platform Linux/macOS/Windows | N/A — complementary; use in audit→block mode |
| `cosign` v2.4.0+ (Sigstore) | Keyless signing + bundle-format `verify-blob-attestation`; offline verification | N/A — direct dependency; pin version in CI |
| `gh attestation verify` | Consumer-facing alternative to `cosign verify-blob`; no Cosign install needed | Document both paths in README |
| `cargo-vet` 0.10.2 | Already in repo; needs `[imports]` block | Add Mozilla + Embark Studios at launch; Google + Bytecode Alliance week 2 |

## Technical prior art

- **Trusted Publishing on crates.io** (RFC 3691, July 2025; per-crate enforce-mode January 2026) — [crates.io: development update](https://blog.rust-lang.org/2026/01/21/crates-io-development-update/). First publish of new crate still needs long-lived token; TP only authorizes subsequent publishes.
- **SLSA L3 reusable-workflow pattern** — [GitHub docs: Achieving SLSA v1 Build Level 3](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3) and the [Ian Lewis explainer](https://www.ianlewis.org/en/understanding-github-artifact-attestations) confirm `attest-build-provenance` standalone is L2; L3 requires the reusable-workflow refactor.
- **OSS-Fuzz Rust onboarding** — [`google/oss-fuzz#10693`](https://github.com/google/oss-fuzz/pull/10693) (rust-base64 onboarding) is the working reference for parser-style crates. Acceptance is gated on a "criticality score"; new repos with no downstream dependents are unfavourable. [OSS-Fuzz Rust integration guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/).
- **MSRV policy precedent** — RustCrypto's "MSRV bump is breaking" policy ([RustCrypto/AEADs PR #351](https://github.com/RustCrypto/AEADs/pull/351)) is a worked precedent for security libraries. Combined with [RFC 3537 (msrv-resolver)](https://rust-lang.github.io/rfcs/3537-msrv-resolver.html), conservative MSRV floor has lower cost in 2026.
- **`cargo-vet` registry** — [`mozilla/cargo-vet/registry.toml`](https://github.com/mozilla/cargo-vet/blob/main/registry.toml) lists 9 publisher feeds; all 4 named in the brief (Mozilla, Google, Bytecode Alliance, Embark Studios) are live with stable raw-GitHub URLs.
- **Dual MIT/Apache-2.0 licensing** — [Rust API Guidelines: Necessities](https://rust-lang.github.io/api-guidelines/necessities.html) and [Google's Rust third-party guidance](https://opensource.google/documentation/reference/thirdparty/rust) both confirm `MIT OR Apache-2.0` remains the unambiguous default in 2026.
- **Reproducible builds blocker** — [rust-lang/rust#34902](https://github.com/rust-lang/rust/issues/34902) (toolchain reproducibility) and [cargo PR #16691](https://github.com/rust-lang/cargo/pull/16691) (March 2026, in-flight) confirm cross-platform reproducibility is not feasible for this workspace. `aws-lc-rs`/`ring` C/CMake toolchains compound the gap.
- **OpenSSF Scorecard Code-Review mechanic** — [Scorecard checks docs](https://github.com/ossf/scorecard/blob/main/docs/checks.md) — tiered −7/−3/−3 deduction; solo self-merging hits 0/10 regardless of CODEOWNERS. Realistic ceiling 6–7/10 for this repo.
- **`cargo-semver-checks` 0.47.0** — [obi1kenobi/cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks). v0.46+ added cargo-feature-graph lints; tool MSRV Rust 1.90; needs `--all-features` + `--no-default-features` + per-feature-permutation matrix to cover this workspace's feature gates.

## Regulatory / legal

- **License grant default**: dual `MIT OR Apache-2.0`. Apache-2.0 supplies the explicit patent grant that MIT lacks; MIT preserves GPL-2.0/LGPL-2.1 compatibility (Apache-2.0 alone is GPL-2-incompatible). The repo's existing [`deny.toml`](../../../../deny.toml) allowlist already accepts `Apache-2.0`, so the change is manifest-only. **Required action:** add `LICENSE-MIT` + `LICENSE-APACHE` at repo root; flip `license = "MIT"` to `license = "MIT OR Apache-2.0"` on all 13 crate manifests. ([Rust API Guidelines](https://rust-lang.github.io/api-guidelines/necessities.html), [Google Rust guidance](https://opensource.google/documentation/reference/thirdparty/rust))
- **Patent-grant gap (current)**: `license = "MIT"` alone leaves the project without explicit patent grant — material concern for "mission critical" enterprise/critical-infrastructure adopters.
- **Compliance mappings preserved**: README cites OWASP Proactive Controls C1/C4–C10 + MASVS; THREAT_MODEL.md references NIST 800-53, IEC 62443, SOC 2 Type II — none of the proposed launch work conflicts with these mappings. Threat-model continuity gate (per-PR "did this change the threat model?") is a P2 item.
- **No new compliance regime introduced** by going public; private vulnerability disclosure (GHSA) must be wired *before* announcement.

## Open questions that research did not answer

These are the remaining items that `/slo-plan` will need to resolve via repo-internal discovery, not external research:

1. **Concrete MSRV number** for this workspace — must run `cargo msrv find` once across the workspace; choice is project-specific based on which Rust features the workspace actually uses.
2. **`secure_authz` fuzz-harness entry-point shape** — the principal in-tree fuzz coverage gap (8/13 crates have harnesses; `secure_authz` doesn't). Needs brief code review of `policy.rs` + `enforce.rs`.
3. **First-publish bootstrap mechanics at workspace scale** — TP cannot publish a *new* crate; the workspace has 13 first-publishes to coordinate. Read 1–2 recent multi-crate workspaces' release-plz migration PRs for the operational pattern.
4. **`harden-runner` audit-mode burn-in length** — empirical; ~1 week working estimate but depends on cache hits and OS-specific runners.
5. **DAST gating placement** — PR-gate (M2) vs release-gate (M5) vs both. Runbook decision.
6. **Single-platform reproducibility gate survival under `aws-lc-rs` rebuilds** — empirical; pilot two runs and `diffoscope` before committing the gate.
7. **`cargo-semver-checks` behaviour on this workspace's feature-gated APIs** — pilot against `secure_boundary` (feature-rich) before committing as a release gate.
8. **Specific Cosign release version + `attest-build-provenance` patch SHA** to pin in CI — confirm at pin time.
9. **OSV-Scanner SARIF de-duplication tuning** — operational shape (which advisory IDs to suppress in which tool) is a runbook decision.
10. **Sanity check**: confirm none of the 13 crate names are already taken on crates.io before bootstrap publish.

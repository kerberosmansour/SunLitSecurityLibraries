# Synthesis — what the research means for the design

This is the actionable read-out for `/slo-plan`. Every paragraph below ends with a "the design must handle X because Y" sentence; if I couldn't write that sentence, the finding is in `dossier.md` §"Open questions" instead.

> **Post-cleanup note (2026-05-01):** M1-style legal/governance scaffolding has
> landed. Treat the remaining recommendations as future CI/CD, provenance,
> release, vet, fuzzing, and 1.0-readiness work.

## 1. Launch posture is "SLSA L2 + Trusted Publishing + cosign," not L3

Three vendor blogs framed `actions/attest-build-provenance@v2` as SLSA L3 out of the box, but GitHub's own docs ([Achieving SLSA v1 Build Level 3](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)) and the [Ian Lewis explainer](https://www.ianlewis.org/en/understanding-github-artifact-attestations) make the requirement explicit: L3 needs the build steps to live in a *reusable workflow* so signing material is unreachable from user-defined steps. The action standalone reaches L2. **The design must handle a launch claim of "SLSA Build Level 2 with documented L3 roadmap" and reject any README copy claiming L3, because GitHub's authoritative docs require a reusable-workflow refactor that the 5–6 day P0+P1 budget cannot absorb.**

## 2. Trusted Publishing is GA, but every new crate needs a one-shot bootstrap-token publish before TP can take over

[RFC 3691](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html) shipped to crates.io production in July 2025; January 2026 added per-crate enforce-mode. But TP only authorizes *subsequent* publishes — first publish of a brand-new crate name still requires a long-lived `CRATES_IO_TOKEN`. With 13 first-publishes to coordinate, the runbook needs an explicit bootstrap step: publish v0.1.0 of every crate via a short-lived gated token, register the TP relationship per crate, enable enforce-mode, then revoke the bootstrap token. **The design must handle a one-shot bootstrap-publish phase for all 13 crates as a discrete pre-TP step, because crates.io TP cannot publish a crate that does not yet exist (per [crates.io: development update](https://blog.rust-lang.org/2026/01/21/crates-io-development-update/)).**

## 3. CodeQL Rust is GA — make it the primary SAST

CodeQL Rust GA shipped in 2.23.3 (2025-10-23) per [GitHub Changelog](https://github.blog/changelog/2025-10-23-codeql-2-23-3-adds-a-new-rust-query-rust-support-and-easier-c-c-scanning/), with rule expansion through 2.23.7/2.23.8 in December 2025. Several 2026 third-party comparison sites still describe it as preview — those are out of date. CodeQL uploads natively to the GitHub Security tab; Semgrep does not. Both are additive: CodeQL gives semantic dataflow, Semgrep `p/rust` + `p/owasp-top-10` give fast pattern coverage. **The design must handle CodeQL as the primary SAST with Semgrep as additive coverage in week 2, because CodeQL Rust GA + native Security-tab integration eliminate the rationale for any third-party SAST as the *default* for a public GitHub repo.**

## 4. Cross-platform reproducible builds are infeasible — single-Ubuntu only

`aws-lc-rs` (FIPS feature in `secure_data`) and `ring 0.17` (in `secure_identity`) both pull C/CMake toolchains; the Rust toolchain itself is not bit-reproducible per [rust-lang/rust#34902](https://github.com/rust-lang/rust/issues/34902); [cargo PR #16691](https://github.com/rust-lang/cargo/pull/16691) (March 2026) is in-flight but unmerged. Cross-OS Ubuntu/macOS/Windows reproducibility cannot be achieved today regardless of how carefully CI is wired. **The design must handle reproducibility as a single-platform Ubuntu sha256-compare gate (one canonical pinned-image runner, two consecutive runs), because the C/CMake toolchain pulls and Rust-toolchain reproducibility gap rule out cross-OS reproducibility in 2026.**

## 5. OpenSSF Scorecard ceiling is 6–7/10 for solo maintainers — don't advertise a target

The Code-Review check uses tiered point deductions per [Scorecard checks docs](https://github.com/ossf/scorecard/blob/main/docs/checks.md) — −7 for one unreviewed change, −3 more for multiple, −3 for unreviewed bot changes — so a solo maintainer who self-merges scores 0/10 on Code-Review regardless of CODEOWNERS. The Contributors check requires "≥3 different companies in last 30 commits, each with ≥5 commits" for full marks, which a solo maintainer also cannot hit. Earlier "8/10 stretch" estimates were too optimistic. **The design must handle OpenSSF Scorecard as a process control (run it, react to findings) without advertising a target score in README, because the structurally-low checks for a solo Rust security repo cap realistic scoring at 6–7/10 and any number printed in README will read as a miss against expectations.**

## 6. OSS-Fuzz onboarding is post-1.0, not launch — the in-tree harnesses already do the work

Per the [OSS-Fuzz Rust integration guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/) and the [`rust-base64` onboarding PR](https://github.com/google/oss-fuzz/pull/10693) reference, acceptance is gated on a "criticality score" — large user base or essential dependents. A brand-new repo with zero downstream dependents on crates.io is unfavourable. The repo already has 18 in-tree `cargo-fuzz` harnesses across 8/13 crates; `secure_authz` is the principal gap and a separately-tracked work item. **The design must handle launch-time fuzzing as an in-tree CI nightly across the existing 18 harnesses + a `secure_authz` harness fill-in, with OSS-Fuzz application deferred to post-1.0, because OSS-Fuzz acceptance is discretionary and unlikely to land for a brand-new repo at announcement time.**

## 7. License sweep is a 30-minute change with downstream patent-grant payoff

[Rust API Guidelines: Necessities](https://rust-lang.github.io/api-guidelines/necessities.html) and [Google's Rust third-party guidance](https://opensource.google/documentation/reference/thirdparty/rust) both confirm `MIT OR Apache-2.0` remains the unambiguous default in 2026. Apache-2.0 supplies the explicit patent grant that MIT lacks; MIT preserves GPL-2/LGPL-2 compatibility. The repo's existing [`deny.toml`](../../../../deny.toml) allowlist already accepts both licenses, so the change is manifest-only — no policy work required. **The design must handle re-licensing all 13 crates from `MIT` to `MIT OR Apache-2.0` and adding `LICENSE-MIT` + `LICENSE-APACHE` at the repo root, because the patent-grant gap of MIT-alone is a material concern for the "mission critical" enterprise/critical-infrastructure adopters this library is built for.**

## 8. cargo-vet `[imports]` should land at launch — Mozilla + Embark first

All four canonical orgs named in the brief publish vet feeds via [`mozilla/cargo-vet/registry.toml`](https://github.com/mozilla/cargo-vet/blob/main/registry.toml); five more (Fermyon, ISRG, Actix, Ariel OS, Zcash) are also live with stable raw-GitHub URLs. The repo currently has zero `[imports]`. Mozilla's audit feed gives the broadest coverage of common-Rust deps; Embark Studios covers gamedev-and-systems crates including `cargo-deny`, `cargo-audit`, and several axum-adjacent crates. Google's feed has narrower scope but high quality; Bytecode Alliance covers wasmtime-adjacent crates that are largely irrelevant here. **The design must handle adding `[imports]` from Mozilla + Embark Studios at launch (the highest-coverage delta) with Google + Bytecode Alliance added in week 2, because `cargo-vet` 0.10.2 imports are reproducible-via-`imports.lock` and the existing ~248–990 exemptions can begin burning down only once external audits are imported.**

## 9. Action SHA-pinning + permission narrowing is the highest-leverage mechanical fix

The current CI pins `actions/checkout@v4`, `Swatinem/rust-cache@v2`, `dtolnay/rust-toolchain@stable`, and `PortSwigger/dastardly-github-action@main` — every one of those is a mutable ref. There is no top-level `permissions:` block in [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml), so workflows inherit broad `GITHUB_TOKEN` scopes. `cargo install cargo-audit cargo-deny cargo-vet` resolves to "whatever's latest at job time" — supply-chain tooling itself is unpinned. **The design must handle SHA-pinning every action + adding `permissions: contents: read` at workflow root + replacing `cargo install` with `taiki-e/install-action` at pinned versions + adding `--locked` to every cargo invocation, because each of those four issues is a discrete supply-chain compromise vector and all four can be closed in M2 without architectural change (per [step-security/harden-runner docs](https://docs.stepsecurity.io/harden-runner) and Dependabot's `package-ecosystem: github-actions` flow).**

## 10. The runbook order is forced by dependencies, not preference

Several items have hard ordering dependencies: cosign signing requires `actions/attest-build-provenance` to emit something to sign; Trusted Publishing requires the bootstrap publish to have happened; `cargo-vet` `[imports]` burn-down is meaningless before imports land; Scorecard improvement requires CODEOWNERS to exist; OSS-Fuzz application requires `secure_authz` to have a harness; `harden-runner` block-mode requires audit-mode burn-in. **The design must handle the runbook as five sequenced milestones (legal → CI hardening → provenance → vet/fuzz/coverage → release readiness), because the cross-milestone dependencies do not permit reordering without rework, and `/slo-plan`'s 5-milestone hard cap aligns with this natural sequence.**

## 11. The 5–6 day budget is realistic only if Option B (hardened MVP) is adopted

The dossier presents three options (full-L3-at-launch, hardened-MVP, conservative). Option A overruns the budget on the reusable-workflow refactor and four scanner-alert streams; Option C undercuts the "mission critical" framing by retaining long-lived publish tokens. Option B — SLSA L2 + TP + cosign + CodeQL + OSV-Scanner + dependency-review + Scorecard + harden-runner audit + Mozilla/Embark vet imports + in-tree fuzz nightly + single-Ubuntu reproducibility — is the only fit. **The design must handle Option B as the launch posture and explicitly defer L3 reusable-workflow refactor + Semgrep + Google/Bytecode-Alliance vet imports + harden-runner block-mode + OSS-Fuzz application + Best Practices Badge + 1.0 cut to post-launch milestones, because Option A overruns budget and Option C produces a launch claim that does not match the "mission critical" framing.**

---

## Hand-off to /slo-plan

The runbook should adopt the 5-milestone split proposed in [`docs/slo/research/oss-public-release/readiness-analysis.md`](readiness-analysis.md) §5, with these research-driven adjustments:

- **M1 (legal/governance):** add `LICENSE-APACHE` alongside `LICENSE-MIT`; flip every manifest to `MIT OR Apache-2.0`. Don't advertise a Scorecard target in README.
- **M2 (CI/CD hardening):** CodeQL is the primary SAST (not Semgrep). Add OSV-Scanner. `taiki-e/install-action` replaces unpinned `cargo install`. `harden-runner` lands in audit mode. MSRV requires `cargo msrv find` discovery (open question for `/slo-plan`).
- **M3 (supply-chain provenance):** Claim **SLSA Build L2** (not L3). Single-platform Ubuntu reproducibility (not cross-OS). Cosign keyless via bundle format (`v2.4.0+`); README documents `gh attestation verify` as no-Cosign-install alternative.
- **M4 (vet hygiene + fuzz):** Mozilla + Embark Studios vet imports at launch; Google + Bytecode Alliance week 2. Defer OSS-Fuzz application to post-1.0. `secure_authz` fuzz-harness is in-scope (gap fill). `cargo-mutants` scoped to security-invariant crates only.
- **M5 (1.0 readiness):** Trusted Publishing for all 13 crates *after* one-shot bootstrap publish. `release-plz` for steady state. `cargo-semver-checks` is a release gate (not PR gate), matrixed over feature combinations. SLSA L3 reusable-workflow refactor lives here, not at launch. OSS-Fuzz application begins here.

**Suggested next command:** `/slo-plan oss-public-release` (skipping `/slo-architect` and `/slo-tla` per slo-architect's "feature-additions to an already-designed system → jump to slo-plan" guidance and slo-tla's "no concurrency surface" exclusion).

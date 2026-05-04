# Sources — OSS Public Release Research

All URLs accessed 2026-04-25 via `sldo-research` pipeline (3 iterations × 5 web searches). Original raw aggregation in [`raw.md`](raw.md) §References.

## Trusted Publishing on crates.io

- [crates.io: development update — Rust Blog (2026-01-21)](https://blog.rust-lang.org/2026/01/21/crates-io-development-update/)
- [RFC 3691 — Trusted Publishing for crates.io](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html)
- [crates.io Trusted Publishing docs](https://crates.io/docs/trusted-publishing)
- [Publishing on crates.io — The Cargo Book](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Crates.io Implements Trusted Publishing Support — Socket.dev](https://socket.dev/blog/crates-launches-trusted-publishing)
- [Rust crates.io security update — Help Net Security (2026-01-21)](https://www.helpnetsecurity.com/2026/01/21/rust-crates-io-security-update/)
- [crates.io: Trusted Publishing — Simon Willison (2025-07-12)](https://simonwillison.net/2025/Jul/12/cratesio-trusted-publishing/)
- [crates.io Trusted Publishing from GitLab — GitLab issue #572760](https://gitlab.com/gitlab-org/gitlab/-/issues/572760)
- [Surfacing Security Advisories on crates.io — Alpha-Omega](https://alpha-omega.dev/blog/surfacing-security-advisories-on-crates-io-bringing-vulnerability-data-to-the-point-of-discovery/)
- [release-plz quickstart](https://release-plz.dev/docs/github/quickstart)

## SLSA build provenance & signing

- [actions/attest-build-provenance — GitHub repo](https://github.com/actions/attest-build-provenance)
- [GitHub Marketplace — Attest Build Provenance](https://github.com/marketplace/actions/attest-build-provenance)
- [Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3 — GitHub Docs](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)
- [Enhance build security and reach SLSA Level 3 with GitHub Artifact Attestations — GitHub Blog](https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/)
- [Achieving SLSA 3 Compliance with GitHub Actions and Sigstore for Go modules — GitHub Blog](https://github.blog/security/supply-chain-security/slsa-3-compliance-with-github-actions/)
- [GitHub Changelog — code-to-cloud + SLSA Build L3 (2026-01-20)](https://github.blog/changelog/2026-01-20-strengthen-your-supply-chain-with-code-to-cloud-traceability-and-slsa-build-level-3-security/)
- [slsa-framework/slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
- [Understanding GitHub Artifact Attestations — Ian Lewis](https://www.ianlewis.org/en/understanding-github-artifact-attestations)
- [SLSA Level 3 in GitHub Actions: Build Provenance Without the Complexity — Peter Müller](https://pettll.net/blog/slsa-build-provenance-github-actions/)
- [Implementing SLSA Level 3 Build Provenance for Kubernetes Container Images — OneUptime](https://oneuptime.com/blog/post/2026-02-09-slsa-level3-build-provenance/view)

## Cosign / Sigstore verification

- [Verifying Signatures — Sigstore docs](https://docs.sigstore.dev/cosign/verifying/verify/)
- [cosign_verify-blob.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md)
- [cosign_verify-attestation.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-attestation.md)
- [cosign_verify.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify.md)
- [cosign_attest.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
- [Cosign Verification of npm Provenance, GitHub Artifact Attestations, and Homebrew Provenance — Sigstore Blog](https://blog.sigstore.dev/cosign-verify-bundles/)
- [Cosign 2.0 released — Sigstore Blog](https://blog.sigstore.dev/cosign-2-0-released/)
- [sigstore/cosign GitHub repository](https://github.com/sigstore/cosign)
- [How to Verify File Signatures with Cosign — Chainguard Academy](https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-verify-file-signatures-with-cosign/)

## CodeQL & Semgrep (SAST)

- [CodeQL scanning Rust and C/C++ without builds is now generally available — GitHub Changelog](https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available/)
- [CodeQL 2.22.1 brings Rust support to public preview — GitHub Changelog](https://github.blog/changelog/2025-07-02-codeql-2-22-1-bring-rust-support-to-public-preview/)
- [CodeQL support for Rust now in public preview — GitHub Changelog](https://github.blog/changelog/2025-06-30-codeql-support-for-rust-now-in-public-preview/)
- [CodeQL 2.23.3 adds a new Rust query, Rust support, and easier C/C++ scanning — GitHub Changelog](https://github.blog/changelog/2025-10-23-codeql-2-23-3-adds-a-new-rust-query-rust-support-and-easier-c-c-scanning/)
- [CodeQL 2.23.7 and 2.23.8 add security queries for Go and Rust — GitHub Changelog](https://github.blog/changelog/2025-12-18-codeql-2-23-7-and-2-23-8-add-security-queries-for-go-and-rust/)
- [Supported languages and frameworks — CodeQL docs](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)
- [CodeQL library for Rust — CodeQL docs](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-rust/)
- [github/codeql GitHub repository](https://github.com/github/codeql)
- [Semgrep vs CodeQL (2026) — Konvu](https://konvu.com/compare/semgrep-vs-codeql)
- [Semgrep vs CodeQL: SAST Head-to-Head (2026) — AppSec Santa](https://appsecsanta.com/sast-tools/semgrep-vs-codeql)
- [GitHub CodeQL Review 2026 — AppSec Santa](https://appsecsanta.com/github-codeql)
- [Semgrep vs CodeQL: Lightweight Patterns vs Semantic Analysis for SAST (2026) — DEV.to](https://dev.to/rahulxsingh/semgrep-vs-codeql-lightweight-patterns-vs-semantic-analysis-for-sast-2026-412k)
- [Semgrep Rust GA support and Swift beta support](https://semgrep.dev/products/product-updates/rust-ga-support-and-swift-beta-support/)
- [Announcing Semgrep's Beta Support for Rust (2023)](https://semgrep.dev/blog/2023/announcing-semgrep-s-beta-support-for-rust/)
- [LinkedIn Redesigns SAST Pipeline — InfoQ (2026-02)](https://www.infoq.com/news/2026/02/linkedin-redesigns-sast-pipeline/)
- [Semgrep Alternatives — Aikido](https://www.aikido.dev/blog/semgrep-alternatives)

## OSV-Scanner & dependency review

- [Announcing OSV-Scanner V2 — Google Security Blog (March 2025)](https://security.googleblog.com/2025/03/announcing-osv-scanner-v2-vulnerability.html)
- [google/osv-scanner](https://github.com/google/osv-scanner)
- [OSV-Scanner docs](https://google.github.io/osv-scanner/)
- [actions/dependency-review-action](https://github.com/actions/dependency-review-action)

## OSS-Fuzz / cargo-fuzz

- [OSS-Fuzz documentation home](https://google.github.io/oss-fuzz/)
- [OSS-Fuzz: Integrating a Rust project](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/)
- [OSS-Fuzz Ideal Integration](https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/)
- [google/oss-fuzz GitHub repository](https://github.com/google/oss-fuzz)
- [oss-fuzz#10693 — Onboard rust-base64 (reference PR)](https://github.com/google/oss-fuzz/pull/10693)
- [OSS-Fuzz — Trail of Bits Testing Handbook](https://appsec.guide/docs/fuzzing/oss-fuzz/)
- [cargo-fuzz — Trail of Bits Testing Handbook](https://appsec.guide/docs/fuzzing/rust/cargo-fuzz/)
- [Rust Fuzz Book — cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [rust-fuzz/cargo-fuzz GitHub repository](https://github.com/rust-fuzz/cargo-fuzz)
- [cargo-fuzz CHANGELOG](https://github.com/rust-fuzz/cargo-fuzz/blob/main/CHANGELOG.md)
- [Debug an open source project with OSS-Fuzz — opensource.com](https://opensource.com/article/22/2/debug-open-source-project-oss-fuzz)

## Licensing

- [Rust API Guidelines — Necessities (licensing)](https://rust-lang.github.io/api-guidelines/necessities.html)
- [Rationale of Apache dual licensing — Rust Internals](https://internals.rust-lang.org/t/rationale-of-apache-dual-licensing/8952)
- [Google Open Source — Rust third-party guidance](https://opensource.google/documentation/reference/thirdparty/rust)

## MSRV policy

- [MSRV Policies — rust-lang/api-guidelines #231](https://github.com/rust-lang/api-guidelines/discussions/231)
- [Rust Update Policy — Firefox Source Docs](https://firefox-source-docs.mozilla.org/writing-rust-code/update-policy.html)
- [RFC 2495 — min-rust-version](https://rust-lang.github.io/rfcs/2495-min-rust-version.html)
- [RFC 3537 — msrv-resolver](https://rust-lang.github.io/rfcs/3537-msrv-resolver.html)
- [Rust Project Primer — MSRV checks](https://rustprojectprimer.com/checks/msrv.html)
- [foresterre/cargo-msrv](https://github.com/foresterre/cargo-msrv)
- [cargo-msrv book — verify command](http://gribnau.dev/cargo-msrv/commands/verify.html)
- [Latest stable rust as MSRV — alexheretic gist](https://gist.github.com/alexheretic/d1e98d8433b602e57f5d0a9637927e0c)
- [time-rs/time discussion #535 — MSRV policy](https://github.com/time-rs/time/discussions/535)
- [apache/datafusion #9082 — MSRV policy discussion](https://github.com/apache/datafusion/issues/9082)
- [Rust MSRV policy and Linux Distros — Rust Internals](https://internals.rust-lang.org/t/rust-msrv-policy-and-linux-distros/17074)
- [RustCrypto/AEADs PR #351 — MSRV bumps treated as breaking](https://github.com/RustCrypto/AEADs/pull/351)

## cargo-vet & supply-chain

- [Cargo Vet — Introduction](https://mozilla.github.io/cargo-vet/)
- [Cargo Vet — Importing Audits](https://mozilla.github.io/cargo-vet/importing-audits.html)
- [Cargo Vet — How It Works](https://mozilla.github.io/cargo-vet/how-it-works.html)
- [Cargo Vet — Performing Audits](https://mozilla.github.io/cargo-vet/performing-audits.html)
- [Cargo Vet — Audit Criteria](https://mozilla.github.io/cargo-vet/audit-criteria.html)
- [Cargo Vet — Multiple Repositories](https://mozilla.github.io/cargo-vet/multiple-repositories.html)
- [mozilla/cargo-vet — registry.toml (canonical imports list)](https://github.com/mozilla/cargo-vet/blob/main/registry.toml)
- [mozilla/cargo-vet GitHub repo](https://github.com/mozilla/cargo-vet)
- [mozilla/supply-chain — aggregated Mozilla audits](https://github.com/mozilla/supply-chain)
- [cargo-vet 0.10.2 — docs.rs](https://docs.rs/crate/cargo-vet/latest)
- [Bytecode Alliance — Security and Correctness in Wasmtime](https://bytecodealliance.org/articles/security-and-correctness-in-wasmtime)
- [Pass-the-SALT 2023 — Rust Supply Chain Security talk](https://archives.pass-the-salt.org/Pass%20the%20SALT/2023/slides/PTS2023-Talk-11-rust-supply-chain-security.pdf)

## OpenSSF Scorecard

- [OpenSSF Scorecard — scorecard.dev](https://scorecard.dev/)
- [ossf/scorecard](https://github.com/ossf/scorecard)
- [OpenSSF Scorecard — checks documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [OpenSSF Scorecard — project page](https://openssf.org/projects/scorecard/)
- [Introducing the OpenSSF Scorecard API — Endor Labs](https://www.endorlabs.com/learn/introducing-the-openssf-scorecard-api)

## SemVer & API stability

- [obi1kenobi/cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)
- [cargo-semver-checks releases](https://github.com/obi1kenobi/cargo-semver-checks/releases)
- [cargo-semver-checks — docs.rs](https://docs.rs/cargo-semver-checks/latest/cargo_semver_checks/)
- [cargo-semver-checks — crates.io](https://crates.io/crates/cargo-semver-checks)
- [SemVer Compatibility — The Cargo Book](https://doc.rust-lang.org/cargo/reference/semver.html)
- [rust-lang/rust-semverver](https://github.com/rust-lang/rust-semverver)

## RustSec / GHSA

- [rustsec/advisory-db](https://github.com/rustsec/advisory-db)
- [rustsec/rustsec — RustSec API & Tooling](https://github.com/rustsec/rustsec)

## Runner hardening

- [step-security/harden-runner](https://github.com/step-security/harden-runner)
- [StepSecurity Harden Runner docs](https://docs.stepsecurity.io/harden-runner)
- [StepSecurity blog — Windows + macOS support for Harden Runner](https://www.stepsecurity.io/blog/harden-runner-now-supports-windows-and-macos-github-actions-runners)

## Reproducible builds

- [rust-lang/rust#34902 — reproducible builds tracking issue](https://github.com/rust-lang/rust/issues/34902)
- [rust-lang/cargo#16691 — reproducible-builds-related cargo PR](https://github.com/rust-lang/cargo/pull/16691)

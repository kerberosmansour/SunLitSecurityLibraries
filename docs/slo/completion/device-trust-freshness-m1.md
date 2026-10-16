# Device-trust freshness M1 completion

## Outcome

Device-trust route authorization now checks current mTLS validity and an
explicit revocation source on every decision. Routes requiring a bound user
session reject future, expired and malformed lifetimes at the same decision
time before applying the existing certificate binding, profile and trust-tier
rules. Actix performs the lookup per request; the loopback reference service
states its no-revocation test assumption explicitly.

## Verification

- The two failing-first regressions returned `Allow` on merged baseline
  `7f1fd2378b00d3411892539da1c2a508c5e05f5f` and deny after the repair.
- Focused suites pass 17/17 and 7/7; locked all-feature workspace tests and
  doctests, Clippy, rustdoc, rustfmt and diff checks pass.
- Cargo audit, cargo-deny and cargo-vet pass. Checksum-verified OSV-Scanner
  2.7.0 reports zero malicious packages across all six dependency inputs; the
  graph is byte-unchanged.
- Supplemental Semgrep reports zero findings, and the repository-pinned
  Semgrep, CodeQL, Kani, secret, packaging, platform and supply-chain jobs all
  pass in the 32-job exact-head record for PR #156.
- The signed reviewed head and verified squash merge share tree
  `146bcbb64a66a839d878f62e34298b17182707d6`.
- Exact merged-main Codex Security run
  `wfr_5a2a676a8f0d15ecc4e6cb57692f671caf448f11c69257ee22e2d7acfd549265`
  has complete coverage, no exclusions or validation warning, and omits the
  frozen finding and route-policy path from its report and findings.

## Shipping handoff

Implementation PR #156 merged as
`d7516202df0326015ce0b092c843e393c89ba9c3`. This milestone changes no
dependency, version, release, workflow authority or published crate; a package
publication is therefore neither required nor permitted by its contract. The
28 retained whole-repository findings remain separate defensive milestones.

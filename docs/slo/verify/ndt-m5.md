# Verification Report - ndt Milestone 5

## What Was Exercised

| Scenario | Category | How exercised | Result | Evidence |
|---|---|---|---|---|
| library release contract | runtime | `cargo fmt --all -- --check && cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features && cargo test -p secure_identity -p secure_authz -p secure_network --all-features` | pass | release-gate library job passed locally |
| reusable workflow syntax | static | Ruby YAML parsed `.github/workflows/native-device-trust-conformance.yml` | pass | workflow file parses |
| release docs | documentation | `docs/dev-guide/native-device-trust-release-gate.md` added and linked from developer guide index | pass | documents ZeroTrustAuth external conformance as release-blocking evidence |
| external dry-run handoff | integration contract | ZeroTrustAuth workflow contract and dry-run harness passed in the conformance repo | pass | proves workflow shape before a public endpoint exists |
| external non-dry-run | runtime | GitHub hosted runner against public staging endpoint | blocked | depends on ZeroTrustAuth staging endpoint and CI bootstrap issuer deployment |

## Bugs Found

| id | severity | scenario | regression test | status |
|---|---|---|---|---|
| none | n/a | n/a | n/a | no verification bugs found in the library release-gate contract |

## Environment

- Repo: `SunLitSecurityLibraries`
- Branch: `native-device-trust-libraries`
- Stack: Rust 2021, Actix Web adapter path, GitHub Actions reusable workflow
- External endpoint: not deployed during this verification pass

## Coverage Gaps

- M5 cannot be closed until the ZeroTrustAuth non-dry-run external workflow
  uploads evidence from a public test/staging endpoint.
- Guardian still needs its release workflow to consume the same reusable
  conformance evidence before native packages rely on the device-trust stack.

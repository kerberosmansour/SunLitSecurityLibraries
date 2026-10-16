# Device-trust freshness M1 verification

## Result

M1 passes local, exact-head CI, merge-integrity and exact merged-main security
verification. The frozen device-trust freshness finding is absent from the
complete Codex Security report and structured findings at the verified merge.

| Outcome | Evidence | Result |
|---|---|---|
| `oc-device-freshness-1` | Expired-at-boundary and not-yet-valid certificate regressions exercise `DeviceTrustRoutePolicy::evaluate` at an explicit time. | pass |
| `oc-device-freshness-2` | A lookup selecting the presented serial denies in the policy and Actix adapter tests. | pass |
| `oc-device-freshness-3` | Expired-at-boundary, future and non-positive-lifetime bound sessions deny. | pass |
| `oc-device-freshness-4` | Existing valid hardware/software, profile, trusted-edge and certificate-binding cases remain green; reference-service routes add expired-certificate and expired-session regressions. | pass |

## Failing-first evidence

On merged baseline `7f1fd2378b00d3411892539da1c2a508c5e05f5f`, the focused
suite ran 12 cases: ten passed and the two new expired-authority regressions
failed because the policy returned `Allow`. The baseline evaluator accepted no
revocation lookup, which is the structural red evidence for lookup revocation.
The saved log SHA-256 is
`95a02f9c733f1eb63409cc3c518494df68c2c0c23ce4d263f2cc2f1681e10a4e`.

## Local gates

- `cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features --locked`:
  17/17 pass.
- `cargo test -p secure_reference_service --test e2e_sunlit_ndt_m4 --locked`:
  7/7 pass.
- `cargo test --workspace --all-features --locked`: pass, including doctests.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  pass.
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked`:
  pass.
- `cargo fmt --all --check` and `git diff --check`: pass.
- Supplemental Semgrep Rust/OWASP and secrets scans: zero findings. The
  Rust/OWASP scan recorded six pre-existing partial-parser warnings outside the
  changed files; exact CI runs the repository-pinned scanner.
- `cargo audit`, `cargo deny check` and `cargo vet`: pass. Vet reports 146 fully
  audited, 49 partially audited and 305 exempted packages.
- `scripts/osv-dependency-gate.py` used checksum-verified OSV-Scanner 2.7.0
  across all six declared dependency inputs. Report SHA-256:
  `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0`.
  It found zero `MAL-*` advisories and four pre-existing vulnerability reports:
  `RUSTSEC-2023-0071`, `RUSTSEC-2026-0249`, `GHSA-6g2r-675j-hx59` and
  `GHSA-84m7-p3x7-pcfv`. This milestone changes no dependency input.

## Scope and graph

The working diff contains exactly the 19 approved paths once the seven SLO
records are included. No `Cargo.toml`, `Cargo.lock`, nested toolchain lock,
requirements file, workflow, version or publication metadata differs from the
merged baseline.

## Shipping evidence

Implementation PR #156 reviewed signed head
`e00ab04f6747eb63ca347aab499fd32c2f499683` and passed all 32 reported
exact-head jobs across CI, CodeQL, Semgrep, Kani, dependency admission and scope
guards. It had no review threads or submitted reviews.

The verified squash merge is
`d7516202df0326015ce0b092c843e393c89ba9c3`, with sole parent
`7f1fd2378b00d3411892539da1c2a508c5e05f5f`. The reviewed head and merge
share tree `146bcbb64a66a839d878f62e34298b17182707d6`; GitHub reports a valid
signature, and `origin/main` resolved to the merge during inspection.

Codex Security run
`wfr_5a2a676a8f0d15ecc4e6cb57692f671caf448f11c69257ee22e2d7acfd549265`
completed against that exact merge without a validation warning. Coverage is
`complete`, repository-wide, with no excluded or deferred paths and no open
questions. Neither the frozen title `Device-trust authorization accepts expired
certificate and user-session state` nor
`crates/secure_authz/src/device_trust.rs` appears in the report, findings or
manifest artifacts. The structured scan occurrence API likewise returns 28
different findings and no frozen occurrence.

- Report SHA-256:
  `fbe28f68797fe0e0a09b48218bfec194e081156ffbcd5ddd7085ccde5be94c5c`.
- Findings SHA-256:
  `b255f2b8896b3230788e5131d265825fed9c2cc6ebf01dd1678980ef418235d4`.
- Manifest SHA-256:
  `e6c6eda52915325cbc13775b268db6062f2ddea40699937ce9a427746682a804`.
- Coverage SHA-256:
  `c231b1b93ff09e0915ce690ab3f5be7adadc219699f170bf5294cc6d2c1fd5bb`.

## Residual limits

The loopback reference service still uses the explicitly named
`NoMtlsRevocations` test provider and is not a production deployment example.
The merged-main scan retained 28 unrelated findings: 2 high, 23 medium and 3
low. One reports passwordless completion certificate revalidation in
`secure_identity`; it is a distinct authorization path and requires its own
bounded milestone. None weakens this route-policy finding closure.

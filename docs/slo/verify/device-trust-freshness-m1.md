# Device-trust freshness M1 verification

## Local result

The implementation satisfies the locally observable M1 contract. Shipping
remains open until exact-head CI, merge-integrity checks and an exact
merged-main Codex Security rescan pass.

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

## Pending immutable evidence

- exact reviewed-head GitHub Actions jobs;
- squash-merge parent/tree/signature and `origin/main` identity;
- exact merged-main Codex Security coverage and absence of the frozen finding
  `Device-trust authorization accepts expired certificate and user-session state`;
- immutable source and verification artifacts recorded on AgentBus.

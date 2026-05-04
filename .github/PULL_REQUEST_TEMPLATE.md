## Summary

<!-- 1-3 bullets describing what changed and why. Link the issue or runbook if there is one. -->

-

## Runbook / Issue

<!-- e.g. docs/slo/future/RUNBOOK-native-device-trust.md M3, Fixes #123, or "N/A - docs only". -->

## Security impact

<!-- Keep the Orchestrate discipline: name the boundary, data, and abuse case rather than saying "none" by reflex. -->

- [ ] No new trust boundary, credential path, parser, network call, crypto behavior, or release artifact.
- [ ] `THREAT_MODEL.md` updated or explicitly not needed.
- [ ] Public output contains no secrets, private keys, tokens, PII, hostnames, internal policy names, or confidential SLO artifacts.
- [ ] New or changed workflow references are pinned to commit SHAs.

## Verification

<!-- Keep only the gates that apply, but leave evidence for every security-sensitive change. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo doc --workspace --no-deps`
- [ ] `bash scripts/audit.sh`
- [ ] `osv-scanner scan source -r .`
- [ ] `semgrep scan --config p/rust --config p/owasp-top-ten --metrics=off --error --exclude target --exclude .git .`
- [ ] `actionlint .github/workflows/*.yml`

## Reviewer notes

<!-- Risk areas, deferred work, intentionally accepted residual risk, or "N/A". -->

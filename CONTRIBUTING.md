# Contributing to SunLit Security Libraries

Thanks for your interest. This repository is a set of security crates, so the
bar for clarity, tests, and threat-model awareness is intentionally high.

## Quick links

- [README](README.md) - project overview and crate map
- [SECURITY.md](SECURITY.md) - vulnerability disclosure policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - community standards
- [GOVERNANCE.md](GOVERNANCE.md) - maintainer-led project governance
- [CHANGELOG.md](CHANGELOG.md) - user-facing release notes
- [docs/dev-guide/](docs/dev-guide/README.md) - integration guides
- [docs/slo/](docs/slo/README.md) - runbooks, lessons, and completion records

## Recommended workflow

1. Fork and clone the repository.
2. Open an issue first for non-trivial work. Tiny docs fixes can go straight to a PR.
3. For larger changes, use a runbook. New runbooks belong in `docs/slo/future/`
   or `docs/slo/current/`, and milestone output belongs in
   `docs/slo/completion/` and `docs/slo/lessons/`.
4. Keep changes scoped. Security-sensitive behavior should have tests and a
   threat-model note when the risk surface changes.
5. Open a PR using the template and include the commands you ran.

## Local checks

Run the narrowest useful checks while iterating, then run the broader baseline
before a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
bash scripts/audit.sh
```

Feature-sensitive crates should also be checked with their relevant feature
combinations, especially `secure_boundary`, `secure_authz`, and `secure_errors`:

```bash
cargo test -p secure_boundary --no-default-features
cargo test -p secure_boundary --features "axum actix-web"
cargo test -p secure_authz --features "axum actix-web"
cargo test -p secure_errors --features "axum actix-web"
```

## Security-sensitive changes

Treat these as high-review areas:

- Authentication, authorization, session, MFA, OIDC, and token validation logic.
- Input validation, deserialization, safe URL handling, CORS, and browser headers.
- Cryptography, key management, secret handling, password hashing, and storage.
- Security event emission, redaction, HMAC sealing, log sinks, and incident paths.
- CI, release, dependency, supply-chain, fuzzing, and DAST configuration.

Do not put secrets, credentials, private keys, customer data, or confidential
runbook material in a PR.

## Sign-off and licensing

Contributions require a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this repository is licensed under `MIT OR Apache-2.0`, without
additional terms or conditions.

## Pull requests

Good PRs are small, reviewable, and evidence-backed. Include:

- What changed and why.
- The issue or runbook/milestone, when one exists.
- The exact tests and security checks you ran.
- Any residual risk, compatibility note, or deferred follow-up.

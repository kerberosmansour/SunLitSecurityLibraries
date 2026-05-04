# Release Process

This repository is prepared for separate crates.io packages. Do not make the
repository public until the secret scan, OSV dependency scan, Semgrep Rust scan,
package dry run, and release signing checks have passed on the exact commit
that will be exposed. CodeQL is configured ahead of time, but the workflow is
gated until the repository is public so findings publish to GitHub code
scanning.

## Publishable crates

The service crates are internal integration fixtures and are marked
`publish = false`:

- `secure_reference_service`
- `secure_smoke_service`

Publish the library crates individually so downstream users can depend only on
the control they need. crates.io package names use the `sunlit_` prefix, while
the Rust library target names stay stable for imports such as
`use secure_data::...`.

Recommended first-publish order:

1. `sunlit_security_core`
2. `sunlit_security_events`
3. `sunlit_secure_output`
4. `sunlit_secure_device_trust`
5. `sunlit_secure_network`
6. `sunlit_secure_errors`
7. `sunlit_secure_boundary`
8. `sunlit_secure_data`
9. `sunlit_secure_resilience`
10. `sunlit_secure_privacy`
11. `sunlit_secure_identity`
12. `sunlit_secure_authz`

Before publishing, package every crate:

```bash
cargo package -p sunlit_security_core
for crate in \
  sunlit_security_events sunlit_secure_output sunlit_secure_device_trust sunlit_secure_network \
  sunlit_secure_errors sunlit_secure_boundary sunlit_secure_data sunlit_secure_resilience \
  sunlit_secure_privacy sunlit_secure_identity sunlit_secure_authz
do
  cargo package -p "$crate" --list > "/tmp/$crate.package-list"
done
```

Only `sunlit_security_core` can fully package-verify before anything is
published. The other first-release crates have versioned local path dependencies
that Cargo resolves against crates.io during package verification, so package
them and publish them one at a time after their prerequisite crates exist in the
registry.

Before publishing or making the repository public, run the local supply-chain
gate. It includes `cargo audit`, `cargo deny`, `cargo vet`, and OSV Scanner:

```bash
bash scripts/audit.sh
```

When ready, publish in the order above:

```bash
cargo login
cargo publish -p sunlit_security_core
```

Publishing to crates.io is permanent for a given version. If a secret ever
enters a published crate, yank is not enough; revoke the secret immediately and
treat the crate contents as public forever.

## Sigstore signing

`.github/workflows/release-sign.yml` packages all publishable crates, copies the
CycloneDX declaration, creates `SHA256SUMS`, and signs each artifact with
Sigstore keyless signing through GitHub Actions OIDC.

To produce signed artifacts without publishing:

1. Run the `Release Artifact Signing` workflow manually with
   `workflow_dispatch` for the crate you are about to publish. Use `all` only
   after internal dependency versions already exist on crates.io. A `v*` tag
   also signs `all`.
2. Download the `signed-release-artifacts` workflow artifact.
3. Verify any artifact locally:

```bash
cosign verify-blob \
  --bundle sunlit_secure_data-0.1.0.crate.sigstore.json \
  --certificate-identity-regexp 'https://github.com/kerberosmansour/SunLitSecurityLibraries/.github/workflows/release-sign.yml@refs/(heads|tags)/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  sunlit_secure_data-0.1.0.crate
```

## GitHub hardening checklist

Current checked state before public release:

- Repository visibility is still private.
- `main` is the default branch and points at the sanitized one-commit release
  candidate.
- `main` has baseline branch protection: stale-review dismissal, conversation
  resolution, and force-push/deletion blocks.
- Default workflow token permission is `contents: read`.
- GitHub Actions cannot approve pull request reviews.
- Workflows use explicit `permissions:` blocks and checkout does not persist
  credentials.
- Mutable high-risk workflow references have been replaced with commit SHAs.
- Semgrep Rust static analysis is configured for private prep branches.
- CodeQL Rust static analysis is configured and will run once the repository is
  public.

Before switching visibility to public, finish these repository settings in
GitHub:

- Delete or replace old private-history remote branches before changing
  repository visibility.
- Upgrade `main` branch protection using
  [`branch-protection.md`](./branch-protection.md).
- Require status checks for CI, supply-chain, secret-pattern, packaging,
  Semgrep Rust, CodeQL Rust, and DAST gates.
- Disable force pushes and branch deletion on protected branches.
- Require signed commits or vigilant mode if that matches maintainer workflow.
- Enable secret scanning and push protection.
- Keep SHA-pinned Actions enforcement enabled; every workflow and reusable
  workflow reference must stay pinned to a commit SHA.

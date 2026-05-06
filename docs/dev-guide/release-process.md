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
the control they need. The current crates.io package names match the Rust
library target names exactly, for example `secure_data` is installed with
`cargo add secure_data` and imported with `use secure_data::...`.

Recommended publish order for the `0.1.2` release:

1. `security_core`
2. `security_events`
3. `secure_errors`
4. `secure_output`
5. `secure_network`
6. `secure_device_trust`
7. `secure_boundary`
8. `secure_data`
9. `secure_resilience`
10. `secure_privacy`
11. `secure_identity`
12. `secure_authz`

Before publishing, package every crate from a clean branch that points at the
release commit:

```bash
cargo package -p security_core
for crate in \
  security_events secure_output secure_device_trust secure_network \
  secure_errors secure_boundary secure_data secure_resilience \
  secure_privacy secure_identity secure_authz
do
  cargo package -p "$crate" --list > "/tmp/$crate.package-list"
done
```

For update releases, run `cargo publish --dry-run -p <crate>` immediately
before publishing each crate in the order above. The manifests keep versioned
local path dependencies; when Cargo prepares the package, the published
manifest resolves those sibling dependencies from crates.io. That means a
dependent crate's dry run only succeeds after its prerequisite `0.1.2` packages
have reached the index.

Before publishing or making the repository public, run the local supply-chain
gate. It includes `cargo audit`, `cargo deny`, `cargo vet`, and OSV Scanner:

```bash
bash scripts/audit.sh
```

When ready, publish in the order above. crates.io publishes are permanent for
the uploaded version. Space each upload by at least 10 minutes to avoid
registry throttling and to give the index time to settle before dependents are
published:

```bash
cargo login
cargo publish -p security_core
sleep 600
cargo publish -p security_events
sleep 600
# continue through the ordered crate list
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
  --bundle secure_data-0.1.2.crate.sigstore.json \
  --certificate-identity-regexp 'https://github.com/kerberosmansour/SunLitSecurityLibraries/.github/workflows/release-sign.yml@refs/(heads|tags)/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  secure_data-0.1.2.crate
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

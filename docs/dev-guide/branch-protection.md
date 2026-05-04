# Branch Protection

This repo should follow the same security posture as SunLitOrchestrate: changes
land through reviewable PRs, evidence is recorded in the PR, and security gates
are enforced by GitHub instead of maintained from memory.

## Live baseline

Applied on 2026-05-04 to `main`, which is now the default branch:

- Pull-request review protection exists with stale-review dismissal enabled.
- Required conversation resolution is enabled.
- Force pushes are disabled.
- Branch deletion is disabled.
- Admin enforcement is disabled for now so the maintainer can still complete the
  remaining remote-branch cleanup before public launch.
- Required status checks are not enabled yet because the public-release branch
  still needs to establish the final check names on GitHub.

## Public-release target

Before making the repository public:

1. Rewrite or squash the public branch so old test private-key fixture commits
   are not exposed. Status: sanitized `main` is a one-commit branch; old
   private-history remote branches still need deletion or replacement.
2. Keep sanitized `main` as the default branch.
   Confirm GitHub then shows `SECURITY.md` as the repository security policy.
3. Protect `main` with:
   - pull requests required before merge,
   - at least one approval once a second maintainer exists,
   - stale approvals dismissed on new commits,
   - conversation resolution required,
   - force pushes disabled,
   - branch deletion disabled,
   - admin enforcement enabled after the history cleanup is complete.
4. Require the security-critical status checks after their first successful run:
   - `Dependency Review`
   - `Secret Pattern Scan`
   - `Test (ubuntu-latest)`
   - `Test (macos-latest)`
   - `Test (windows-latest)`
   - `Rustdoc (zero warnings)`
   - `Crate Packaging Preflight`
   - `Supply-Chain Security`
   - `Semgrep Rust`
   - `CodeQL Rust` once the repository is public
   - `Dastardly (Burp Suite) Scan`
   - `Library device-trust contract`
   - `ZeroTrustAuth external conformance`
5. Require the feature-matrix checks for crates that have framework adapters:
   `sunlit_secure_boundary`, `sunlit_secure_authz`, and
   `sunlit_secure_errors`.
6. Enable secret scanning and push protection once GitHub exposes them for the
   public repository.
7. Disable Projects or Wiki if they are not intentionally used for the public
   project.

Code-owner review can be enabled once there is at least one reviewer other than
the author of a change. Until then, `.github/CODEOWNERS` is still useful for
routing and for making sensitive paths obvious.

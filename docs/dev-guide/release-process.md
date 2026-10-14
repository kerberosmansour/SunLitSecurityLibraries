# Release process

The repository is public. Twelve independently installable libraries share version 0.2.0; secure_reference_service and secure_smoke_service have publish=false and are integration fixtures.

## Verification

Use a clean release commit on main. Run workspace tests, feature tests, Clippy, rustdoc, formatting, secret/static scans, cargo audit, cargo deny --locked check, cargo vet --locked and scripts/check-native-dependencies.py. Review exact source, audit exceptions and packaged file lists; credentials must never enter source or packages. The guard enforces the 2026-11-14 native/maintenance/RSA verification exception deadline. Do not refresh the whole dependency graph to satisfy packaging.

## Publishing

Publish in dependency order: security_core, security_events, secure_errors, secure_output, secure_network, secure_device_trust, secure_boundary, secure_data, secure_resilience, secure_privacy, secure_identity, secure_authz. Use cargo package --list for each crate to inspect contents. Before each upload run cargo publish --dry-run --locked -p <crate>, then cargo publish --locked -p <crate>. Cargo resolves versioned sibling path dependencies from crates.io for verification, so each prerequisite must reach the registry index first. Cargo waits for availability after an upload; use bounded registry checks or honor Retry-After if throttled rather than a fixed ten-minute delay for every crate.

Publishing a version is permanent. A multi-crate release is sequential and can be partial; confirm the registry version/checksum before retrying an interrupted run. Never overwrite or blindly republish an existing version. If a secret enters a published crate, revoke it: yanking cannot erase its contents.

## Signed release artifacts

After registry publication, commit declarations/release-<version>-packages.json with the independently verified registry checksums and clean source commit. Tag the tested library commit with its version. release-sign.yml downloads committed-checksum-approved registry archives without OIDC authority, verifies identity/source and generates CycloneDX 1.6 dependency SBOMs, then signs those exact files in an isolated job and uploads signed-release-artifacts. It does not publish to crates.io. A manual run is allowed on main for a selected crate or all after dependencies exist in the registry. The workflow verifies the tag version and that its commit belongs to main.

Verify downloaded files and their Sigstore bundles using cosign verify-blob, the exact workflow identity (https://github.com/kerberosmansour/SunLitSecurityLibraries/.github/workflows/release-sign.yml@refs/tags/v0.2.0) and issuer https://token.actions.githubusercontent.com. Confirm SHA256SUMS. Attach the artifacts to the GitHub release.

## Repository controls

Keep workflow tokens read-only by default, checks and dependency changes reviewed, Actions SHA-pinned, checkout credentials disabled, and build code separated from publishing/signing tokens. Inspect live branch protection, secret scanning and push-protection availability; do not assume account features are enabled from documentation alone. Daily scans and offline drills report evidence without creating or merging PRs.


The 0.2.0 signing recovery uses a manual main run after archive repacking on CI changed file-mode metadata for two packages despite identical contents. The v0.2.0 source tag remains bf52c98180ca4794cc01ca06b3ca71d2981737ef. Verify the recovered bundles against the exact release-sign.yml identity at refs/heads/main and the documented signing run; checksums must match the committed release record and crates.io. Fresh repackaging is not a substitute for the immutable registry bytes. The producer downloads/reads archives but never builds or executes crate code; OIDC remains confined to the signing job.

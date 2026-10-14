# Release process

The repository is public. Twelve independently installable libraries share version 0.3.0; secure_reference_service and secure_smoke_service have publish=false and are integration fixtures.

## Verification

Use a clean release commit on main. Run workspace tests, feature tests, Clippy, rustdoc, formatting, secret/static scans, cargo audit, cargo deny --locked check, cargo vet --locked and scripts/check-native-dependencies.py. Review exact source, audit exceptions and packaged file lists; credentials must never enter source or packages. The guard enforces the 2026-11-14 native/maintenance/RSA verification exception deadline. Do not refresh the whole dependency graph to satisfy packaging.

## Publishing

Publish in dependency order: security_core, security_events, secure_errors,
secure_output, secure_network, secure_device_trust, secure_boundary, secure_data,
secure_resilience, secure_privacy, secure_identity, secure_authz.

1. On the clean reviewed release commit, run `python3 scripts/osv-dependency-gate.py
   --output .cache/release-root-osv.json`. Review the complete graph/provenance.
2. Resolve each candidate without compilation: `cargo package --no-verify
   --locked -p <crate>`. Inspect the generated archive's file list and metadata.
3. Run `python3 scripts/admit-release-package.py target/package/<name>-<version>.crate
   --root-report .cache/release-root-osv.json --root-receipt
   .cache/release-root-osv.receipt.json --published-records <verified-prerequisites.json>`.
   The records are a JSON list of exact previously published sibling names,
   versions, sourceCommit and registry-matched archive checksum. Start with `[]`.
   The helper binds every shipped source byte to clean Git, checks normalized
   manifest authority and exact checksum-subset membership, then scans the
   packaged Cargo.lock with the official pinned scanner. Same product exceptions
   apply only after this review; tool graphs cannot inherit them. Keep reports.
4. Only after admission, run `cargo package --locked -p <crate>` for normal
   compile verification. Check that the archive still matches its admission
   receipt before `cargo publish --no-verify --locked -p <crate>`; no second build
   is needed. Verify immutable registry checksum,
   archive source/contents and candidate receipt against the admitted bytes.
   Record each prerequisite before the next dependent crate is considered.

Cargo resolves versioned sibling path dependencies from crates.io, so each
prerequisite must reach the index first. Use bounded registry checks and honor
Retry-After rather than fixed ten-minute delays. Any new package/version/checksum
outside the admitted workspace graph fails closed; review it explicitly before
verification, procedural macro/build-script execution or publication.


Publishing a version is permanent. A multi-crate release is sequential and can be partial; confirm the registry version/checksum before retrying an interrupted run. Never overwrite or blindly republish an existing version. If a secret enters a published crate, revoke it: yanking cannot erase its contents.

## Signed release artifacts

After registry publication, commit declarations/release-<version>-packages.json with the independently verified registry checksums and clean source commit. For future releases, tag the verified release commit containing the approval record and current workflow. The record identifies the immutable package source commit, which can precede that metadata commit. Library source/manifests/lock must remain unchanged between them. The existing 0.2.0 tag predates this recovery workflow and is intentionally left unchanged; dispatch the main recovery run instead. release-sign.yml downloads committed-checksum-approved registry archives without OIDC authority, verifies identity/source and generates CycloneDX 1.6 dependency SBOMs, then signs those exact files in an isolated job and uploads signed-release-artifacts. It does not publish to crates.io. A manual run is allowed on main for a selected crate or all after dependencies exist in the registry. The workflow verifies the tag version and that its commit belongs to main.

Verify downloaded files and their Sigstore bundles using cosign verify-blob, the exact workflow identity (https://github.com/kerberosmansour/SunLitSecurityLibraries/.github/workflows/release-sign.yml@refs/tags/v<version>) and issuer https://token.actions.githubusercontent.com. Confirm SHA256SUMS. Attach the artifacts to the GitHub release.

## Repository controls

Keep workflow tokens read-only by default, checks and dependency changes reviewed, Actions SHA-pinned, checkout credentials disabled, and build code separated from publishing/signing tokens. Inspect live branch protection, secret scanning and push-protection availability; do not assume account features are enabled from documentation alone. Daily scans and offline drills report evidence without creating or merging PRs.


The 0.2.0 signing recovery uses a manual main run after archive repacking on CI changed file-mode metadata for two packages despite identical contents. The v0.2.0 source tag remains bf52c98180ca4794cc01ca06b3ca71d2981737ef. Verify the recovered bundles against the exact release-sign.yml identity at refs/heads/main and the documented signing run; checksums must match the committed release record and crates.io. Fresh repackaging is not a substitute for the immutable registry bytes. The producer downloads/reads archives but never builds or executes crate code; OIDC remains confined to the signing job.

Verified 0.2.0 recovery: [run 38570598294](https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38570598294), workflow commit ef4d41a8d08f3376301ace1020f71036b3ee165f. All twelve signed archive bytes match crates.io; 27 payload signatures/digest manifest and twelve official-schema SBOMs verify.

The 0.3.0 mobile release preserves the external dependency graph. Its twelve family version changes are coordinated; the native SDK references introduce no Maven, SPM or Rust dependency. Consult [mobile migration](mobile-bridge-migration.md) for the typed native error handling and independent consumer/device gates. Registry checksum approval records are created only after downloading and verifying all published archives; never populate them from expected or fabricated checksums.

Verified 0.3.0 release: [run 38627967780](https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38627967780), tag/approval commit 8f77c4db26f3250386b3695a3339adb77bf75da3, immutable package source e1f45068bfa011e559a8702d1407d05f7ab4ff0a. Twelve registry archives/source/checksums, 27 exact-tag signatures, twelve official-schema SBOMs and 54 GitHub asset digests verify. No external dependency version/source/checksum changed.

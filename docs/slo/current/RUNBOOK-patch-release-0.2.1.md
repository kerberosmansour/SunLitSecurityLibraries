# Coordinated 0.2.1 patch release — SLO maintenance contract

User authorized versioning/publication and verified merges. This urgent release
ships the merged role-cache fix and four Rustls repairs before longer native
qualification. It does not include mobile M1/M2. No new external product package.

Allow-list: root Cargo.toml/Cargo.lock/CHANGELOG/README/.gitignore; all twelve publishable crate
Cargo.toml/README files; declarations/cyclonedx-1.6-capabilities.json;
docs/dev-guide/release-process.md; scripts/admit-release-package.py;
scripts/test_release_admission.py; scripts/osv-dependency-gate.py;
scripts/test_osv_dependency_gate.py; this runbook. Post-publication checksum record,
release evidence and signature artifacts are separate immutable closeout data.
Dependencies: only twelve local library versions 0.2.0 → 0.2.1. Preserve every third-party
identity/checksum and existing audit/expiry. No audit or exception fabrication.

Outcome: users can install fixed 0.2.1 libraries, exact registry bytes match a
clean main commit and are signed; issue #55 closes only after fixed publication.
Package graph must be admitted before Cargo verification executes any build
script/procedural macro. Script-disabled packaging creates the archive; admission
checks source bytes, normalized manifest/dependency authority and complete exact
lock inventory. Verified sibling records bind registry path dependencies.
Known MAL advisories cannot be excepted. Fail on partial/network/parse errors.

Measurements: twelve registry checksums, sourcecommit/evidence, twelve exact
packaged lock scans, official CycloneDX1.6 and Sigstore verifications. Sequential
publish may be partial; verify existing versions before a bounded retry.

BDD: exact source/checksum graph accepted; new transitive dependency, changed
checksum/source, injected source, dirty VCS and new build authority rejected.
Verify inherited workspace feature merging. Four fixture regressions pass.
Security: existing root admission sixlocks/1448 passes; targeted external source
provenance unchanged; native guard enforces exact expiring limits. New helper gets
source review/SAST before real packaging. No credentials/files outside package
source allowed. Only generated fixture archives are used by tests.

DoD: local/static gates and full CI pass; source PR merged; all twelve published and
exact registry bytes/source checked; checksum record merged; tag/signing run and
all signatures/schema match; docs updated; issue #55 final workpad/closure done.
No unsupported mobile/platform or universal malware-absence claim.

Evidence: local workspace version diff only; current rootOSV: six locks / 1,448 package occurrences pass.
Python fixtures: four pass. Remaining helper source review, fullCI and publication
are pending and will be recorded without substituting narration for evidence.

Independent review found five concrete gaps. Path-only development dependencies
are deliberately omitted by Cargo and are normalized accordingly. Archive bytes
are snapshotted before parsing, decompressed input is bounded before tar metadata
parsing, and member iteration is bounded. The receipt retains that reviewed
snapshot digest and rejects replacement before receipt issuance. Normalized
package/dependency/feature/lint/target authority is matched to clean sources;
trusted script-disabled Cargo metadata identifies the authorized target paths.
Published manifests cannot retain dependency paths. Ecosystem identities must
match each lock format; exceptions require crates.io identity. Regressions for
path-only normalization and injected target/path authority failed before repairs;
seven package fixture tests now pass. All 37 Python tests and 1,387 all-feature Rust
tests pass; workspace Clippy passes. Actual package admission remains required.

Actual security_core 0.2.1 archive: clean source and 100 packaged dependency
identities admitted with official OSV; no compilation/upload preceded the scan.
Cargo publish dry-run uses a temporary archive directory, so the documented
candidate command is cargo package --no-verify --locked.

Follow-up review's two remaining cases were reproduced with committed failing
regressions before fixes: unexpected normalized top-level tables are rejected,
and scanner exit 1 without represented advisories fails closed. 39 Python tests
now pass. Actual core package verification compiled only after admission and
preserved its exact admitted archive bytes. The inherited secure_data README's
obsolete constructor/argument order was corrected without adding mobile APIs.

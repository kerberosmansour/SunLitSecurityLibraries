# Lessons Learned — JWT HMAC Profile Milestone 2

## What changed
Published all twelve coordinated libraries at 0.4.0. Updated feature/startup
migration, install examples, changelog and optional capability declaration.
Only local family versions changed; runtime/helper/workflow/tool/audit/exception
source stayed unchanged. Registry approval uses actual downloaded checksums.

## Results vs thesis
The reviewed HMAC profile is now installable from crates.io. The registry-only
normal/build consumer has 195 packages and zero rsa; exception-free OSV admission
and all six real consumer/startup/race scenarios pass. No downstream adoption,
production security outcome or arbitrary feature-union claim is inferred.

## Outcome vs promise
oc-jwt-publish-1 / cuj-jwt-publish-1 pass across source/manifest/lock, actual admitted
package, registry bytes/VCS, real consumer authentication and signed release
assets. Existing 1395 workspace tests pass with three existing ignored tests;
selected profile/key-utility tests, formatting and Clippy pass. All 28 source PR
checks passed, including three OSes and actual Kani acceptance-kernel evidence.
Mobile hardware/physical/consumer qualification remains a separate boundary.

## Design decisions and why
Use 0.4.0 for the public feature grouping and previous no-default-feature migration.
Preserve legacy defaults and all external identities instead of merging pending
small dependency batches into this release. Reuse the unchanged reviewed uploader
and immutable producer. Commit the actual approval record before creating the tag.

## Mistakes made
A mechanical README replacement initially changed the historical mobile-introduction
version. Diff review corrected it before the source commit. One release preflight
expected four OSV jobs, but this path triggers three (the separate advisory Kani
workflow is not triggered); the assertion failed before any merge and was corrected
against the actual complete workflow set, with every present OSV gate required green.

## Root causes
Mechanical replacements must distinguish install versions from historical claims;
workflow count must come from the actual triggered surface. No scanner result,
source identity, registry checksum or security disposition was weakened.

## What was harder than expected
Keep the generic six-lock archive-helper receipt separate from the positive
consumer's seven-lock admission. A root-only scan cannot admit that excluded fixture.

## Naming conventions established
release-0.4.0-packages.json records immutable package source 49612e1; tag 318512a
contains the merged approval record. Do not confuse package source with tag commit.

## Test patterns that worked well
Full external-package dictionary equality, real registry-only consumer, exact
archive admission before compile/upload, independent immutable producer equality,
official SBOM schema, exact signature identity/issuer/commit/ref and re-downloaded
GitHub assets. No contrived documentation tests or fabricated audits were needed.

## Kani scope
Fresh source CI 38685528995 also passed the strict raw red/green classifier: two
weakened assertions fail, two restored kernels pass, thirteen covers satisfied,
automatic assertion reachability enabled, no heap/loop bound or stub. Three HMAC
kinds and all usize lengths on Linux x86_64; cryptography, entropy, global process
scheduling and internal-copy erasure remain unproved. No new M2 proof code.

## Missing tests that should exist now
None within M2's confirmed publication boundary. Consumer/device/Guardian adoption
is downstream work, not evidence from this fixture. Pending dependency batches
need their own current seven-lock admission and honest cargo-vet review.

## Rules for the next milestone
Never repackage or retag this immutable release. Preserve external holds/audits;
review later dependency batches separately. Do not inherit product exceptions into
tools/fixtures, waive MAL advisories or present OSV as unknown-malware detection.

## Filing/disposition record
All M2 findings were fix_now within the confirmed files and are resolved. Existing
issue54 covers this work; no new upstream defect or duplicate follow-up is filed.
Other Hulumi features and dependency batches remain in the broad maintenance task.

Explicit migration validation also passed: `cargo test -p secure_identity --no-default-features --features asymmetric-jwt,ssh-public-keys --test openssh_public_key --test sunlit_imp_capability --locked` —15 SSH and36 capability tests, zero failures, on the unchanged admitted workspace graph.

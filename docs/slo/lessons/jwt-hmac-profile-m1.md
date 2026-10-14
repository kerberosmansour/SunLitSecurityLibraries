# Lessons Learned — JWT HMAC Profile Milestone 1

## What changed
Added the explicit reduced jwt-hmac profile while preserving default asymmetric/
SSH APIs through named default groups. Reused ring and vendor JWT11 interfaces,
checked provider initialization and bounded keys/tokens. The standalone real
consumer resolves 195 normal/build packages with zero rsa.

## Results vs thesis
Leading metric: the isolated consumer graph now excludes rsa; the pre-change
graph assertion failed because rsa was present. Outcome: real HS256 authentication
and rejection/startup cases pass on Linux, macOS and Windows. Legacy 1395 all-feature
workspace tests, Clippy and required security/package/documentation gates pass.
No production deployment/adoption metric is invented; ship the separately
confirmed publication milestone after its readiness gates.

## Outcome vs promise
oc-jwt-hmac-1 and cuj-jwt-hmac-1 pass across manifest/lock, production provider,
real vendor signing/verification and authenticated role/error boundaries.
Existing identity/public-key behavior is preserved by default feature groups;
workspace/platform/feature-matrix gates cover adjacent library outcomes.

## Design decisions and why
Use ring HMAC and vendor parsing rather than custom crypto/parsers. Use std
OnceLock to cache a checked own install result; foreign/frozen provider conflicts
fail closed. Gate SSH/RustCrypto feature edges explicitly, including the prior dev
edge. Advertise only the actual isolated graph; additive Cargo features can restore rsa.

## Mistakes made
The generic scanner deliberately excludes fixtures; a positive executable consumer
needed explicit seven-lock admission. Offline all-platform metadata failed in a
cold cache. Initial artifact upload omitted hidden-cache reports. Legacy Kani old
output classified raw reachability exits incorrectly. An existential proof parser
accepted contradictory records, and proof-time ownership checks were incomplete.

## Root causes
Fixture policy, host-only cache assumptions, artifact action defaults, and treating
legacy CBMC output as Kani-classified results. Fixes preserve the unchanged pinned
scanner core and existing source/SDK verifier graph. No advisory waiver was added.

## What was harder than expected
Vendor process-global registration requires actual isolated processes; key utilities
and non-exhaustive hashes need fixed unsupported errors. Regular-mode Kani results
must be parsed per harness with unique checks, exact policy descriptions/status,
complete records and no trailing results.

## Naming conventions established
asymmetric-jwt / ssh-public-keys preserve defaults; jwt-hmac names the reduced
consumer. JHK_KEY_* and JHK_MESSAGE_* identify thirteen explicit coverage cases.

## Test patterns that worked well
Graph red first without compiling unadmitted fixtures; real vendor round trips;
six separate process order/race cases; cold-cache metadata regression; exact Windows
slash-path aliases; strict parser red/green fixtures and same-byte alias rejection.
Both real deliberately weakened assertions fail; restored kernels pass.

## Kani scope and evidence
Actual CI38645105658 on implementation 78b3bc7: admitted source-verified 0.68.0,
SDK SHA32e2b484d73ede0bbf64a2cf0879c4259422497d8aec4ee67d448de9ae7843d3.
Three HMAC kinds and all usize values on Linux x86_64, independent key/tag/token
constants, no heap/loop/unwind bound or stub. Both original policy assertions pass;
all thirteen covers SATISFIED with automatic assertion reachability enabled.
Crypto/entropy/process scheduling/I/O/internal key-copy erasure remain unproved.

## Missing tests that should exist now
None within confirmed M1. New parser findings have ten negative cases, and POSIX
same-byte file/parent symlink cases reject. Windows guard remains enabled without
claiming the POSIX symlink fixture ran there. Published-consumer proof belongs to M2.

## Rules for the next milestone
Confirm M2's 37 files before execution. Preserve external package identities,
audits and exact expiring dispositions. Admit all seven locks and exact package
archives before compilation/upload; validate registry source/checksums and signing.
Never fabricate a vet audit, inherit root exceptions into fixtures, or waive MAL.

## Template improvements suggested
No new filing. Existing issue54 tracks publication/migration. The upstream
repo-of-origin convention is already tracked by Hulumi31; no duplicate issue.

## Filing/disposition record
All concrete implementation/verification findings are fix_now and resolved in M1.
Publication confirmation is operator_action for M2, already tracked by issue54.
No new upstream defect or accepted-risk waiver is claimed; no additional issue filed.

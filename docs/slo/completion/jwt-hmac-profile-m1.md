# JWT HMAC profile M1 — source verification in progress

Status: in_progress. User confirmed eighteen files. Source preserves legacy default
asymmetric/SSH APIs through named feature groups and adds the explicit reduced
profile. Normal/build consumer graph and its 195-package lock exclude rsa; all
external identities/sources/checksums are a root subset and root package dictionaries
are unchanged. No publication/version/capability declaration update in this phase.

Before implementation, offline metadata showed the old reduced graph still included
rsa and the assertion failed without compiling an unpatched fixture. Focused legacy
identity baseline 203 tests passed. Official checksum-pinned OSV 2.7.0 admitted seven
root/tool/consumer locks and 1643 package occurrences before new-profile compilation;
fixture exceptions do not inherit root dispositions.

Selected real JWT tests 2, private key utility test 1 and six separate consumer
process scenarios passed. They cover HMAC algorithms/key bounds, signature/claims
rejection, own concurrent init, foreign-first, own-first, competing registration
and early upstream misuse. Existing 1395 all-feature workspace tests and workspace/
selected-profile/consumer Clippy with warnings denied passed. Formatter and four
workflow-boundary regressions pass. Empty-cache metadata regression was red before
fix, green with locked build-free fetching. Independent review found no concrete
authentication bypass/key exposure/unsupported startup race.

Still required: final source/security checks, fail-closed Kani red/green two-kernel
CI verdict, remaining platform gates and closeout. The kernels cover three HMAC
kinds and all usize values on Linux x86_64 without heaps/loops/stubs; they do not prove
vendor crypto, entropy, scheduling or key-copy erasure. Publication/issue 54 closure
requires its separately confirmed next milestone. No pending proof is claimed
SUCCESSFUL or waived as a local-tool skip.

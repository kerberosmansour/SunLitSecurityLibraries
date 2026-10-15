# Completion — JWT HMAC Profile Milestone 2

Status: done, 2026-10-15. User confirmed the 37-file publication contract.

All twelve 0.4.0 crates are published. Source PR #139 merged at
49612e1fe525ec87a9e0c60181d7d023a08aaa51 after all 28 checks passed. Exact candidate
archives were source/checksum-graph reviewed and officially OSV-scanned before
compile/upload. Downloaded registry bytes, API checksums and VCS match source.
Root/consumer external dictionaries and audits/exceptions are unchanged.

Approval record PR #140 merged at 318512ab65a6894d81a8b73e3ac8df4eef0753ea before the
v0.4.0 tag. Its metadata-only admin merge followed successful admission/static
checks and the independent producer; repeated platform/security jobs continued.
The approval record never substitutes expected values for actual registry data.

[Signing run 38687007436](https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38687007436)
succeeded. All 27 payload signatures verify exact workflow identity, issuer,
318512a commit and v0.4.0 ref; payload bytes equal the independent producer.
Twelve dependency SBOMs and the capability declaration pass official CycloneDX 1.6
schemas. All 54 GitHub asset sizes/digests and downloaded bytes match verified files.
[Release](https://github.com/kerberosmansour/SunLitSecurityLibraries/releases/tag/v0.4.0).

oc-jwt-publish-1 / cuj-jwt-publish-1: actual registry-only reduced consumer has 195
normal/build packages, zero rsa; exact family registry checksums and unchanged
external graph reviewed, official OSV passes without exceptions, then all six
real authentication/startup/race scenarios pass. Defaults and explicit asymmetric
migration retain source/platform regression evidence. Local 1,395 workspace tests,
selected 2 profile/1 key-utility tests, formatter and Clippy passed; fresh Linux
Kani red/green two kernels and 13 covers also verified from actual raw logs.

UI/cloud deployment/physical-device testing is not applicable to this local
package publication. No hardware, entropy, crypto-correctness, scheduling,
internal-copy erasure or arbitrary feature-union/RSA-code-elimination claim.
Mobile qualification limits and exact expiring advisory exceptions remain.

Self review: scope/external graph, migration/API/docs, operator readiness,
outcome/regressions, admission/source/provenance, signing/schema/assets and
rollback documentation pass. No undisposed finding or pending M2 scenario remains.
Post-publication rollback requires a new version; never overwrite/retag.

Lessons: docs/slo/lessons/jwt-hmac-profile-m2.md. Issue54 can close with published
capability evidence; Guardian application migration is not claimed complete.
The broader maintenance task and larger Hulumi features remain incomplete.

Explicit migration validation also passed: `cargo test -p secure_identity --no-default-features --features asymmetric-jwt,ssh-public-keys --test openssh_public_key --test sunlit_imp_capability --locked` —15 SSH and36 capability tests, zero failures, on the unchanged admitted workspace graph.

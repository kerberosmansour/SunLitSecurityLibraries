# Mobile publication M3 — source preparation

Status: in_progress. User confirmed the 38-file publication contract. The sealed
adapter and SDK native references are prepared for coordinated 0.3.0 publication;
other crate API source and all external locked dependencies remain unchanged.

Verified source evidence: six-lock official OSV v2.7.0 admission passed for 1448
package occurrences under the existing exact expiring reachability exceptions;
1395 all-feature workspace tests passed, zero failures; workspace all-target
all-feature Clippy with warnings denied, formatter and native dependency guard
passed. Official CycloneDX 1.6 capability schema and file/graph scope checks pass.
Independent publication review's two documentation findings were corrected:
family install versions now agree; packaged migration links use the release tag.

M1/M2 evidence qualifies real envelope/native software recovery, tamper and key
loss. No physical-device, hardware, consumer FFI or Guardian exactly-once claim is
added. iOS requires WhenPasscodeSetThisDeviceOnly with no fallback and trusted
re-enrolment after passcode removal/reset. Migration describes direct zeroizing
DEK handoff, native-owner closure, completion/cancellation ownership and durable
ciphertext before acknowledgement.

Still required: successful exact source CI/merge, twelve script-disabled archive
admissions before package compile/upload, registry source/bytes/checksums, committed
approval record, exact workflow signatures, 54 asset digests and twelve official
SBOM schemas. Issue98 stays open until these publication outcomes pass. No checksum
is populated from an expected/fabricated value and no tag precedes its approval
record. Existing expiring advisory limits remain in force for downstream graphs.

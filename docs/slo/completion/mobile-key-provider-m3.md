# Mobile publication M3 — verified release

Status: done. User confirmed the 38-file publication contract. The sealed
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

Released all twelve libraries as 0.3.0 from clean source
e1f45068bfa011e559a8702d1407d05f7ab4ff0a (#135). Each exact archive passed
source/graph/provenance and official OSV admission before compilation/upload;
downloaded registry bytes/checksums/VCS match. The actual registry approval record
is merged in #136; tag v0.3.0 points to 8f77c4db26f3250386b3695a3339adb77bf75da3.
Library source/manifests/lock and capability bytes are unchanged between source
and tag. Metadata-only admin merge was explicitly user-authorized after OSV and
read-only producer verification; no library source validation was waived.

Signing run 38627967780 succeeded. All 27 exact workflow-identity signatures,
SHA256SUMS, independent producer payload equality, twelve official CycloneDX 1.6
SBOM schemas and 54 uploaded GitHub asset digests verify. Public release:
https://github.com/kerberosmansour/SunLitSecurityLibraries/releases/tag/v0.3.0.
The upstream mobile issue98 is closed with publication/migration evidence;
Guardian issue1503 still owns application binding/reconciliation/device proof.
No checksum was fabricated, tag preceded its approval record, advisory was
blanket-waived or hardware/physical capability was claimed.

ship_state: shipped. Rollback retains prior immutable versions/providers until
application migration verifies durable ciphertext; never persist plaintext as a
fallback. Daily OSV admission and the 2026-11-14 exception review remain required.

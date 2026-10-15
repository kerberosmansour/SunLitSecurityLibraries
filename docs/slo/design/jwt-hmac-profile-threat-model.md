# JWT reduced-profile threat model

The new profile is trusted local library code using admitted ring HMAC and vendor
JWT parsing/validation. Keys and tokens are Restricted; claims Confidential.
Legacy defaults keep asymmetric/JWKS/SSH behavior and existing audited exceptions.

| Scenario | Control / required proof |
|---|---|
| Attacker selects RSA/none or swaps key family to bypass HMAC validation | HMAC-only factories and key-family checks; existing vendor algorithm/claims validation; real forged/wrong-family/unsupported tests |
| Foreign provider wins process startup and library silently delegates | Check and cache own install result before decode; foreign-first returns ProviderUnavailable, callback never reached; isolated processes/races |
| Unbounded JWT/key work exhausts CPU/memory | <=64KiB JWT and <=1024byte keys, algorithm-specific minimum32/48/64; reject before crypto work; runtime/Kani bounds |
| Optional/dev features reintroduce rsa while the profile is advertised minimal | Explicit asymmetric/SSH groups; remove unconditional dev crypto edge; standalone normal/build graph plus exact lock/provenance scan; no feature-unified universal claim |
| Runtime or error leaks configured keys/token/native diagnostics | Private non-Debug crypto owners, fixed typed errors, no secret logs; limited synthetic fixtures |
| Agent compiles unpatched candidate graph under a blanket inherited exception | Stage every fixture lock; pinned official OSV across all locks before build; no tool/fixture inheritance or MAL waiver |

TLA suitability false: standard local OnceLock synchronization and API/feature
selection, no new distributed protocol or custom mutex algorithm. Isolated process
ordering/race tests exercise actual registration calls. Kani required for pure
acceptance kernels; vendor cryptography/scheduling and internal key-copy erasure
are outside its proof. Owner maintainer; review at M1 closeout and before publication.
No RSA code-elimination claim about ring or arbitrary Cargo feature unification.

## M2 publication boundaries

| Scenario | Control / required proof |
|---|---|
| Registry archive or source is substituted after review | Exact candidate archive/source and checksum-subset admission before compilation/upload; downloaded registry bytes and VCS identity must match |
| Partial release or guessed checksum is advertised complete | Sequential verified siblings, actual registry approval record committed before tag, immutable version retry checks |
| Different workflow/source signs substituted SBOMs or assets | Independent producer equality, exact tag workflow identity/issuer, manifest digests, twelve official-schema SBOMs and every GitHub asset digest |

These supply-chain/integrity classes are mitigated by verification, not a claim
that signing detects unknown malware. M2 changes version/docs/declarations only;
all external identities, audits, exceptions, proof kernels and runtime code stay.

# Role-sensitive authorization cache — SLO Ticket Contract v1

## 1. Ticket Metadata
- ID: ticket-55-role-cache
- Source: https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/55
- Owner: repository maintainer; branch: `slo/ticket-55-role-cache`
- Stack: Rust; public APIs remain source-compatible; no new dependencies or migrations.
- Commands: `cargo fmt --all -- --check`; `cargo check -p secure_authz --all-features --locked`; `cargo clippy -p secure_authz --all-targets --all-features --locked -- -D warnings`; `cargo test -p secure_authz --all-features --locked`.

## 2. Sizing Gate
One outcome: changing a principal's roles must cause a fresh authorization decision. Seven implementation files plus this contract; one PR; no new public surface, dependency, migration, or subsystem rewrite. Ticket-sized.

## 3. Issue Context
The current cache reuses an allow for the same actor/action/resource/version/tenant even after its roles change. Acceptance: an owner-to-child transition for the same actor must deny immediately without waiting for TTL. A newly granted role must also be evaluated. The published 0.2.0 code still exhibits the omission.
Non-goals: identity-provider freshness/revocation, policy-engine redesign, unrelated issue capabilities. Authorizers backed by different policy engines require separate caches.

## 4. Compact Architecture Delta
`DefaultAuthorizer` uses private request-bound cache operations. An internal key pairs the existing public `CacheKey` with the complete ordered role vector. Legacy low-level cache operations occupy a separate key domain. Ordered roles preserve engine error/short-circuit semantics; no lossy fingerprint or delimiter encoding.
Flow: validated subject → existing tenant/time/ABAC checks → request key + exact roles → bounded cache → policy evaluation on miss.

## 5. Contract Block
| Row | Contract |
|---|---|
| Inputs/outputs | Issue 55, existing cache/authorizer; corrected cache, regression tests, migration guidance and evidence |
| Interfaces | Existing `CacheKey` fields, `for_request`, `DecisionCache::get/insert`, authorizer signatures remain compatible; low-level get no longer introspects authorizer entries (documented security boundary) |
| Files allowed to change | `crates/secure_authz/src/cache.rs`, `crates/secure_authz/src/enforcer.rs`, `crates/secure_authz/tests/role_cache_regression.rs`, `crates/secure_authz/README.md`, `CHANGELOG.md`, `crates/secure_authz/tests/e2e_sunlit_imp_m15.rs`, `crates/secure_authz/tests/e2e_sunlit_m6.rs`, this ticket contract |
| Read first | Those existing files; `crates/secure_authz/src/subject.rs`, `resource.rs`, `policy.rs`, `tests/sunlit_authz_cache.rs`, `ARCHITECTURE.md`, root and crate Cargo manifests |
| New files | Regression file and contract only |
| Dependencies/migration | None; release version changes are a separately scoped closeout |
| Data | Internal authorization context; synthetic test identities; no new logs |
| Proactive controls | OWASP C7 authorization; deny-by-default; exact role-vector equality |
| Abuse scenarios | Removed role cannot reuse allow; manually seeded cache cannot poison an authorizer |
| Resource bounds | Existing cache capacity and TTL retained across both key domains; roles copied once per entry, linear in supplied role vector; no new unbounded collection |
| Invariants | Different role vectors never share decisions; unchanged roles can hit; all original pre-cache guards still execute |
| Debugger | Inspect test decision and cache miss assertions; no debugger needed for deterministic reproduction |
| Static gates | Formatter, all-feature check/clippy/tests; locked metadata, native dependency guard and cargo-vet; no third-party graph change |
| Rollback | Revert PR only in emergency; removing fix restores known stale-allow vulnerability; no persisted cache migration |
| Exemplar | Existing LRU capacity/TTL and version/tenant isolation |
| Anti-exemplar | Actor-only key, lossy role hashes, concatenated role strings, public struct field additions |
| IAM mapping | N/A — no IAM/workflow/trust policy touched |
| Refactoring | Only cache-key wrapper and shared private access helpers; tests before implementation |
| AI | N/A — no AI component |
| Forbidden shortcuts | No disable-cache workaround, ignored tests, unsafe code, broad dependency refresh or weakened audit gates |

## 6. Implementation Plan
1. Record clean branch and baseline.
2. Add failing real-authorizer role downgrade/grant tests and legacy-poisoning regression.
3. Pair internal cache keys with roles; route authorizer through private request operations.
4. Verify unchanged-role hit, capacity eviction, TTL and all existing cache/tenant guards.
5. Run static/runtime gates, record evidence and update single workpad.
6. Open PR, merge on passing checks under user authorization; release separately.

## 7. BDD Acceptance Scenarios
| Scenario | Given/When | Then | Evidence |
|---|---|---|---|
| Role removal / abuse | Same actor first owner then child or no roles | Previous allow is not reused | real authorizer regression |
| Role grant / happy path | Same actor first child then owner | Previous deny is not reused | real authorizer regression |
| Role order | Same set in different order with engine errors | Evaluate according to current order | exact ordered cache binding |
| Legacy poisoning / abuse | Low-level public key manually seeded allow | Authorizer must evaluate denied role | regression |
| Invalid input | Empty actor after warm entry | Incomplete context denial | existing guards + regression |
| Unchanged context | Same request and roles | Cache hit remains available | request-key helper test |
| Degraded/cache bounds | Capacity one; TTL zero | Eviction and expiry remain misses | private helper test |

## 8. Validation Plan
| Check | Expected | Actual | Status |
|---|---|---|---|
| Repo hygiene | Clean task branch | Detached clean → slo/ticket-55-role-cache; main preserved | pass |
| Baseline cache tests | Pass | 5 passed | pass |
| Regression before fix | Fails on stale allow/deny/poison | 4 expected assertion failures; invalid-context control passed | pass |
| Formatter/check/clippy | Pass | All ran successfully, all targets/features | pass |
| All-feature authz tests/runtime | Pass | 107 tests including 27 doctests; real policy-engine transitions passed | pass |
| Locked graph/native guard/vet | Pass, no graph change | Guard passed; vet: 146 full / 49 partial / 305 exempted; Cargo.lock unchanged | pass |
| Scope/compatibility | Exact allow-list; public signatures/fields unchanged | Seven implementation files + contract; public signatures unchanged. Manual get no longer introspects authorizer entries, documented | pass |

## 9. Workpad
One persistent comment with marker `<!-- slo-ticket-workpad:v1 -->` on issue 55; tracks branch, plan, acceptance and evidence.

## 10. Self-Review Gate
[x] Exact allow-list, red-first, source compatibility, documented cache-domain behavior, capacity/TTL, static/runtime checks, no temporary artifacts. PR/workpad handoff below.

## 11. Closure Summary
Verified role downgrades/grants and adversarial manual seeding against the real policy engine. Preserve role order because policy errors can short-circuit. Low-level public APIs retain their manual behavior, but authorizer entries now have a separate domain; consumers must not use legacy get to introspect them. No new dependency or unsafe code.

Validation: 107 tests (27 doctests), all-feature check and clippy, formatter, native dependency guard and cargo-vet passed. The third-party graph is unchanged. Four regressions failed before implementation as expected. New private key tests cover cache hits, role order, expiry and shared capacity.

Issue: https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/55
PR: created by ticket closeout; independent review pending before merge.
Publication: next coordinated release after the newly authorized capability milestones; do not close issue before a fixed published version is available.

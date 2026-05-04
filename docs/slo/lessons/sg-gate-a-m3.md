# Lessons Learned — sg-gate-a Milestone 3

## What changed
- `is_private_ipv4` (in `secure_boundary::safe_types`) gained one branch: `224.0.0.0/4` multicast.
- `is_private_ipv6` gained three branches: `fe80::/10` link-local, `ff00::/8` multicast, `::/128` unspecified.
- `SafeUrl` rustdoc expanded to enumerate all 12 CIDRs with one-line reasons per entry.
- New integration guide `docs/dev-guide/safe-url-ssrf.md`.

## Design decisions and why
- **Variant analysis, one `#[test]` per CIDR.** The test file has 12 CIDR-rejection tests, 4 edge-upper tests (for `/12`, `/10`, `/7` ranges), 4 negative controls, and 2 scheme sanity checks — 22 total. Each CIDR-rejection test is named after the CIDR (`rejects_cidr_fe80_slash_10`) so any future edit that removes a single branch fails a specific, obvious test.
- **Bitmask for IPv6 link-local.** `fe80::/10` covers `fe80:: – febf::`; the mask is `0xffc0`. Used the same style as the existing `fc00::/7` branch rather than `Ipv6Addr::is_unicast_link_local_strict` (unstable).
- **`Ipv6Addr::is_loopback()` and `::is_unspecified()` stay as method calls** rather than inline bitmasks. They're stable, clear, and match std's intent.
- **No URL parser rewrite.** The existing hand-rolled parser has known quirks (IPv4-mapped IPv6 like `[::ffff:127.0.0.1]` is not currently detected, see next section). These are explicitly out of scope for Gate A — a later runbook can address them without touching Gate A's contract.

## Mistakes made
- None worth recording. The test-first approach flagged exactly the 4 missing CIDR families (6 failing tests — 2 for the two CIDR ranges that got edge-upper tests, 1 each for the others). Implementation was surgical — 4 added branches.

## Root causes
- The pre-M3 `SafeUrl` doc string said "private or loopback IP" but the code covered less than what Sunlit Guardian's audit list requires. Root cause: pre-M3 text was aspirational rather than enumerative. The fix for future: when a classifier is a set, the doc enumerates the set.

## What was harder than expected
- IPv6 host strings in `SafeUrl::try_from`: the parser strips brackets before calling `parse::<Ipv6Addr>`. The test helper `url_for` needed to produce `http://[fe80::1]/` (bracketed) — the parser then strips the brackets internally. Took one iteration to align test strings and parser expectations.

## Naming conventions established
- `rejects_cidr_<slug>` for rejection tests (slug form: `10_slash_8`, `169_254_slash_16`, `fe80_slash_10`, `ipv6_unspecified_slash_128`).
- Edge-upper tests get `_upper` suffix: `rejects_cidr_172_31_slash_12_upper`.
- Negative controls: `accepts_<descriptor>`.

## Test patterns that worked well
- **Pre-implementation confirmation run.** Running the test file BEFORE making any code change surfaced exactly which 6 tests would fail. That confirmed the scope of the implementation change (4 branches, matching 4 missing CIDRs) and gave clean variant-analysis evidence.

## Missing tests that should exist now
- **IPv4-mapped IPv6** — `[::ffff:127.0.0.1]` currently parses as a valid public-ish IPv6 and is accepted. This is a legitimate bypass if Sunlit Guardian's workload ever sees IPv6 mixed-form addresses. Deferred as an explicit follow-up candidate.
- **DNS rebinding** — `SafeUrl` validates host *strings*, not resolved IPs. Connect-time revalidation is out of scope but should be documented for downstream consumers (and is, in the dev-guide).

## Rules for the next milestone (M4)
- M4 adds two helpers (A4, A5), a CI gate, and license housekeeping. No framework code. No existing file modifications beyond allow-list.
- Run the full feature matrix (`--all-features`, `--no-default-features`, each framework alone, both together) as part of the Evidence Log for M4's CI-gate design. The CI workflow must encode exactly those matrix combinations.
- Before editing any Cargo.toml for license reconciliation, do a `grep` audit and paste the result into the Evidence Log. The feedback doc's premise of divergence was stale; verify against repo truth before editing.

## Template improvements suggested
- The runbook template could add a "Pre-implementation test run" step to the Evidence Log template — for variant-analysis milestones like this one, the `N tests fail for expected reason` line is load-bearing evidence that shouldn't be optional.

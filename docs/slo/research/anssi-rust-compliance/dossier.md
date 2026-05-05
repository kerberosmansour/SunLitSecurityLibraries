---
name: anssi-rust-compliance
researched: 2026-05-05
incomplete: false
---

# Research Dossier — ANSSI Rust Secure Coding Guidelines compliance

## ANSSI guide — canonical version and pinning

Canonical source: GitHub repo [`ANSSI-FR/rust-guide`](https://github.com/ANSSI-FR/rust-guide) (default branch `master`, rendered at `https://anssi-fr.github.io/rust-guide` from `gh-pages`). As of 2026-05-05, master HEAD = **`84e6ae181712c9ed797aeaf695c9965a13a1d5fa`**, dated **2026-04-07T15:20:39Z** ("add examples and fix typos"). The repo carries a single Git tag `v1.0` at commit `28076d10f274` (2020-06-15); no further `vN.M` tags, no CHANGELOG, no release notes. The published site banner reads "Secure Rust Guidelines (unstable)". Pinning therefore must be by commit SHA, not by tag, with the SHA cross-checked against the rendered site to detect drift.

## Rule index — major rule families and counts

Rules are encoded as `<div class="reco" id="<FAMILY>-<SLUG>" type="Rule|Recommendation|Warning" title="...">` blocks. Counting `id="..."` occurrences across `src/en/*.md` at commit `84e6ae18` yields **61 rules total** in 6 families:

| Family | Count | Source files (under `src/en/`) | Coverage in idiomatic Rust crates |
|---|---|---|---|
| DENV (development environment) | 8 | `devenv.md` | high — toolchain/cargo settings; satisfied by `rust-toolchain.toml`, `Cargo.lock` policy, CI invocations of `clippy`/`rustfmt` |
| LIBS (third-party dependencies) | 5 | `libraries.md` | high — `cargo-deny`, `cargo-audit`, `cargo-outdated`, `cargo-geiger` map directly |
| LANG (language constructs) | 16 | `naming.md` (1), `integer.md` (1), `errors.md` (4), `standard.md` (8), `unsafe/generalities.md` (2) | partial — naming/derive lints from clippy; panic-limit + arithmetic require restriction-group lints + discipline |
| MEM (memory management) | 10 | `unsafe/memory.md` (9), `standard.md` (1, MEM-MUT-REC-RC) | partial — clippy `mem_forget` plus design conventions; some rules doc-only |
| FFI (foreign function interface) | 21 | `unsafe/ffi.md` | minimal in pure-Rust libs — for `forbid(unsafe_code)` libs most FFI rules are N/A |
| UNSAFE (umbrella) | 1 | `unsafe/generalities.md` (UNSAFE-NOUB) | high in `forbid(unsafe_code)` crates |

(Source: `src/en/SUMMARY.md` plus per-file `id="..."` extraction at commit `84e6ae18`. `unsafe.md`, `guarantees.md` carry 0 rules; `macros.md`, `typesystem.md`, `testfuzz.md` are commented-out TODOs in `SUMMARY.md`.)

## Existing public ANSSI compliance documents (Rust or otherwise)

| Project / org | Doc URL | Shape | Notes |
|---|---|---|---|
| ANSSI-FR / MLA | [github.com/ANSSI-FR/MLA](https://github.com/ANSSI-FR/MLA) audit `doc/20260130-mla-security-assessment.pdf` | CESTI Synacktiv free-form findings PDF (severity-graded), **not** a per-rule mapping table | Closest example of an ANSSI-blessed Rust project; per-rule compliance is implicit. |
| ANSSI-FR org evaluations | [ANSSI-FR/.github/profile/evaluations.md](https://github.com/ANSSI-FR/.github/blob/main/profile/evaluations.md) | List of audited OSS projects (HAProxy, step-ca, MLA, etc.) with 1-line status | None of the listed audits are formatted as ANSSI-rust-guide rule tables. |
| Rust crates ecosystem | searched github.com, crates.io | **No public ANSSI-rust-guide compliance dossier found** for `rustls`, `tonic`, `actix-web`, `tokio`, `hyper`, or any French-government-funded Rust project as of 2026-05-05. | Search note: queries `"rust-guide" ANSSI compliance` and `"ANSSI" "rust" compliance dossier` return only the guide repo itself. SunLit's mapping would be the first published example. |

## Cross-walk to EU regulations

- **NIS2 (Article 21 implementing acts)** — Article 21(2) lists 10 risk-management areas (incl. supply-chain security and cryptography policy). The implementing act is Commission Implementing Regulation (EU) 2024/2690 (17 Oct 2024). Neither the directive nor 2024/2690 names the ANSSI Rust guide. National competent authorities issue their own implementation guidance under a generic "national CA guidance" hook. **Verdict: not cited; leverage is via French national implementation, not via the EU directive.**
- **EU CRA technical-documentation requirements** — Regulation (EU) 2024/2847 (in force 2024-12-10; main obligations from 2027-12-11) requires technical documentation of conformance with Annex I "essential cybersecurity requirements". Standardisation request M/606 lists 41 standards — none is the ANSSI Rust guide. CRA permits "state of the art" demonstrations, under which the guide is admissible evidence in French markets. **Verdict: not cited; admissible as state-of-the-art evidence only.**
- **ENISA secure-coding recommendations citing ANSSI** — ENISA's June 2025 Technical Implementation Guidance v1.0 and the December 2025 Secure-Use-of-Package-Managers Technical Advisory do not name the ANSSI Rust guide. **Verdict: ENISA does not cite the rust-guide.**

## Tooling that auto-checks subsets of ANSSI rules

| Tool | ANSSI rule(s) covered (estimated overlap) | URL |
|---|---|---|
| Clippy `restriction` group | LANG-LIMIT-PANIC / LANG-LIMIT-PANIC-SRC (`clippy::panic`, `clippy::unwrap_used`, `clippy::expect_used`); LANG-ARRINDEXING (`clippy::indexing_slicing`); LANG-ARITH (`clippy::arithmetic_side_effects`); MEM-FORGET / MEM-FORGET-LINT (`clippy::mem_forget`); FFI/MEM transmute (`clippy::transmute_*`); LANG-UNSAFE-ENCP (`clippy::undocumented_unsafe_blocks`, `clippy::multiple_unsafe_ops_per_block`). **~12 of 61 (~20%)** | https://rust-lang.github.io/rust-clippy/master/index.html?groups=restriction |
| Clippy default groups | LANG-NAMING; LANG-CMP-* (`clippy::derive_ord_xor_partial_ord`, `clippy::derived_hash_with_manual_eq`); LANG-DROP-NO-PANIC (`clippy::panic_in_drop`). **~6 of 61 (~10%)** | https://doc.rust-lang.org/clippy/lints.html |
| `cargo-deny` | LIBS-VETTING-DIRECT, LIBS-VETTING-TRANSITIVE, LIBS-AUDIT, DENV-CARGO-LOCK. **~4 of 61** | https://embarkstudios.github.io/cargo-deny/ |
| `cargo-audit` | LIBS-AUDIT (RustSec advisory scan). **1 of 61** | https://crates.io/crates/cargo-audit |
| `cargo-outdated` | LIBS-OUTDATED. **1 of 61** | https://github.com/kbknapp/cargo-outdated |
| `cargo-geiger` | LIBS-UNSAFE, LANG-UNSAFE, LANG-UNSAFE-ENCP (visibility). **~3 of 61** | https://github.com/geiger-rs/cargo-geiger |
| `rustc` `forbid(unsafe_code)` | LANG-UNSAFE (hard-enforced); UNSAFE-NOUB subsumed in pure-safe crates. **~2 of 61** | https://doc.rust-lang.org/rustc/lints/listing/ |
| Semgrep `p/rust` | Partial overlap with FFI-CK-PTR-VALID-style patterns and side-channel hygiene (`args_os`, `current_exe`, `temp_dir`). **~3 of 61** | https://registry.semgrep.dev/ruleset/rust |

Aggregate (deduplicated): roughly **25 of 61 rules (~40%)** can be backed by an automated tool today; the rest require code review, doc-only evidence, or tests. No `cargo-anssi` or "Clippy ANSSI mode" exists.

## Regulatory / certification angle (broader)

- **IEC 62443-4-1** — requires a secure-coding-standard practice (SD-3 / SI-1) without naming a language. The ANSSI Rust guide is admissible as that documented standard for Rust components, but 62443 itself does not cite it.
- **ENISA Rust security recommendations** — none published as of 2026-05-05; ENISA's package-manager advisory (Dec 2025) is language-agnostic.
- **SecNumCloud** — ANSSI cloud-provider qualification, orthogonal to the Rust guide; cloud providers using Rust benefit from a rust-guide mapping in their own technical dossier, but SecNumCloud does not enumerate Rust rules.

## Open questions that research did not answer

- **Exact ENISA passage on national-CA secure-coding guides** — the June 2025 Technical Implementation Guidance PDF could not be parsed by WebFetch (FlateDecode); a local PDF download is required to quote any specific endorsement.
- **CRA harmonised standards still to come** — M/606's 41 standards are not yet individually published; whether any will normatively cite ANSSI guidance is undeterminable until CEN-CENELEC drafts appear (expected 2026–2027).
- **English vs. French rule-ID parity** — confirmed identical English slugs in both renderings (resolves idea-doc open question #2).

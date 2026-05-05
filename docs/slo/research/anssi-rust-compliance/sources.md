# Sources — anssi-rust-compliance
Access date for all entries: 2026-05-05.

## ANSSI Rust guide — primary

- [ANSSI-FR/rust-guide GitHub repository](https://github.com/ANSSI-FR/rust-guide) — canonical source repo for the ANSSI "Programming Rules for Developing Secure Applications in Rust" guide (the `master` branch is what `anssi-fr.github.io/rust-guide` renders).
- [ANSSI-FR/rust-guide commits API (master HEAD)](https://api.github.com/repos/ANSSI-FR/rust-guide/commits/master) — confirms latest commit `84e6ae181712c9ed797aeaf695c9965a13a1d5fa` dated 2026-04-07T15:20:39Z, message "add examples and fix typos".
- [ANSSI-FR/rust-guide tag v1.0](https://api.github.com/repos/ANSSI-FR/rust-guide/commits/v1.0) — only published Git tag, points to commit `28076d10f274` dated 2020-06-15; no further `vN.M` tags exist.
- [ANSSI-FR/rust-guide branches API](https://api.github.com/repos/ANSSI-FR/rust-guide/branches) — confirms publishing branches: `master` (source) and `gh-pages` (rendered).
- [Secure Rust Guidelines — published rendering](https://anssi-fr.github.io/rust-guide/) — public site banner reads "Secure Rust Guidelines (unstable)"; no version number/date displayed in the page header.
- [src/en/SUMMARY.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/SUMMARY.md) — English table-of-contents grouping (Lifecycle, Language, Ecosystem).
- [src/fr/SUMMARY.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/fr/SUMMARY.md) — French table-of-contents (parity with English: same chapters, French headings).
- [src/en/devenv.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/devenv.md) — DENV-* rules (8 entries).
- [src/en/libraries.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/libraries.md) — LIBS-* rules (5 entries: VETTING-DIRECT, VETTING-TRANSITIVE, OUTDATED, AUDIT, UNSAFE).
- [src/en/naming.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/naming.md) — LANG-NAMING.
- [src/en/integer.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/integer.md) — LANG-ARITH.
- [src/en/errors.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/errors.md) — LANG-ERRWRAP, LANG-LIMIT-PANIC, LANG-LIMIT-PANIC-SRC, LANG-ARRINDEXING.
- [src/en/standard.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/standard.md) — LANG-SYNC-TRAITS, LANG-CMP-* (3), LANG-DROP-* (4), MEM-MUT-REC-RC.
- [src/en/unsafe/generalities.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/unsafe/generalities.md) — UNSAFE-NOUB, LANG-UNSAFE, LANG-UNSAFE-ENCP.
- [src/en/unsafe/memory.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/unsafe/memory.md) — MEM-NO-LEAK, MEM-FORGET, MEM-FORGET-LINT, MEM-LEAK, MEM-MANUALLYDROP, MEM-NORAWPOINTER, MEM-INTOFROMRAWALWAYS, MEM-INTOFROMRAWONLY, MEM-UNINIT.
- [src/en/unsafe/ffi.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/src/en/unsafe/ffi.md) — FFI-* rules (21 entries).
- [SECURITY.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/SECURITY.md) — vulnerability disclosure contact `opensource@ssi.gouv.fr`.
- [CONTRIBUTING.md @ 84e6ae18](https://raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae181712/CONTRIBUTING.md) — explicitly describes the guide as a "living document" (drives refresh-cadence reasoning).
- [Issue #10 — Forbid unsafe code](https://github.com/ANSSI-FR/rust-guide/issues/10) — discusses `#![forbid(unsafe_code)]` as the lint backing for LANG-UNSAFE; status: open.
- [Issue #44 — mem::forget / ManuallyDrop too strict](https://github.com/ANSSI-FR/rust-guide/issues/44) — community pushback on MEM-FORGET/MEM-MANUALLYDROP, useful for "waiver" framing.

## Existing public ANSSI-related Rust dossiers / audits

- [ANSSI-FR/MLA repository](https://github.com/ANSSI-FR/MLA) — pure-Rust archive format published by ANSSI; closest example of an ANSSI-blessed Rust project but does not itself ship an ANSSI-rust-guide compliance dossier.
- [ANSSI-FR org evaluations index](https://github.com/ANSSI-FR/.github/blob/main/profile/evaluations.md) — annual ANSSI-funded open-source security audits; lists MLA 2.0.0-beta audited by CESTI Synacktiv (2026-01-30), report path `doc/20260130-mla-security-assessment.pdf` in the MLA repo. No public per-rule mapping document is linked.
- [Hacker News thread "Secure Rust Guidelines"](https://news.ycombinator.com/item?id=31405896) — community discussion noting wish for "Clippy ANSSI mode"; useful evidence that no shipped tooling exposes such a mode.

## EU regulatory cross-walk

- [NIS2 Directive Article 21 (cybersecurity risk-management measures)](https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html) — the obligation hook entities cite during procurement.
- [Commission Implementing Regulation (EU) 2024/2690 (NIS2 technical & methodological requirements)](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj) — the only NIS2 implementing act for Article 21(2)(a)–(j); does not name ANSSI-FR/rust-guide.
- [ENISA Technical Implementation Guidance on cybersecurity risk-management measures, v1.0 (June 2025)](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance) — companion to 2024/2690; references "national cybersecurity authorities" generically rather than ANSSI's Rust guide specifically (PDF body could not be parsed by WebFetch; structure/scope confirmed from the publication landing page).
- [EU Cyber Resilience Act — DG CONNECT policy page](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) — entry into force 2024-12-10; main obligations from 2027-12-11.
- [EU CRA — standardisation page (M/606)](https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation) — standardisation request M/606 lists 41 horizontal/vertical standards but does not name ANSSI guidance as a citable standard.
- [EUR-Lex — Cyber Resilience Act, Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) — full CRA text; Annex I essential cybersecurity requirements are language-agnostic.
- [ENISA Technical Advisory — Secure Use of Package Managers (Dec 2025 draft)](https://www.enisa.europa.eu/sites/default/files/2025-12/ENISA%20Technical%20Advisory%20-%20Package_Managers_v_0.8_draft.pdf) — closest current ENISA work product touching Cargo/Rust supply chain; no ANSSI Rust guide citation.

## Tooling sources

- [Clippy lints book (groups overview)](https://doc.rust-lang.org/clippy/lints.html) — defines Correctness, Suspicious, Complexity, Perf, Style, Pedantic, Restriction, Cargo, Nursery groups.
- [Clippy lint list (filterable, restriction group)](https://rust-lang.github.io/rust-clippy/master/index.html?groups=restriction) — exposes individual lints used to back ANSSI rules: `clippy::mem_forget`, `clippy::transmute_*`, `clippy::arithmetic_side_effects`, `clippy::indexing_slicing`, `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`.
- [rust-lang/rust-clippy repo](https://github.com/rust-lang/rust-clippy) — confirms 750+ lints across groups (count cited as "over 500" in older docs; current README states 750+).
- [cargo-audit on crates.io](https://crates.io/crates/cargo-audit) — RustSec Advisory DB scanner backing LIBS-AUDIT.
- [EmbarkStudios/cargo-deny](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html) — supersedes cargo-audit for advisories + adds licenses, sources, bans; backs LIBS-VETTING-DIRECT, LIBS-VETTING-TRANSITIVE, LIBS-AUDIT.
- [geiger-rs/cargo-geiger](https://github.com/geiger-rs/cargo-geiger) — counts/locates `unsafe` in dep tree; backs LIBS-UNSAFE and LANG-UNSAFE-ENCP visibility.
- [Semgrep registry — rust ruleset](https://registry.semgrep.dev/ruleset/rust) — public Rust rules incl. `args_os`, `current_exe`, `temp_dir` patterns; partial overlap with FFI-CK-PTR-VALID, MEM-UNINIT.
- [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) — third-party semgrep rules including Rust patterns covering panic, unwrap, transmute usage.
- [rust-lang/rust-clippy issue #9330 (undocumented_unsafe_blocks)](https://github.com/rust-lang/rust-clippy/issues/9330) — backs LANG-UNSAFE-ENCP "SAFETY:" comment requirement.
- [High Assurance Rust — Recommended Tooling](https://highassurance.rs/chp3/tooling.html) — independent practitioner inventory of clippy/cargo-audit/rustfmt; useful for triangulating tool-coverage table.
- [SecNumCloud overview (Scalingo blog, EN)](https://scalingo.com/blog/secnumcloud-qualification-anssi-guide) — confirms SecNumCloud is an ANSSI-issued *cloud-provider* qualification, not a developer/secure-coding scheme; explains why it does not directly cite the Rust guide.

## French-language references (with English gloss)

- [Pierre Chifflier (ANSSI), "Rust: Towards Better Code Security" (GDR Sécurité)](https://gdr-securite.irisa.fr/wp-content/uploads/PChifflier-rust.pdf) — slide deck from the ANSSI author of the guide; English already.
- [Cyber.gouv.fr — Open-source strategy page](https://cyber.gouv.fr/enjeux-technologiques/open-source/) — confirms ANSSI's official endorsement of the rust-guide repo. Key sentence (FR): "L'ANSSI publie et maintient sur GitHub des projets open source." Translation: "ANSSI publishes and maintains open-source projects on GitHub."

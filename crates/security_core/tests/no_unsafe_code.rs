//! Workspace-level regression test for the `#![forbid(unsafe_code)]` posture.
//!
//! Lives in `security_core/tests/` because the workspace root has no
//! `[package]` block (it is a virtual manifest). Putting the test here gives it
//! the same execution surface — every CI test run executes it — without the
//! structural cost of converting the root into a hybrid root-package.
//!
//! Asserts that every workspace member's `lib.rs` (or `main.rs` for binary
//! crates with no library) declares `#![forbid(unsafe_code)]` within the first
//! 20 lines, before any item declaration. Removal of the attribute fails the
//! build with a named-crate error.
//!
//! This is the regression test for runbook
//! `docs/slo/future/RUNBOOK-forbid-unsafe-and-geiger.md` M1.

use std::fs;
use std::path::{Path, PathBuf};

/// Every workspace crate that ships Rust code; verified manually as of M1.
///
/// Explicit list (rather than parsing the root `Cargo.toml`) so the test fails
/// loudly if a crate is added without thinking about its unsafe posture.
const CRATES_REQUIRING_FORBID: &[&str] = &[
    "security_core",
    "secure_errors",
    "security_events",
    "secure_boundary",
    "secure_authz",
    "secure_data",
    "secure_output",
    "secure_identity",
    "secure_device_trust",
    "secure_reference_service",
    "secure_smoke_service",
    "secure_network",
    "secure_resilience",
    "secure_privacy",
];

/// Resolves the workspace root from the per-crate test working directory.
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at `crates/security_core/`; go up two levels.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR must be two levels below workspace root")
        .to_path_buf()
}

/// All compiled crate roots, including binary targets in library packages.
fn crate_root_files(workspace: &Path, krate: &str) -> Vec<PathBuf> {
    let src = workspace.join("crates").join(krate).join("src");
    [src.join("lib.rs"), src.join("main.rs")]
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

fn has_real_forbid(contents: &str) -> bool {
    let mut depth = 0usize;
    for line in contents.lines() {
        let mut rest = line.trim();
        loop {
            if depth > 0 {
                let open = rest.find("/*");
                let close = rest.find("*/");
                match (open, close) {
                    (Some(start), end) if end.is_none_or(|end| start < end) => {
                        depth += 1;
                        rest = &rest[start + 2..];
                    }
                    (_, Some(end)) => {
                        depth -= 1;
                        rest = rest[end + 2..].trim();
                    }
                    _ => break,
                }
                continue;
            }
            if rest.starts_with("/*") {
                depth += 1;
                rest = &rest[2..];
                continue;
            }
            if rest.is_empty() || rest.starts_with("//") {
                break;
            }
            if rest == "#![forbid(unsafe_code)]" {
                return true;
            }
            if rest.starts_with("#![") && rest.ends_with(']') {
                break;
            }
            return false;
        }
    }
    false
}

#[test]
fn commented_attribute_is_not_an_attestation() {
    assert!(!has_real_forbid(
        "/*\n#![forbid(unsafe_code)]\n*/\nfn main() {}"
    ));
    assert!(!has_real_forbid("// #![forbid(unsafe_code)]\nfn main() {}"));
    assert!(!has_real_forbid(
        "/* outer /* inner */\n#![forbid(unsafe_code)]\n*/\nfn main() {}"
    ));
    assert!(has_real_forbid(
        "//! docs\n#![forbid(unsafe_code)]\nfn main() {}"
    ));
}

#[test]
fn registered_members_match_cargo_workspace() {
    let root = workspace_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let members: std::collections::BTreeSet<_> = manifest
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("\"crates/")
                .and_then(|v| v.strip_suffix("\","))
        })
        .collect();
    let registered: std::collections::BTreeSet<_> =
        CRATES_REQUIRING_FORBID.iter().copied().collect();
    assert_eq!(
        members, registered,
        "new members must participate in compiler unsafe checks"
    );
}

#[test]
fn every_workspace_crate_forbids_unsafe_code() {
    let workspace = workspace_root();
    let mut failures: Vec<String> = Vec::new();

    for krate in CRATES_REQUIRING_FORBID {
        let files = crate_root_files(&workspace, krate);
        if files.is_empty() {
            failures.push(format!("crate `{krate}` has no compiled root"));
        }
        for file in files {
            let contents = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(err) => {
                    failures.push(format!(
                        "crate `{krate}`: cannot read {}: {err}",
                        file.display()
                    ));
                    continue;
                }
            };

            if !has_real_forbid(&contents) {
                failures.push(format!(
                "crate `{krate}`: expected `#![forbid(unsafe_code)]` in the first 20 lines of {}; not found.\n\
                 Add the attribute at the top of the file (before any item declaration).\n\
                 If the crate genuinely needs unsafe, document the exception in \
                 docs/dev-guide/unsafe-budget.md and update CRATES_REQUIRING_FORBID.",
                file.display()
            ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "forbid(unsafe_code) regression test failed for {} crate(s):\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

#[test]
fn no_unsafe_keyword_in_workspace_sources() {
    // Sanity check: even with `forbid(unsafe_code)`, ensure no `unsafe ` keyword
    // appears in any crate's `src/`. Catches macros or includes that might
    // sneak unsafe in via a path the lint cannot see.
    let workspace = workspace_root();
    let mut found: Vec<String> = Vec::new();

    for krate in CRATES_REQUIRING_FORBID {
        let src_dir = workspace.join("crates").join(krate).join("src");
        if !src_dir.exists() {
            continue;
        }
        scan_for_unsafe(&src_dir, krate, &mut found);
    }

    assert!(
        found.is_empty(),
        "found `unsafe` keyword in workspace sources (must be empty under forbid(unsafe_code)):\n  - {}",
        found.join("\n  - ")
    );
}

fn scan_for_unsafe(dir: &Path, krate: &str, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_for_unsafe(&path, krate, found);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for (lineno, line) in contents.lines().enumerate() {
            // Skip comments to avoid false positives from doc comments mentioning unsafe.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
                continue;
            }
            // Match `unsafe ` followed by `{`, `fn`, `impl`, `trait`, or another keyword
            // — this is the actual code-form of the keyword, not a string literal.
            if has_unsafe_keyword(line) {
                found.push(format!(
                    "crate `{krate}`: {}:{} — {}",
                    path.display(),
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn has_unsafe_keyword(line: &str) -> bool {
    // `unsafe ` followed by `{`, `fn`, `impl`, or `trait` — the keyword forms
    // that mark an actual unsafe block / fn / impl / trait. Avoids matching
    // identifiers like `assume_unsafe_aliasing` or string literals.
    const FORMS: &[&str] = &["unsafe {", "unsafe fn", "unsafe impl", "unsafe trait"];
    FORMS.iter().any(|f| line.contains(f))
}

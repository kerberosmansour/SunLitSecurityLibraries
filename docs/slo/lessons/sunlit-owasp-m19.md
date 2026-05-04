# Lessons Learned — sunlit-owasp Milestone 19

## What changed
- Added `ldap.rs` module to `secure_output` with `LdapDnEncoder` (RFC 4514) and `LdapFilterEncoder` (RFC 4515)
- Added `shell.rs` module to `secure_output` with `ShellEncoder` (POSIX single-quoting)
- All three encoders implement `OutputEncoder` trait and provide convenience free functions
- Updated `lib.rs` with new module declarations and re-exports
- 6 new doc-tests covering all public APIs

## Design decisions and why
- **Single-quoting for shell encoding** — single quotes are the safest POSIX shell quoting mechanism. Inside single quotes, no metacharacters are interpreted (no `$`, `\`, `` ` ``, `!`, etc.). The only special case is embedded single quotes, escaped as `'\''`. This is more robust than backslash-escaping individual characters, which risks missing edge cases.
- **Free functions as primary API** — follows M18 lesson and Kevin Wall's ESAPI principle adapted for Rust. `encode_dn()`, `encode_filter()`, and `shell::encode()` are the primary entry points; trait impls exist for polymorphic contexts.
- **Hex-encoding for LDAP filter** — RFC 4515 specifies `\XX` hex notation for special characters. Using byte-level hex encoding handles multi-byte characters correctly.
- **Backslash-escaping for LDAP DN** — RFC 4514 uses `\<char>` for most special characters and `\XX` hex notation for null bytes, matching the standard's specification.
- **Null byte handling** — DN encoder hex-escapes null bytes as `\00`; filter encoder hex-escapes them; shell encoder strips them (POSIX shell cannot handle null bytes in arguments).

## Mistakes made
- Initial shell BDD tests used substring-absence checks (e.g., `!result.contains("; rm")`) which fail with single-quoting strategy because the characters appear inside quotes but are harmless. Fixed to verify single-quoting structure instead.

## Root causes
- Confusing "character not present" with "character neutralized" — single-quoting neutralizes metacharacters without removing them.

## What was harder than expected
- Nothing significant. The encoders are pure string manipulation with well-defined RFC specifications.

## Naming conventions established
- Module names: `ldap.rs`, `shell.rs` (match the output context)
- Encoder types: `LdapDnEncoder`, `LdapFilterEncoder`, `ShellEncoder` (context-specific, not generic)
- Free functions: `encode_dn()`, `encode_filter()`, `shell::encode()` (verb pattern matching existing API style)

## Test patterns that worked well
- `assert_single_quoted()` helper for verifying shell encoding output structure
- Testing free function ↔ trait equivalence with an array of inputs in a loop
- Exact string equality assertions for LDAP encoding (deterministic output)

## Missing tests that should exist now
- Property-based tests for LDAP encoders (proptest: all RFC special chars are always escaped)
- Fuzz targets for all three encoders
- Benchmark comparing encoding throughput across all contexts

## Rules for the next milestone
- M20 (password hashing) introduces new dependencies — verify compile-time cost with `cargo tree`
- Follow the same free-function-first API pattern for `hash_password()` and `verify_password()`

## Template improvements suggested
- None

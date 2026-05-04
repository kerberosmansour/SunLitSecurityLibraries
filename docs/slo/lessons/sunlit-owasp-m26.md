# Lessons — M26 Documentation & Ergonomics Retrofit

## What went well

1. **Batch editing is effective for doc tasks** — `multi_replace_string_in_file` allowed adding
   `# Examples` to many items in a single operation, keeping the workflow fast.
2. **Running `cargo test --doc -p <crate>` after each crate** caught issues immediately
   (e.g. private tuple struct destructuring in `SecureJson`, incorrect `Display` output
   in `Action::to_string()`), preventing error cascading.
3. **Convenience free functions in `secure_output`** (`html::encode()`, `url::encode()`, etc.)
   provide a dramatically simpler API surface — users no longer need to instantiate encoder structs
   for the common case.
4. **Pre-flight audit** (reading every public item across all 8 crates) gave a clear work list
   and prevented missed items.

## What could be improved

1. **Sealed traits limit doc examples** — `Authenticator` and `PolicyEngine` are sealed, so
   examples must use concrete types like `ApiKeyAuthenticator` or `MockAuthorizer` rather than
   showing trait usage directly. Consider whether sealed traits warrant a "How to use" section
   on the trait itself pointing to concrete implementations.
2. **Async examples require `# async fn` wrappers** — many items in `secure_data` and
   `secure_identity` are async, requiring boilerplate `async fn example()` wrappers in doc tests.
   The `tokio::test` macro isn't available in doc tests without extra setup.
3. **Feature-gated modules** (e.g. `dev` authenticator, `vault` resolver, `html-sanitize`)
   are harder to cover with doc examples since they require conditional compilation.

## Patterns worth repeating

- Run baseline tests **before** any changes to confirm the starting state is green.
- Work crate-by-crate, verifying doc tests after each crate, rather than editing all crates
  then debugging failures at the end.
- Use `no_run` for examples that need a runtime (axum handlers, async code with real services).
- Keep doc examples minimal — show one constructor call and one assertion, not full workflows.

## Metrics

| Crate | Doc tests before | Doc tests after |
|-------|-----------------|-----------------|
| security_core | 0 | 15 |
| secure_errors | 1 (ignore) | 11 |
| security_events | 7 | 22 |
| secure_output | 4 | 20 |
| secure_boundary | 10 | 32 |
| secure_data | 6 | 24 |
| secure_identity | 12 | 21 |
| secure_authz | 12 | 23 |
| **Total** | **52** | **168** |

New convenience free functions: 6 (secure_output: html, url, js, css, xml, json).

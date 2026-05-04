//! Minimal runnable demonstration of `assert_no_dev_identity_in_production`.
//!
//! Build & run:
//!
//! ```sh
//! # Safe: staging with dev identity -> Ok, prints "boot check passed".
//! APP_ENV=staging cargo run --example production_boot -p secure_identity
//!
//! # Unsafe: production with dev identity -> panics at boot.
//! APP_ENV=production cargo run --example production_boot -p secure_identity
//!
//! # Safe: production without dev identity -> Ok.
//! APP_ENV=production HAS_DEV_SOURCE=false cargo run --example production_boot -p secure_identity
//! ```
//!
//! In a real service this check runs once inside `main()` (or your
//! service-initialiser) before any request-handling code starts.

use secure_identity::boot::assert_no_dev_identity_in_production;

fn main() {
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    // In a real service, set `has_dev_source` based on your configured
    // authenticator chain (e.g. true iff you registered `DevAuthenticator`).
    let has_dev_source = std::env::var("HAS_DEV_SOURCE")
        .map(|v| v != "false")
        .unwrap_or(true);

    if let Err(violation) = assert_no_dev_identity_in_production(&app_env, has_dev_source) {
        panic!("{violation}");
    }

    println!("boot check passed (app_env={app_env:?}, has_dev_source={has_dev_source})");
}

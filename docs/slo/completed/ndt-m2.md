# Completion — ndt M2

## Summary

M2 is complete for the library-side S3 gate. `secure_device_trust` now provides
the supported session certificate lifecycle surface: typed CSR profiles,
bounded TTL policy, clientAuth-only issuance profiles, allowed URI SAN policy,
signer adapter boundary, refresh windows, and revocation handles/checks.

`secure_network` now exposes `MtlsClientIdentity` so Actix Web services and
trusted edge adapters can reject untrusted, expired, not-yet-valid, or revoked
mTLS identities before user authentication.

## Evidence

| Command | Result |
|---|---|
| `cargo test --workspace` baseline | Pass |
| `cargo test -p secure_device_trust --test e2e_sunlit_ndt_m2` BDD-first | Failed before implementation for expected behavior gaps |
| `cargo test -p secure_device_trust --test e2e_sunlit_ndt_m2` final | Pass |
| `cargo test -p secure_network --test mtls_identity_tests` | Pass |
| `cargo fmt --all -- --check && cargo test --workspace` | Pass |
| `cargo check --workspace --all-features && cargo check --workspace --no-default-features` | Pass |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Pass |

## Security Notes

- No production filesystem CA signer path was added.
- The library signs only a pre-validated profile through an adapter trait.
- Forbidden CSR extensions and browser-style DNS SANs are rejected safely.
- Revoked bootstrap decisions and revoked session handles block refresh.
- Expired mTLS identities are rejected by `secure_network`.

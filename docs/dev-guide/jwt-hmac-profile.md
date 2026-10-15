# HMAC-only identity profile — 0.4.0

This capability begins in coordinated 0.4.0; published 0.3.0 has no `jwt-hmac`
feature. The release approval record and signed assets bind registry bytes to the
reviewed source.

```toml
secure_identity = { version = "=0.4.0", default-features = false, features = ["jwt-hmac"] }
jsonwebtoken = { version = "=11.0.0", default-features = false }
```

Existing defaults retain asymmetric JWT/capability/JWKS helpers and SSH validation
through named `asymmetric-jwt` and `ssh-public-keys` default groups. `jwks` and
`oidc` imply their asymmetric requirements. The reduced profile gates those
surfaces off; previous no-default-feature asymmetric callers must opt in to the
appropriate group. For example, preserve prior asymmetric JWT and SSH imports with
`secure_identity = { version = "=0.4.0", default-features = false, features = ["asymmetric-jwt", "ssh-public-keys"] }`.
The `jwt_hmac` module exists only when `asymmetric-jwt` is disabled. Cargo features are additive: enabling SSH/asymmetric/OIDC or
another dependency's crypto feature can restore `rsa`. This profile's proof is
for the actual isolated consumer normal/build graph, not arbitrary feature unions
or complete absence of RSA code from ring. Legacy reachability exceptions remain.

## Initialize the process provider

At trusted application startup, before any direct vendor JWT encoding or another
JWT user, call `secure_identity::jwt_hmac::install_default_provider()?`.
`TokenValidator` also calls this before decoding in the reduced profile. The local
OnceLock caches a checked installation result: own repeated/concurrent calls are
idempotent; a preexisting provider fails with fixed `IdentityError::ProviderUnavailable`.
No foreign provider is inspected, replaced or assumed compatible. If an upstream
JWT call freezes its default before this hook, authentication remains unavailable;
restart with correct startup order. Never catch that error and downgrade validation.
The vendor's global provider API is documented in
[jsonwebtoken 11](https://docs.rs/jsonwebtoken/11.0.0/jsonwebtoken/crypto/struct.CryptoProvider.html).

Use existing `TokenValidator`, issuer/audience configuration and authentication
request types. They validate real HS256 signatures and claims through the vendor
boundary. The provider supports HS256/384/512 factories for direct vendor use;
TokenValidator's existing HS256-only algorithm policy does not silently broaden.
Unsupported algorithms/key families and asymmetric key utilities return typed
errors. No raw JWT parser, insecure_decode, hand-written signature comparison or
HMAC implementation is introduced; ring performs HMAC verification.

## Bounds and keys

The reduced profile requires secret keys at least 32/48/64 bytes for
HS256/384/512 and at most 1024 bytes. This follows the hash-strength minimum in
[RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2).
Length checks do not prove randomness or entropy. Use securely generated secrets of adequate strength and existing secret-management
boundaries; example/fixture keys are synthetic and never production credentials.
Do not log keys, raw tokens or claims. Private provider owners omit Debug; this
feature does not guarantee erasure of ring/internal copies or all application
plaintext memory. The existing configuration owns a byte vector, not a hardware
custody claim or new zeroizing secret API.

TokenValidator accepts a complete token at most 64 KiB and rejects larger input
before vendor parsing. IdentitySource.resolve checks that bound before copying.
Provider signing accounts for the separator and encoded signature, so a successful
mint does not exceed the complete-token bound; verification checks message and
exact tag size before HMAC. Direct vendor parsing remains the caller's boundary:
apply size limits before invoking vendor APIs rather than assuming a provider can
retroactively prevent their initial parsing/allocation.

## Admission and verification

The generic OSV gate excludes deliberately vulnerable fixture directories. This
exact executable consumer is an admitted positive fixture. Run:

```sh
python3 scripts/check-jwt-hmac-profile.py --admit --output .cache/jwt-hmac-osv.json
cargo test -p secure_identity --no-default-features --features jwt-hmac --test jwt_hmac_profile --locked
cargo test -p secure_identity --no-default-features --features jwt-hmac --lib jwt_hmac::tests --locked
cargo run --manifest-path fixtures/jwt-hmac-consumer/Cargo.toml --locked -- all
```

The profile checker reuses the unchanged pinned official OSV core over all root,
tool and this exact consumer lock, checks the isolated normal/build graph has no
rsa and that external identities/sources/checksums are a root subset. No fixture
advisory inherits root exceptions; scanner/network/parsing errors fail closed.
New candidate locks resolve without builds/scripts before admission. CI runs this
all-lock gate before compilation, including every profile scenario. Do not treat
a generic six-lock root scan as admission of this excluded consumer lock.

The executable fixture uses real JWT signing/authentication and separate processes
for own concurrent initialization, foreign-first, own-first, competing registration
and early upstream misuse. Its fixed token/key/identity are test-only. Legacy
RSA integration tests are selected under their default/asymmetric profile; the
new selected test and consumer cover the reduced profile separately. Do not run
all legacy asymmetric integration targets under a deliberately reduced API and
call their unavailable imports a security regression. Pure acceptance helpers
have bounded Kani obligations using the existing approved 0.68.0 Linux CI toolchain.

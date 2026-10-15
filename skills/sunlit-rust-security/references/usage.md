# SunLit Rust published usage reference

Reviewed against **0.4.0**, release commit
`318512ab65a6894d81a8b73e3ac8df4eef0753ea`. All twelve crates were verified on
crates.io with repository metadata pointing to `kerberosmansour/SunLitSecurityLibraries`.
Package and Rust import names use underscores, not inferred kebab-case spellings.

## Choose the crate

| Task                                | Published package                                                   | Versioned API                                                           |
| ----------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Shared identity and security types  | [security_core](https://crates.io/crates/security_core)             | [0.4.0](https://docs.rs/security_core/0.4.0/security_core/)             |
| Security events and redaction       | [security_events](https://crates.io/crates/security_events)         | [0.4.0](https://docs.rs/security_events/0.4.0/security_events/)         |
| Safe error boundaries               | [secure_errors](https://crates.io/crates/secure_errors)             | [0.4.0](https://docs.rs/secure_errors/0.4.0/secure_errors/)             |
| Request validation                  | [secure_boundary](https://crates.io/crates/secure_boundary)         | [0.4.0](https://docs.rs/secure_boundary/0.4.0/secure_boundary/)         |
| Output encoding                     | [secure_output](https://crates.io/crates/secure_output)             | [0.4.0](https://docs.rs/secure_output/0.4.0/secure_output/)             |
| Authentication and identity         | [secure_identity](https://crates.io/crates/secure_identity)         | [0.4.0](https://docs.rs/secure_identity/0.4.0/secure_identity/)         |
| Authorization and tenant boundaries | [secure_authz](https://crates.io/crates/secure_authz)               | [0.4.0](https://docs.rs/secure_authz/0.4.0/secure_authz/)               |
| Secrets and envelope encryption     | [secure_data](https://crates.io/crates/secure_data)                 | [0.4.0](https://docs.rs/secure_data/0.4.0/secure_data/)                 |
| Network security helpers            | [secure_network](https://crates.io/crates/secure_network)           | [0.4.0](https://docs.rs/secure_network/0.4.0/secure_network/)           |
| Resilience controls                 | [secure_resilience](https://crates.io/crates/secure_resilience)     | [0.4.0](https://docs.rs/secure_resilience/0.4.0/secure_resilience/)     |
| Privacy controls                    | [secure_privacy](https://crates.io/crates/secure_privacy)           | [0.4.0](https://docs.rs/secure_privacy/0.4.0/secure_privacy/)           |
| Device-trust evidence               | [secure_device_trust](https://crates.io/crates/secure_device_trust) | [0.4.0](https://docs.rs/secure_device_trust/0.4.0/secure_device_trust/) |

Read the [published manifests](https://github.com/kerberosmansour/SunLitSecurityLibraries/tree/v0.4.0/crates)
for feature and dependency bounds. `secure_authz` enables Axum by default;
`secure_data` features such as `password`, `vault`, `aws-kms` and `mobile-storage`
are opt-in. Do not infer available APIs from feature names alone.
Use exact reviewed versions, for example `secure_data = "=0.4.0"`, and resolve
Cargo.lock without building. Complete OSV/provenance admission before executing
build scripts or procedural macros; preserve stricter consumer rules and cargo-vet.

## Deny-by-default authorization

This function accepts the application's authenticated subject. Construct it from
trusted identity data, never roles or tenant IDs taken from the request body.
In an existing admitted async application:

```rust
use secure_authz::{
    action::Action,
    decision::Decision,
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    subject::Subject,
};
use std::sync::Arc;

async fn check_default_deny(subject: &Subject) -> Result<(), Box<dyn std::error::Error>> {
    let engine = Arc::new(DefaultPolicyEngine::new_empty().await?);
    let authorizer = DefaultAuthorizer::new(engine);
    let resource = ResourceRef::new("article").with_tenant("example-tenant");
    let decision = authorizer.authorize(subject, &Action::Read, &resource).await;
    assert!(matches!(decision, Decision::Deny { .. }));
    Ok(())
}
```

An empty policy denies access. Add only required allow rules and test permitted
operations and cross-tenant denial. For Axum, inspect `AuthzLayer` and middleware
ordering for the installed version. Evidence:
[published deny-default tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_authz/tests/sunlit_authz_deny_default.rs).
This fragment is not a standalone server.

## Envelope encryption for stored state

This local round-trip uses an intentionally insecure development provider.
**Never use StaticDevKeyProvider for production or real secrets.** Configure an
appropriate production provider, credentials, key custody and recovery policy
before protecting user data.

```rust
use secure_data::{
    envelope::{decrypt_for_use, encrypt_for_storage},
    kms::StaticDevKeyProvider,
};

async fn local_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"synthetic test data";
    let envelope = encrypt_for_storage(plaintext, "example-key", &provider).await?;
    let recovered = decrypt_for_use(&envelope, &provider).await?;
    assert_eq!(recovered, plaintext);
    Ok(())
}
```

Test ciphertext tampering and wrong-key failures too. Evidence:
[published envelope tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_data/tests/sunlit_data_envelope.rs)
and [provider contract](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_data/src/kms.rs).
Mobile references and bridge APIs do not prove physical-device security or a
consumer's Guardian integration; retain the release's qualification limits.

## Emit a security event

```rust
use security_core::severity::SecuritySeverity;
use security_events::{
    emit::emit_security_event,
    event::{EventOutcome, SecurityEvent},
    kind::EventKind,
};

let event = SecurityEvent::new(
    EventKind::AdminAction,
    SecuritySeverity::Info,
    EventOutcome::Success,
);
emit_security_event(event);
```

This matches the [published emission doctest](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/security_events/src/emit.rs).
It uses application tracing, and is not a report to SunLit, remote telemetry or
automatically HMAC-signed evidence. Configure a signing/sink path explicitly if
required. Classify and redact fields before export; never log credentials,
raw prompts or private payloads.

For request validation, inspect `secure_boundary::SecureJson`, route limits and
framework features in the [versioned API](https://docs.rs/secure_boundary/0.4.0/secure_boundary/).
Test malformed, oversized and unauthorized requests against the actual service.

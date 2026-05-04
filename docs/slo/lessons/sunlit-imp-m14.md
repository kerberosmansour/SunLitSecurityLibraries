# Lessons Learned — Milestone 14: Identity & Authentication Hardening

**Date:** 2026-04-06  
**Milestone:** M14 — Identity & Authentication Hardening

---

## 1. EC key format matters: PKCS8 vs SEC1
`jsonwebtoken::EncodingKey::from_ec_pem()` requires PKCS8-formatted private key material, not SEC1-formatted EC key material. OpenSSL's `ecparam -genkey` produces SEC1 by default. Use `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve` to generate PKCS8 keys with named curve encoding. Public-release tests should prefer committed public keys plus pre-signed JWT fixtures so private test keys are not present in the repository tree.

## 2. ring 0.17 deprecations require alternative crates
`ring::constant_time::verify_slices_are_equal` is deprecated in ring 0.17. The `subtle` crate (v2) with `ConstantTimeEq` is a clean replacement. The `subtle` crate is well-maintained, widely used in the Rust crypto ecosystem, and provides the same timing-safety guarantees.

## 3. jsonwebtoken default leeway is 60 seconds
`jsonwebtoken::Validation::new()` sets `leeway: 60` by default. Tests that set `exp: now - 60` will pass validation because the token is within the leeway window. Set `exp: now - 120` or greater to reliably test expiration rejection. Alternatively, set `validation.leeway = 0` in the validator, but changing the default affects production behavior.

## 4. ring 0.17 lacks runtime key generation
`RsaKeyPair::generate_pkcs8()` does not exist in ring 0.17. Tests that need asymmetric JWT validation can use pre-generated public keys plus pre-signed JWT fixtures for deterministic verification without committing private-key material.

## 5. Constant-time comparison must handle length mismatch
A naive constant-time comparison that short-circuits on length mismatch leaks length information via timing. `ApiKeyAuthenticator` handles this by performing a dummy constant-time compare against a same-length slice when lengths differ, ensuring the timing profile is consistent regardless of input length.

## 6. Sealed trait pattern continues to work well
Adding `ApiKeyAuthenticator` and `AsymmetricTokenValidator` to the sealed `Authenticator` trait followed the same pattern as M13's `KeyProvider` extensions — implement `private::Sealed` for the new type, then implement the trait. No changes to the trait definition or existing implementations required.

## 7. JWKS cache design uses Arc<RwLock>
`JwksKeyStore` uses `Arc<RwLock<CacheState>>` for thread-safe caching. The `RwLock` allows concurrent reads during cache hits while serializing writes during cache refresh. TTL-based invalidation is checked on every `get_key()` call.

---

## Rules for the next milestone
- EC keys must use PKCS8 format with named curve encoding for `jsonwebtoken` compatibility
- Expired token tests should use at least 120 seconds past (`now - 120`) to exceed jsonwebtoken's 60-second default leeway
- Public-key fixtures plus pre-signed JWTs are preferred over committed private-key fixtures for determinism and open-source readiness
- Use `subtle::ConstantTimeEq` instead of deprecated `ring::constant_time` for constant-time comparisons

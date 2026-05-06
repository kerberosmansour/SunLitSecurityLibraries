# `secure_identity` — Developer Guide

> **OWASP C6**: Pluggable authentication — JWT validation, API keys, sessions, and MFA.

`secure_identity` is **one of many possible** implementations of the `security_core::IdentitySource` trait. You can use it as-is, replace it entirely with your own identity provider (Keycloak, Auth0, custom OIDC), or mix and match.

---

## Quick Start

```toml
[dependencies]
secure_identity = "0.1.2"

# For development/testing only:
secure_identity = { version = "0.1.2", features = ["dev"] }
```

---

## Architecture Decision: Identity-Agnostic Authorization

```
┌──────────────────────────────────────────┐
│  YOUR IDENTITY PROVIDER                  │
│  (secure_identity, Keycloak, Auth0, ...) │
│                                          │
│  Implements: IdentitySource              │
│  Returns:    AuthenticatedIdentity       │
└────────────────┬─────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────┐
│  secure_authz                            │
│                                          │
│  Accepts: AuthenticatedIdentity          │
│  Via:     SubjectResolver                │
│  Returns: Decision::Allow / Deny         │
└──────────────────────────────────────────┘
```

`secure_authz` depends on `security_core::IdentitySource`, **never** on `secure_identity`. You can swap identity providers without touching authorization code.

---

## JWT Authentication (HS256)

### Symmetric Token Validation

```rust
use secure_identity::{
    TokenValidator, TokenValidatorConfig,
    AuthenticationRequest, TokenKind,
};
use security_core::identity::IdentitySource;

// 1. Configure the validator
let config = TokenValidatorConfig {
    issuer: "https://auth.example.com".to_string(),
    audience: "my-api".to_string(),
    secret: b"your-256-bit-secret-key-here-min32".to_vec(),
};

let validator = TokenValidator::new(config);

// 2a. Via the Authenticator trait (detailed control)
let request = AuthenticationRequest {
    token: "eyJhbGciOiJIUzI1NiJ9...".to_string(),
    token_kind: TokenKind::BearerJwt,
};
let identity = validator.authenticate(&request).await?;
// identity.actor_id, identity.roles, identity.tenant_id, etc.

// 2b. Via the IdentitySource trait (simpler, works with secure_authz)
let identity = validator.resolve("eyJhbGciOiJIUzI1NiJ9...").await?;
```

### What Gets Validated

- Signature (HMAC-SHA256, constant-time via `ring`)
- Expiration (`exp` claim)
- Issuer (`iss` must match configured issuer)
- Audience (`aud` must match configured audience)
- Algorithm (only HS256 accepted — `alg: none` is always rejected)

### What Gets Emitted on Failure

Every authentication failure emits an `EventKind::AuthnFailure` security event, allowing your security team to detect credential stuffing, token replay, and brute force attacks.

---

## JWT Authentication (RS256 / ES256)

### Asymmetric Token Validation

```rust
use secure_identity::{
    AsymmetricTokenValidator, AsymmetricTokenValidatorConfig,
    AlgorithmConfig,
};
use jsonwebtoken::DecodingKey;

// RS256 — RSA 2048+ public key
let config = AsymmetricTokenValidatorConfig {
    issuer: "https://auth.example.com".to_string(),
    audience: "my-api".to_string(),
    algorithm: AlgorithmConfig::RS256 {
        decoding_key: DecodingKey::from_rsa_pem(include_bytes!("public.pem")).unwrap(),
    },
};
let validator = AsymmetricTokenValidator::new(config);

// ES256 — ECDSA P-256 public key
let config = AsymmetricTokenValidatorConfig {
    issuer: "https://auth.example.com".to_string(),
    audience: "my-api".to_string(),
    algorithm: AlgorithmConfig::ES256 {
        decoding_key: DecodingKey::from_ec_pem(include_bytes!("ec-public.pem")).unwrap(),
    },
};
let validator = AsymmetricTokenValidator::new(config);

// Both implement IdentitySource and Authenticator
let identity = validator.resolve("eyJhbGciOiJSUzI1NiJ9...").await?;
```

---

## JWKS Key Store

Fetch and cache public keys from your identity provider's JWKS endpoint:

```rust
use secure_identity::jwks::JwksKeyStore;
use std::time::Duration;

// Create a key store with 5-minute TTL cache
let store = JwksKeyStore::new(
    "https://auth.example.com/.well-known/jwks.json",
    Duration::from_secs(300),
);

// Fetch keys (caches automatically)
store.fetch().await?;

// Look up a key by Key ID (kid)
if let Some(decoding_key) = store.get_key("my-key-id").await {
    // Use with AsymmetricTokenValidator
}

// Check algorithm for a key
if let Some(alg) = store.get_algorithm("my-key-id").await {
    println!("Algorithm: {alg}"); // "RS256", "ES256", etc.
}

// Cache is thread-safe (Arc<RwLock>) and auto-refreshes when TTL expires
assert!(store.is_cache_valid().await);
```

---

## API Key Authentication

Constant-time API key comparison to prevent timing side-channel attacks:

```rust
use secure_identity::api_key::ApiKeyAuthenticator;
use secure_identity::{AuthenticationRequest, TokenKind};
use security_core::types::ActorId;
use uuid::Uuid;

// Configure with the expected key
let auth = ApiKeyAuthenticator::new(
    "example-api-key".to_string(),
    ActorId::from(Uuid::new_v4()),
    vec!["api-user".into(), "read-only".into()],
);

// Authenticate a request
let request = AuthenticationRequest {
    token: "example-api-key".into(),
    token_kind: TokenKind::ApiKey,
};
let identity = auth.authenticate(&request).await?;
// identity.actor_id == configured actor_id
// identity.roles == ["api-user", "read-only"]
```

**Security properties:**
- Uses `subtle::ConstantTimeEq` for comparison — no timing leaks
- Handles length mismatch without early exit
- Emits `AuthnFailure` security event on invalid keys

---

## Session Management

```rust
use secure_identity::{InMemorySessionManager, SessionManager};
use security_core::identity::AuthenticatedIdentity;

let session_mgr = InMemorySessionManager::new();

// Create a session (1-hour lifetime)
let session = session_mgr.create_session(&identity, 3600).await?;
// session.id is 128-bit cryptographically random (ring::SystemRandom), hex-encoded

// Validate a session
match session_mgr.validate_session(&session.id).await {
    Ok(session) => {
        println!("Actor: {:?}", session.actor_id);
        println!("Roles: {:?}", session.roles);
        println!("Expires: {:?}", session.expires_at);
    }
    Err(e) => {
        // IdentityError::SessionExpired
    }
}

// Extend session lifetime (sliding window — add 30 minutes)
let refreshed = session_mgr.refresh_session(&session.id, 1800).await?;

// Revoke a session (logout)
session_mgr.revoke_session(&session.id).await?;
// Subsequent validate_session calls will return SessionExpired
```

### `Session` Fields

| Field | Type | Description |
|---|---|---|
| `id` | `String` | 128-bit random hex (cryptographically secure) |
| `actor_id` | `ActorId` | Who owns this session |
| `tenant_id` | `Option<TenantId>` | Tenant context |
| `roles` | `Vec<String>` | Session roles |
| `created_at` | `OffsetDateTime` | When session was created |
| `expires_at` | `OffsetDateTime` | When session expires |
| `last_accessed` | `OffsetDateTime` | Last validation/refresh time |

### Implementing a Custom Session Store

```rust
use secure_identity::SessionManager;
use secure_identity::Session;
use secure_identity::IdentityError;
use security_core::identity::AuthenticatedIdentity;

struct RedisSessionManager {
    // your Redis connection
}

impl SessionManager for RedisSessionManager {
    async fn create_session(
        &self,
        identity: &AuthenticatedIdentity,
        lifetime_secs: u64,
    ) -> Result<Session, IdentityError> {
        // Store in Redis with TTL
        todo!()
    }

    async fn validate_session(&self, id: &str) -> Result<Session, IdentityError> {
        // Look up in Redis; return SessionExpired if not found/expired
        todo!()
    }

    async fn refresh_session(&self, id: &str, extend_secs: u64) -> Result<Session, IdentityError> {
        // Extend TTL in Redis
        todo!()
    }

    async fn revoke_session(&self, id: &str) -> Result<(), IdentityError> {
        // Delete from Redis
        todo!()
    }
}
```

---

## Redis Session Store (feature: `session-redis`)

`secure_identity` now includes a Redis-backed implementation of `SessionManager`.

```toml
[dependencies]
secure_identity = { version = "0.1.2", features = ["session-redis"] }
```

```rust
use secure_identity::session_redis::RedisSessionManager;
use secure_identity::SessionManager;

let store = RedisSessionManager::new("redis://127.0.0.1:6379/")?;
// Same SessionManager API as in-memory implementation.
```

---

## OIDC Discovery (feature: `oidc`)

OIDC integration is intentionally a thin wrapper over the `openidconnect` crate with secure defaults.

```toml
[dependencies]
secure_identity = { version = "0.1.2", features = ["oidc"] }
```

```rust
use secure_identity::oidc::OidcClient;

let oidc = OidcClient::new(300);
let provider = oidc.discover("https://accounts.example.com").await?;
let auth = oidc
    .auth_url(
        "https://accounts.example.com",
        "client-id",
        "https://app.example.com/callback",
    )
    .await?;

assert!(auth.authorization_url.contains("code_challenge="));
```

Security defaults applied by `OidcClient`:
- HTTPS issuer enforcement (unless explicit test override is enabled)
- Redirects disabled for discovery HTTP client (SSRF hardening)
- Metadata cache with TTL
- PKCE challenge included in generated authorization URLs

---

## MFA (Multi-Factor Authentication)

The MFA module includes a concrete RFC 6238 implementation via `totp::TotpProvider`:

```rust
use secure_identity::totp::TotpProvider;

let provider = TotpProvider::new("SunLit", 1);
let enrollment = provider.generate_secret("alice@example.com")?;
let code = provider.generate_current_code(&enrollment.secret)?;
assert!(provider.verify_code(&enrollment.secret, &code)?);
```

---

## Authentication Event Auditing

Successful and failed authentication attempts can be emitted as structured security events.

```rust
use secure_identity::auth_events::{AuthEventContext, AuthEventEmitter};
use security_events::sink::InMemorySink;

let sink = InMemorySink::new();
let emitter = AuthEventEmitter::new(sink.clone());

emitter.emit_success(AuthEventContext {
    user_id: "user-123".to_string(),
    method: "jwt".to_string(),
    source_ip: Some("127.0.0.1".parse().unwrap()),
    user_agent: Some("Mozilla/5.0".to_string()),
});

emitter.emit_failure(
    AuthEventContext {
        user_id: "user-123".to_string(),
        method: "jwt".to_string(),
        source_ip: Some("127.0.0.1".parse().unwrap()),
        user_agent: Some("Mozilla/5.0".to_string()),
    },
    "invalid_credentials",
);
```

---

## Development Authenticator

**For development and testing only.** Accepts any token and returns a configurable identity:

```rust
// Cargo.toml: secure_identity = { ..., features = ["dev"] }

#[cfg(feature = "dev")]
use secure_identity::dev::DevAuthenticator;
use security_core::types::{ActorId, TenantId};
use uuid::Uuid;

let dev_auth = DevAuthenticator::new(
    ActorId::from(Uuid::nil()),
    Some(TenantId::from(Uuid::nil())),
    vec!["admin".into()],
);
// WARNING: Emits tracing::warn! on construction
// NEVER use in production — accepts ANY token
```

---

## Error Handling

All identity errors map cleanly to `AppError` for HTTP responses:

```rust
use secure_identity::IdentityError;
use secure_errors::kind::AppError;

let err = IdentityError::InvalidCredentials;
let app_err: AppError = err.into();
// → AppError::Forbidden { policy: "authentication" }

let err = IdentityError::TokenExpired;
let app_err: AppError = err.into();
// → AppError::Forbidden { policy: "authentication" }

let err = IdentityError::ProviderUnavailable;
let app_err: AppError = err.into();
// → AppError::Dependency { dep: "identity_provider" }
```

**All `IdentityError` variants:**

| Variant | Maps to `AppError` | HTTP Status |
|---|---|---|
| `InvalidCredentials` | `Forbidden` | 403 |
| `TokenExpired` | `Forbidden` | 403 |
| `TokenMalformed` | `Validation` | 400 |
| `MfaRequired` | `Forbidden` | 403 |
| `SessionExpired` | `Forbidden` | 403 |
| `ProviderUnavailable` | `Dependency` | 503 |

---

## Bringing Your Own Identity Provider

You don't need `secure_identity` at all. Implement `IdentitySource` directly:

```rust
use security_core::identity::{
    AuthenticatedIdentity, IdentityResolutionError, IdentitySource,
};
use security_core::types::ActorId;
use std::collections::HashMap;
use time::OffsetDateTime;

struct KeycloakAdapter {
    jwks_url: String,
    issuer: String,
}

impl IdentitySource for KeycloakAdapter {
    async fn resolve(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, IdentityResolutionError> {
        // 1. Fetch/cache JWKS from Keycloak
        // 2. Validate JWT signature, expiration, issuer
        // 3. Extract claims
        let claims = validate_with_keycloak(token, &self.jwks_url, &self.issuer)
            .await
            .map_err(|_| IdentityResolutionError::InvalidToken)?;

        Ok(AuthenticatedIdentity {
            actor_id: ActorId::from(claims.sub),
            tenant_id: claims.tenant_id.map(Into::into),
            roles: claims.realm_access.roles,
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}

// Use directly with secure_authz — no secure_identity dependency needed:
// let authorizer = DefaultAuthorizer::new(engine);
// let identity = keycloak_adapter.resolve(token).await?;
// let subject = DefaultSubjectResolver::resolve(&identity);
// let decision = authorizer.authorize(&subject, &action, &resource).await;
```

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `TokenValidator` | `token` | HS256 JWT validator |
| `TokenValidatorConfig` | `token` | Config for HS256 |
| `AsymmetricTokenValidator` | `token` | RS256/ES256 JWT validator |
| `AsymmetricTokenValidatorConfig` | `token` | Config for RS256/ES256 |
| `AlgorithmConfig` | `token` | Algorithm + key material |
| `ApiKeyAuthenticator` | `api_key` | Constant-time API key auth |
| `JwksKeyStore` | `jwks` | JWKS key fetch + cache |
| `InMemorySessionManager` | `session` | In-memory session store |
| `Session` | `session` | Session data struct |
| `SessionManager` | `session` | Open trait for session stores |
| `Authenticator` | `authenticator` | Sealed authentication trait |
| `AuthenticationRequest` | `authenticator` | Auth request input |
| `TokenKind` | `authenticator` | BearerJwt / ApiKey / SessionCookie |
| `IdentityError` | `error` | Authentication error enum |
| `MfaProvider` | `mfa` | Open trait for MFA backends |
| `MfaChallenge` | `mfa` | MFA challenge struct |
| `MfaResponse` | `mfa` | MFA response struct |
| `DevAuthenticator` | `dev` | Dev-only authenticator (feature `dev`) |

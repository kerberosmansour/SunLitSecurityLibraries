# Attack Tree: Data Protection & Secrets Management

> **Crate:** `secure_data` (Milestone M8 — OWASP C8)  
> **Supporting Crates:** `security_core` (M1), `security_events` (M3), `secure_errors` (M2)  
> **Related Threats:** THREAT-T-03, THREAT-I-04, THREAT-D-03, THREAT-I-02  
> **Classification:** INTERNAL — Security Sensitive  
> **Version:** 1.0.0

---

## Introduction

This attack tree models all credible paths by which an attacker can **compromise data confidentiality, data integrity, or the secret material** managed by `secure_data`. The tree covers data-at-rest protection, data-in-transit protection, secrets lifecycle management, and cryptographic material security.

Since M22, the audit plane also relies on per-event HMAC sealing in `security_events`; undetected audit forgery now requires both log-store access and compromise of the separate audit signing key.

Critical infrastructure context: in energy systems, compromised encryption keys can expose SCADA command histories; in healthcare, decryption of patient records triggers HIPAA/GDPR breach notification; in finance, key compromise enables offline decryption of historical transaction archives; in government, classified document exfiltration enables espionage.

**FIPS note:** `secure_data` supports a `fips` feature flag that routes all cryptographic operations through FIPS 140-3 validated modules. Threats in sections 1 and 2 assume the non-FIPS path unless stated otherwise.

**Node notation:**
- `[OR]` — any one child path achieves the parent goal
- `[AND]` — all child paths must succeed simultaneously
- `[LEAF]` — terminal attack action (no further decomposition)
- `(M)` — mitigating control from `secure_data` or a peer crate
- `(R)` — residual risk requiring compensating control from consuming team

---

## Attack Tree

```
GOAL: Compromise Data Protection — Decrypt, forge, or steal protected data or key material
│
├── [OR] 1. Obtain Cryptographic Key Material
│   │
│   ├── [OR] 1.1 Extract Keys from Process Memory (THREAT-I-04) [Abuse Case AC-05]
│   │   │
│   │   ├── [AND] 1.1.1 Achieve code execution + read process memory
│   │   │   ├── [LEAF] 1.1.1a Exploit RCE vulnerability in HTTP handler
│   │   │   ├── [LEAF] 1.1.1b Use /proc/self/mem or process_vm_readv (Linux)
│   │   │   └── [LEAF] 1.1.1c Trigger core dump and read from dump file
│   │   │           Mitigations: (M) zeroize crate zeroes key material on Drop;
│   │   │                         (M) Keys held in dedicated SecretBuffer type that
│   │   │                              clears on drop and prevents Debug/Display;
│   │   │                         (R) seccomp-BPF profile must block ptrace/mem syscalls;
│   │   │                         (R) Core dumps must be disabled in container config
│   │   │
│   │   ├── [AND] 1.1.2 Key material written to swap and read from swap device
│   │   │   ├── [LEAF] 1.1.2a Key pages swapped to disk under memory pressure
│   │   │   └── [LEAF] 1.1.2b Attacker reads swap device after container stop
│   │   │           Mitigations: (M) secure_data uses mlock() to pin key pages;
│   │   │                         (R) Host swap partition encrypted (LUKS);
│   │   │                         (R) Swap disabled for services handling key material
│   │   │
│   │   └── [AND] 1.1.3 Crash dump / OOM kill dumps keys to persistent storage
│   │       ├── [LEAF] 1.1.3a OOM killer terminates service mid-operation
│   │       └── [LEAF] 1.1.3b /proc/sys/kernel/core_pattern writes crash to disk
│   │               Mitigations: (R) `ulimit -c 0` in container entrypoint;
│   │                             (R) `kernel.core_pattern=|/bin/false` via sysctl
│   │
│   ├── [OR] 1.2 Compromise the Secrets Manager (THREAT-D-03)
│   │   │
│   │   ├── [AND] 1.2.1 Steal service account credentials for secrets manager
│   │   │   ├── [LEAF] 1.2.1a Extract Vault token from environment variable
│   │   │   │           Mitigations: (M) secure_data does not read tokens from env vars
│   │   │   │                             in production mode; reads from metadata API or file
│   │   │   ├── [LEAF] 1.2.1b Obtain IAM role credentials via SSRF to metadata service
│   │   │   │           Mitigations: (M) secure_boundary blocks requests to 169.254.169.254;
│   │   │   │                         (R) IMDSv2 with session tokens required (AWS)
│   │   │   └── [LEAF] 1.2.1c Read secret from container environment variable leak
│   │   │               Mitigations: (M) secure_data warns and refuses to run if
│   │   │                                 secrets are found in environment variables
│   │   │
│   │   ├── [LEAF] 1.2.2 Exploit secrets manager API vulnerability
│   │   │           Mitigations: (R) Keep secrets manager software patched and monitored;
│   │   │                         (M) secure_data uses least-privilege IAM policy for
│   │   │                              accessing only required secrets
│   │   │
│   │   └── [AND] 1.2.3 Enumerate accessible secrets via over-permissioned IAM role
│   │       ├── [LEAF] 1.2.3a Service account has ListSecrets permission
│   │       └── [LEAF] 1.2.3b Attacker enumerates and retrieves all secrets
│   │               Mitigations: (M) IAM policy scoped to specific secret ARNs/paths;
│   │                             (M) security_events logs all secret retrieval operations;
│   │                             (R) Consuming team must apply principle of least privilege
│   │
│   ├── [OR] 1.3 Intercept Key During Rotation (THREAT-T-03)
│   │   │
│   │   ├── [AND] 1.3.1 Race between key rotation and re-encryption
│   │   │   ├── [LEAF] 1.3.1a Old key still accessible during rotation window
│   │   │   └── [LEAF] 1.3.1b Attacker reads both old ciphertext and old key
│   │   │           Mitigations: (M) Envelope encryption: data keys wrapped by master key;
│   │   │                         rotating master key does not expose data keys;
│   │   │                         (M) Key versioning in secure_data; old versions retired
│   │   │                              after re-encryption grace period
│   │   │
│   │   └── [LEAF] 1.3.2 Key rotation writes new key to secrets manager before
│   │                     deleting old → window where both are readable
│   │               Mitigations: (M) Key retirement logged in security_events;
│   │                             (M) Minimum access to secrets manager enforced by IAM
│   │
│   └── [AND] 1.4 Brute-Force Weak Key / Recover Key from Weak Derivation
│       ├── [LEAF] 1.4.1 KDF uses low iteration count (e.g., PBKDF2 < 600,000 rounds)
│       ├── [LEAF] 1.4.2 Derived key based on guessable password
│       └── [LEAF] 1.4.3 Offline brute-force against encrypted data samples
│               Mitigations: (M) secure_data enforces Argon2id for password-derived keys;
│                             (M) Minimum key entropy validated at initialisation;
│                             (M) Hardware-generated random keys preferred over password-derived
│
├── [OR] 2. Subvert Encryption (Decrypt Without Key)
│   │
│   ├── [AND] 2.1 Exploit Cryptographic Implementation Weakness
│   │   │
│   │   ├── [LEAF] 2.1.1 IV/nonce reuse in AES-GCM → authentication tag forgery
│   │   │           Mitigations: (M) secure_data uses random 96-bit nonces for every encryption;
│   │   │                         (M) Nonce generated by ring::rand::SystemRandom (CSPRNG);
│   │   │                         (M) FIPS mode uses NIST-validated DRBG
│   │   │
│   │   ├── [LEAF] 2.1.2 AES-GCM with 2^32 encryptions under same key (birthday bound)
│   │   │           Mitigations: (M) Key rotation triggered after configurable usage limit
│   │   │                             (default: 2^24 encryptions per key, well below the bound)
│   │   │
│   │   └── [LEAF] 2.1.3 Padding oracle attack on CBC mode (if used)
│   │               Mitigations: (M) secure_data only supports AES-256-GCM (AEAD);
│   │                             CBC mode is not available; padding oracles cannot apply
│   │
│   ├── [AND] 2.2 Downgrade Cryptographic Algorithm
│   │   ├── [LEAF] 2.2.1 Manipulate algorithm identifier in ciphertext header
│   │   └── [LEAF] 2.2.2 Service accepts ciphertext encrypted with weak algorithm
│   │           Mitigations: (M) Algorithm identifier is part of AEAD authenticated data;
│   │                         modification is detected and decryption fails with error;
│   │                         (M) Only approved algorithms are accepted; algorithm negotiation
│   │                              is not supported
│   │
│   └── [LEAF] 2.3 Exploit Side-Channel in Constant-Time Operations (THREAT-I-02)
│               Mitigations: (M) All MAC/signature verification uses subtle crate;
│                             (M) Constant-time operations reviewed in security audit;
│                             (R) Microarchitectural side-channels (Spectre/Meltdown)
│                                  require hardware mitigations (out of scope)
│
├── [OR] 3. Corrupt or Forge Protected Data (Integrity Attacks)
│   │
│   ├── [LEAF] 3.1 Modify Ciphertext to Cause Incorrect Decryption (Bit-Flip)
│   │           Mitigations: (M) AES-256-GCM provides authenticated encryption;
│   │                         any bit-flip in ciphertext causes authentication tag failure;
│   │                         decryption is refused and error logged to security_events
│   │
│   ├── [AND] 3.2 Replay Old Ciphertext Version (THREAT-T-03)
│   │   ├── [LEAF] 3.2.1 Capture older version of encrypted record
│   │   └── [LEAF] 3.2.2 Re-submit old version to overwrite current record
│   │           Mitigations: (M) Additional authenticated data (AAD) includes record ID
│   │                             and version; replaying old ciphertext against new AAD fails;
│   │                         (M) Version numbers validated by application layer
│   │
│   └── [AND] 3.3 Cross-Context Ciphertext Substitution
│       ├── [LEAF] 3.3.1 Copy ciphertext from low-sensitivity context to high-sensitivity
│       └── [LEAF] 3.3.2 Decryption succeeds but data is semantically incorrect
│               Mitigations: (M) AAD encodes DataClassification and context identifier;
│                             cross-context substitution detected as AAD mismatch
│
├── [OR] 4. Exhaust Resources via Cryptographic Operations (THREAT-D-03)
│   │
│   ├── [LEAF] 4.1 Flood decryption endpoint to exhaust CPU (AES-GCM is fast, but still)
│   │           Mitigations: (M) secure_boundary enforces request rate limits;
│   │                         (M) Decryption operations are bounded per request
│   │
│   ├── [AND] 4.2 Trigger Repeated Secrets Manager Calls to Hit Rate Limit
│   │   ├── [LEAF] 4.2.1 Request path forces cache miss (e.g., large tenant count)
│   │   └── [LEAF] 4.2.2 Each miss triggers a secrets manager API call
│   │           Mitigations: (M) secure_data implements write-through cache with TTL;
│   │                         (M) Circuit breaker prevents cascading secrets manager calls;
│   │                         (R) Consuming team must size cache for expected tenant count
│   │
│   └── [AND] 4.3 Memory Exhaustion via Large Plaintext Allocation
│       ├── [LEAF] 4.3.1 Attacker sends very large ciphertext blob
│       └── [LEAF] 4.3.2 Decryption allocates full plaintext buffer before authentication
│               Mitigations: (M) secure_data enforces maximum ciphertext size limit;
│                             (M) secure_boundary enforces request body size limit upstream
│
└── [OR] 5. Attack the FIPS Boundary
    │
    ├── [LEAF] 5.1 Disable FIPS mode via configuration flag in non-production environment
    │           Mitigations: (M) FIPS mode cannot be disabled at runtime; only at compile-time
    │                             with feature flag; production binaries built with FIPS enabled;
    │                         (R) Build pipeline must enforce FIPS feature for production builds
    │
    └── [AND] 5.2 Use non-FIPS code path via feature flag confusion
        ├── [LEAF] 5.2.1 Attacker submits PR removing fips feature from Cargo.toml
        └── [LEAF] 5.2.2 Code review fails to catch the change
                Mitigations: (R) Cargo feature flags must be reviewed in security-focused PR review;
                              (R) CI/CD must verify FIPS feature is present in release builds;
                              (M) secure_data emits startup warning when running without FIPS
```

---

## Encryption Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Data Protection Layers in secure_data                  │
│                                                          │
│  Plaintext                                              │
│       │                                                  │
│       ▼  encrypt(data_key, AAD{classification, id, ver}) │
│  Ciphertext + Auth Tag (AES-256-GCM)                    │
│       │                                                  │
│       ▼  wrap(master_key)                               │
│  Wrapped Data Key                                       │
│       │                                                  │
│       ▼  store                                          │
│  Secrets Manager (Vault / KMS / HSM)                    │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Master Key  (HSM-backed in FIPS mode)           │   │
│  │  Key Version N, N-1 (rotation support)          │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Envelope encryption** means that compromising the secrets manager exposes only wrapped data keys — the master key (HSM-backed in FIPS mode) is never exposed through the secrets manager API.

---

## Mitigating Controls Summary

| Attack Path | Primary Control | Crate | Milestone |
|---|---|---|---|
| Memory dump key extraction (1.1.x) | Zeroize on Drop; mlock | `secure_data` | M8 |
| Secrets manager credential theft (1.2.x) | Metadata API auth; least-privilege IAM | `secure_data` | M8 |
| Weak key derivation (1.4.x) | Argon2id; entropy validation | `secure_data` | M8 |
| Nonce reuse in AES-GCM (2.1.1) | CSPRNG nonce; per-encryption random | `secure_data` | M8 |
| Algorithm downgrade (2.2.x) | AAD includes algorithm; no negotiation | `secure_data` | M8 |
| Ciphertext integrity (3.1) | AEAD authentication tag | `secure_data` | M8 |
| Replay / cross-context (3.2/3.3) | AAD encodes ID, version, classification | `secure_data` | M8 |
| Secrets throttle DoS (4.2.x) | Write-through cache + circuit breaker | `secure_data` | M8 |
| FIPS bypass (5.x) | FIPS mode enforced at compile-time | `secure_data` | M8 |

---

## Residual Risk Cross-Reference

| Attack Path | Residual Risk | See Threat Model |
|---|---|---|
| Memory forensics (1.1.x) | seccomp, core dumps, swap encryption | RR-01 |
| Secrets manager availability (4.2.x) | Cache sizing, circuit breaker, HA secrets manager | RR-05 |
| Microarchitectural side-channels (2.3) | Hardware mitigations (Intel TME, AMD SME) | RR-01 |

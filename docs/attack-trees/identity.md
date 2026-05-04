# Attack Tree: Identity & Authentication

> **Crate:** `secure_identity` (Milestone M6 — OWASP C6)  
> **Related Threats:** THREAT-S-01, THREAT-S-02, THREAT-S-03, THREAT-E-02, THREAT-I-02, THREAT-R-03  
> **Classification:** INTERNAL — Security Sensitive  
> **Version:** 1.0.0

---

## Introduction

This attack tree models all credible paths an attacker can take to **compromise, bypass, or abuse** the identity and authentication layer provided by `secure_identity`. The tree is rooted at the adversarial goal and decomposes into sub-goals connected by AND (all children required) and OR (any child sufficient) nodes.

Critical infrastructure context: authentication bypass in energy management systems can lead to SCADA command injection; in healthcare to patient record mass disclosure; in finance to fraudulent transaction authorisation.

**Node notation:**
- `[OR]` — any one child path achieves the parent goal
- `[AND]` — all child paths must succeed simultaneously
- `[LEAF]` — terminal attack action (no further decomposition)
- `(M)` — mitigating control from `secure_identity` or a peer crate
- `(R)` — residual risk requiring compensating control

---

## Attack Tree

```
GOAL: Compromise Authentication — Gain access as a legitimate identity
│
├── [OR] 1. Forge or Steal a Valid Token
│   │
│   ├── [OR] 1.1 Steal a Live Token (THREAT-S-01)
│   │   ├── [LEAF] 1.1.1 Extract JWT from browser localStorage via XSS
│   │   │           Mitigations: (M) secure_output sets HttpOnly cookies;
│   │   │                         (M) CSP headers block injected scripts
│   │   │
│   │   ├── [LEAF] 1.1.2 Intercept token from unencrypted channel
│   │   │           Mitigations: (M) secure_identity requires TLS 1.3;
│   │   │                         (M) HSTS header enforced by secure_output
│   │   │
│   │   ├── [LEAF] 1.1.3 Extract token from server-side logs / error messages
│   │   │           Mitigations: (M) secure_errors never logs auth tokens;
│   │   │                         (M) security_events redacts bearer tokens
│   │   │
│   │   └── [LEAF] 1.1.4 Session fixation — attacker sets token before auth
│   │               Mitigations: (M) secure_identity issues new token on login;
│   │                             tokens are server-generated, not client-supplied
│   │
│   ├── [OR] 1.2 Forge a Token via Algorithm Confusion (THREAT-E-02)
│   │   │
│   │   ├── [LEAF] 1.2.1 Use alg:none to produce unsigned JWT with elevated claims
│   │   │           Mitigations: (M) secure_identity pins accepted algorithm list;
│   │   │                         none algorithm rejected at compile-time via type
│   │   │
│   │   ├── [LEAF] 1.2.2 RS256 → HS256 confusion: sign with RS256 public key as HMAC
│   │   │           Mitigations: (M) algorithm is pinned in ValidatorConfig;
│   │   │                         asymmetric and symmetric validators are separate types
│   │   │
│   │   └── [LEAF] 1.2.3 Weak HMAC secret brute-force (secret < 256 bits)
│   │               Mitigations: (M) secure_data enforces minimum 256-bit key length;
│   │                             (R) key entropy verified at startup via health check
│   │
│   ├── [OR] 1.3 Replay a Revoked Token (THREAT-S-01)
│   │   │
│   │   ├── [AND] 1.3.1 Token lifetime misconfigured long AND no revocation list
│   │   │   ├── [LEAF] 1.3.1a Steal token from ex-employee / suspended account
│   │   │   └── [LEAF] 1.3.1b Token still valid hours/days after account suspension
│   │   │           Mitigations: (M) recommended token TTL ≤ 15 minutes;
│   │   │                         (R) consuming service must implement revocation list
│   │   │                             (see RR-01 in THREAT_MODEL.md)
│   │   │
│   │   └── [LEAF] 1.3.2 Capture token from network and replay within expiry window
│   │               Mitigations: (M) jti (JWT ID) claim uniqueness check;
│   │                             (M) secure_identity supports nonce-based replay prevention
│   │
│   └── [OR] 1.4 Obtain Credential Directly (Credential Theft)
│       │
│       ├── [LEAF] 1.4.1 Phishing — trick user into entering credentials on fake portal
│       │           Mitigations: (M) secure_identity supports FIDO2/WebAuthn (phishing-resistant);
│       │                         (R) user security awareness training (out of scope for library)
│       │
│       ├── [LEAF] 1.4.2 Credential stuffing — reuse leaked username/password pairs
│       │           Mitigations: (M) secure_boundary rate-limits authentication attempts;
│       │                         (M) secure_identity supports MFA requirement
│       │
│       └── [LEAF] 1.4.3 Timing side-channel on password/API key comparison (THREAT-I-02)
│                   Mitigations: (M) All comparisons use constant-time equality
│                                    (subtle::ConstantTimeEq or ring::constant_time);
│                                 (M) secure_data enforces constant-time for HMAC verify
│
├── [OR] 2. Abuse the Identity Provider (THREAT-S-02)
│   │
│   ├── [AND] 2.1 Redirect JWKS/Discovery Endpoint via SSRF
│   │   ├── [LEAF] 2.1.1 Find SSRF in consuming service (URL parameter, webhook, import)
│   │   ├── [LEAF] 2.1.2 Point OIDC discovery URL to attacker-controlled server
│   │   └── [LEAF] 2.1.3 Return attacker's JWKS; service fetches and trusts it
│   │           Mitigations: (M) JWKS URL pinned in ValidatorConfig at startup;
│   │                         (M) secure_boundary validates URL allowlist;
│   │                         (M) TLS certificate of JWKS endpoint verified
│   │
│   ├── [LEAF] 2.2 Compromise IdP Admin Account and Issue Malicious Tokens
│   │           Mitigations: (R) IdP hardening outside library scope;
│   │                         (M) secure_authz enforces additional claim validation
│   │                             beyond token validity (tenant, role, device checks)
│   │
│   └── [AND] 2.3 DNS Hijack JWKS Domain
│       ├── [LEAF] 2.3.1 Compromise DNS resolver or registrar
│       └── [LEAF] 2.3.2 Redirect JWKS domain to attacker-controlled IP
│               Mitigations: (M) Certificate pinning or HPKP for JWKS endpoint;
│                             (M) DNSSEC validation in service DNS resolver;
│                             (R) Consuming team must configure DNS security
│
├── [OR] 3. Abuse mTLS / Certificate-Based Identity (THREAT-S-03)
│   │
│   ├── [AND] 3.1 Obtain Fraudulent Certificate from Internal CA
│   │   ├── [LEAF] 3.1.1 Compromise internal CA private key
│   │   ├── [LEAF] 3.1.2 Social-engineer CA administrator into issuing certificate
│   │   └── [LEAF] 3.1.3 Exploit misconfigured ACME/auto-enrolment endpoint
│   │           Mitigations: (M) secure_identity validates certificate CN/SAN against allowlist;
│   │                         (M) Certificate serial numbers logged via security_events;
│   │                         (R) CA governance and HSM-backed CA keys (out of scope)
│   │
│   └── [LEAF] 3.2 Present Expired/Revoked Certificate (CRL/OCSP not checked)
│               Mitigations: (M) secure_identity checks certificate validity period;
│                             (R) Consuming team must configure OCSP stapling / CRL checking
│
└── [OR] 4. Exploit Clock Skew to Extend Token Window (THREAT-R-03)
    │
    ├── [AND] 4.1 NTP Spoofing + Token Replay
    │   ├── [LEAF] 4.1.1 Spoof NTP to advance server clock past token expiry
    │   └── [LEAF] 4.1.2 Replay captured token that would otherwise be expired
    │           Mitigations: (M) secure_identity enforces hard maximum clock skew (configurable);
    │                         (R) Deploy authenticated NTP (NTS / RFC 8915)
    │
    └── [LEAF] 4.2 Manipulate nbf/exp Claims When Signing Key is Weak
                Mitigations: (M) Token claims validated strictly (nbf, exp, iss, aud, jti);
                              (M) All custom claim validation via typed ClaimsValidator trait
```

---

## Mitigating Controls Summary

| Attack Path | Primary Control | Crate | Status |
|---|---|---|---|
| Algorithm confusion (1.2.x) | Algorithm pinning in `ValidatorConfig` | `secure_identity` | M6 |
| Token replay (1.3.x) | Short TTL + `jti` uniqueness check | `secure_identity` | M6 |
| Timing oracle (1.4.3) | `subtle::ConstantTimeEq` for all comparisons | `secure_identity`, `secure_data` | M6/M8 |
| SSRF → JWKS redirect (2.1.x) | JWKS URL pinned at startup | `secure_identity` | M6 |
| mTLS cert abuse (3.1.x) | CN/SAN allowlist validation | `secure_identity` | M6 |
| Clock skew replay (4.1.x) | Hard maximum clock skew enforcement | `secure_identity` | M6 |

---

## Residual Risk Cross-Reference

| Attack Path | Residual Risk | See Threat Model |
|---|---|---|
| Token revocation (1.3.1) | Revocation list is consuming-service responsibility | RR-01 |
| CA governance (3.1.x) | Internal CA security outside library scope | RR-04 |
| NTP spoofing (4.1.x) | Authenticated NTP deployment outside library scope | RR-04 |

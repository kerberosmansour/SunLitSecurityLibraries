# Threat Model — SunLit Security Libraries

> **Classification:** INTERNAL — Security Sensitive  
> **Version:** 1.0.0  
> **Status:** Approved  
> **Last Updated:** 2025  
> **Authors:** SunLit Security Libraries Security Team
> **Review Cycle:** Quarterly or on major architectural change

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [STRIDE Analysis](#3-stride-analysis)
4. [Abuse Cases](#4-abuse-cases)
5. [Control-to-Threat Traceability Matrix](#5-control-to-threat-traceability-matrix)
6. [Compliance Framework Mapping](#6-compliance-framework-mapping)
7. [Residual Risks](#7-residual-risks)
8. [Peer-Review Checklist](#8-peer-review-checklist)

---

## 1. Introduction

### 1.1 Purpose

This document defines the formal threat model for the **SunLit Security Libraries** workspace — a suite of Rust crates implementing OWASP Proactive Controls (C1, C4–C10) for web services deployed in critical infrastructure sectors including energy, finance, healthcare, and government.

The threat model serves four purposes:

1. **Identify and enumerate** credible threats against the library and its consumers.
2. **Map threats to controls** so gaps and coverage can be tracked across milestones (M1–M10).
3. **Define abuse cases** concrete enough for red-team and penetration testing exercises.
4. **Surface residual risks** that the library cannot fully mitigate, enabling consuming teams to apply compensating controls.

### 1.2 Scope

| In Scope | Out of Scope |
|---|---|
| All nine crates in the workspace | End-user applications built on top of the library |
| Trust boundaries between crates | Infrastructure (OS, hardware, cloud provider) |
| Data flows involving secrets, PII, and audit records | Supply-chain threats against Rust toolchain itself |
| Library API surface presented to consuming services | Physical security of data centres |
| Compile-time and runtime security properties | Network perimeter controls (firewalls, WAF) |

### 1.3 Assumptions and Constraints

- Consuming services run on Linux x86-64 or ARM64 in containerised environments.
- The threat actor capability ranges from **opportunistic script kiddie (Tier 1)** to **nation-state APT (Tier 4)**.
- The library is consumed as a Rust crate dependency; the compiled binary is the attack surface, not source code directly.
- FIPS 140-3 validated cryptographic modules are available via the host HSM or software provider when `feature = "fips"` is enabled.
- Secrets are never stored in environment variables in production; a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault) is assumed.

### 1.4 Threat Actor Profiles

| Actor | Tier | Motivation | Capability |
|---|---|---|---|
| Opportunistic attacker | T1 | Financial gain, notoriety | Automated scanners, public exploits |
| Insider threat | T2 | Sabotage, espionage, financial | Privileged access, knowledge of internals |
| Organised crime group | T3 | Financial gain, ransomware | Custom tooling, persistence, lateral movement |
| Nation-state APT | T4 | Espionage, disruption, sabotage | Zero-days, supply chain, long dwell time |

---

## 2. System Overview

### 2.1 Crate Inventory

| Crate | OWASP Proactive Control | Role |
|---|---|---|
| `security_core` | C1 — Define Security Requirements | Shared ID types, data classification, severity levels, `IdentitySource` trait |
| `secure_errors` | C10 — Handle All Errors and Exceptions | Centralised, context-rich error handling; prevents information leakage |
| `security_events` | C9 — Implement Security Logging and Monitoring | Structured audit events, per-event HMAC sealing, event correlation, and SIEM/file sink integration |
| `secure_boundary` | C5/C8 — Validate All Inputs + Leverage Browser Security Features | Input validation, size limits, type-safe extractors, deny-by-default parsers, browser security headers, CORS, Fetch Metadata validation |
| `secure_output` | C4 — Encode and Escape Data | Context-aware output encoding, security response headers, CSP management |
| `secure_identity` | C6 — Implement Digital Identity | Pluggable authentication abstraction; supports OIDC, mTLS, API keys |
| `secure_authz` | C7 — Enforce Access Controls | Deny-by-default RBAC/ABAC; policy evaluation engine |
| `secure_data` | C8 — Protect Data Everywhere | Data-at-rest and in-transit protection, secrets management, FIPS readiness |
| `secure_reference_service` | Integration | Reference axum/tower integration showing all controls in concert |

### 2.2 Milestone Map

| Milestone | Crate(s) | OWASP Control |
|---|---|---|
| M1 | `security_core` | C1 |
| M2 | `secure_errors` | C10 |
| M3 | `security_events` | C9 |
| M4 | `secure_boundary` | C5 |
| M5 | `secure_output` | C4 |
| M6 | `secure_identity` | C6 |
| M7 | `secure_authz` | C7 |
| M8 | `secure_data` | C8 |
| M9 | `secure_reference_service` | Integration |
| M10 | All crates | Hardening, audit, compliance sign-off |

### 2.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  EXTERNAL TRUST ZONE (Internet / Partner Network)                   │
│                                                                      │
│   Clients (browsers, mobile apps, partner APIs, IoT devices)        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  TLS 1.3  (TB-1: External Boundary)
┌──────────────────────────────▼──────────────────────────────────────┐
│  DMZ / INGRESS ZONE                                                  │
│                                                                      │
│   Load Balancer / Reverse Proxy / API Gateway                        │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  secure_boundary  (TB-2: Service Ingress)                   │   │
│   │  secure_identity                                            │   │
│   └──────────────────────────────┬──────────────────────────────┘   │
└──────────────────────────────────┼──────────────────────────────────┘
                                   │  (TB-3: Inter-Service)
┌──────────────────────────────────▼──────────────────────────────────┐
│  APPLICATION ZONE (Trusted Service Execution)                        │
│                                                                      │
│   ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│   │ security_core  │  │ secure_authz │  │  secure_output       │   │
│   └────────────────┘  └──────────────┘  └──────────────────────┘   │
│   ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│   │ secure_errors  │  │ secure_data  │  │  security_events     │   │
│   └────────────────┘  └──────────────┘  └──────────────────────┘   │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │  (TB-4: Data Store Boundary)
┌──────────────────────────────────▼──────────────────────────────────┐
│  DATA ZONE                                                           │
│   Databases, Object Storage, Message Queues, HSM, Secrets Manager   │
└─────────────────────────────────────────────────────────────────────┘
```

**Trust Boundaries:**

| ID | Boundary | Description |
|---|---|---|
| TB-1 | External Boundary | Internet-facing TLS termination; all traffic treated hostile |
| TB-2 | Service Ingress | Input validation and authentication enforcement point |
| TB-3 | Inter-Service | Mutual TLS + service identity; lateral movement chokepoint |
| TB-4 | Data Store | Encrypted channels; credentials rotated via secrets manager |

### 2.4 Data Flows

| Flow ID | Source | Destination | Data Classification | Controls Applied |
|---|---|---|---|---|
| DF-1 | External client | secure_boundary | Untrusted input | C5 validation, size limits, Fetch Metadata checks |
| DF-2 | secure_boundary | secure_identity | Authentication material | C6 identity verification |
| DF-3 | secure_identity | secure_authz | Verified identity + claims | C7 policy evaluation |
| DF-4 | secure_authz | Application logic | Authorisation decision | Deny-by-default |
| DF-5 | Application logic | secure_output / secure_boundary | Response data | C4 encoding + headers + CSP nonces + Permissions-Policy |
| DF-6 | Any component | security_events | Audit record | C9 tamper-evident log |
| DF-7 | Any component | secure_errors | Error context | C10 safe error propagation |
| DF-8 | secure_data | Data Zone | Secrets / PII / classified | C8 encryption + FIPS |

---

## 3. STRIDE Analysis

> **Key:** Each threat is assigned a unique ID in the format `STRIDE-{Category}-{Seq}`.  
> Likelihood: **H** High / **M** Medium / **L** Low  
> Impact: **C** Critical / **H** High / **M** Medium / **L** Low

---

### 3.1 Spoofing

Spoofing threats target the ability to impersonate a legitimate identity — user, service, or data source.

#### THREAT-S-01: Token Replay After Revocation

| Field | Detail |
|---|---|
| **ID** | THREAT-S-01 |
| **Category** | Spoofing |
| **Component** | `secure_identity` (M6) |
| **Description** | An attacker obtains a valid bearer token (JWT or opaque) through credential theft, traffic interception, or session fixation and replays it after the legitimate user has logged out or had their account suspended. The `secure_identity` crate does not maintain server-side state for token revocation by default, relying on short-lived tokens; if consuming services extend token lifetime without implementing revocation, the window of exposure grows. |
| **Likelihood** | H |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Spoofing |
| **Affected Data Flows** | DF-2 |

#### THREAT-S-02: Identity Provider (IdP) Impersonation via SSRF

| Field | Detail |
|---|---|
| **ID** | THREAT-S-02 |
| **Category** | Spoofing |
| **Component** | `secure_identity` (M6), `secure_boundary` (M4) |
| **Description** | An attacker exploits a Server-Side Request Forgery (SSRF) vulnerability in a consuming service to redirect OIDC discovery or JWKS endpoint resolution to an attacker-controlled server. The library then validates tokens signed by the attacker's private key as legitimate, allowing full identity spoofing. This is especially dangerous in critical infrastructure where operator identities may trigger physical actuation commands. |
| **Likelihood** | M |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Spoofing |
| **Affected Data Flows** | DF-2 |

#### THREAT-S-03: mTLS Certificate Spoofing via Mis-issued Certificate

| Field | Detail |
|---|---|
| **ID** | THREAT-S-03 |
| **Category** | Spoofing |
| **Component** | `secure_identity` (M6), `secure_data` (M8) |
| **Description** | A rogue internal service obtains a client certificate from a poorly-governed internal CA (or a compromised CA) and presents it to another service to impersonate a trusted peer. If certificate pinning or additional claim validation beyond chain validation is not implemented, the attacker gains inter-service trust at TB-3. |
| **Likelihood** | L |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-3 |
| **STRIDE Category** | Spoofing |
| **Affected Data Flows** | DF-2, DF-3 |

---

### 3.2 Tampering

Tampering threats target the integrity of data, code, and audit records.

#### THREAT-T-01: Audit Log Tampering to Erase Evidence

| Field | Detail |
|---|---|
| **ID** | THREAT-T-01 |
| **Category** | Tampering |
| **Component** | `security_events` (M3) |
| **Description** | An attacker with write access to the log store (through a compromised service account, misconfigured storage policy, or insider privilege abuse) modifies or deletes audit records to cover tracks after a breach. Without cryptographic chaining of log entries, individual records can be altered without detectable inconsistency. |
| **Likelihood** | M |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-4 |
| **STRIDE Category** | Tampering |
| **Affected Data Flows** | DF-6 |

#### THREAT-T-02: Input Mutation Between Validation and Use (TOCTOU)

| Field | Detail |
|---|---|
| **ID** | THREAT-T-02 |
| **Category** | Tampering |
| **Component** | `secure_boundary` (M4) |
| **Description** | In an async multi-threaded Rust service, validated input may be cloned or serialised across await points. If consuming code holds a mutable reference or re-deserialises from an untrusted buffer after the validation layer, an attacker with local code execution or a race condition in a shared queue can tamper with the value between validation and use. This TOCTOU pattern is particularly relevant when validated data is written to a shared cache and read back. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-2 |
| **STRIDE Category** | Tampering |
| **Affected Data Flows** | DF-1 |

#### THREAT-T-03: Cryptographic Material Substitution in secure_data

| Field | Detail |
|---|---|
| **ID** | THREAT-T-03 |
| **Category** | Tampering |
| **Component** | `secure_data` (M8) |
| **Description** | An attacker with write access to the secrets backend (Vault, KMS) replaces a current encryption key or HMAC signing key with a known or weak value. If key material is not version-pinned at the point of use or if key rotation does not invalidate old data, the attacker can decrypt previously protected data or forge HMAC signatures, undermining data protection across the entire service. |
| **Likelihood** | L |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-4 |
| **STRIDE Category** | Tampering |
| **Affected Data Flows** | DF-8 |

---

### 3.3 Repudiation

Repudiation threats enable actors to deny having performed an action.

#### THREAT-R-01: Missing or Incomplete Audit Trail for Privileged Operations

| Field | Detail |
|---|---|
| **ID** | THREAT-R-01 |
| **Category** | Repudiation |
| **Component** | `security_events` (M3), `secure_authz` (M7) |
| **Description** | If consuming services invoke privileged operations (e.g., administrative commands, bulk data export, configuration changes) without emitting structured audit events via `security_events`, there is no non-repudiable record. An insider can perform unauthorised actions and deny involvement, with no forensic evidence to attribute the action. This is especially critical in energy and healthcare sectors where audit trails are mandated by regulation. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-3 |
| **STRIDE Category** | Repudiation |
| **Affected Data Flows** | DF-6 |

#### THREAT-R-02: Log Injection to Forge Audit Records

| Field | Detail |
|---|---|
| **ID** | THREAT-R-02 |
| **Category** | Repudiation |
| **Component** | `security_events` (M3), `secure_boundary` (M4) |
| **Description** | An attacker injects newline characters, JSON control sequences, or ANSI escape codes into user-controlled fields that are subsequently written to audit logs. In a structured log pipeline, this can create spurious log entries that attribute actions to other users or fabricate authorisation approvals, making it impossible to determine the true sequence of events during incident response. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Repudiation |
| **Affected Data Flows** | DF-1, DF-6 |

#### THREAT-R-03: Clock Skew Enabling Replay Attack with Deniability

| Field | Detail |
|---|---|
| **ID** | THREAT-R-03 |
| **Category** | Repudiation |
| **Component** | `secure_identity` (M6), `security_events` (M3) |
| **Description** | Significant NTP drift between nodes in a distributed deployment causes audit timestamps to be inconsistent. An attacker who has replayed a captured request exploits the ambiguous timestamp record to claim the request was not issued by them, as the audit record cannot be definitively correlated with network flow logs. Also enables `nbf`/`exp` JWT claim manipulation to extend token validity window. |
| **Likelihood** | L |
| **Impact** | M |
| **Trust Boundary Crossed** | TB-3 |
| **STRIDE Category** | Repudiation |
| **Affected Data Flows** | DF-2, DF-6 |

---

### 3.4 Information Disclosure

Information Disclosure threats expose data to unauthorised parties.

#### THREAT-I-01: Verbose Error Messages Leaking Internal State

| Field | Detail |
|---|---|
| **ID** | THREAT-I-01 |
| **Category** | Information Disclosure |
| **Component** | `secure_errors` (M2) |
| **Description** | If the `secure_errors` crate's safe error boundary is bypassed — for example, by a consuming crate that unwraps errors and formats them directly into HTTP responses — internal details such as stack traces, SQL queries, file system paths, service names, internal IP addresses, and library version strings are returned to the caller. This gives attackers reconnaissance information that significantly reduces the effort required to mount further attacks. |
| **Likelihood** | H |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-1 |
| **STRIDE Category** | Information Disclosure |
| **Affected Data Flows** | DF-7 |

#### THREAT-I-02: Side-Channel Timing Attack on Authentication

| Field | Detail |
|---|---|
| **ID** | THREAT-I-02 |
| **Category** | Information Disclosure |
| **Component** | `secure_identity` (M6), `secure_data` (M8) |
| **Description** | If credential comparison (password hash verification, HMAC token comparison, or API key lookup) uses non-constant-time operations, an attacker performing a timing oracle can determine partial credential values. Over thousands of requests this enables full credential reconstruction. This is particularly relevant for API key validation paths that may use short-circuit string comparison. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Information Disclosure |
| **Affected Data Flows** | DF-2 |

#### THREAT-I-03: PII Leakage Through Overly Permissive Serialisation

| Field | Detail |
|---|---|
| **ID** | THREAT-I-03 |
| **Category** | Information Disclosure |
| **Component** | `secure_output` (M5), `security_core` (M1) |
| **Description** | Data structures carrying fields classified as `DataClassification::Restricted` or `DataClassification::Secret` by `security_core` may be inadvertently serialised in full when serialised responses are constructed. If `secure_output` does not enforce field-level redaction based on classification metadata at serialisation time, PII (names, health identifiers, financial account numbers) flows to lower-privilege consumers or external clients. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-1 |
| **STRIDE Category** | Information Disclosure |
| **Affected Data Flows** | DF-5 |

#### THREAT-I-04: Secrets in Memory Accessible via Process Dump

| Field | Detail |
|---|---|
| **ID** | THREAT-I-04 |
| **Category** | Information Disclosure |
| **Component** | `secure_data` (M8) |
| **Description** | Cryptographic key material and secrets loaded from the secrets manager are held in process memory as plain bytes. If the host OS or container runtime allows core dumps, `/proc/mem` reads, or ptrace attachment (e.g., via a misconfigured seccomp profile), an attacker with local code execution can extract key material and secrets from the heap, potentially compromising all encrypted data. |
| **Likelihood** | M |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-4 |
| **STRIDE Category** | Information Disclosure |
| **Affected Data Flows** | DF-8 |

---

### 3.5 Denial of Service

Denial of Service threats degrade availability of the library and consuming services.

#### THREAT-D-01: Algorithmic Complexity Attack via Crafted Input

| Field | Detail |
|---|---|
| **ID** | THREAT-D-01 |
| **Category** | Denial of Service |
| **Component** | `secure_boundary` (M4, M11) |
| **Description** | An attacker submits inputs specifically crafted to trigger worst-case behaviour in input validation logic — for example, a deeply nested JSON object, a pathological regex backtrack, a Unicode normalisation bomb, or a zip bomb in file upload processing. If `secure_boundary` does not enforce structural depth limits, regex complexity limits, and decompressed-size limits, a single malformed request can cause CPU exhaustion or unbounded memory allocation, denying service to legitimate users. In critical infrastructure, this translates to operator lockout during an incident. |
| **Likelihood** | H |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Denial of Service |
| **Affected Data Flows** | DF-1 |
| **Mitigations (M11)** | `SecureJson` now enforces `max_nesting_depth` (default 10) and `max_field_count` (default 100) via a single-pass byte scanner before serde deserialization. `SecureXml` blocks DOCTYPE/entity declarations (billion-laughs prevention). Both emit `BoundaryViolation` events and return 422. |

#### THREAT-D-02: Audit Log Flooding to Exhaust Storage and Degrade SIEM

| Field | Detail |
|---|---|
| **ID** | THREAT-D-02 |
| **Category** | Denial of Service |
| **Component** | `security_events` (M3) |
| **Description** | An attacker (or runaway automated process) generates enormous volumes of audit events — for example, by triggering repeated authentication failures, making rapid unauthenticated requests, or flooding a validation-failed path. If `security_events` does not implement event rate limiting or back-pressure, the audit log storage can be exhausted, causing legitimate events to be dropped or the logging subsystem to crash. A SIEM that ingests from this source may also become overloaded, blinding the security operations centre. |
| **Likelihood** | H |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-3, TB-4 |
| **STRIDE Category** | Denial of Service |
| **Affected Data Flows** | DF-6 |

#### THREAT-D-03: Secrets Manager Throttling Causing Service Outage

| Field | Detail |
|---|---|
| **ID** | THREAT-D-03 |
| **Category** | Denial of Service |
| **Component** | `secure_data` (M8) |
| **Description** | If `secure_data` fetches secrets or performs key operations synchronously on every request without caching, an attacker can trigger API rate-limit throttling of the secrets manager by flooding the service with requests. Once throttled, legitimate requests that require key material fail, causing a cascading service outage. This is particularly dangerous during key rotation windows. |
| **Likelihood** | M |
| **Impact** | H |
| **Trust Boundary Crossed** | TB-4 |
| **STRIDE Category** | Denial of Service |
| **Affected Data Flows** | DF-8 |

---

### 3.6 Elevation of Privilege

Elevation of Privilege threats allow an actor to gain more access than authorised.

#### THREAT-E-01: Policy Bypass via Default-Permit Misconfiguration

| Field | Detail |
|---|---|
| **ID** | THREAT-E-01 |
| **Category** | Elevation of Privilege |
| **Component** | `secure_authz` (M7), `secure_boundary` (M11) |
| **Description** | If a consuming service registers a route or handler without explicitly attaching an authorisation policy — or if the `secure_authz` middleware is not applied to all routes in the axum router — the deny-by-default guarantee is broken. An unauthenticated or low-privilege user can reach administrative endpoints that were assumed to be protected. In the `secure_reference_service`, any route that is added without going through the policy registry falls into this gap. |
| **Likelihood** | M |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-2, TB-3 |
| **STRIDE Category** | Elevation of Privilege |
| **Affected Data Flows** | DF-3, DF-4 |
| **Mitigations (M11)** | `SafePath` prevents path traversal attacks that could bypass authorisation by accessing files outside the intended directory. Rejects `../`, encoded traversal, and absolute paths before the request reaches handlers. |

#### THREAT-E-02: JWT Claim Manipulation via Algorithm Confusion

| Field | Detail |
|---|---|
| **ID** | THREAT-E-02 |
| **Category** | Elevation of Privilege |
| **Component** | `secure_identity` (M6) |
| **Description** | A classic JWT `alg:none` or RS256→HS256 algorithm confusion attack: an attacker crafts a JWT with inflated privilege claims (elevated role, extended scope, or a different `sub`) and signs it using either the `none` algorithm or by using the RS256 public key as an HS256 HMAC secret. If the `secure_identity` validation layer does not pin the expected algorithm, the forged token is accepted and the attacker gains the privileges encoded in the manipulated claims. |
| **Likelihood** | M |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-1, TB-2 |
| **STRIDE Category** | Elevation of Privilege |
| **Affected Data Flows** | DF-2, DF-3 |

#### THREAT-E-03: Indirect Object Reference via Insecure Authorisation

| Field | Detail |
|---|---|
| **ID** | THREAT-E-03 |
| **Category** | Elevation of Privilege |
| **Component** | `secure_authz` (M7), `security_core` (M1) |
| **Description** | A horizontal privilege escalation where a low-privilege user manipulates a resource identifier (user ID, record ID, device ID) in a request path or body to access another user's data. If `secure_authz` policy evaluation only checks role-level access and not resource-level ownership (i.e., ABAC ownership attribute), an attacker can enumerate and access arbitrary records belonging to other users. In healthcare, this exposes patient records; in energy, it exposes SCADA device configurations. |
| **Likelihood** | H |
| **Impact** | C |
| **Trust Boundary Crossed** | TB-2 |
| **STRIDE Category** | Elevation of Privilege |
| **Affected Data Flows** | DF-3, DF-4 |

#### THREAT-E-04: Dependency Confusion / Crate Substitution Attack

| Field | Detail |
|---|---|
| **ID** | THREAT-E-04 |
| **Category** | Elevation of Privilege |
| **Component** | All crates (M10) |
| **Description** | An attacker publishes a malicious crate on crates.io with the same name as an internal SunLit crate (if the crates are not published under a reserved namespace). Build pipelines that pull from the public registry without checksum pinning could resolve to the attacker's version. The malicious crate could embed a backdoor that exfiltrates secrets, bypasses authorisation checks, or establishes a reverse shell in the compiled binary. |
| **Likelihood** | L |
| **Impact** | C |
| **Trust Boundary Crossed** | All |
| **STRIDE Category** | Elevation of Privilege |
| **Affected Data Flows** | All |

---

## 4. Abuse Cases

Each abuse case below documents a concrete attack scenario mapped to one or more STRIDE threats.

---

### AC-01: Operator Account Takeover in an Energy Management System

**Mapped Threats:** THREAT-S-01, THREAT-E-02  
**Attacker Tier:** T3 (Organised Crime / Industrial Espionage)

#### Attacker Motivation
Gain persistent access to an energy grid management system to exfiltrate operational data, position for ransomware deployment, or prepare for a physical disruption of power generation.

#### Preconditions
- The target service uses `secure_identity` with OIDC JWT authentication.
- The attacker has compromised an operator's workstation via phishing and obtained a valid bearer token from browser storage.
- Token lifetime is 8 hours (misconfigured by the consuming team beyond the recommended 15 minutes).
- The energy management service does not implement a server-side token revocation list.

#### Attack Steps
1. Attacker exfiltrates the bearer token from the compromised workstation's browser storage or OS keyring.
2. Attacker discovers the `alg` header is not pinned in the service's `secure_identity` configuration.
3. Attacker crafts a new JWT with the same `sub` claim but elevates the `role` claim from `operator` to `admin`, signs it using `alg: none`.
4. Attacker submits the forged token to the administrative API endpoint `/api/v1/grid/control`.
5. `secure_identity` (if improperly configured) accepts the `alg: none` token.
6. `secure_authz` evaluates the `admin` role claim and grants access.
7. Attacker issues commands to switch load-shedding configuration and prepares a ransomware deployment package.

#### Impact
- **Availability:** Grid operator lockout; potential physical disruption of power distribution.
- **Confidentiality:** SCADA topology and operational data exfiltrated.
- **Integrity:** Control commands injected; configuration tampered.
- **Regulatory:** NERC CIP violation; potential criminal liability for board.

---

### AC-02: Patient Record Enumeration in a Healthcare Portal

**Mapped Threats:** THREAT-E-03, THREAT-I-03  
**Attacker Tier:** T2 (Malicious Insider — low-privilege nurse account)

#### Attacker Motivation
Access medical records of high-profile patients for blackmail, sale to media, or insurance fraud.

#### Preconditions
- The healthcare portal uses `secure_authz` with role-based access control.
- The RBAC policy checks that the user has the `medical_staff` role but does not verify record ownership.
- Patient record IDs are sequential integers (IDOR vulnerability in the consuming API layer).
- The consuming service does not use `security_core`'s typed ID wrappers that enforce ownership checks.

#### Attack Steps
1. Attacker authenticates as a legitimate `medical_staff` user.
2. Attacker observes a URL pattern: `GET /api/patients/{patient_id}/records`.
3. Attacker writes a script that iterates `patient_id` from 1 to 100,000.
4. `secure_authz` evaluates the `medical_staff` role — this passes for all requests.
5. No ABAC ownership attribute is checked (the policy only checks role).
6. The API returns full patient records including diagnosis, medication, and contact information.
7. Attacker exfiltrates approximately 80,000 records before rate limiting triggers.

#### Impact
- **Confidentiality:** Mass PII / PHI breach; HIPAA violation.
- **Financial:** Multi-million dollar regulatory fines; class-action liability.
- **Reputational:** Loss of patient trust; media coverage.
- **Availability:** Incident response effort diverts resources from clinical operations.

---

### AC-03: Audit Log Poisoning to Cover Lateral Movement

**Mapped Threats:** THREAT-T-01, THREAT-R-02  
**Attacker Tier:** T4 (Nation-State APT)

#### Attacker Motivation
Maintain deniable persistent access to a government financial clearinghouse while exfiltrating transaction data over months without triggering SOC alerts.

#### Preconditions
- The attacker has already achieved initial access via a supply-chain compromise of a dependency.
- The attacker has write access to the message queue that feeds the audit log pipeline.
- `security_events` stores log entries in a append-only structured log; however, the log sink (Elasticsearch) has write API access enabled for the service account.

#### Attack Steps
1. Attacker enumerates the audit log pipeline from the compromised service process.
2. Attacker identifies that log entries are written as JSON to Elasticsearch without cryptographic chaining.
3. Attacker crafts a log entry injection payload containing `\n` characters followed by a synthetic log record attributing their access to a legitimate service account.
4. Attacker modifies existing log entries in Elasticsearch to remove their session IDs from authentication records.
5. Attacker begins exfiltrating transaction records, with all queries appearing in the audit log as originating from the legitimate service account.
6. After 6 months, attacker deploys ransomware and deletes the log history for the exfiltration period.

#### Impact
- **Integrity:** Audit record integrity destroyed; forensic investigation fails.
- **Confidentiality:** Months of financial transaction data exfiltrated.
- **Regulatory:** SOX, FISMA violations; potential criminal prosecution.
- **Availability:** Ransomware deployment encrypts production databases.

---

### AC-04: Algorithmic DoS via Nested JSON Bomb

**Mapped Threats:** THREAT-D-01  
**Attacker Tier:** T1 (Opportunistic / Hacktivist)

#### Attacker Motivation
Disrupt availability of a government benefits portal during a high-traffic period (e.g., tax filing deadline) for political reasons or to demonstrate capability.

#### Preconditions
- The benefits portal exposes a JSON API endpoint that accepts nested configuration or document structures.
- `secure_boundary` is deployed but structural depth limits and decompressed-size limits are not configured (using permissive defaults).
- The endpoint is partially public (requires only a valid (unauthenticated) reCAPTCHA token).

#### Attack Steps
1. Attacker crafts a JSON payload with 10,000 levels of nesting, total serialised size 1 KB.
2. Attacker bypasses reCAPTCHA using a low-cost CAPTCHA-solving service.
3. Attacker sends 50 concurrent requests with the nested JSON payload.
4. The deserialisation library (serde_json) recursively allocates stack frames for each nesting level.
5. Stack overflow crashes the worker threads; the Tokio runtime spawns replacement threads but they crash immediately on the same input.
6. The service becomes unresponsive within seconds; connection queue fills; load balancer health checks fail.
7. The portal is unavailable for 4 hours during the filing deadline.

#### Impact
- **Availability:** 4-hour service outage during peak usage.
- **Financial:** Citizens unable to file; helpdesk call volume spikes 10×.
- **Reputational:** Media coverage; political fallout.
- **Recovery cost:** Incident response, post-mortem, patching cycle.

---

### AC-05: Secret Exfiltration via Memory Dump on Compromised Container

**Mapped Threats:** THREAT-I-04, THREAT-T-03  
**Attacker Tier:** T3 / T4

#### Attacker Motivation
Obtain master encryption keys used by `secure_data` to protect a financial institution's customer data, enabling offline decryption of exfiltrated encrypted backups.

#### Preconditions
- The attacker has obtained container-level code execution through a vulnerability in the application's HTTP handler.
- The container runs with a permissive seccomp profile (ptrace allowed).
- `secure_data` loads the AES-256 master key into a `Vec<u8>` that is not zeroised on drop.
- No memory encryption (AMD SME / Intel TME) is configured on the host.

#### Attack Steps
1. Attacker exploits a buffer overflow in an HTTP handler to achieve remote code execution within the container.
2. Attacker reads `/proc/self/maps` to identify heap regions.
3. Attacker uses `process_vm_readv` (permitted by the seccomp profile) to dump heap memory.
4. Attacker writes a pattern-matching script to identify 256-bit AES key candidates (high entropy 32-byte sequences adjacent to `secure_data` allocations).
5. Attacker exfiltrates the candidate keys and tests against known encrypted blobs.
6. Master key is recovered; attacker decrypts the entire customer data archive exfiltrated previously.

#### Impact
- **Confidentiality:** Full customer data archive decrypted; millions of records exposed.
- **Financial:** Regulatory fines, litigation, remediation.
- **Integrity:** Trust in the encryption posture of the institution is destroyed.
- **Recovery:** All data must be re-encrypted; all keys must be rotated; HSM migration required.

---

### AC-06: Cross-Tenant Authorisation Bypass in a Multi-Tenant SaaS Platform

**Mapped Threats:** THREAT-E-01, THREAT-E-03  
**Attacker Tier:** T2 (Malicious Tenant)

#### Attacker Motivation
A competitor subscribes to the same SaaS platform and attempts to access another tenant's data.

#### Preconditions
- A multi-tenant platform built on `secure_authz` uses JWT `tenant_id` claim to scope data access.
- A new API route was added during a hotfix deployment without attaching the `secure_authz` middleware.
- The route is documented in an internal API specification that leaked to the attacker.

#### Attack Steps
1. Attacker subscribes to the platform with a legitimate account and obtains a valid JWT with their `tenant_id`.
2. Attacker discovers the unprotected route from the leaked API specification.
3. Attacker sends a request to the unprotected route with a different `tenant_id` path parameter.
4. No authorisation policy is evaluated (middleware was not applied).
5. The application reads the `tenant_id` from the URL path and queries the database, returning the target tenant's data.
6. Attacker repeats the enumeration across all known tenant IDs.

#### Impact
- **Confidentiality:** Cross-tenant data breach; all tenant data exposed.
- **Regulatory:** GDPR, SOC 2 violation; potential loss of certification.
- **Financial:** Customer churn, regulatory fines.
- **Legal:** Civil liability to affected tenants.

---

## 5. Control-to-Threat Traceability Matrix

> This matrix maps every documented threat to the milestones and crates that provide primary and secondary controls. Every threat must trace to at least one milestone; every milestone must trace to at least one threat.

| Threat ID | Threat Summary | M1 `security_core` | M2 `secure_errors` | M3 `security_events` | M4 `secure_boundary` | M5 `secure_output` | M6 `secure_identity` | M7 `secure_authz` | M8 `secure_data` | M9 `ref_service` | M10 Hardening |
|---|---|---|---|---|---|---|---|---|---|---|---|
| THREAT-S-01 | Token replay after revocation | | | ◉ (audit) | | | ◉ (primary) | ◉ (deny stale) | | ◉ (demo) | ◉ (revocation list) |
| THREAT-S-02 | IdP impersonation via SSRF | | | ◉ (alert) | ◉ (URL validation) | | ◉ (primary) | | | ◉ (demo) | ◉ (pin JWKS URL) |
| THREAT-S-03 | mTLS certificate spoofing | ◉ (identity types) | | ◉ (alert) | | | ◉ (primary) | ◉ (cert claims) | ◉ (cert storage) | ◉ (demo) | ◉ (CA governance) |
| THREAT-T-01 | Audit log tampering | | | ◉ (primary) | | | | | ◉ (HMAC chain) | ◉ (demo) | ◉ (WORM storage) |
| THREAT-T-02 | Input TOCTOU mutation | ◉ (typed IDs) | ◉ (error guard) | | ◉ (primary) | | | | | ◉ (demo) | ◉ (immutable types) |
| THREAT-T-03 | Crypto key substitution | | | ◉ (alert) | | | | | ◉ (primary) | ◉ (demo) | ◉ (key versioning) |
| THREAT-R-01 | Missing audit trail | ◉ (severity types) | | ◉ (primary) | | | | ◉ (mandatory audit) | | ◉ (demo) | ◉ (compliance audit) |
| THREAT-R-02 | Log injection / forgery | | | ◉ (primary) | ◉ (sanitise input) | ◉ (encode output) | | | | ◉ (demo) | ◉ (structured logs) |
| THREAT-R-03 | Clock skew / replay deniability | | | ◉ (timestamps) | | | ◉ (nbf/exp) | | | ◉ (demo) | ◉ (NTP monitoring) |
| THREAT-I-01 | Verbose error leakage | | ◉ (primary) | | | ◉ (safe headers) | | | | ◉ (demo) | ◉ (error review) |
| THREAT-I-02 | Timing attack on auth | | | | | | ◉ (primary) | | ◉ (const-time) | ◉ (demo) | ◉ (timing audit) |
| THREAT-I-03 | PII leakage via serialisation | ◉ (data class) | | | | ◉ (primary) | | ◉ (policy scope) | | ◉ (demo) | ◉ (data flow review) |
| THREAT-I-04 | Secrets in memory / process dump | | | | | | | | ◉ (primary) | ◉ (demo) | ◉ (seccomp / mlock) |
| THREAT-D-01 | Algorithmic complexity DoS | | ◉ (timeout guard) | | ◉ (primary) | | | | | ◉ (demo) | ◉ (fuzzing) |
| THREAT-D-02 | Audit log flood DoS | | | ◉ (primary) | ◉ (rate limit) | | | | | ◉ (demo) | ◉ (back-pressure) |
| THREAT-D-03 | Secrets manager throttling DoS | | ◉ (fallback err) | | | | | | ◉ (primary) | ◉ (demo) | ◉ (caching / circuit) |
| THREAT-E-01 | Default-permit misconfiguration | ◉ (policy types) | | | | | | ◉ (primary) | | ◉ (demo) | ◉ (route audit) |
| THREAT-E-02 | JWT algorithm confusion | | | ◉ (audit) | | | ◉ (primary) | | | ◉ (demo) | ◉ (alg pinning) |
| THREAT-E-03 | Insecure direct object ref | ◉ (typed IDs) | | ◉ (audit) | ◉ (path validate) | | | ◉ (primary) | | ◉ (demo) | ◉ (ABAC review) |
| THREAT-E-04 | Dependency confusion | | | | | | | | | | ◉ (primary) |

**Legend:** ◉ = primary or significant secondary control for this threat at this milestone.

### Milestone Coverage Summary

| Milestone | # Threats Covered | Primary Coverage |
|---|---|---|
| M1 `security_core` | 6 | Typed IDs, data classification, severity types |
| M2 `secure_errors` | 5 | Safe error boundaries, timeout guards, fallback errors |
| M3 `security_events` | 13 | Audit trail, tamper detection, alerts, timestamps |
| M4 `secure_boundary` | 8 | Input validation, size limits, rate limiting, path validation |
| M5 `secure_output` | 4 | Safe headers, encoding, classification-aware serialisation |
| M6 `secure_identity` | 8 | Token validation, algorithm pinning, constant-time ops |
| M7 `secure_authz` | 7 | Deny-by-default, ABAC, mandatory audit, policy scope |
| M8 `secure_data` | 7 | Key versioning, HMAC chain, const-time, memory protection |
| M9 `ref_service` | 19 | Integration demonstration of all controls |
| M10 Hardening | 20 | All threats addressed in hardening pass |

---

## 6. Compliance Framework Mapping

### 6.1 NIST SP 800-53 Rev 5

| Control Family | Controls | Threats Addressed | Implementing Crates |
|---|---|---|---|
| **AC — Access Control** | AC-2 Account Management, AC-3 Access Enforcement, AC-4 Information Flow, AC-6 Least Privilege, AC-17 Remote Access | THREAT-E-01, THREAT-E-02, THREAT-E-03, THREAT-S-01 | `secure_authz` (M7), `secure_identity` (M6) |
| **AU — Audit and Accountability** | AU-2 Event Logging, AU-3 Content of Audit Records, AU-9 Protection of Audit Info, AU-10 Non-repudiation, AU-12 Audit Record Generation | THREAT-T-01, THREAT-R-01, THREAT-R-02, THREAT-R-03 | `security_events` (M3), `secure_data` (M8) |
| **IA — Identification and Authentication** | IA-2 Identification/Authentication, IA-5 Authenticator Management, IA-7 Cryptographic Module Authentication, IA-8 Non-Org Users | THREAT-S-01, THREAT-S-02, THREAT-S-03, THREAT-I-02, THREAT-E-02 | `secure_identity` (M6), `secure_data` (M8) |
| **SC — System and Communications Protection** | SC-8 Transmission Confidentiality, SC-12 Cryptographic Key Management, SC-13 Cryptographic Protection, SC-28 Protection at Rest | THREAT-I-04, THREAT-T-03, THREAT-D-03, THREAT-S-03 | `secure_data` (M8), `secure_identity` (M6) |
| **SI — System and Information Integrity** | SI-2 Flaw Remediation, SI-3 Malicious Code Protection, SI-10 Info Input Validation, SI-12 Info Output Handling | THREAT-D-01, THREAT-T-02, THREAT-I-01, THREAT-I-03, THREAT-E-04 | `secure_boundary` (M4), `secure_output` (M5), `secure_errors` (M2) |

### 6.2 IEC 62443 (Industrial Automation and Control Systems Security)

Applicable to energy and industrial deployments of SunLit Security Libraries.

| IEC 62443 Requirement | SL Level | Threats Addressed | Implementing Crates |
|---|---|---|---|
| **SR 1.1** Human User Identification and Authentication | SL 2–3 | THREAT-S-01, THREAT-S-02, THREAT-E-02 | `secure_identity` (M6) |
| **SR 1.5** Authenticator Management | SL 2–3 | THREAT-I-02, THREAT-T-03 | `secure_identity` (M6), `secure_data` (M8) |
| **SR 2.1** Authorization Enforcement | SL 2–4 | THREAT-E-01, THREAT-E-03 | `secure_authz` (M7) |
| **SR 2.8** Auditable Events | SL 2–4 | THREAT-R-01, THREAT-R-02 | `security_events` (M3) |
| **SR 3.1** Communication Integrity | SL 2–4 | THREAT-T-01, THREAT-T-03 | `secure_data` (M8), `security_events` (M3) |
| **SR 3.4** Software and Information Integrity | SL 2–4 | THREAT-T-02, THREAT-E-04 | `secure_boundary` (M4) |
| **SR 7.1** Denial of Service Protection | SL 2–3 | THREAT-D-01, THREAT-D-02, THREAT-D-03 | `secure_boundary` (M4), `security_events` (M3) |

### 6.3 SOC 2 Type II

| SOC 2 Trust Service Criteria | Threats Addressed | Implementing Crates |
|---|---|---|
| **CC6.1** Logical access security — authentication | THREAT-S-01, THREAT-S-02, THREAT-E-02 | `secure_identity` (M6) |
| **CC6.2** Prior to access — identity provisioning | THREAT-S-03, THREAT-E-01 | `secure_identity` (M6), `secure_authz` (M7) |
| **CC6.3** Role-based access control | THREAT-E-01, THREAT-E-03 | `secure_authz` (M7) |
| **CC7.2** Monitoring for anomalies | THREAT-R-01, THREAT-D-02 | `security_events` (M3) |
| **CC8.1** Change management | THREAT-E-04, THREAT-T-03 | M10 Hardening |
| **C1.1** Confidentiality of information | THREAT-I-01, THREAT-I-03, THREAT-I-04 | `secure_errors` (M2), `secure_output` (M5), `secure_data` (M8) |

Additional secure-coding evidence:

| Evidence Set | Mapping |
|---|---|
| ANSSI Rust Secure Coding Guidelines (FR) | [`docs/compliance/anssi-rust.md`](docs/compliance/anssi-rust.md) — 61-rule mapping pinned to ANSSI `84e6ae18`; framed as state-of-the-art evidence in French markets / IEC 62443-4-1 SD-3 audit support |

---

## 7. Residual Risks

Residual risks are threats that the SunLit Security Libraries **cannot fully mitigate** because they depend on runtime environment, consuming-application behaviour, or factors outside the library's control. Consuming teams **must** implement compensating controls.

---

### RR-01: Post-Exploitation Memory Forensics (THREAT-I-04)

| Field | Detail |
|---|---|
| **Residual Risk ID** | RR-01 |
| **Mapped Threat** | THREAT-I-04 |
| **Why Residual** | Rust's memory safety prevents buffer overflows and use-after-free, but it does not prevent an attacker with existing code execution from reading process memory via OS APIs. The `secure_data` crate can use the `zeroize` crate to clear key material from memory on drop, but there are windows between key loading and zeroing during which a memory dump captures the key. Additionally, OS-level swap and hibernation can persist memory to disk. |
| **Likelihood After Controls** | Low |
| **Impact If Realised** | Critical — all encrypted data at risk |

**Compensating Controls (consuming team must implement):**

1. **seccomp-BPF profile:** Block `ptrace`, `process_vm_readv`, and `mem_open` syscalls in the container seccomp profile. Use a hardened baseline such as the Docker default seccomp profile plus additional restrictions.
2. **Disable core dumps:** Set `ulimit -c 0` in the container entrypoint. Configure `kernel.core_pattern` to discard cores.
3. **Memory-locked secret storage:** Use `mlock2(MLOCK_ONFAULT)` to prevent key material pages from being swapped to disk. Investigate `memfd_secret` on Linux 5.14+.
4. **HSM / Confidential Computing:** For highest assurance (energy, finance, government), execute key operations inside an HSM or AMD SEV / Intel TDX confidential VM enclave.
5. **Swap encryption:** Ensure host swap partitions are encrypted (LUKS) and preferably disabled for services handling key material.

---

### RR-02: Consuming Service Misconfiguration of Authorisation Middleware (THREAT-E-01)

| Field | Detail |
|---|---|
| **Residual Risk ID** | RR-02 |
| **Mapped Threat** | THREAT-E-01 |
| **Why Residual** | `secure_authz` can only protect routes to which the middleware is applied. In axum, it is possible to add routes after the middleware layer, or to construct sub-routers that bypass the middleware entirely. The library provides deny-by-default semantics within its policy engine, but cannot enforce that all routes are registered through it. This is a Rust API surface limitation — enforcement would require a proc-macro or lint that is not currently implemented. |
| **Likelihood After Controls** | Medium |
| **Impact If Realised** | Critical — authentication bypass possible |

**Compensating Controls (consuming team must implement):**

1. **Integration test coverage:** Write end-to-end tests that enumerate every registered route and assert that an unauthenticated request receives a 401/403 response. Include this as a CI/CD gate.
2. **Router audit tooling:** Use `cargo-vet` and `axum-router-audit` (or equivalent) to enumerate all routes and flag those without the authorisation layer.
3. **Architecture review:** Mandate a security architecture review before any new API endpoint goes to production.
4. **Automated DAST:** Run OWASP ZAP or Nuclei against the deployed service in a staging environment to detect unauthenticated endpoints.
5. **Proc-macro enforcement (future):** Raise a GitHub issue on SunLit Security Libraries to implement a `#[deny_unauthenticated]` proc-macro that fails compilation if a handler is registered without an authorisation policy.

---

### RR-03: Supply Chain Compromise via Transitive Dependencies (THREAT-E-04)

| Field | Detail |
|---|---|
| **Residual Risk ID** | RR-03 |
| **Mapped Threat** | THREAT-E-04 |
| **Why Residual** | SunLit Security Libraries has transitive dependencies on widely-used crates (e.g., `tokio`, `serde`, `axum`, `ring`, `rustls`). A compromise of any upstream crate maintainer account could introduce a backdoor into the supply chain. While `Cargo.lock` pins exact versions and checksums, a maintainer can publish a new version that looks legitimate. The library cannot control upstream maintainer account security. |
| **Likelihood After Controls** | Low |
| **Impact If Realised** | Critical — all services using the library could be compromised |

**Compensating Controls (consuming team must implement):**

1. **`cargo-vet` and supply chain audit:** Implement `cargo vet` with a policy that requires all dependencies to be audited. Use the Mozilla / Google / crates.io supply chain audit database.
2. **Checksum pinning in `Cargo.lock`:** Ensure `Cargo.lock` is committed and validated in CI. Any checksum change triggers a mandatory review.
3. **Private registry mirror:** Mirror approved crate versions to a private registry (e.g., Artifactory, Cloudsmith) and prohibit direct crates.io access from build agents.
4. **SBOM generation and monitoring:** Generate a Software Bill of Materials (SBOM) at build time using `cargo-cyclonedx` or `syft`. Monitor for CVEs against the SBOM using Grype or OSV-Scanner.
5. **Reproducible builds:** Implement reproducible build verification so that the same source always produces the same binary, enabling independent verification of build artefacts.

---

### RR-04: Clock Synchronisation Failure Undermining Audit Integrity (THREAT-R-03)

| Field | Detail |
|---|---|
| **Residual Risk ID** | RR-04 |
| **Mapped Threat** | THREAT-R-03 |
| **Why Residual** | The `security_events` crate records timestamps using the system clock. It cannot enforce or verify that the system clock is accurately synchronised with a trusted time source. In distributed deployments, network time attacks (NTP spoofing, NTP amplification) or simple configuration drift can cause event timestamps to become unreliable, undermining audit trail integrity and enabling replay attacks. |
| **Likelihood After Controls** | Low |
| **Impact If Realised** | Medium — audit integrity degraded; replay windows extended |

**Compensating Controls (consuming team must implement):**

1. **Authenticated NTP (NTS):** Deploy Network Time Security (RFC 8915) instead of unauthenticated NTPv4. Use a dedicated NTS server or cloud-provider time service with NTS support.
2. **Monotonic clock cross-check:** In addition to wall-clock timestamps, include a monotonic sequence number in audit records to detect out-of-order or replayed records.
3. **Time synchronisation monitoring:** Alert when clock drift exceeds ±500ms across cluster nodes. Treat clock drift as a security event.
4. **JWT clock skew limits:** Configure `secure_identity` to reject tokens where `nbf` or `exp` drift exceeds a defined maximum (e.g., 30 seconds), tuned to observed clock skew in the deployment environment.

---

### RR-05: Secrets Manager Unavailability Causing Security Degradation (THREAT-D-03)

| Field | Detail |
|---|---|
| **Residual Risk ID** | RR-05 |
| **Mapped Threat** | THREAT-D-03 |
| **Why Residual** | If the secrets manager becomes unavailable (throttled, network partitioned, or down), `secure_data` must choose between failing closed (denying all requests) or failing open (using cached or default key material). The correct choice is context-dependent and must be configured by the consuming team. Either option carries risk: failing closed causes a DoS; failing open with stale keys may allow decryption with a compromised key. |
| **Likelihood After Controls** | Medium |
| **Impact If Realised** | High — service outage or security degradation |

**Compensating Controls (consuming team must implement):**

1. **Secrets caching with TTL:** Cache secrets in memory with a configurable TTL (recommended: 5–15 minutes for production). Implement background refresh so the cache is refreshed before expiry rather than on-demand.
2. **Circuit breaker pattern:** Implement a circuit breaker around secrets manager calls. When the circuit opens, the service continues to operate with cached secrets and alerts the operations team.
3. **Fail-closed for new sessions:** Configure the service to fail-closed for new authentication attempts when the secrets manager is unavailable for longer than the cache TTL. Existing sessions should continue with cached material.
4. **Multi-region / HA secrets manager:** Deploy the secrets manager in a high-availability configuration across multiple availability zones. For AWS Secrets Manager, use cross-region replication.
5. **Secrets manager health monitoring:** Include the secrets manager in health check endpoints and alert on degraded availability before it becomes an outage.

---

## 8. Peer-Review Checklist

This checklist must be reviewed and signed off by at least two security engineers before the threat model is approved for a release milestone.

| # | Checklist Item | Status |
|---|---|---|
| 1 | All STRIDE categories (S, T, R, I, D, E) have at least 2 documented threats | ✅ Satisfied — S: 3, T: 3, R: 3, I: 4, D: 3, E: 4 |
| 2 | Every threat has a unique ID, component mapping, likelihood, and impact rating | ✅ Satisfied — 20 threats documented with full metadata |
| 3 | Control-to-Threat Traceability Matrix covers all milestones M1–M10 | ✅ Satisfied — all 10 milestones have at least one threat mapped |
| 4 | Every milestone maps to at least one threat in the traceability matrix | ✅ Satisfied — see Section 5 Milestone Coverage Summary |
| 5 | Every threat maps to at least one milestone/crate | ✅ Satisfied — all 20 threats have primary milestone coverage |
| 6 | At least 6 abuse cases documented with full attacker profile | ✅ Satisfied — 6 abuse cases (AC-01 through AC-06) |
| 7 | Every abuse case includes attacker motivation, preconditions, attack steps, and impact | ✅ Satisfied — all 6 abuse cases include all four fields |
| 8 | At least 3 residual risks with compensating controls | ✅ Satisfied — 5 residual risks (RR-01 through RR-05) |
| 9 | NIST 800-53 compliance mapping covers AC, AU, IA, SC, SI control families | ✅ Satisfied — all 5 families mapped in Section 6.1 |
| 10 | IEC 62443 compliance mapping present for industrial deployments | ✅ Satisfied — 7 IEC 62443 requirements mapped in Section 6.2 |
| 11 | SOC 2 Type II TSC mapping present | ✅ Satisfied — 6 SOC 2 criteria mapped in Section 6.3 |
| 12 | All trust boundaries defined and labelled (TB-1 through TB-4) | ✅ Satisfied — 4 trust boundaries with descriptions and diagrams |
| 13 | All data flows identified and mapped to controls (DF-1 through DF-8) | ✅ Satisfied — 8 data flows documented in Section 2.4 |
| 14 | Threat actor profiles documented (T1–T4) | ✅ Satisfied — 4 threat actor tiers in Section 1.4 |
| 15 | Attack tree files created and cross-referenced | ✅ Satisfied — 4 attack tree files in `docs/attack-trees/` |
| 16 | Document reviewed for information that should not be made public | ⚠️ Pending — classify as INTERNAL before distribution |
| 17 | Threat model scheduled for next quarterly review | ⚠️ Pending — add calendar reminder for Q+1 review |
| 18 | All referenced controls verified as implemented in the codebase | ⚠️ Pending — verify at M10 hardening milestone |

---

*End of Threat Model Document*

> **Next Review Date:** Q+1 (add to security team calendar)  
> **Distribution:** Security Team, Lead Engineers, Compliance Officer  
> **Classification:** INTERNAL — Security Sensitive

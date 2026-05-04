# Attack Tree: Input Validation & Output Encoding

> **Crates:** `secure_boundary` (Milestone M4 — OWASP C5) and `secure_output` (Milestone M5 — OWASP C4)  
> **Supporting Crates:** `secure_errors` (M2), `security_events` (M3), `security_core` (M1)  
> **Related Threats:** THREAT-D-01, THREAT-T-02, THREAT-I-01, THREAT-I-03, THREAT-R-02  
> **Classification:** INTERNAL — Security Sensitive  
> **Version:** 1.0.0

---

## Introduction

This attack tree models all credible paths by which an attacker can **inject malicious input** or **extract sensitive output** through weaknesses in the input validation and output encoding boundary. It covers two complementary crates:

- **`secure_boundary` (M4):** The inbound trust boundary — validates, sanitises, and type-coerces all external input before it reaches application logic.
- **`secure_output` (M5):** The outbound trust boundary — context-aware encoding of data in responses, security header enforcement, and classification-aware serialisation.

Critical infrastructure context: injection attacks on energy management APIs can forge SCADA commands; in healthcare, XSS can steal clinician session tokens enabling patient data access; in finance, injection can manipulate transaction data; output information disclosure leaks architecture details that accelerate further attacks.

**The Validation Sandwich Principle:**  
Every request passes through `secure_boundary` on ingress and `secure_output` on egress. Application logic between these boundaries must only receive and produce validated, typed data.

**Node notation:**
- `[OR]` — any one child path achieves the parent goal
- `[AND]` — all child paths must succeed simultaneously
- `[LEAF]` — terminal attack action (no further decomposition)
- `(M)` — mitigating control from `secure_boundary` / `secure_output` or a peer crate
- `(R)` — residual risk requiring compensating control from consuming team

---

## Part 1: Input Validation Attack Tree (`secure_boundary`)

```
GOAL-INPUT: Bypass Input Validation — Deliver malicious input to application logic
│
├── [OR] 1. Injection Attacks via Malicious Input Content
│   │
│   ├── [OR] 1.1 SQL Injection
│   │   │
│   │   ├── [LEAF] 1.1.1 Classic UNION-based SQL injection in query parameter
│   │   │           Mitigations: (M) secure_boundary rejects raw SQL syntax patterns;
│   │   │                         (R) Application must use parameterised queries / ORM;
│   │   │                         (M) secure_errors never returns SQL error details to caller
│   │   │
│   │   ├── [LEAF] 1.1.2 Blind time-based SQL injection via boolean inference
│   │   │           Mitigations: (M) Input type-coercion: integers, UUIDs, and enums
│   │   │                             validated before reaching query layer;
│   │   │                         (R) Database user must have minimum required privileges
│   │   │
│   │   └── [LEAF] 1.1.3 Second-order SQL injection: malicious data stored then executed
│   │               Mitigations: (M) All data validated on input AND on subsequent retrieval;
│   │                             (R) Consuming team must use parameterised queries throughout
│   │
│   ├── [OR] 1.2 Cross-Site Scripting (XSS)
│   │   │
│   │   ├── [LEAF] 1.2.1 Reflected XSS: script payload echoed directly in HTML response
│   │   │           Mitigations: (M) secure_output HTML-encodes all dynamic content;
│   │   │                         (M) secure_output sets Content-Security-Policy header;
│   │   │                         (M) secure_boundary rejects inputs containing script tags
│   │   │
│   │   ├── [LEAF] 1.2.2 Stored XSS: payload stored and rendered to other users
│   │   │           Mitigations: (M) secure_output context-aware encoding applied at render time;
│   │   │                         (M) CSP with nonce/hash prevents inline script execution
│   │   │
│   │   └── [LEAF] 1.2.3 DOM-based XSS: client-side JS inserts unencoded data into DOM
│   │               Mitigations: (M) secure_output encodes JSON for JS contexts;
│   │                             (R) Client-side code must use safe DOM APIs (textContent, not innerHTML)
│   │
│   ├── [OR] 1.3 Command Injection
│   │   │
│   │   ├── [LEAF] 1.3.1 OS command injection via shell metacharacters in input field
│   │   │           Mitigations: (M) secure_boundary rejects inputs containing shell metacharacters
│   │   │                             (;, |, &, $, `, (, ), <, >) when input type is not expected
│   │   │                             to contain these characters;
│   │   │                         (R) Application must never pass user input to shell commands
│   │   │
│   │   └── [LEAF] 1.3.2 LDAP injection in directory service queries
│   │               Mitigations: (M) secure_boundary provides LDAP-safe string validation;
│   │                             (M) LDAP special characters escaped in output encoding
│   │
│   ├── [OR] 1.4 Path Traversal
│   │   │
│   │   ├── [LEAF] 1.4.1 Directory traversal: ../../../etc/passwd in file path parameter
│   │   │           Mitigations: (M) secure_boundary normalises path components;
│   │   │                         (M) Path validation rejects .. and null bytes;
│   │   │                         (M) Absolute paths validated against allowlisted root
│   │   │
│   │   └── [LEAF] 1.4.2 Encoded traversal: %2e%2e%2f, %252e, UTF-8 overlong encoding
│   │               Mitigations: (M) secure_boundary decodes before validation
│   │                                 (URL decode → Unicode normalise → validate);
│   │                             (M) Multi-layer decoding applied to prevent bypass
│   │
│   └── [OR] 1.5 Log Injection (THREAT-R-02)
│       │
│       ├── [LEAF] 1.5.1 Inject CRLF into user-controlled field that appears in logs
│       │           Mitigations: (M) security_events sanitises all fields before logging;
│       │                         (M) secure_boundary strips CRLF from string inputs
│       │
│       └── [LEAF] 1.5.2 Inject JSON control characters to forge log record structure
│                   Mitigations: (M) security_events uses structured logging; all fields
│                                     serialised via serde with explicit field names;
│                                 (M) User-controlled data always in typed fields, never
│                                     interpolated into log format strings
│
├── [OR] 2. Structural and Size-Based Attacks (THREAT-D-01) [Abuse Case AC-04]
│   │
│   ├── [OR] 2.1 JSON/XML Complexity Attacks
│   │   │
│   │   ├── [LEAF] 2.1.1 Deeply nested JSON (10,000 levels) → stack overflow
│   │   │           Mitigations: (M) secure_boundary enforces maximum JSON nesting depth;
│   │   │                         (M) Deserialisation uses iterative (not recursive) parser
│   │   │                             where supported; depth limit enforced before allocation
│   │   │
│   │   ├── [LEAF] 2.1.2 Large array with many unique keys → HashMap DoS
│   │   │           Mitigations: (M) Maximum array length limit enforced;
│   │   │                         (M) Maximum object key count enforced
│   │   │
│   │   └── [LEAF] 2.1.3 XML Bomb (billion laughs): exponential entity expansion
│   │               Mitigations: (M) XML entity expansion limit enforced;
│   │                             (M) XML external entity (XXE) processing disabled
│   │
│   ├── [OR] 2.2 Payload Size Attacks
│   │   │
│   │   ├── [LEAF] 2.2.1 Oversized request body → memory exhaustion
│   │   │           Mitigations: (M) secure_boundary enforces configurable body size limit
│   │   │                             (default: 1 MiB; configurable per-route);
│   │   │                         (M) Limit applied before body is read into memory
│   │   │
│   │   ├── [LEAF] 2.2.2 Zip bomb: small compressed payload → huge decompressed data
│   │   │           Mitigations: (M) Decompressed-size limit enforced independently of
│   │   │                             compressed size; streaming decompression with limit;
│   │   │                         (M) Decompression ratio limit (e.g., max 100:1)
│   │   │
│   │   └── [LEAF] 2.2.3 Multipart bomb: many small parts → large total allocation
│   │               Mitigations: (M) Maximum part count enforced in multipart validation;
│   │                             (M) Total decompressed size tracked across all parts
│   │
│   ├── [OR] 2.3 Regex Denial of Service (ReDoS)
│   │   │
│   │   ├── [LEAF] 2.3.1 Pathological input triggers backtracking in regex validator
│   │   │           Mitigations: (M) secure_boundary uses linear-time regex engine (regex crate
│   │   │                             uses finite automaton — no backtracking by design);
│   │   │                         (M) Regex complexity audited as part of M10 hardening
│   │   │
│   │   └── [LEAF] 2.3.2 Regex engine timeout exceeded causing goroutine/thread leak
│   │               Mitigations: (M) Per-request validation timeout enforced;
│   │                             (M) secure_errors surfaces timeout as 400 Bad Request
│   │
│   └── [OR] 2.4 Unicode and Encoding Attacks
│       │
│       ├── [LEAF] 2.4.1 Unicode normalisation attack: visually identical strings that
│       │               compare differently (homoglyph, NFD vs NFC mismatch)
│       │           Mitigations: (M) secure_boundary normalises to NFC before validation;
│       │                         (M) Username/identifier canonicalisation enforced
│       │
│       ├── [LEAF] 2.4.2 Overlong UTF-8 encoding to bypass character filter
│       │           Mitigations: (M) Rust's str type rejects invalid UTF-8 at decode time;
│       │                         (M) Bytes validated as well-formed UTF-8 before processing
│       │
│       └── [LEAF] 2.4.3 Bidirectional (BiDi) text injection to deceive reviewers
│                   Mitigations: (M) secure_boundary rejects Unicode BiDi control characters
│                                     in non-display contexts (filenames, identifiers, code);
│                                 (M) BiDi characters stripped from audit log fields
│
├── [OR] 3. TOCTOU — Input Mutation Between Validation and Use (THREAT-T-02)
│   │
│   ├── [AND] 3.1 Shared Mutable State Race Condition
│   │   ├── [LEAF] 3.1.1 Validated input cloned into shared Arc<Mutex<T>>
│   │   ├── [LEAF] 3.1.2 Second thread mutates value through alias before use
│   │   └── [LEAF] 3.1.3 Application reads mutated (unvalidated) value
│   │           Mitigations: (M) secure_boundary returns owned, immutable validated types;
│   │                         (M) Validated types use #[non_exhaustive] + private fields
│   │                             to prevent external mutation;
│   │                         (M) Rust ownership system prevents aliased mutation in safe code
│   │
│   ├── [AND] 3.2 Cache Poisoning Between Validation and Retrieval
│   │   ├── [LEAF] 3.2.1 Validated value written to shared cache
│   │   └── [LEAF] 3.2.2 Attacker with cache write access overwrites with malicious value
│   │           Mitigations: (M) Cache entries include HMAC over value content;
│   │                         (R) Cache ACLs must prevent unauthorised write access
│   │
│   └── [AND] 3.3 Deserialisation After Re-Serialisation Mutation
│       ├── [LEAF] 3.3.1 Validated struct serialised to JSON for message queue
│       └── [LEAF] 3.3.2 Queue consumer re-deserialises without re-validating
│               Mitigations: (M) secure_boundary validation types implement serde; validation
│                                 is invoked automatically on deserialisation via custom visitor;
│                             (R) All deserialisation of untrusted data must go through
│                                 secure_boundary validators
│
└── [OR] 4. Content Type and Protocol Confusion
    │
    ├── [LEAF] 4.1 Send JSON body with Content-Type: text/plain to bypass JSON validator
    │           Mitigations: (M) secure_boundary validates Content-Type header before
    │                             attempting to parse body; rejects mismatched content types
    │
    ├── [LEAF] 4.2 HTTP parameter pollution: duplicate parameters with conflicting values
    │           Mitigations: (M) secure_boundary uses first-value semantics for duplicate
    │                             parameters and logs the presence of duplicates to security_events
    │
    └── [LEAF] 4.3 HTTP request smuggling via conflicting Content-Length and Transfer-Encoding
                Mitigations: (M) secure_boundary rejects requests with both Content-Length
                                  and Transfer-Encoding headers;
                              (R) Reverse proxy must also reject ambiguous framing
```

---

## Part 2: Output Encoding Attack Tree (`secure_output`)

```
GOAL-OUTPUT: Exploit Output Encoding Weakness — Extract sensitive data or inject content
│
├── [OR] 5. Information Disclosure via Unsafe Error Responses (THREAT-I-01)
│   │
│   ├── [LEAF] 5.1 Stack trace / panic message returned in HTTP response body
│   │           Mitigations: (M) secure_errors converts all errors to opaque safe responses;
│   │                         (M) Internal error details logged to security_events, not caller;
│   │                         (M) Rust panics caught at tower middleware boundary
│   │
│   ├── [LEAF] 5.2 Database error message returned (table names, SQL, etc.)
│   │           Mitigations: (M) secure_errors maps all database errors to generic 500;
│   │                         (M) Correlation ID returned to caller; full details in internal log
│   │
│   └── [LEAF] 5.3 Version information in Server / X-Powered-By headers
│               Mitigations: (M) secure_output removes Server, X-Powered-By, X-AspNet-Version;
│                             (M) Adds security headers replacing fingerprinting headers
│
├── [OR] 6. Cross-Site Scripting via Insufficient Encoding
│   │
│   ├── [LEAF] 6.1 HTML context: unencoded < > " & ' in response body
│   │           Mitigations: (M) secure_output HTML-entity-encodes all dynamic values;
│   │                         (M) Template rendering uses auto-escaping engine
│   │
│   ├── [LEAF] 6.2 JavaScript context: string not JS-encoded → script injection
│   │           Mitigations: (M) secure_output provides JS-context encoding (JSON.stringify
│   │                             equivalent with Unicode escape for non-ASCII)
│   │
│   ├── [LEAF] 6.3 URL context: unencoded characters in href/src attributes
│   │           Mitigations: (M) secure_output URL-encodes dynamic URL components;
│   │                         (M) JavaScript: URIs rejected in href context
│   │
│   └── [LEAF] 6.4 CSS context: expression injection via style attributes
│               Mitigations: (M) secure_output CSS-context encoding for style values;
│                             (M) CSP blocks inline styles by default
│
├── [OR] 7. Security Header Bypass
│   │
│   ├── [LEAF] 7.1 Clickjacking via missing X-Frame-Options / frame-ancestors CSP
│   │           Mitigations: (M) secure_output sets X-Frame-Options: DENY by default;
│   │                         (M) CSP frame-ancestors 'none' included in default policy
│   │
│   ├── [LEAF] 7.2 MIME sniffing attack via missing X-Content-Type-Options
│   │           Mitigations: (M) secure_output sets X-Content-Type-Options: nosniff
│   │
│   ├── [LEAF] 7.3 Browser caches sensitive response (no Cache-Control directives)
│   │           Mitigations: (M) secure_output sets Cache-Control: no-store for authenticated
│   │                             and sensitive responses
│   │
│   ├── [LEAF] 7.4 Referrer leaks path information to third parties
│   │           Mitigations: (M) secure_output sets Referrer-Policy: strict-origin-when-cross-origin
│   │
│   └── [LEAF] 7.5 Cross-site browser request abuses ambient credentials or open CORS policy
│               Mitigations: (M) secure_boundary CORS helper defaults to deny-all;
│                             (M) only explicit allowlists via SecureCorsBuilder grant access;
│                             (M) FetchMetadataLayer blocks unsafe `Sec-Fetch-Site: cross-site`
│                                 API requests except safe top-level navigations
│
├── [OR] 8. PII/Sensitive Data Leakage via Over-Serialisation (THREAT-I-03)
│   │
│   ├── [AND] 8.1 Data Classification Not Enforced at Serialisation
│   │   ├── [LEAF] 8.1.1 Response includes Restricted/Secret classified fields
│   │   └── [LEAF] 8.1.2 Caller's clearance level below data classification
│   │           Mitigations: (M) secure_output checks DataClassification against caller's
│   │                             clearance level before serialising each field;
│   │                         (M) Fields classified above caller's clearance are
│   │                             replaced with redaction marker or omitted;
│   │                         (R) security_core DataClassification must be applied to
│   │                              all sensitive struct fields
│   │
│   ├── [LEAF] 8.2 Debug serialisation includes fields excluded from normal output
│   │           Mitigations: (M) Debug and Display implementations for classified types
│   │                             are explicitly redacted via custom derive;
│   │                         (M) Classified types do not implement Serialize directly;
│   │                              only via secure_output context-aware serialiser
│   │
│   └── [LEAF] 8.3 Error response includes PII from failed validation context
│               Mitigations: (M) secure_errors strips PII from validation error messages;
│                             (M) Field names reported but values are not echoed back
│
└── [OR] 9. Content Security Policy Bypass
    │
    ├── [LEAF] 9.1 CSP too permissive (unsafe-inline, unsafe-eval, wildcard sources)
    │           Mitigations: (M) secure_output provides a strict CSP baseline;
    │                         (M) CSP builder API guides towards secure configuration;
    │                         (R) Consuming team must review CSP for their specific frontend
    │
    ├── [LEAF] 9.2 CSP injection via user-controlled nonce predictability
    │           Mitigations: (M) Nonces generated by CSPRNG per request;
    │                         (M) Nonces are 128-bit base64url encoded values
    │
    └── [AND] 9.3 JSONP endpoint bypasses CSP entirely
        ├── [LEAF] 9.3.1 Legacy JSONP endpoint exists without CSP coverage
        └── [LEAF] 9.3.2 Attacker exploits JSONP callback for data exfiltration
                Mitigations: (M) secure_output does not support JSONP;
                              (R) Legacy JSONP endpoints must be removed by consuming team
```

---

## Validation-to-Encoding Pipeline

```
HTTP Request
     │
     ▼
┌────────────────────────────────────────────┐
│  secure_boundary (M4)                      │
│                                            │
│  1. Content-Type validation                │
│  2. Body size limit enforcement            │
│  3. UTF-8 normalisation (NFC)              │
│  4. Structural depth/count limits          │
│  5. Type-safe extractor validation         │
│  6. BiDi / CRLF / injection char filter   │
│  7. Return owned, immutable typed value    │
└────────────────┬───────────────────────────┘
                 │  Validated, typed input
                 ▼
     Application Logic (business rules)
                 │  Response data
                 ▼
┌────────────────────────────────────────────┐
│  secure_output (M5)                        │
│                                            │
│  1. DataClassification enforcement         │
│  2. Context-aware encoding (HTML/JS/URL)   │
│  3. PII redaction for caller's clearance   │
│  4. Security header injection              │
│  5. Error response sanitisation            │
│  6. CSP nonce generation                   │
└────────────────┬───────────────────────────┘
                 │
                 ▼
         HTTP Response
```

---

## Mitigating Controls Summary

| Attack Path | Primary Control | Crate | Milestone |
|---|---|---|---|
| SQL/Command injection (1.1/1.3) | Type-safe extractors; parameterised queries guidance | `secure_boundary` | M4 |
| XSS reflected/stored (1.2.x) | Context-aware encoding; CSP | `secure_boundary`, `secure_output` | M4/M5 |
| Algorithmic complexity DoS (2.1–2.3) | Nesting limits; size limits; linear-time regex | `secure_boundary` | M4 |
| Unicode / encoding bypass (2.4.x) | NFC normalisation; UTF-8 validation; BiDi rejection | `secure_boundary` | M4 |
| TOCTOU mutation (3.x) | Owned immutable types; Rust ownership | `secure_boundary` | M4 |
| Information disclosure errors (5.x) | Opaque error responses; correlation IDs | `secure_errors` | M2 |
| XSS via insufficient encoding (6.x) | Context-aware encoding (HTML/JS/URL/CSS) | `secure_output` | M5 |
| Missing security headers (7.x) | Mandatory security header middleware | `secure_output` | M5 |
| PII over-serialisation (8.x) | DataClassification enforcement at serialisation | `secure_output` | M5 |
| CSP bypass (9.x) | Strict CSP baseline; CSPRNG nonces | `secure_output` | M5 |

---

## Residual Risk Cross-Reference

| Attack Path | Residual Risk | See Threat Model |
|---|---|---|
| SQL injection (1.1.x) | Consuming team must use parameterised queries | RR-02 |
| DOM-based XSS (1.2.3) | Client-side code must use safe DOM APIs | RR-02 |
| Cache poisoning TOCTOU (3.2.x) | Cache ACL enforcement outside library scope | RR-01 |
| PII classification (8.1.x) | All sensitive fields must have DataClassification applied | RR-02 |

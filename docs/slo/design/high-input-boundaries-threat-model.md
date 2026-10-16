# High input boundaries — threat model

Frozen source: merged-main Codex Security run
`wfr_4a87ac67ebc4b17474ac10c6cb2ba50ae1f4afbe190f6ccf6e66c9d65290a8db`
at commit `379efff4255674ad755654b64dde086066802218`.

| ID | Attacker and concrete action | Boundary and asset | Bad outcome | M1 control | Residual |
|---|---|---|---|---|---|
| `tm-high-input-boundaries-abuse-1` | A web user submits leading C0 whitespace, embedded tab/newline, or quotes around an executable URI and a consumer follows the documented href example. | Untrusted URI text to browser URL and HTML-attribute parsing; application origin/session. | Script executes in the victim origin (CWE-79). | Reject browser-ignored/attribute-breaking syntax and require attribute encoding in the documented sink. | A consumer that bypasses both controls can still create XSS; type-safe template integration is later product work. |
| `tm-high-input-boundaries-abuse-2` | An unauthenticated client streams a chunked JSON/XML body larger than the configured limit. | Network body frames to contiguous parser buffer; process memory/availability. | Full request allocation causes memory exhaustion before rejection (CWE-770). | One shared Axum limited collector, request-specific limit for both formats, fixed overflow mapping and runtime oversized witnesses. | Upstream proxies and connection-count/time limits remain deployment controls. |
| `tm-high-input-boundaries-abuse-3` | A remote user supplies decimal/short/octal-like IPv4, a carrier-grade/provider-metadata address such as `100.100.100.200`, or a backslash authority that a narrow classifier treats as public. | URL text or DNS answer to outbound HTTP client; metadata and private services. | The client reaches a protected or non-public destination (CWE-918). | Parse using the locked WHATWG model, require public-unicast typed IPs for both literal and resolved-address paths, reject ambiguous authority syntax, and retain only canonical serialization. | DNS rebinding remains a caller duty requiring bounded resolve/classify/pin at connect time; M1 makes no DNS guarantee. |
| `tm-high-input-boundaries-abuse-4` | A remote user supplies `/\\evil.example`, an encoded separator, or a control-bearing redirect that a downstream framework normalizes differently. | Redirect parameter to HTTP `Location` semantics; user navigation and application trust. | A path-only check becomes an attacker-controlled network-path redirect (CWE-601). | Reject raw/encoded parser differentials, resolve against a fixed HTTPS origin, verify the origin, and retain only the canonical relative reference. | Callers must construct `Location` from the validated value and must not decode or concatenate untrusted suffixes afterward. |

Security invariants:

1. Validation and sink encoding are separate mandatory steps.
2. No extractor can buffer byte `limit + 1` successfully.
3. SafeUrl never returns a different parser interpretation from the one it
   classified.
4. SafeRedirectUrl never returns a value that resolves outside its fixed origin.
5. Parser or transport ambiguity fails closed with fixed non-secret errors.
6. Dependency admission precedes code execution and never waives `MAL-*`.

Variant analysis covers all URI schemes and browser whitespace/control classes;
both custom Axum body extractors and request-limit sources; and SafeUrl numeric,
userinfo, slash/backslash, port, IPv4, IPv6 and public-domain forms.

# High input boundaries — threat model

Frozen source: merged-main Codex Security run
`wfr_4a87ac67ebc4b17474ac10c6cb2ba50ae1f4afbe190f6ccf6e66c9d65290a8db`
at commit `379efff4255674ad755654b64dde086066802218`.

| ID | Attacker and concrete action | Boundary and asset | Bad outcome | M1 control | Residual |
|---|---|---|---|---|---|
| `tm-high-input-boundaries-abuse-1` | A web user submits leading C0 whitespace, embedded tab/newline, or quotes around an executable URI and a consumer follows the documented href example. | Untrusted URI text to browser URL and HTML-attribute parsing; application origin/session. | Script executes in the victim origin (CWE-79). | Reject browser-ignored/attribute-breaking syntax and require attribute encoding in the documented sink. | A consumer that bypasses both controls can still create XSS; type-safe template integration is later product work. |
| `tm-high-input-boundaries-abuse-2` | An unauthenticated client streams a chunked JSON/XML body larger than the configured limit. | Network body frames to contiguous parser buffer; process memory/availability. | Full request allocation causes memory exhaustion before rejection (CWE-770). | One shared Axum limited collector, request-specific limit for both formats, fixed overflow mapping and runtime oversized witnesses. | Upstream proxies and connection-count/time limits remain deployment controls. |
| `tm-high-input-boundaries-abuse-3` | A remote user supplies decimal/short/octal-like IPv4 or a backslash authority that the manual parser treats as a public domain. | URL text to outbound HTTP client; metadata and private services. | The client normalizes the accepted value to a protected destination (CWE-918). | Parse using the locked WHATWG model, classify the parsed host, reject credentials/backslashes/fragments, and retain only canonical serialization. | DNS rebinding is accepted only as a documented caller duty requiring resolve/classify/pin at connect time; M1 makes no DNS guarantee. |

Security invariants:

1. Validation and sink encoding are separate mandatory steps.
2. No extractor can buffer byte `limit + 1` successfully.
3. SafeUrl never returns a different parser interpretation from the one it
   classified.
4. Parser or transport ambiguity fails closed with fixed non-secret errors.
5. Dependency admission precedes code execution and never waives `MAL-*`.

Variant analysis covers all URI schemes and browser whitespace/control classes;
both custom Axum body extractors and request-limit sources; and SafeUrl numeric,
userinfo, slash/backslash, port, IPv4, IPv6 and public-domain forms.

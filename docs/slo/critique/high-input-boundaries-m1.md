# Sequential critique — high input boundaries M1

Runbook: `docs/slo/current/RUNBOOK-high-input-boundaries.md`.
Threat model: `docs/slo/design/high-input-boundaries-threat-model.md`.
The pre-schema threat model is consumed in documented degraded mode; its three
IDs are frozen in this milestone.

| id | persona | category | runbook section | finding | concrete scenario | recommendation |
|---|---|---|---|---|---|---|
| HIB-CEO-1 | CEO | hold-scope | Contract | Shipping all three high findings together is justified because they share one untrusted-input release gate; adding the 13 lower findings would make review and rollback unsafe. | A broad batch fails CI and maintainers cannot isolate whether URL parsing, body streaming or an unrelated cache race caused it. | Keep M1 to the three high findings; route the remaining findings into later severity-ordered batches. |
| HIB-ENG-1 | engineering | auto-fix | Body limit | A Content-Length-only fix would leave chunked requests unbounded. | An attacker omits Content-Length and streams chunks until the process exhausts memory. | Require the streaming limiter as the authority; Content-Length is only an early rejection optimization. |
| HIB-ENG-2 | engineering | auto-fix | SafeUrl | Parsing for validation but returning the raw input preserves the parser differential. | Validation sees canonical loopback while the raw alternate spelling is later reparsed by the client. | Store and return only the canonical serialization from the exact parsed value that was classified. |
| HIB-SEC-1 | security | auto-fix | URI outcome | **High (CWE-79):** URI allowlisting does not perform HTML attribute encoding. | A consumer interpolates an accepted relative value containing a quote and creates an event-handler attribute. | Reject delimiters defensively and make `HtmlEncoder.encode` mandatory in the copyable example; class mitigated at both validation and sink. Variant: every C0/space/quote/backtick/angle-bracket class. |
| HIB-SEC-2 | security | auto-fix | Body outcome | **High (CWE-770):** a post-allocation check is not a transport bound. | One unauthenticated chunked request allocates far beyond `max_body_bytes` before returning 413. | Use Axum's limited collector and prove JSON/XML per-request limits with over-limit witnesses; class eliminated in these extractors. Variant: both content types and absent/misleading Content-Length. |
| HIB-SEC-3 | security | auto-fix | SafeUrl outcome | **High (CWE-918):** manual host parsing disagrees with the downstream WHATWG parser. | `http://2130706433/` passes as a domain and is fetched as 127.0.0.1. | Reuse locked `url`, reject ambiguous authority syntax and classify its typed host before preserving canonical output; parser-differential class eliminated. DNS rebinding remains explicit. |
| HIB-DESIGN-1 | design | defer | N/A | No UI surface exists. | No user interaction is changed by this library maintenance milestone. | Skip design review. |

## Expanded high-severity findings

### HIB-SEC-1 — CWE-79 cross-site scripting

Evidence: `sanitize_uri_scheme` checked the raw prefix and the guide interpolated
the untouched input inside quotes. Remediation is two-layer: reject ambiguous URI
syntax and encode the accepted value for the HTML attribute context. Verification
must reproduce browser-ignored controls and quote breakout. OWASP A03 Injection;
ASVS V5 validation and V3 output encoding.

### HIB-SEC-2 — CWE-770 allocation without limits

Evidence: both Axum extractors called `collect()` before comparing length; XML
also ignored the request extension. The streaming collector is the enforcing
control and must stop at `max_body_bytes`; a header check alone is insufficient.
Verification covers chunked-equivalent bodies for both formats and custom limits.

### HIB-SEC-3 — CWE-918 server-side request forgery

Evidence: SafeUrl manually split the authority and treated failed IP parsing as a
domain, then returned the original bytes to a different parser. M1 uses the same
WHATWG model as the outbound client and stores its canonical serialization.
Verification covers decimal, shortened, octal-like, trailing-dot, credentials and
backslashes. DNS answers still require resolve/classify/pin and are not claimed.

All findings were incorporated mechanically or held within the already confirmed
scope. There is no unresolved `ask` item before execution.

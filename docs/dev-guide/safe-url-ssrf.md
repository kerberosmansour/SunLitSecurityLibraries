# `SafeUrl` — SSRF prevention integration guide

> Part of the [SunLitSecurityLibraries dev-guide](./README.md). Target audience: engineers handling outbound URLs that originated from untrusted input.

## What SSRF is and why `SafeUrl` exists

Server-Side Request Forgery happens when an attacker persuades your service to fetch a URL they chose — often targeting internal systems the attacker can't reach directly. Classic exploits:

- `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` — AWS IMDS credential theft (the Capital One breach mechanism).
- `http://127.0.0.1:6379/` — Redis on localhost from an exposed webhook handler.
- `http://[fe80::1]/` — IPv6 link-local reaching the host's own management interface.
- `http://10.0.0.5:8080/admin` — LAN pivot from a cloud-hosted API.

`SafeUrl` is a type that rejects these at the validation boundary — a [`BoundaryRejection::SsrfAttempt`](../../crates/secure_boundary/src/error.rs) result before your outbound fetch ever runs.

## The public-unicast policy

`SafeUrl::try_from(&str)` parses with the same WHATWG URL model used by common
Rust HTTP clients, canonicalizes the result, and accepts typed IP hosts only when
they are public unicast addresses. It rejects these non-global or special-purpose
families:

| CIDR | What it is | Why it's blocked |
|---|---|---|
| `10.0.0.0/8` | RFC 1918 private | Classic LAN SSRF |
| `100.64.0.0/10` | Shared address space | Carrier-grade NAT and provider metadata, including `100.100.100.200` |
| `172.16.0.0/12` | RFC 1918 private | Classic LAN SSRF |
| `192.168.0.0/16` | RFC 1918 private | Classic LAN SSRF |
| `169.254.0.0/16` | IPv4 link-local | AWS IMDS + credential exfiltration |
| `127.0.0.0/8` | IPv4 loopback | Localhost services |
| `0.0.0.0/8` | Current network / unspecified | Stack-internal behavior |
| `192.0.0.0/24` | IETF protocol assignments | Special-purpose endpoints |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation | Non-routable examples |
| `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.175.48.0/24` | IANA special-purpose | Anycast and transition infrastructure |
| `198.18.0.0/15` | Benchmarking | Non-public test networks |
| `224.0.0.0/4` | IPv4 multicast | Lateral-movement response surface |
| `240.0.0.0/4` | Reserved / broadcast | Non-public destinations |
| outside IPv6 `2000::/3` | Non-global-unicast IPv6 | Loopback, local, multicast and reserved space |
| IPv6 `2001::/23`, `2001:db8::/32`, `2002::/16`, `3fff::/20` | Special-purpose, documentation and 6to4 | Ambiguous or non-public destinations |

The original Gate A ranges retain named regression tests in
[`sg_gate_a_safeurl_cidrs.rs`](../../crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs).
The Codex Security regressions additionally exercise shared, metadata,
documentation, benchmarking, reserved and IPv6 special-purpose addresses through
both URL-literal and resolver-answer paths. The policy deliberately fails closed
when an address is not ordinary public unicast.

Allowed schemes: `http` and `https` only. Credentials, fragments, backslashes,
missing hosts, alternate numeric forms that normalize to protected IPs, and
anything else (`javascript:`, `file://`, `data:`, `gopher://`, …) are rejected.

## How to use `SafeUrl` (copy-paste)

```rust
use secure_boundary::safe_types::SafeUrl;

let input: &str = read_from_user_input();
let safe = match SafeUrl::try_from(input) {
    Ok(url) => url,
    Err(e) => {
        tracing::warn!(error = ?e, "rejected outbound URL");
        return reject();
    }
};

// Resolve with your bounded resolver, reject every protected answer, then pin
// one approved address in the connector so a second lookup cannot rebind it.
let addresses = bounded_resolve(safe.as_inner()).await?;
for address in &addresses {
    SafeUrl::validate_resolved_ip(*address)?;
}
let resp = send_with_pinned_address(&safe, addresses[0]).await?;
```

Always validate at the **entry point** (deserializer or DTO `SecureValidate`) rather than immediately before the fetch. That way every code path that touches the URL has already been vetted.

## Serde integration (reject at deserialize time)

`SafeUrl` implements `Deserialize`. Use it directly in DTOs to guarantee validation happens during request parsing:

```rust
use secure_boundary::safe_types::SafeUrl;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookConfig {
    callback: SafeUrl,
}
```

A POST body containing `{"callback":"http://169.254.169.254/"}` now fails at the `serde_json::from_slice` step with an SSRF rejection — before your handler body ever runs.

## What `SafeUrl` does NOT do

- **DNS rebinding.** `SafeUrl` canonicalizes and validates URL text, but it does
  not resolve names. Check every resolver answer with
  `SafeUrl::validate_resolved_ip` and pin an approved address through connection
  establishment. Checking and then allowing the HTTP client to perform a second
  lookup is still vulnerable.
- **SNI/TLS-layer attacks.** `SafeUrl` is a string check. Use `secure_network` for TLS-layer controls (cert pinning, cleartext rejection).
- **Open redirect.** See [`SafeRedirectUrl`](../../crates/secure_boundary/src/safe_types.rs) — a distinct type that parses and canonicalizes same-origin path redirects. It rejects network paths, backslashes, controls, malformed escapes and encoded path separators.

## How to extend if you need stricter rules

The classifier is shared by construction-time URL checks and the public
`validate_resolved_ip` connect-time helper. If you need additional blocked ranges
beyond Gate A:

1. Add literal-host and resolved-address regressions for the new range — variant analysis first.
2. Extend the private functions with the new branch.
3. Update the rustdoc CIDR table and this dev-guide.

Don't introduce a runtime-configurable blocked list — that would let a misconfiguration silently weaken SSRF protection. The blocked set is code, not configuration.

## See also

- `SafeUrl` rustdoc — full blocked-CIDR table + examples
- [`BoundaryRejection::SsrfAttempt`](../../crates/secure_boundary/src/error.rs) — the rejection variant you'll see in logs
- [`SafeRedirectUrl`](../../crates/secure_boundary/src/safe_types.rs) — companion type for HTTP redirect URLs
- [`docs/dev-guide/README.md`](./README.md) — dev-guide index

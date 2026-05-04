# `SafeUrl` — SSRF prevention integration guide

> Part of the [SunLitSecurityLibraries dev-guide](./README.md). Target audience: engineers handling outbound URLs that originated from untrusted input.

## What SSRF is and why `SafeUrl` exists

Server-Side Request Forgery happens when an attacker persuades your service to fetch a URL they chose — often targeting internal systems the attacker can't reach directly. Classic exploits:

- `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` — AWS IMDS credential theft (the Capital One breach mechanism).
- `http://127.0.0.1:6379/` — Redis on localhost from an exposed webhook handler.
- `http://[fe80::1]/` — IPv6 link-local reaching the host's own management interface.
- `http://10.0.0.5:8080/admin` — LAN pivot from a cloud-hosted API.

`SafeUrl` is a type that rejects these at the validation boundary — a [`BoundaryRejection::SsrfAttempt`](../../crates/secure_boundary/src/error.rs) result before your outbound fetch ever runs.

## The 12-CIDR blocked set

`SafeUrl::try_from(&str)` rejects any URL whose host string parses as an IP inside any of these ranges:

| CIDR | What it is | Why it's blocked |
|---|---|---|
| `10.0.0.0/8` | RFC 1918 private | Classic LAN SSRF |
| `172.16.0.0/12` | RFC 1918 private | Classic LAN SSRF |
| `192.168.0.0/16` | RFC 1918 private | Classic LAN SSRF |
| `169.254.0.0/16` | IPv4 link-local | AWS IMDS + credential exfiltration |
| `127.0.0.0/8` | IPv4 loopback | Localhost services |
| `224.0.0.0/4` | IPv4 multicast | Lateral-movement response surface |
| `0.0.0.0/32` | IPv4 unspecified | Stack-internal vulnerabilities |
| `fc00::/7` | IPv6 ULA | Analogue of RFC 1918 on IPv6 |
| `fe80::/10` | IPv6 link-local | IPv6 analogue of IMDS |
| `::1/128` | IPv6 loopback | Localhost on IPv6 |
| `ff00::/8` | IPv6 multicast | Same as IPv4 multicast |
| `::/128` | IPv6 unspecified | Stack-internal |

These are all on Sunlit Guardian's v3-K2 required blocked list, derived from Google / OWASP / CVE landscape data. Each CIDR has a named regression test in [`sg_gate_a_safeurl_cidrs.rs`](../../crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs); any future edit that removes one branch fails a specific named test.

Allowed schemes: `http` and `https` only. Anything else (`javascript:`, `file://`, `data:`, `gopher://`, …) is rejected.

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

let client = reqwest::Client::new();
let resp = client.get(safe.as_inner()).send().await?;
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

- **DNS rebinding.** `SafeUrl` only validates the host *string*. If the host is `evil.example.com` and the resolver returns `169.254.169.254` at connect time, `SafeUrl` doesn't catch it. Defense: use a DNS resolver that enforces a public-IP policy, or re-check the resolved `IpAddr` at connect time with the same predicate used here.
- **IPv4-mapped IPv6.** A host like `[::ffff:127.0.0.1]` is not currently rejected. If a Sunlit Guardian-style audit adds this requirement, open a follow-up runbook. (Deferred from sg-gate-a M3 to keep scope tight.)
- **SNI/TLS-layer attacks.** `SafeUrl` is a string check. Use `secure_network` for TLS-layer controls (cert pinning, cleartext rejection).
- **Open redirect.** See [`SafeRedirectUrl`](../../crates/secure_boundary/src/safe_types.rs) — a distinct type that enforces path-only URLs for HTTP redirects.

## How to extend if you need stricter rules

The classifier (`is_private_ipv4` / `is_private_ipv6`) is private to `secure_boundary`. If you need additional blocked ranges beyond Gate A:

1. Add a `#[test]` per new CIDR in `sg_gate_a_safeurl_cidrs.rs` — variant analysis first.
2. Extend the private functions with the new branch.
3. Update the rustdoc CIDR table and this dev-guide.

Don't introduce a runtime-configurable blocked list — that would let a misconfiguration silently weaken SSRF protection. The blocked set is code, not configuration.

## See also

- `SafeUrl` rustdoc — full blocked-CIDR table + examples
- [`BoundaryRejection::SsrfAttempt`](../../crates/secure_boundary/src/error.rs) — the rejection variant you'll see in logs
- [`SafeRedirectUrl`](../../crates/secure_boundary/src/safe_types.rs) — companion type for HTTP redirect URLs
- [`docs/dev-guide/README.md`](./README.md) — dev-guide index

//! BDD: SafeUrl blocked-CIDR coverage — sg-gate-a M3.
//!
//! One `#[test]` per CIDR on Sunlit Guardian's required blocked list
//! (v3-K2). Variant-analysis principle: any future edit that removes a
//! single line from `is_private_ipv4` or `is_private_ipv6` fails a
//! specific named test so the regression is obvious from the test output.

use secure_boundary::safe_types::SafeUrl;

/// Builds a URL targeting the given host, using bracketed form for IPv6.
fn url_for(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("http://[{host}]/")
    } else {
        format!("http://{host}/")
    }
}

fn assert_rejected(host: &str) {
    let s = url_for(host);
    let result = SafeUrl::try_from(s.as_str());
    assert!(
        result.is_err(),
        "SafeUrl::try_from({s:?}) should reject host {host} but returned {result:?}"
    );
}

fn assert_accepted(host: &str) {
    let s = url_for(host);
    let result = SafeUrl::try_from(s.as_str());
    assert!(
        result.is_ok(),
        "SafeUrl::try_from({s:?}) should accept host {host} but returned {result:?}"
    );
}

// ── IPv4 CIDRs ──────────────────────────────────────────────────────────────

#[test]
fn rejects_cidr_10_slash_8() {
    assert_rejected("10.0.0.1");
    assert_rejected("10.255.255.254");
}

#[test]
fn rejects_cidr_172_16_slash_12() {
    assert_rejected("172.16.0.1");
    assert_rejected("172.20.1.1");
}

#[test]
fn rejects_cidr_172_31_slash_12_upper() {
    // Upper edge of /12 — still inside the private range.
    assert_rejected("172.31.255.254");
}

#[test]
fn rejects_cidr_192_168_slash_16() {
    assert_rejected("192.168.0.1");
    assert_rejected("192.168.255.254");
}

#[test]
fn rejects_cidr_169_254_slash_16() {
    // Link-local, includes AWS IMDS (169.254.169.254).
    assert_rejected("169.254.169.254");
    assert_rejected("169.254.1.1");
}

#[test]
fn rejects_cidr_127_slash_8() {
    assert_rejected("127.0.0.1");
    assert_rejected("127.255.255.254");
}

#[test]
fn rejects_cidr_224_slash_4() {
    // IPv4 multicast 224.0.0.0/4.
    assert_rejected("224.0.0.1");
    assert_rejected("230.1.2.3");
}

#[test]
fn rejects_cidr_239_255_upper() {
    // Upper edge of 224.0.0.0/4 (239.255.255.255 is within the range).
    assert_rejected("239.255.255.254");
}

#[test]
fn rejects_cidr_0_slash_32() {
    // IPv4 unspecified.
    assert_rejected("0.0.0.0");
}

// ── IPv6 CIDRs ──────────────────────────────────────────────────────────────

#[test]
fn rejects_cidr_fc00_slash_7() {
    // Unique Local Address.
    assert_rejected("fc00::1");
}

#[test]
fn rejects_cidr_fd00_slash_7_upper() {
    // Upper edge of fc00::/7 — `fd..` is inside the range.
    assert_rejected("fdff:ffff:ffff:ffff::1");
}

#[test]
fn rejects_cidr_fe80_slash_10() {
    // IPv6 link-local — analogue of the 169.254.0.0/16 IMDS attack vector.
    assert_rejected("fe80::1");
}

#[test]
fn rejects_cidr_fe80_slash_10_upper() {
    // Upper edge of fe80::/10 — `febf::` is still inside.
    assert_rejected("febf::1");
}

#[test]
fn rejects_cidr_loopback_v6() {
    // ::1/128.
    assert_rejected("::1");
}

#[test]
fn rejects_cidr_ff00_slash_8() {
    // IPv6 multicast.
    assert_rejected("ff02::1");
    assert_rejected("ff01::1");
}

#[test]
fn rejects_cidr_ipv6_unspecified_slash_128() {
    // :: (all zeros).
    assert_rejected("::");
}

// ── IPv4-mapped IPv6 literals ───────────────────────────────────────────────

#[test]
fn rejects_ipv4_mapped_cidr_127_slash_8() {
    assert_rejected("::ffff:127.0.0.1");
}

#[test]
fn rejects_ipv4_mapped_cidr_10_slash_8() {
    assert_rejected("::ffff:10.0.0.1");
}

#[test]
fn rejects_ipv4_mapped_cidr_169_254_slash_16() {
    assert_rejected("::ffff:169.254.169.254");
}

// ── Negative controls (must still be accepted) ──────────────────────────────

#[test]
fn accepts_public_ipv4_8_8_8_8() {
    assert_accepted("8.8.8.8");
}

#[test]
fn accepts_public_ipv4_1_1_1_1() {
    assert_accepted("1.1.1.1");
}

#[test]
fn accepts_public_ipv6_2606() {
    // Cloudflare public DNS — must still be accepted.
    assert_accepted("2606:4700:4700::1111");
}

#[test]
fn accepts_public_ipv4_mapped_ipv6_8_8_8_8() {
    assert_accepted("::ffff:8.8.8.8");
}

#[test]
fn accepts_public_hostname() {
    assert_accepted("example.com");
}

// ── Dangerous schemes (sanity control — unchanged by M3) ───────────────────

#[test]
fn rejects_javascript_scheme() {
    assert!(SafeUrl::try_from("javascript:alert(1)").is_err());
}

#[test]
fn rejects_file_scheme() {
    assert!(SafeUrl::try_from("file:///etc/passwd").is_err());
}

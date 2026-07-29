//! Property tests for the single-use tenant+operation capability.
//!
//! The BDD suite pins named scenarios. These pin *invariants* — statements that
//! must hold for every input, not just the ones someone thought to enumerate.

use proptest::prelude::*;
use secure_identity::capability::{
    CapabilityError, CapabilityIssuer, CapabilityRequest, CapabilityVerifier, Expected,
    InMemoryReplayStore, Operation, RsaCapabilitySigner, MAX_TTL_SECONDS,
};

/// Test-only RSA material, inlined so no out-of-scope fixture files are needed.
const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRb/iDkP6qo4FJ
v/iB1LBkq2XpOohIJB8QFAoTptmrLkic8adVb25uhG6O3Ox/2GegPEIAa+yhncvI
kwROQJFWwfV5JcmmWbUuJc+Xyebvs9MgoDfoDK32kNctdJ8jb36Y02SYxkjzbGV6
yz3NDTBKNxrry9pVexxD/aLFIN6ZCvCgoqeg5CREnFk/ORiLOa2Bome4bkd6QCzp
G/GVyjoXC+AmqHgyYpgoacceIDlhKk3fwblP5LYLZTA0J8gpHtP4DbGgzr8OiKTb
W59sohVFP/hisM+8xZwbFllHr/DM04RPbO2U+Vqu8jIjf5NaNBMnGsBVlhEzwG4d
PTt+Vdc5AgMBAAECggEAAeZlWjfeJZO7kXzrOa320TJQXP4AfJYOTZXUSb1vYgBh
coILNx5Ttu80NmR+RUJ5czB6FqP5VuCAzST59VCcOO3OxtP0eRIShOoH0MwpOwwL
X+iwL9EwoVO1o1u4h13kh5P7CJtGOrtv+BNAsDvnb/RBcLmYqsKbMlSKWIXjMGnO
/HGoA8PyAaFNeV9CKIsIKnIKZuYbOnJSe4C6T+NKwXIErO9Y+/k4npSbbHtFDPag
wQbimxlEgd5bkOJhWaX+mIe5Z7TuUSbz8mpZ8vf5jXLgmeJsrOO+otmZ2REF03iE
gQYJHXtIhe5iuoLPPsiRQXylciMEyJGWyGffxuvHsQKBgQD75MNoQMceTxEYPKVH
CWQ0JcoBYdzNPKrd+BqPBe8uDBTh/1gyyhlJBgrIBAfyKubmO7iHiuWEAZOZEjs1
m2+pjeEkETf27Mbj/6QmJ4iCuUDCHs/VQWkEbMDtkmdJVYVgkyz43v50vedv9biE
InV6Xpvrn0g8+W+lDbaQOh8BEQKBgQDU2gX7ZRUQ6BSsRplnIXsIhQnklD7uGT+5
eoW1LymoEChL4EsMl/BagSnV46HjwR8Wn9TkoVSxRWMaH4Z1gzhBWcOEtbZiMPZU
5GpLy5Ua4KMHE0QBQP+KGENJcMTeuiGH/WT67dH9nvu6GJc+eFvi8h/zt8XDU1y+
g3ucRCvzqQKBgBF1E03gX2xsUmT5nwLDVdx/Wfaqj6DxuW3UyhJreN4aHEBlb/ll
JEd5Ubn2/Y39By+hp/JM4Ac8DLypFM1sTlrT6GyVfOlyE36tsvSp/L4ClMhfVkwT
UnHqD5znbp0YfjvpN06wNbZliuqpfvY5ZSbr86ZqzZjcOK6ZurNYM9nhAoGAMIM0
o9SpFX5f39gDdK771LhFxfRH14qnrIWRXfdO3kA4fvqzAD7NCEOyHk7QghFtHYH2
Stm+bNzstnKC+dubgcGMv32PARg5vKWG2Jmg9UxHvAAXGtYOqBHZnC54oG75333Q
eySjHNQUeZjLN/DEuJgI0kqLZ3ZjiAR9suMSxWkCgYAcOH1FyFfUUy3PAL2DgClB
Q2w2G9IL6jhvLp7nokA6sksm+44OoyYYc4Oe/p58pBLENJWt7HXUs9weANmEhnn3
zPh0Fw7hC7Fd+tNSB/H15GAo2j84g4uvTu1gLgv6Hepp5CR3JRovTqLz/7flfxuz
yTQ0K6igAd7gfA/FZ1Vf8A==
-----END PRIVATE KEY-----\n";
const TEST_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W/4g5D+qqOBSb/4gdSw
ZKtl6TqISCQfEBQKE6bZqy5InPGnVW9uboRujtzsf9hnoDxCAGvsoZ3LyJMETkCR
VsH1eSXJplm1LiXPl8nm77PTIKA36Ayt9pDXLXSfI29+mNNkmMZI82xless9zQ0w
Sjca68vaVXscQ/2ixSDemQrwoKKnoOQkRJxZPzkYizmtgaJnuG5HekAs6Rvxlco6
FwvgJqh4MmKYKGnHHiA5YSpN38G5T+S2C2UwNCfIKR7T+A2xoM6/Doik21ufbKIV
RT/4YrDPvMWcGxZZR6/wzNOET2ztlPlarvIyI3+TWjQTJxrAVZYRM8BuHT07flXX
OQIDAQAB
-----END PUBLIC KEY-----\n";

const ISS: &str = "https://auth.sunlit.test";
const AUD: &str = "sunlit-broker";

fn issuer() -> CapabilityIssuer<RsaCapabilitySigner> {
    CapabilityIssuer::new(
        ISS.to_string(),
        AUD.to_string(),
        RsaCapabilitySigner::from_pkcs8_pem(TEST_PRIVATE_PEM.as_bytes()).expect("key"),
    )
}

fn verifier() -> CapabilityVerifier {
    CapabilityVerifier::from_rsa_pem(ISS.to_string(), AUD.to_string(), TEST_PUBLIC_PEM.as_bytes())
        .expect("key")
}

fn any_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Read),
        Just(Operation::Append),
        Just(Operation::Update),
        Just(Operation::Delete),
        Just(Operation::Aggregate),
    ]
}

proptest! {
    /// Anything the issuer mints within the TTL bound must verify exactly once.
    #[test]
    fn any_valid_capability_verifies_once(
        subject in "[a-z0-9-]{1,40}",
        tenant in "[a-z0-9-]{1,40}",
        body in proptest::collection::vec(any::<u8>(), 0..512),
        op in any_operation(),
        ttl in 1u64..=MAX_TTL_SECONDS,
    ) {
        let request = CapabilityRequest::new(&tenant, op, &body);
        let token = issuer().issue(&subject, &request, ttl).expect("issue");
        let expected = Expected::new(&subject, &tenant, op, &body);
        let store = InMemoryReplayStore::default();
        let v = verifier();

        prop_assert!(v.verify(&token, &expected, &store).is_ok());
        prop_assert!(matches!(
            v.verify(&token, &expected, &store),
            Err(CapabilityError::Replayed)
        ));
    }

    /// A TTL above the maximum is refused, whatever the other inputs are.
    #[test]
    fn excess_ttl_is_always_refused(
        subject in "[a-z0-9-]{1,20}",
        tenant in "[a-z0-9-]{1,20}",
        ttl in (MAX_TTL_SECONDS + 1)..=100_000u64,
    ) {
        let request = CapabilityRequest::new(&tenant, Operation::Read, b"x");
        prop_assert!(matches!(
            issuer().issue(&subject, &request, ttl),
            Err(CapabilityError::TtlTooLong)
        ));
    }

    /// Mutating ANY single byte of the token must break verification. This is
    /// the property that signature checking actually binds the whole token.
    #[test]
    fn any_single_byte_mutation_breaks_verification(
        idx in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let request = CapabilityRequest::new("acct", Operation::Read, b"body");
        let token = issuer().issue("svc", &request, 30).expect("issue");
        let expected = Expected::new("svc", "acct", Operation::Read, b"body");

        let mut bytes = token.clone().into_bytes();
        let i = idx.index(bytes.len());
        bytes[i] = bytes[i].wrapping_add(delta);

        // A mutation may produce invalid UTF-8; that is itself a rejection.
        let store = InMemoryReplayStore::default();
        let outcome = match String::from_utf8(bytes) {
            Ok(mutated) if mutated == token => return Ok(()), // no-op mutation
            Ok(mutated) => verifier().verify(&mutated, &expected, &store).is_err(),
            Err(_) => true,
        };
        prop_assert!(outcome, "a mutated token must not verify");
    }

    /// Distinct (tenant, operation, body) triples must produce distinct digests.
    /// Length framing is what makes this hold for adjacent-field shifts.
    #[test]
    fn distinct_requests_have_distinct_digests(
        t1 in "[a-z]{1,12}", b1 in proptest::collection::vec(any::<u8>(), 0..40),
        t2 in "[a-z]{1,12}", b2 in proptest::collection::vec(any::<u8>(), 0..40),
        op1 in any_operation(), op2 in any_operation(),
    ) {
        let a = CapabilityRequest::new(&t1, op1, &b1);
        let b = CapabilityRequest::new(&t2, op2, &b2);
        if (t1.as_str(), op1, b1.as_slice()) == (t2.as_str(), op2, b2.as_slice()) {
            prop_assert_eq!(a.digest(), b.digest());
        } else {
            prop_assert_ne!(a.digest(), b.digest());
        }
    }

    /// A capability REJECTED for any reason must not be consumed — otherwise an
    /// attacker could burn a victim's capability by replaying it against the
    /// wrong expectation, and the legitimate holder would then be denied.
    #[test]
    fn a_rejected_capability_is_never_spent(
        wrong_tenant in "[a-z0-9-]{1,20}",
    ) {
        prop_assume!(wrong_tenant != "acct");

        let request = CapabilityRequest::new("acct", Operation::Read, b"body");
        let token = issuer().issue("svc", &request, 30).expect("issue");
        let store = InMemoryReplayStore::default();
        let v = verifier();

        // Attacker presents the capability against a tenant it does not authorise.
        let wrong = Expected::new("svc", &wrong_tenant, Operation::Read, b"body");
        prop_assert!(v.verify(&token, &wrong, &store).is_err());

        // The legitimate holder must still be able to use it.
        let right = Expected::new("svc", "acct", Operation::Read, b"body");
        prop_assert!(
            v.verify(&token, &right, &store).is_ok(),
            "a failed verification must not burn the jti"
        );
    }

    /// Arbitrary bytes presented as a token must be rejected without panicking.
    #[test]
    fn arbitrary_input_never_panics(raw in ".{0,600}") {
        let store = InMemoryReplayStore::default();
        let expected = Expected::new("svc", "acct", Operation::Read, b"body");
        let _ = verifier().verify(&raw, &expected, &store);
    }
}

# `secure_privacy` — Developer Guide

> **OWASP MASVS-PRIVACY**: data minimization, PII discovery, pseudonymization, consent checks, and retention status.

`secure_privacy` provides small policy primitives for privacy-sensitive applications. It does not store consent records, delete data, or render UI; those responsibilities stay in your application, while this crate gives you typed decisions and consistent security events.

---

## Quick Start

```toml
[dependencies]
secure_privacy = "0.1.2"
```

```rust
use secure_privacy::{PiiClassification, PiiClassifier};

let classifier = PiiClassifier::new();
let classification = classifier.classify("Contact sherif@example.com for access.");

assert_eq!(classification, PiiClassification::Email);
```

---

## PII Classification

The built-in classifier recognizes common privacy-sensitive values and can be extended with your own regex patterns:

```rust
use secure_privacy::{PiiClassification, PiiClassifier};

let mut classifier = PiiClassifier::new();
classifier.add_custom_pattern("customer_id", r"CUST-[0-9]{6}")?;

assert_eq!(classifier.classify("+44 20 7946 0958"), PiiClassification::PhoneNumber);
assert_eq!(classifier.classify("CUST-123456"), PiiClassification::Custom("customer_id".into()));
assert_eq!(classifier.classify("ordinary text"), PiiClassification::None);
# Ok::<(), secure_privacy::PrivacyError>(())
```

Classification is intentionally conservative and deterministic. Use it to route records into review, minimization, or redaction workflows; do not treat a `None` result as proof that no personal data exists.

---

## Pseudonymization

`Pseudonymizer` creates deterministic, non-reversible HMAC-SHA256 pseudonyms. Use a deployment-specific salt from your secret manager, not a literal in production code:

```rust
use secure_privacy::Pseudonymizer;

let pseudonymizer = Pseudonymizer::new(b"release-specific-salt")?;
let a = pseudonymizer.pseudonymize("user-123");
let b = pseudonymizer.pseudonymize("user-123");

assert_eq!(a, b);
assert_ne!(a.value, "user-123");
# Ok::<(), secure_privacy::PrivacyError>(())
```

Batch processing is available when you need stable joins across an export:

```rust
use secure_privacy::Pseudonymizer;

let pseudonymizer = Pseudonymizer::new(b"analytics-export-salt")?;
let values = pseudonymizer.pseudonymize_batch(&["user-1", "user-2"]);

assert_eq!(values.len(), 2);
# Ok::<(), secure_privacy::PrivacyError>(())
```

Changing the salt intentionally breaks linkability between old and new datasets.

---

## Consent Decisions

Create one `ConsentPolicy` per purpose and deny by default until consent is granted:

```rust
use secure_privacy::{ConsentDecision, ConsentPolicy, ConsentPurpose};
use security_events::sink::InMemorySink;

let purpose = ConsentPurpose::new("analytics");
let mut policy = ConsentPolicy::new(purpose.clone());
let sink = InMemorySink::new();

assert_eq!(
    policy.check_consent(&purpose, &sink),
    ConsentDecision::NotCollected
);

policy.grant();
assert_eq!(policy.check_consent(&purpose, &sink), ConsentDecision::Allowed);

policy.withdraw();
assert_eq!(policy.check_consent(&purpose, &sink), ConsentDecision::Withdrawn);
```

Purpose mismatch is blocked and emits a `ConsentViolation` event with both the consented and requested purpose labels.

---

## Retention Status

Retention policies report whether data is still active or should be removed. They do not delete records themselves:

```rust
use secure_privacy::{RetentionPolicy, RetentionStatus};
use security_events::sink::InMemorySink;
use time::{Duration, OffsetDateTime};

let policy = RetentionPolicy::new(30, "support-transcripts");
let now = OffsetDateTime::now_utc();
let created_at = now - Duration::days(45);
let sink = InMemorySink::new();

assert_eq!(
    policy.check_status(created_at, now, &sink),
    RetentionStatus::Expired
);
assert_eq!(sink.events().len(), 1);
```

When no policy exists, make that explicit:

```rust
use secure_privacy::{check_no_policy, RetentionStatus};

assert_eq!(check_no_policy(), RetentionStatus::NoPolicy);
```

---

## Operational Pattern

| Workflow | Recommended Use |
|---|---|
| User input or import scanning | `PiiClassifier::classify()` |
| Analytics joins without direct identifiers | `Pseudonymizer::pseudonymize()` |
| Purpose-scoped processing checks | `ConsentPolicy::check_consent()` |
| Scheduled retention sweeps | `RetentionPolicy::check_status()` |

Emit privacy decisions to `security_events` and keep storage/UI responsibilities in your application. That split gives auditors a clean policy trail without forcing a database model on downstream projects.

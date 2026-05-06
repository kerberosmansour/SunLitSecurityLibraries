# `secure_resilience` — Developer Guide

> **OWASP MASVS-RESILIENCE**: runtime environment signals, app integrity results, RASP policy decisions, and verified circuit-breaker behavior.

`secure_resilience` is a pure policy engine. Mobile or service code performs platform-specific detection, then feeds normalized signals into this crate for consistent decisions, security events, and testable state transitions.

---

## Quick Start

```toml
[dependencies]
secure_resilience = "0.1.2"
```

```rust
use secure_resilience::{CircuitBreaker, CircuitBreakerPolicy};
use std::time::Duration;

let policy = CircuitBreakerPolicy::new()
    .with_failure_threshold(3)
    .with_open_duration(Duration::from_secs(10));
let breaker = CircuitBreaker::new(policy);

let value = breaker.call(|| Ok::<_, &'static str>(42)).unwrap();
assert_eq!(value, 42);
```

---

## Circuit Breaker

Wrap downstream calls so repeated failures trip the circuit and later allow exactly one half-open probe:

```rust
use secure_resilience::{CircuitBreaker, CircuitBreakerError, CircuitBreakerPolicy};
use std::time::Duration;

let breaker = CircuitBreaker::new(
    CircuitBreakerPolicy::new()
        .with_failure_threshold(2)
        .with_open_duration(Duration::from_millis(100)),
);

let _ = breaker.call::<(), _, _>(|| Err("first"));
let _ = breaker.call::<(), _, _>(|| Err("second"));

let blocked: Result<(), CircuitBreakerError<&str>> = breaker.call(|| Ok(()));
assert!(matches!(blocked, Err(CircuitBreakerError::CircuitOpen)));
```

The half-open single-probe rule is backed by TLA+ specs under [`specs/CircuitBreaker.tla`](../../specs/CircuitBreaker.tla) and the design note [`docs/slo/design/circuit-breaker-verified.md`](../slo/design/circuit-breaker-verified.md). CI runs the hardened spec as advisory evidence and keeps the naive counterexample variant visible.

---

## RASP Signal Processing

Construct `EnvironmentSignal` values from your platform detectors, then let `RaspEngine` apply a policy and emit a security event:

```rust
use secure_resilience::{
    Confidence, EnvironmentSignal, RaspDecision, RaspEngine, RaspPolicy, ResponseAction,
};
use security_events::sink::InMemorySink;

let policy = RaspPolicy {
    debugger_response: ResponseAction::Block,
    ..RaspPolicy::default()
};
let engine = RaspEngine::new(policy);
let sink = InMemorySink::new();

let signal = EnvironmentSignal::DebuggerAttached {
    confidence: Confidence::High,
    evidence: "ptrace/debugger flag set".to_string(),
};

let decision = engine.process_signal(&signal, &sink);
assert_eq!(
    decision,
    RaspDecision::Block {
        signal_category: "debugger_attached".to_string(),
    }
);
assert_eq!(sink.events().len(), 1);
```

`RaspPolicy::default()` warns on known signals and allows unknown signals. Tighten the policy per route or capability: blocking payment submission may be appropriate while allowing low-risk help screens.

---

## Environment Signals

`EnvironmentSignal` deliberately stores evidence as a caller-provided string. Keep it short, non-secret, and actionable:

```rust
use secure_resilience::{Confidence, EnvironmentSignal};

let signal = EnvironmentSignal::RootDetected {
    confidence: Confidence::Medium,
    evidence: "su binary found in expected search path".to_string(),
};

assert_eq!(signal.category(), "root_detected");
assert_eq!(signal.confidence(), Some(Confidence::Medium));
```

The crate does not inspect devices directly. That boundary keeps platform code auditable and makes server-side policy tests deterministic.

---

## App Integrity Results

Use integrity types to normalize app-signature, bundle, or checksum checks before they feed a wider risk decision:

```rust,ignore
use secure_resilience::{IntegrityCheck, IntegrityCheckResult, IntegrityResult};

let result = IntegrityCheckResult {
    check: IntegrityCheck::AppSignature,
    result: IntegrityResult::Pass,
    evidence: "release signature matched pinned key".to_string(),
};
```

Exact detector implementation belongs in the mobile client or deployment agent; this crate keeps the result vocabulary stable across those integrations.

---

## Verification Trail

Formal-verification support is intentionally visible to users:

| Asset | Purpose |
|---|---|
| [`docs/dev-guide/formal-verification.md`](formal-verification.md) | Developer workflow for Kani and TLA+ gates |
| [`specs/CircuitBreaker.tla`](../../specs/CircuitBreaker.tla) | Hardened circuit-breaker state machine |
| [`specs/SessionStepUp.tla`](../../specs/SessionStepUp.tla) | Hardened session step-up state machine |
| [`.github/workflows/tla.yml`](../../.github/workflows/tla.yml) | Advisory TLC matrix, including naive counterexample jobs |

Treat the advisory verification jobs as release evidence. A failure should block publication until it is understood, even when GitHub does not mark the check as required.

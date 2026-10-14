//! BDD scenarios for fv-readiness M4: circuit-breaker module.
//! Closes GH issue #14.

use std::thread;
use std::time::Duration;

use secure_resilience::{
    CircuitBreaker, CircuitBreakerError, CircuitBreakerPolicy, CircuitBreakerState,
};

// ── Closed-state success ─────────────────────────────────────────────────────

#[test]
fn closed_state_success_keeps_breaker_closed() {
    let breaker = CircuitBreaker::new(CircuitBreakerPolicy::new());
    let result = breaker.call(|| Ok::<u32, &'static str>(42));
    assert_eq!(result.unwrap(), 42);
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Closed);
}

// ── Failure threshold opens the breaker ──────────────────────────────────────

#[test]
fn consecutive_failures_open_breaker() {
    let policy = CircuitBreakerPolicy::new().with_failure_threshold(2);
    let breaker = CircuitBreaker::new(policy);

    let _r1: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("fail1"));
    let _r2: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("fail2"));

    // After 2 failures the breaker should be Open.
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Open);

    // Subsequent call short-circuits.
    let r3: Result<u32, _> = breaker.call(|| Ok::<u32, &'static str>(100));
    assert!(matches!(r3, Err(CircuitBreakerError::CircuitOpen)));
}

// ── Open → HalfOpen after open_duration ──────────────────────────────────────

#[test]
fn open_breaker_transitions_to_halfopen_after_duration() {
    let policy = CircuitBreakerPolicy::new()
        .with_failure_threshold(1)
        .with_open_duration(Duration::from_millis(50));
    let breaker = CircuitBreaker::new(policy);

    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("fail"));
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Open);

    // Wait past the open duration.
    thread::sleep(Duration::from_millis(80));

    // Next call triggers state ageing inside `call`. A success here
    // causes Closed transition; an exception would re-Open.
    let r: Result<u32, _> = breaker.call(|| Ok::<u32, &'static str>(7));
    assert_eq!(r.unwrap(), 7);
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Closed);
}

// ── Probe failure re-opens ──────────────────────────────────────────────────

#[test]
fn halfopen_probe_failure_returns_to_open() {
    let policy = CircuitBreakerPolicy::new()
        .with_failure_threshold(1)
        .with_open_duration(Duration::from_millis(20));
    let breaker = CircuitBreaker::new(policy);

    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("trip"));
    thread::sleep(Duration::from_millis(40));

    // Probe call also fails.
    let r: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("probe-fail"));
    assert!(matches!(r, Err(CircuitBreakerError::DownstreamFailed(_))));
    // Re-opened.
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Open);
}

// ── Single-probe rule (tm-fv-abuse-6) ───────────────────────────────────────

#[test]
fn halfopen_double_probe_returns_probe_in_flight() {
    use std::sync::Arc;
    use std::sync::Barrier;

    let policy = CircuitBreakerPolicy::new()
        .with_failure_threshold(1)
        .with_open_duration(Duration::from_millis(20));
    let breaker = Arc::new(CircuitBreaker::new(policy));

    // Trip the breaker.
    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("trip"));
    thread::sleep(Duration::from_millis(40));

    // First call enters HalfOpen and reserves the probe slot. While
    // its closure is running (we hold it via the Barrier), a concurrent
    // call must observe ProbeInFlight.
    let barrier = Arc::new(Barrier::new(2));
    let breaker_clone = Arc::clone(&breaker);
    let barrier_clone = Arc::clone(&barrier);

    let probe_handle = thread::spawn(move || {
        breaker_clone.call(|| {
            // Inside the probe — let the second thread try to enter.
            barrier_clone.wait();
            // Hold the probe a bit so the concurrent call observes
            // probe_inflight = true.
            thread::sleep(Duration::from_millis(30));
            Ok::<u32, &'static str>(0)
        })
    });

    // Wait until the probe is inside the closure.
    barrier.wait();

    // Concurrent call — must short-circuit with ProbeInFlight.
    let concurrent: Result<u32, _> = breaker.call(|| Ok::<u32, &'static str>(1));
    assert!(
        matches!(concurrent, Err(CircuitBreakerError::ProbeInFlight)),
        "expected ProbeInFlight, got: {:?}",
        concurrent.as_ref().err()
    );

    // Probe completes successfully → breaker closes.
    let probe_result = probe_handle.join().expect("probe thread");
    assert!(probe_result.is_ok());
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Closed);
}

// ── Default policy values ────────────────────────────────────────────────────

#[test]
fn default_policy_values_are_sane() {
    let _ = CircuitBreakerPolicy::default();
    // Just constructs without panicking; specific values are documented
    // in the rustdoc and can change with a deliberate runbook.
}

// ── Closed-path failures reset on success ────────────────────────────────────

#[test]
fn closed_path_failure_counter_resets_on_success() {
    let policy = CircuitBreakerPolicy::new().with_failure_threshold(3);
    let breaker = CircuitBreaker::new(policy);

    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("a"));
    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("b"));
    // 2 failures — still Closed.
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Closed);

    let _: Result<u32, _> = breaker.call(|| Ok::<u32, &'static str>(0));
    // Success resets — another failure shouldn't trip.
    let _: Result<u32, _> = breaker.call(|| Err::<u32, &'static str>("c"));
    assert_eq!(breaker.state().unwrap(), CircuitBreakerState::Closed);
}

#[test]
fn stale_closed_completion_cannot_release_half_open_probe() {
    use std::sync::{mpsc, Arc};
    let breaker = Arc::new(CircuitBreaker::new(
        CircuitBreakerPolicy::new()
            .with_failure_threshold(1)
            .with_open_duration(Duration::ZERO),
    ));
    let (started_tx, started_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let old_breaker = Arc::clone(&breaker);
    let old = thread::spawn(move || {
        old_breaker.call(|| {
            started_tx.send(()).unwrap();
            finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok::<_, &'static str>(())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(breaker.call(|| Err::<(), _>("trip")).is_err());
    let (probe_tx, probe_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let probe_breaker = Arc::clone(&breaker);
    let probe = thread::spawn(move || {
        probe_breaker.call(|| {
            probe_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok::<_, &'static str>(())
        })
    });
    probe_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    finish_tx.send(()).unwrap();
    old.join().unwrap().unwrap();
    let state = breaker.state().unwrap();
    let rejected = breaker.call(|| Ok::<_, &'static str>(()));
    release_tx.send(()).unwrap();
    probe.join().unwrap().unwrap();
    assert_eq!(state, CircuitBreakerState::HalfOpen);
    assert!(matches!(rejected, Err(CircuitBreakerError::ProbeInFlight)));
}

#[test]
fn panicking_half_open_probe_releases_its_reservation() {
    let breaker = CircuitBreaker::new(
        CircuitBreakerPolicy::new()
            .with_failure_threshold(1)
            .with_open_duration(Duration::ZERO),
    );
    let _ = breaker.call(|| Err::<(), &str>("trip"));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = breaker.call(|| -> Result<(), &str> { panic!("probe fixture panic") });
    }));
    assert!(panic.is_err());
    assert_eq!(breaker.call(|| Ok::<_, &str>(42)).unwrap(), 42);
}

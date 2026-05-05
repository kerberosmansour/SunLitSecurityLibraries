//! Circuit breaker for resilient service calls.
//!
//! Implements the closed/open/half-open state machine with the
//! single-probe rule: when the breaker is in `HalfOpen` only **one**
//! probe call may be in flight at a time; subsequent calls
//! short-circuit with [`CircuitBreakerError::ProbeInFlight`] until the
//! probe completes.
//!
//! The design was TLA+-verified before implementation (see
//! [`docs/slo/design/circuit-breaker-verified.md`](../../../docs/slo/design/circuit-breaker-verified.md)
//! and [`specs/CircuitBreaker.tla`](../../../specs/CircuitBreaker.tla)).
//! The Naive variant of the spec deliberately omits the
//! `probe_inflight` check; TLC must find the double-probe
//! counterexample before this implementation is considered sound.
//!
//! # Threading model
//!
//! The breaker is **single-process**. Internal state is guarded by a
//! `Mutex` for the lifecycle fields and an `AtomicBool` for the
//! `probe_inflight` flag (the load-bearing invariant of the half-open
//! design). Distributed circuit breakers are out of scope; that
//! requires a separate runbook.
//!
//! # Example
//!
//! ```
//! use secure_resilience::circuit_breaker::{CircuitBreaker, CircuitBreakerError, CircuitBreakerPolicy};
//! use std::time::Duration;
//!
//! let policy = CircuitBreakerPolicy::new()
//!     .with_failure_threshold(3)
//!     .with_open_duration(Duration::from_millis(100));
//! let breaker = CircuitBreaker::new(policy);
//!
//! // Wraps any FnOnce returning Result<T, E>.
//! let result: Result<u32, CircuitBreakerError<&'static str>> =
//!     breaker.call(|| Ok::<_, &'static str>(42));
//! assert_eq!(result.unwrap(), 42);
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::ResilienceError;

/// Lifecycle state of the circuit breaker.
///
/// State transitions are TLA+-verified in
/// [`specs/CircuitBreaker.tla`](../../../specs/CircuitBreaker.tla).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Normal operation — calls pass through; failures count toward the
    /// threshold.
    Closed,
    /// The threshold was crossed — calls short-circuit with
    /// [`CircuitBreakerError::CircuitOpen`] until `open_duration`
    /// elapses.
    Open,
    /// The open-duration has elapsed and the breaker is willing to try
    /// **one** probe call. The single-probe rule is enforced via
    /// `probe_inflight` — concurrent calls during the probe receive
    /// [`CircuitBreakerError::ProbeInFlight`].
    HalfOpen,
}

/// Configuration for a [`CircuitBreaker`].
#[derive(Debug, Clone)]
pub struct CircuitBreakerPolicy {
    failure_threshold: u32,
    open_duration: Duration,
}

impl CircuitBreakerPolicy {
    /// Default policy: failure threshold = 5, open duration = 30s.
    #[must_use]
    pub fn new() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
        }
    }

    /// Number of consecutive failures that trip the breaker.
    #[must_use]
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Duration the breaker stays in `Open` before transitioning to
    /// `HalfOpen` and accepting a single probe.
    #[must_use]
    pub fn with_open_duration(mut self, duration: Duration) -> Self {
        self.open_duration = duration;
        self
    }
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Error produced by [`CircuitBreaker::call`].
///
/// `E` is the error type produced by the wrapped closure when it fails
/// for a downstream reason (network error, parse error, etc.).
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// The breaker is `Open`; the call short-circuited without
    /// invoking the closure.
    CircuitOpen,
    /// The breaker is `HalfOpen` and a probe is already in flight; the
    /// call short-circuited per the single-probe rule.
    ProbeInFlight,
    /// The wrapped closure returned an error. The breaker counted
    /// this toward the failure threshold.
    DownstreamFailed(E),
    /// An internal lock could not be acquired (poisoned mutex).
    Internal(ResilienceError),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CircuitOpen => f.write_str("circuit breaker is open"),
            Self::ProbeInFlight => {
                f.write_str("circuit breaker is half-open and a probe is in flight")
            }
            Self::DownstreamFailed(e) => write!(f, "downstream call failed: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for CircuitBreakerError<E> {}

#[derive(Debug)]
struct Internal {
    state: CircuitBreakerState,
    failure_count: u32,
    opened_at: Option<Instant>,
}

/// Single-process circuit breaker.
///
/// Wrap downstream calls with [`Self::call`] to gain failure isolation:
/// after the configured threshold of consecutive failures, the breaker
/// short-circuits subsequent calls until the open-duration elapses.
/// Then a single probe is permitted; on probe success the breaker
/// closes, on probe failure it re-opens.
#[derive(Debug)]
pub struct CircuitBreaker {
    policy: CircuitBreakerPolicy,
    inner: Mutex<Internal>,
    /// Load-bearing invariant for the half-open design. The TLA+
    /// `NoDoubleProbe` property is the property this flag enforces.
    probe_inflight: AtomicBool,
}

impl CircuitBreaker {
    /// Create a new breaker with the given policy.
    #[must_use]
    pub fn new(policy: CircuitBreakerPolicy) -> Self {
        Self {
            policy,
            inner: Mutex::new(Internal {
                state: CircuitBreakerState::Closed,
                failure_count: 0,
                opened_at: None,
            }),
            probe_inflight: AtomicBool::new(false),
        }
    }

    /// Returns the current state. (Used by tests; production callers
    /// don't typically introspect the state directly.)
    pub fn state(&self) -> Result<CircuitBreakerState, ResilienceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| ResilienceError::Internal("circuit-breaker mutex poisoned".into()))?;
        Ok(guard.state)
    }

    /// Wrap a downstream call with the circuit breaker.
    ///
    /// - In `Closed` state, the closure runs and successes/failures
    ///   accumulate toward the threshold.
    /// - In `Open` state, the closure does not run; the call returns
    ///   [`CircuitBreakerError::CircuitOpen`].
    /// - In `HalfOpen` state, **one** probe call is permitted; further
    ///   concurrent calls return [`CircuitBreakerError::ProbeInFlight`].
    ///   On probe success the breaker transitions to `Closed`; on
    ///   probe failure it returns to `Open`.
    ///
    /// # Errors
    ///
    /// - [`CircuitBreakerError::CircuitOpen`] when `Open`.
    /// - [`CircuitBreakerError::ProbeInFlight`] when `HalfOpen` and the
    ///   single probe is already running.
    /// - [`CircuitBreakerError::DownstreamFailed`] when the closure
    ///   itself fails.
    /// - [`CircuitBreakerError::Internal`] on internal lock poisoning.
    pub fn call<T, E, F>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Phase 1: pre-call state check + probe reservation.
        let allow_probe = {
            let mut guard = self.inner.lock().map_err(|_| {
                CircuitBreakerError::Internal(ResilienceError::Internal(
                    "circuit-breaker mutex poisoned".into(),
                ))
            })?;

            // First, age the open-state into half-open if the timer has elapsed.
            if guard.state == CircuitBreakerState::Open {
                if let Some(opened_at) = guard.opened_at {
                    if opened_at.elapsed() >= self.policy.open_duration {
                        guard.state = CircuitBreakerState::HalfOpen;
                    }
                }
            }

            match guard.state {
                CircuitBreakerState::Closed => false,
                CircuitBreakerState::Open => return Err(CircuitBreakerError::CircuitOpen),
                CircuitBreakerState::HalfOpen => true,
            }
        };

        // Phase 2: single-probe reservation (only relevant in HalfOpen).
        if allow_probe {
            // Reserve the probe slot atomically. If another caller has
            // already reserved it, return ProbeInFlight without
            // touching the closure.
            if self
                .probe_inflight
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err(CircuitBreakerError::ProbeInFlight);
            }
        }

        // Phase 3: invoke the closure.
        let outcome = f();

        // Phase 4: post-call state transition.
        let mut guard = self.inner.lock().map_err(|_| {
            // Release the probe reservation even on poison so a future
            // breaker (after recovery) is in a known state.
            self.probe_inflight.store(false, Ordering::SeqCst);
            CircuitBreakerError::Internal(ResilienceError::Internal(
                "circuit-breaker mutex poisoned".into(),
            ))
        })?;

        match (&outcome, guard.state) {
            // Probe success in HalfOpen → transition to Closed.
            (Ok(_), CircuitBreakerState::HalfOpen) => {
                guard.state = CircuitBreakerState::Closed;
                guard.failure_count = 0;
                guard.opened_at = None;
                self.probe_inflight.store(false, Ordering::SeqCst);
            }
            // Probe failure in HalfOpen → re-open.
            (Err(_), CircuitBreakerState::HalfOpen) => {
                guard.state = CircuitBreakerState::Open;
                guard.opened_at = Some(Instant::now());
                self.probe_inflight.store(false, Ordering::SeqCst);
            }
            // Closed-path success → reset failure counter.
            (Ok(_), CircuitBreakerState::Closed) => {
                guard.failure_count = 0;
            }
            // Closed-path failure → bump counter; trip if threshold met.
            (Err(_), CircuitBreakerState::Closed) => {
                guard.failure_count += 1;
                if guard.failure_count >= self.policy.failure_threshold {
                    guard.state = CircuitBreakerState::Open;
                    guard.opened_at = Some(Instant::now());
                }
            }
            // Should not happen — Phase 1 short-circuits on Open.
            (_, CircuitBreakerState::Open) => {}
        }
        // Drop guard before potentially returning the error variant.
        drop(guard);

        outcome.map_err(CircuitBreakerError::DownstreamFailed)
    }
}

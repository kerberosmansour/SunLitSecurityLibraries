//! Fail-closed global filtering for dependency tracing targets.

use std::fmt;
use std::sync::Arc;

use tracing::subscriber::Interest;
use tracing::{Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Configuration errors returned by [`HardDenyTargetsLayer::try_new`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HardDenyTargetsError {
    /// No targets were supplied, so the layer would not enforce a boundary.
    NoTargets,
    /// A target was empty, contained whitespace, or began or ended with `::`.
    InvalidTarget {
        /// Zero-based position of the invalid target in the constructor input.
        index: usize,
    },
}

impl fmt::Display for HardDenyTargetsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTargets => formatter.write_str("at least one hard-deny target is required"),
            Self::InvalidTarget { index } => {
                write!(formatter, "hard-deny target at index {index} is invalid")
            }
        }
    }
}

impl std::error::Error for HardDenyTargetsError {}

/// A global `tracing-subscriber` layer that unconditionally drops configured targets.
///
/// Matching is vendor-agnostic and module-boundary aware. A configured target such as
/// `dependency` denies both `dependency` and descendants such as `dependency::client`, but does
/// not deny near prefixes such as `dependency_extra`. The decision is enforced from both
/// [`Layer::register_callsite`] and [`Layer::enabled`], so a permissive [`EnvFilter`] elsewhere in
/// the subscriber stack cannot re-enable a denied callsite.
///
/// This is a whole-stack boundary: matching spans and events are rejected before formatting,
/// storage, or OpenTelemetry export layers see their fields or messages. Emit replacement
/// operational telemetry from an application-owned target using a reviewed, typed schema.
///
/// # Example
///
/// ```
/// use security_events::HardDenyTargetsLayer;
/// use tracing_subscriber::layer::SubscriberExt;
///
/// let dependency_boundary =
///     HardDenyTargetsLayer::try_new(["dependency", "dependency_core"])?;
/// let subscriber = tracing_subscriber::registry()
///     .with(tracing_subscriber::EnvFilter::new("trace"))
///     .with(dependency_boundary)
///     .with(tracing_subscriber::fmt::layer());
///
/// # let _ = subscriber;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`EnvFilter`]: tracing_subscriber::EnvFilter
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardDenyTargetsLayer {
    targets: Arc<[Box<str>]>,
}

impl HardDenyTargetsLayer {
    /// Builds a hard-deny layer from exact tracing target roots.
    ///
    /// Duplicate targets are removed. The constructor rejects an empty list and malformed target
    /// roots rather than silently installing a boundary that cannot match the intended dependency.
    pub fn try_new<I, T>(targets: I) -> Result<Self, HardDenyTargetsError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut validated = Vec::<Box<str>>::new();

        for (index, candidate) in targets.into_iter().enumerate() {
            let candidate = candidate.as_ref();
            if !is_valid_target_root(candidate) {
                return Err(HardDenyTargetsError::InvalidTarget { index });
            }
            validated.push(candidate.into());
        }

        if validated.is_empty() {
            return Err(HardDenyTargetsError::NoTargets);
        }

        validated.sort_unstable();
        validated.dedup();

        Ok(Self {
            targets: Arc::from(validated.into_boxed_slice()),
        })
    }

    /// Returns `true` when `target` is an exact configured target or its `::` descendant.
    #[must_use]
    pub fn denies(&self, target: &str) -> bool {
        self.targets.iter().any(|denied| {
            target == denied.as_ref()
                || target
                    .strip_prefix(denied.as_ref())
                    .is_some_and(|suffix| suffix.starts_with("::"))
        })
    }
}

impl<S> Layer<S> for HardDenyTargetsLayer
where
    S: Subscriber,
{
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.denies(metadata.target()) {
            Interest::never()
        } else {
            Interest::always()
        }
    }

    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        !self.denies(metadata.target())
    }
}

fn is_valid_target_root(target: &str) -> bool {
    !target.is_empty()
        && !target.starts_with("::")
        && !target.ends_with("::")
        && !target.chars().any(char::is_whitespace)
}

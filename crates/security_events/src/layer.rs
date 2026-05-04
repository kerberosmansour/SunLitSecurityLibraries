//! `tracing-subscriber` layer for security event processing.

/// A `tracing_subscriber` layer that intercepts events containing a `security_event` field.
///
/// This layer is a no-op unless an event carries a field named `"security_event"`.
#[derive(Clone, Debug, Default)]
pub struct SecurityLayer<S> {
    _phantom: std::marker::PhantomData<fn(S)>,
}

impl<S> SecurityLayer<S> {
    /// Creates a new [`SecurityLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for SecurityLayer<S>
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = SecurityFieldVisitor::default();
        event.record(&mut visitor);
        // If a "security_event" field was found, it has been recorded.
    }
}

#[derive(Default)]
struct SecurityFieldVisitor {
    found: bool,
}

impl tracing::field::Visit for SecurityFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, _value: &str) {
        if field.name() == "security_event" {
            self.found = true;
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        if field.name() == "security_event" {
            self.found = true;
        }
    }
}

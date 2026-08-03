use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use security_events::{HardDenyTargetsError, HardDenyTargetsLayer};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{EnvFilter, Layer, Registry};

const PROMPT_CANARY: &str = "PROMPT_CANARY_7f135f0c_do_not_export";
const ARGUMENT_CANARY: &str = "ARGUMENT_CANARY_8d35f6b1_do_not_export";
const RESULT_CANARY: &str = "RESULT_CANARY_bec6d4aa_do_not_export";

static DENIED_CALLSITE: tracing::callsite::DefaultCallsite =
    tracing::callsite::DefaultCallsite::new(&DENIED_METADATA);
static DENIED_METADATA: Metadata<'static> = tracing::metadata! {
    name: "denied_metadata_probe",
    target: "rig::completion",
    level: tracing::Level::TRACE,
    fields: tracing::fieldset!("message"),
    callsite: &DENIED_CALLSITE,
    kind: tracing::metadata::Kind::EVENT,
};

static ALLOWED_CALLSITE: tracing::callsite::DefaultCallsite =
    tracing::callsite::DefaultCallsite::new(&ALLOWED_METADATA);
static ALLOWED_METADATA: Metadata<'static> = tracing::metadata! {
    name: "allowed_metadata_probe",
    target: "rigged::completion",
    level: tracing::Level::TRACE,
    fields: tracing::fieldset!("message"),
    callsite: &ALLOWED_CALLSITE,
    kind: tracing::metadata::Kind::EVENT,
};

#[derive(Clone, Default)]
struct CaptureLayer {
    lines: Arc<Mutex<Vec<String>>>,
}

impl CaptureLayer {
    fn output(&self) -> String {
        self.lines
            .lock()
            .expect("capture mutex must not be poisoned")
            .join("\n")
    }

    fn push(&self, line: String) {
        self.lines
            .lock()
            .expect("capture mutex must not be poisoned")
            .push(line);
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        let mut line = format!("span target={} name={}", metadata.target(), metadata.name());
        attrs.record(&mut FieldCapture(&mut line));
        self.push(line);
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut line = format!(
            "event target={} name={}",
            metadata.target(),
            metadata.name()
        );
        event.record(&mut FieldCapture(&mut line));
        self.push(line);
    }
}

struct FieldCapture<'a>(&'a mut String);

impl Visit for FieldCapture<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = write!(self.0, " {}={value}", field.name());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

#[test]
fn exact_and_module_descendant_targets_are_denied_without_prefix_overreach() {
    let layer = HardDenyTargetsLayer::try_new(["rig", "rig_core"])
        .expect("static target configuration must be valid");

    assert!(layer.denies("rig"));
    assert!(layer.denies("rig::completion"));
    assert!(layer.denies("rig_core::agent::tool"));
    assert!(!layer.denies("rigged"));
    assert!(!layer.denies("rig_core_extra"));
    assert!(!layer.denies("application::rig"));
}

#[test]
fn empty_or_malformed_configuration_is_rejected() {
    assert_eq!(
        HardDenyTargetsLayer::try_new(std::iter::empty::<&str>()),
        Err(HardDenyTargetsError::NoTargets)
    );
    assert_eq!(
        HardDenyTargetsLayer::try_new(["rig", ""]),
        Err(HardDenyTargetsError::InvalidTarget { index: 1 })
    );
    assert_eq!(
        HardDenyTargetsLayer::try_new(["rig::"]),
        Err(HardDenyTargetsError::InvalidTarget { index: 0 })
    );
}

#[test]
fn register_callsite_and_enabled_both_fail_closed_against_trace_env_filter() {
    let subscriber = Registry::default()
        .with(EnvFilter::new("trace"))
        .with(HardDenyTargetsLayer::try_new(["rig"]).expect("valid target"));

    let denied_interest = subscriber.register_callsite(&DENIED_METADATA);
    assert!(denied_interest.is_never());
    assert!(!subscriber.enabled(&DENIED_METADATA));

    let allowed_interest = subscriber.register_callsite(&ALLOWED_METADATA);
    assert!(!allowed_interest.is_never());
    assert!(subscriber.enabled(&ALLOWED_METADATA));
}

#[test]
fn subscriber_capture_proves_vendor_content_is_absent_and_safe_events_survive() {
    let unsafe_capture = CaptureLayer::default();
    let unsafe_subscriber = Registry::default()
        .with(EnvFilter::new("trace"))
        .with(unsafe_capture.clone());
    tracing::subscriber::with_default(unsafe_subscriber, emit_positive_control);
    let unsafe_output = unsafe_capture.output();

    assert!(unsafe_output.contains(PROMPT_CANARY));
    assert!(unsafe_output.contains(ARGUMENT_CANARY));
    assert!(unsafe_output.contains(RESULT_CANARY));

    let safe_capture = CaptureLayer::default();
    let safe_subscriber = Registry::default()
        .with(EnvFilter::new("trace,rig=trace,rig_core=trace"))
        .with(
            HardDenyTargetsLayer::try_new(["rig", "rig_core"])
                .expect("static target configuration must be valid"),
        )
        .with(safe_capture.clone());
    tracing::subscriber::with_default(safe_subscriber, emit_gated_telemetry);
    let safe_output = safe_capture.output();

    for forbidden in [
        PROMPT_CANARY,
        "PROMPT_CANARY_7f135f0c",
        ARGUMENT_CANARY,
        "ARGUMENT_CANARY_8d35f6b1",
        RESULT_CANARY,
        "RESULT_CANARY_bec6d4aa",
        "human completion response",
        "raw tool invocation",
    ] {
        assert!(
            !safe_output.contains(forbidden),
            "captured denied telemetry contained {forbidden:?}: {safe_output}"
        );
    }

    assert!(!safe_output.contains("target=rig "));
    assert!(!safe_output.contains("target=rig::"));
    assert!(!safe_output.contains("target=rig_core::"));
    assert!(safe_output.contains("target=rigged::adapter"));
    assert!(safe_output.contains("near_prefix=retained"));
    assert!(safe_output.contains("target=guardian::agent"));
    assert!(safe_output.contains("tool_name=shell"));
    assert!(safe_output.contains("outcome=success"));
    assert!(safe_output.contains("arguments_bytes=41"));
    assert!(safe_output.contains("safe tool metadata"));
}

fn emit_positive_control() {
    let span = tracing::info_span!(
        target: "rig",
        "positive_control_span",
        system_prompt = PROMPT_CANARY
    );
    let _entered = span.enter();
    tracing::info!(
        target: "rig",
        arguments = ARGUMENT_CANARY,
        "raw tool invocation"
    );
    tracing::info!(
        target: "rig::completion",
        result = RESULT_CANARY,
        "human completion response"
    );
}

fn emit_gated_telemetry() {
    let span = tracing::info_span!(
        target: "rig",
        "gated_vendor_span",
        system_prompt = PROMPT_CANARY
    );
    let _entered = span.enter();
    tracing::info!(
        target: "rig",
        arguments = ARGUMENT_CANARY,
        "raw tool invocation"
    );
    tracing::info!(
        target: "rig::completion",
        result = RESULT_CANARY,
        "human completion response"
    );
    tracing::debug!(
        target: "rig_core::agent::tool",
        result = RESULT_CANARY,
        "descendant vendor event"
    );
    drop(_entered);

    tracing::info!(
        target: "rigged::adapter",
        near_prefix = "retained",
        "near-prefix target remains visible"
    );
    tracing::info!(
        target: "guardian::agent",
        tool_name = "shell",
        outcome = "success",
        arguments_bytes = 41_u64,
        "safe tool metadata"
    );
}

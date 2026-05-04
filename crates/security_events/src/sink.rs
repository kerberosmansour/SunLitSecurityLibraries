//! Security event sink adapters.

use crate::event::SecurityEvent;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use time::OffsetDateTime;

mod private {
    /// Sealing marker.
    pub trait Sealed {}
}

/// Errors returned by fallible security sinks.
#[derive(Debug)]
#[non_exhaustive]
pub enum SinkError {
    /// The sink configuration was invalid.
    InvalidConfig(&'static str),
    /// The event could not be serialized.
    Serialization(serde_json::Error),
    /// An I/O operation failed.
    Io(std::io::Error),
    /// The HTTP webhook sink request failed.
    #[cfg(feature = "http-sink")]
    Http(reqwest::Error),
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid sink configuration: {message}"),
            Self::Serialization(error) => write!(f, "failed to serialize security event: {error}"),
            Self::Io(error) => write!(f, "sink I/O error: {error}"),
            #[cfg(feature = "http-sink")]
            Self::Http(error) => write!(f, "HTTP sink request failed: {error}"),
        }
    }
}

impl std::error::Error for SinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(_) => None,
            Self::Serialization(error) => Some(error),
            Self::Io(error) => Some(error),
            #[cfg(feature = "http-sink")]
            Self::Http(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for SinkError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

impl From<std::io::Error> for SinkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(feature = "http-sink")]
impl From<reqwest::Error> for SinkError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

/// A sealed trait for security event sinks.
pub trait SecuritySink: private::Sealed + Send + Sync {
    /// Writes a security event to the sink.
    fn write_event(&self, event: &SecurityEvent);

    /// Attempts to write a security event to the sink and returns the underlying error.
    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        self.write_event(event);
        Ok(())
    }
}

/// A sink that writes JSON-serialized events to stdout, one per line.
pub struct StdoutJsonSink;

impl private::Sealed for StdoutJsonSink {}

impl SecuritySink for StdoutJsonSink {
    fn write_event(&self, event: &SecurityEvent) {
        if let Err(error) = self.try_write_event(event) {
            tracing::warn!("StdoutJsonSink: {error}");
        }
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        let json = serde_json::to_string(event)?;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{json}")?;
        Ok(())
    }
}

/// A sink that emits events via `tracing::info!`.
pub struct TracingSink;

impl private::Sealed for TracingSink {}

impl SecuritySink for TracingSink {
    fn write_event(&self, event: &SecurityEvent) {
        if let Err(error) = self.try_write_event(event) {
            tracing::warn!("TracingSink: {error}");
        }
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        let json = serde_json::to_string(event)?;
        tracing::info!(security_event = %json, "security_event");
        Ok(())
    }
}

/// A sink that stores emitted events in memory for tests and local inspection.
#[derive(Clone, Debug, Default)]
pub struct InMemorySink {
    events: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl InMemorySink {
    /// Creates a new empty in-memory sink.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_events::sink::InMemorySink;
    ///
    /// let sink = InMemorySink::new();
    /// assert!(sink.events().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot of the events stored so far.
    #[must_use]
    pub fn events(&self) -> Vec<SecurityEvent> {
        self.events
            .lock()
            .expect("in-memory sink mutex poisoned")
            .clone()
    }
}

impl private::Sealed for InMemorySink {}

impl SecuritySink for InMemorySink {
    fn write_event(&self, event: &SecurityEvent) {
        let _ = self.try_write_event(event);
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        self.events
            .lock()
            .expect("in-memory sink mutex poisoned")
            .push(event.clone());
        Ok(())
    }
}

/// A sink that appends JSON-serialized events to a file, one event per line.
#[derive(Clone, Debug)]
pub struct FileSink {
    path: PathBuf,
    max_bytes: u64,
}

impl FileSink {
    const DEFAULT_MAX_BYTES: u64 = 1_048_576;

    /// Creates a new [`FileSink`] with a secure default rotation threshold.
    ///
    /// Missing parent directories are created automatically.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if the parent directory cannot be created.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_events::sink::FileSink;
    ///
    /// let path = std::env::temp_dir().join("security-events-doc-example.jsonl");
    /// let sink = FileSink::new(&path)?;
    /// let _ = std::fs::remove_file(&path);
    /// # Ok::<(), security_events::sink::SinkError>(())
    /// ```
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SinkError> {
        Self::with_rotation(path, Self::DEFAULT_MAX_BYTES)
    }

    /// Creates a new [`FileSink`] with an explicit rotation threshold in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::InvalidConfig`] if `max_bytes` is zero.
    /// Returns [`SinkError::Io`] if the parent directory cannot be created.
    pub fn with_rotation(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self, SinkError> {
        if max_bytes == 0 {
            return Err(SinkError::InvalidConfig(
                "max_bytes must be greater than zero",
            ));
        }

        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self { path, max_bytes })
    }

    /// Returns the active log file path used by this sink.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate_if_needed(&self, incoming_bytes: u64) -> Result<(), SinkError> {
        let current_len = fs::metadata(&self.path).map(|meta| meta.len()).unwrap_or(0);
        if current_len == 0 || current_len.saturating_add(incoming_bytes) <= self.max_bytes {
            return Ok(());
        }

        let rotated_path = self.rotated_path();
        fs::rename(&self.path, rotated_path)?;
        Ok(())
    }

    fn rotated_path(&self) -> PathBuf {
        let suffix = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let stem = self
            .path
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("security-events");
        let extension = self.path.extension().and_then(std::ffi::OsStr::to_str);
        let file_name = match extension {
            Some(extension) => format!("{stem}-{suffix}.{extension}"),
            None => format!("{stem}-{suffix}"),
        };
        self.path.with_file_name(file_name)
    }
}

impl private::Sealed for FileSink {}

impl SecuritySink for FileSink {
    fn write_event(&self, event: &SecurityEvent) {
        if let Err(error) = self.try_write_event(event) {
            tracing::warn!(path = %self.path.display(), "FileSink: {error}");
        }
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string(event)?;
        self.rotate_if_needed((json.len() + 1) as u64)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

/// A buffered sink that flushes events to an inner sink in the background.
pub struct BatchingSink<S>
where
    S: SecuritySink + 'static,
{
    inner: Arc<S>,
    buffer: Arc<Mutex<Vec<SecurityEvent>>>,
    max_batch_size: usize,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl<S> std::fmt::Debug for BatchingSink<S>
where
    S: SecuritySink + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchingSink")
            .field("max_batch_size", &self.max_batch_size)
            .finish_non_exhaustive()
    }
}

impl<S> BatchingSink<S>
where
    S: SecuritySink + 'static,
{
    /// Creates a new batching sink around `inner`.
    ///
    /// Events are buffered in memory and flushed when the batch reaches `max_batch_size`
    /// or when the background interval elapses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_events::sink::{BatchingSink, InMemorySink};
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// let sink = Arc::new(InMemorySink::new());
    /// let batcher = BatchingSink::new(sink, 10, Duration::from_millis(50));
    /// batcher.flush()?;
    /// # Ok::<(), security_events::sink::SinkError>(())
    /// ```
    #[must_use]
    pub fn new(inner: Arc<S>, max_batch_size: usize, flush_interval: Duration) -> Self {
        let max_batch_size = max_batch_size.max(1);
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let worker = {
            let inner = Arc::clone(&inner);
            let buffer = Arc::clone(&buffer);
            let stop = Arc::clone(&stop);
            thread::Builder::new()
                .name("security-events-batcher".to_string())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        thread::sleep(flush_interval);
                        if let Err(error) = flush_buffer(&inner, &buffer) {
                            tracing::warn!("BatchingSink background flush failed: {error}");
                        }
                    }
                    if let Err(error) = flush_buffer(&inner, &buffer) {
                        tracing::warn!("BatchingSink final flush failed: {error}");
                    }
                })
                .ok()
        };

        Self {
            inner,
            buffer,
            max_batch_size,
            stop,
            worker: Mutex::new(worker),
        }
    }

    /// Forces the current buffered events to be flushed immediately.
    ///
    /// # Errors
    ///
    /// Returns the first error raised by the inner sink while flushing the batch.
    pub fn flush(&self) -> Result<(), SinkError> {
        flush_buffer(&self.inner, &self.buffer)
    }
}

impl<S> Drop for BatchingSink<S>
where
    S: SecuritySink + 'static,
{
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = flush_buffer(&self.inner, &self.buffer);
        if let Some(handle) = self
            .worker
            .lock()
            .expect("batch worker mutex poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl<S> private::Sealed for BatchingSink<S> where S: SecuritySink + 'static {}

impl<S> SecuritySink for BatchingSink<S>
where
    S: SecuritySink + 'static,
{
    fn write_event(&self, event: &SecurityEvent) {
        if let Err(error) = self.try_write_event(event) {
            tracing::warn!("BatchingSink: {error}");
        }
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        let should_flush = {
            let mut buffer = self.buffer.lock().expect("batch buffer mutex poisoned");
            buffer.push(event.clone());
            buffer.len() >= self.max_batch_size
        };

        if should_flush {
            self.flush()?;
        }

        Ok(())
    }
}

fn flush_buffer<S>(inner: &Arc<S>, buffer: &Mutex<Vec<SecurityEvent>>) -> Result<(), SinkError>
where
    S: SecuritySink + 'static,
{
    let events = {
        let mut guard = buffer.lock().expect("batch buffer mutex poisoned");
        if guard.is_empty() {
            return Ok(());
        }
        guard.drain(..).collect::<Vec<_>>()
    };

    for event in events {
        inner.try_write_event(&event)?;
    }

    Ok(())
}

/// A sink that delivers events to an HTTP webhook endpoint.
#[cfg(feature = "http-sink")]
#[derive(Clone, Debug)]
pub struct HttpWebhookSink {
    url: reqwest::Url,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "http-sink")]
impl HttpWebhookSink {
    /// Creates a new HTTP webhook sink.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::InvalidConfig`] if the URL is not a valid HTTP(S) URL.
    /// Returns [`SinkError::Http`] if the client cannot be constructed.
    pub fn new(url: &str) -> Result<Self, SinkError> {
        let url = reqwest::Url::parse(url)
            .map_err(|_| SinkError::InvalidConfig("webhook URL must be a valid HTTP(S) URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(SinkError::InvalidConfig(
                "webhook URL must use http or https",
            ));
        }

        let client = reqwest::blocking::Client::builder().build()?;
        Ok(Self { url, client })
    }
}

#[cfg(feature = "http-sink")]
impl private::Sealed for HttpWebhookSink {}

#[cfg(feature = "http-sink")]
impl SecuritySink for HttpWebhookSink {
    fn write_event(&self, event: &SecurityEvent) {
        if let Err(error) = self.try_write_event(event) {
            tracing::warn!(url = %self.url, "HttpWebhookSink: {error}");
        }
    }

    fn try_write_event(&self, event: &SecurityEvent) -> Result<(), SinkError> {
        self.client
            .post(self.url.clone())
            .json(event)
            .send()?
            .error_for_status()?;
        Ok(())
    }
}

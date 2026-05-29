//! Progress reporting API for pull and download operations.
//!
//! Library crates emit [`ProgressEvent`]s through a [`ProgressReporter`] trait
//! object.  The default implementation, [`NullReporter`], discards all events
//! at zero cost.  Callers such as `cfsctl` supply their own implementation
//! (e.g. an `indicatif`-backed renderer) via [`PullOptions::progress`].

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// Identity of a component being tracked, typically an OCI layer diff_id or
/// an HTTP object path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComponentId(String);

impl ComponentId {
    /// Return the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the id and return the owned underlying string.
    ///
    /// Useful when converting an owned [`ProgressEvent`] into another
    /// representation without re-allocating the identifier.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<S: Into<String>> From<S> for ComponentId {
    fn from(s: S) -> Self {
        ComponentId(s.into())
    }
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The unit of measurement for a progress component.
///
/// Progress events may track either raw bytes (for layer downloads) or an
/// abstract item count (for object fetches where individual sizes are unknown).
/// Renderers should adapt their display accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressUnit {
    /// The `fetched`/`total` fields count bytes.
    Bytes,
    /// The `fetched`/`total` fields count discrete items (e.g. objects).
    Items,
}

/// Events emitted during a pull or download operation.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ProgressEvent {
    /// A new component (layer/object) has started being fetched.
    Started {
        /// Identifier for this component.
        id: ComponentId,
        /// Total amount to transfer (bytes or items depending on `unit`), if known.
        total: Option<u64>,
        /// Unit of measurement for `total` and subsequent `Progress` events.
        unit: ProgressUnit,
    },
    /// Progress update for a component.
    Progress {
        /// Identifier for this component.
        id: ComponentId,
        /// Amount transferred so far (bytes or items depending on the `Started` unit).
        fetched: u64,
        /// Total amount (bytes or items), if known.
        total: Option<u64>,
    },
    /// A component was skipped because it was already present.
    ///
    /// This event may be emitted without a preceding [`ProgressEvent::Started`]
    /// when the component is determined to be cached before any download begins.
    /// Renderers must handle this case gracefully.
    Skipped {
        /// Identifier for the skipped component.
        id: ComponentId,
    },
    /// A component completed successfully.
    Done {
        /// Identifier for this component.
        id: ComponentId,
        /// Amount actually transferred (bytes or items per the `Started` unit).
        transferred: u64,
    },
    /// A human-readable status message (replaces progress-bar text lines).
    Message(String),
}

/// Receives progress events from a pull or download operation.
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// tasks.  All methods take `&self` so that the reporter can be held behind an
/// `Arc` without requiring interior mutability beyond what the implementation
/// itself manages (typically a `Mutex`).
pub trait ProgressReporter: Send + Sync {
    /// Handle a single progress event.
    fn report(&self, event: ProgressEvent);
}

/// A no-op reporter that discards all events.
///
/// This is the default when no reporter is provided.  Because it has no
/// branches or allocations it compiles away entirely in release builds.
#[derive(Debug, Default)]
pub struct NullReporter;

impl ProgressReporter for NullReporter {
    #[inline]
    fn report(&self, _event: ProgressEvent) {}
}

/// Convenience type alias for a shared, type-erased progress reporter.
pub type SharedReporter = Arc<dyn ProgressReporter>;

/// An [`AsyncRead`] wrapper that tracks bytes read via a `watch` channel.
///
/// The reader itself is intentionally minimal: it only increments a counter and
/// publishes it through a non-blocking [`tokio::sync::watch`] channel on each
/// successful read.  This keeps the hot I/O path free from any reporter logic.
///
/// Backpressure is handled by the watch channel itself: if the progress
/// renderer is slow, intermediate byte counts are coalesced — the sender
/// never blocks waiting for the receiver to catch up.
///
/// Use [`ProgressRead::new`] to construct the reader and its companion driver
/// future.  The driver must run concurrently with the read (e.g. via
/// `tokio::join!`) to actually emit [`ProgressEvent::Progress`] events.
///
/// Place this wrapper *before* any decompressor so that the `fetched` counter
/// reflects compressed bytes-over-the-wire, matching the `total` from the
/// preceding [`ProgressEvent::Started`] event.
pub struct ProgressRead<R> {
    inner: R,
    /// Non-blocking sender; updating it on every read is fine.
    tx: tokio::sync::watch::Sender<u64>,
}

impl<R: std::fmt::Debug> std::fmt::Debug for ProgressRead<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressRead")
            .field("inner", &self.inner)
            .field("bytes_read", &*self.tx.borrow())
            .finish_non_exhaustive()
    }
}

impl<R> ProgressRead<R> {
    /// Wrap `inner` and return `(reader, driver)`.
    ///
    /// The driver is a future that translates raw byte counts into
    /// [`ProgressEvent::Progress`] events via `reporter`.  It completes when
    /// the reader is dropped (i.e. the channel closes).  Run it concurrently:
    ///
    /// ```ignore
    /// let (reader, driver) = ProgressRead::new(blob, reporter, id, total);
    /// let decompressor = decompress_async(reader, media_type)?;
    /// let (import_result, ()) = tokio::join!(import_tar_async(repo, decompressor), driver);
    /// ```
    ///
    /// `total` should match the value passed to the preceding `Started` event
    /// so the renderer can compute a meaningful percentage.
    pub fn new(
        inner: R,
        reporter: SharedReporter,
        id: ComponentId,
        total: Option<u64>,
    ) -> (Self, impl Future<Output = ()>) {
        let (tx, mut rx) = tokio::sync::watch::channel(0u64);
        let driver = async move {
            while rx.changed().await.is_ok() {
                let fetched = *rx.borrow_and_update();
                reporter.report(ProgressEvent::Progress {
                    id: id.clone(),
                    fetched,
                    total,
                });
            }
        };
        (Self { inner, tx }, driver)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 {
                // Overflow-safe: update by adding the delta. Errors are
                // ignored — if the driver has already dropped its receiver
                // (e.g. the pull was cancelled), we simply stop sending.
                self.tx.send_modify(|v| *v += n);
            }
        }
        result
    }
}

// Bring `Future` into scope for the `impl Future<Output=()>` return type.
use std::future::Future;

#[cfg(any(test, feature = "test"))]
pub mod test_support {
    //! Test helpers for verifying progress event sequences.

    use std::sync::Mutex;

    use super::{ProgressEvent, ProgressReporter};

    /// A [`ProgressReporter`] that records all events for later inspection.
    ///
    /// Useful in unit tests to assert that the correct sequence of events
    /// was emitted during a pull or download operation.
    pub struct RecordingReporter {
        events: Mutex<Vec<ProgressEvent>>,
    }

    impl std::fmt::Debug for RecordingReporter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RecordingReporter")
                .field("events", &self.events.lock().unwrap().len())
                .finish()
        }
    }

    impl Default for RecordingReporter {
        fn default() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }

    impl RecordingReporter {
        /// Create a new empty recorder.
        pub fn new() -> Self {
            Self::default()
        }

        /// Return a snapshot of all events recorded so far.
        pub fn events(&self) -> Vec<ProgressEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ProgressReporter for RecordingReporter {
        fn report(&self, event: ProgressEvent) {
            self.events.lock().unwrap().push(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::test_support::RecordingReporter;
    use super::*;

    // ── NullReporter ────────────────────────────────────────────────────────

    /// Calling `report` on `NullReporter` with every variant must not panic.
    #[test]
    fn test_null_reporter_does_not_panic() {
        let reporter = NullReporter;
        reporter.report(ProgressEvent::Started {
            id: "layer1".into(),
            total: Some(1024),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Progress {
            id: "layer1".into(),
            fetched: 512,
            total: Some(1024),
        });
        reporter.report(ProgressEvent::Skipped {
            id: "layer2".into(),
        });
        reporter.report(ProgressEvent::Done {
            id: "layer1".into(),
            transferred: 1024,
        });
        reporter.report(ProgressEvent::Message("done".to_string()));
    }

    // ── ComponentId ─────────────────────────────────────────────────────────

    /// `ComponentId` can be constructed from `&str` and `String`, and its
    /// `Display` impl round-trips the inner value.
    #[test]
    fn test_component_id_conversions() {
        let cases = [
            "sha256:abc123",
            "objects:my-stream",
            "",
            "docker://quay.io/foo:latest",
        ];
        for input in cases {
            let from_str: ComponentId = input.into();
            let from_string: ComponentId = input.to_string().into();
            assert_eq!(
                from_str.as_str(),
                input,
                "ComponentId::from(&str) should store value"
            );
            assert_eq!(
                from_string.as_str(),
                input,
                "ComponentId::from(String) should store value"
            );
            assert_eq!(from_str.to_string(), input, "Display should round-trip");
            assert_eq!(from_str, from_string, "both constructors should be equal");
        }
    }

    /// `ComponentId` implements `Hash` + `Eq` correctly, so it works as a
    /// `HashMap` key — which `IndicatifReporter` relies on.
    #[test]
    fn test_component_id_hash_map_key() {
        let mut map: HashMap<ComponentId, u32> = HashMap::new();
        let id: ComponentId = "layer1".into();
        map.insert(id.clone(), 42);

        assert_eq!(
            map.get(&ComponentId::from("layer1")),
            Some(&42),
            "lookup by equal ComponentId should succeed"
        );
        assert_eq!(
            map.get(&ComponentId::from("layer2")),
            None,
            "lookup by different ComponentId should return None"
        );

        // Ensure remove also works (used in IndicatifReporter on Done/Skipped)
        let removed = map.remove(&id);
        assert_eq!(removed, Some(42));
        assert!(map.is_empty());
    }

    // ── ProgressEvent ────────────────────────────────────────────────────────

    /// Every `ProgressEvent` variant must implement `Debug` without panicking.
    #[test]
    fn test_progress_event_debug_all_variants() {
        let events = [
            ProgressEvent::Started {
                id: "x".into(),
                total: Some(100),
                unit: ProgressUnit::Bytes,
            },
            ProgressEvent::Started {
                id: "y".into(),
                total: None,
                unit: ProgressUnit::Items,
            },
            ProgressEvent::Progress {
                id: "x".into(),
                fetched: 50,
                total: Some(100),
            },
            ProgressEvent::Skipped { id: "z".into() },
            ProgressEvent::Done {
                id: "x".into(),
                transferred: 100,
            },
            ProgressEvent::Message("status update".into()),
        ];
        for event in &events {
            let debug = format!("{event:?}");
            assert!(!debug.is_empty(), "Debug output must not be empty");
        }
    }

    /// `ProgressEvent` must be `Clone` and the clone must have the same
    /// `Debug` representation as the original.
    #[test]
    fn test_progress_event_clone() {
        let event = ProgressEvent::Started {
            id: "layer".into(),
            total: Some(1000),
            unit: ProgressUnit::Bytes,
        };
        let cloned = event.clone();
        assert_eq!(
            format!("{event:?}"),
            format!("{cloned:?}"),
            "Clone should produce an identical value"
        );
    }

    // ── RecordingReporter ────────────────────────────────────────────────────

    /// `RecordingReporter` captures events in order and returns them via
    /// `events()`.
    #[test]
    fn test_recording_reporter_captures_events_in_order() {
        let reporter = RecordingReporter::new();
        reporter.report(ProgressEvent::Message("hello".into()));
        reporter.report(ProgressEvent::Started {
            id: "c1".into(),
            total: Some(100),
            unit: ProgressUnit::Bytes,
        });
        reporter.report(ProgressEvent::Done {
            id: "c1".into(),
            transferred: 100,
        });

        let events = reporter.events();
        assert_eq!(events.len(), 3, "all three events should be recorded");
        assert!(
            matches!(&events[0], ProgressEvent::Message(m) if m == "hello"),
            "first event should be Message"
        );
        assert!(
            matches!(&events[1], ProgressEvent::Started { id, .. } if id.as_str() == "c1"),
            "second event should be Started for c1"
        );
        assert!(
            matches!(&events[2], ProgressEvent::Done { id, .. } if id.as_str() == "c1"),
            "third event should be Done for c1"
        );
    }

    /// `SharedReporter = Arc<dyn ProgressReporter>` must be safely usable
    /// from multiple threads simultaneously.
    #[test]
    fn test_shared_reporter_is_send_sync() {
        let inner = Arc::new(RecordingReporter::new());
        let handles: Vec<_> = (0..4u32)
            .map(|i| {
                let r = Arc::clone(&inner);
                std::thread::spawn(move || {
                    r.report(ProgressEvent::Message(format!("thread {i}")));
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread should not panic");
        }
        assert_eq!(
            inner.events().len(),
            4,
            "all four threads should have recorded their event"
        );
    }

    // ── ProgressUnit ─────────────────────────────────────────────────────────

    /// Both `ProgressUnit` variants must be accessible and `Debug`-able.
    #[test]
    fn test_progress_unit_variants() {
        let bytes = ProgressUnit::Bytes;
        let items = ProgressUnit::Items;
        assert_ne!(bytes, items);
        assert!(!format!("{bytes:?}").is_empty());
        assert!(!format!("{items:?}").is_empty());
    }

    // ── ProgressRead ─────────────────────────────────────────────────────────

    /// Helper: run `ProgressRead` over `data` with a concurrent driver task,
    /// and return all recorded `Progress` events.
    async fn run_progress_read(
        data: Vec<u8>,
        id: ComponentId,
        total: Option<u64>,
    ) -> Vec<ProgressEvent> {
        use tokio::io::AsyncReadExt;

        let reporter = Arc::new(test_support::RecordingReporter::new());
        let cursor = tokio::io::BufReader::new(std::io::Cursor::new(data));
        let (mut reader, driver) =
            ProgressRead::new(cursor, Arc::clone(&reporter) as SharedReporter, id, total);
        // Spawn the driver so it runs independently.  When the reader is
        // dropped (after read_to_end), the watch sender closes and the driver
        // task completes on its own.
        let driver_handle = tokio::spawn(driver);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        // Drop the reader explicitly so the watch sender closes, which lets
        // the driver task observe channel closure and exit.
        drop(reader);
        driver_handle.await.unwrap();
        reporter.events()
    }

    /// `ProgressRead` emits at least one `Progress` event when non-empty data
    /// is read.  Every byte goes through the watch channel, so any non-empty
    /// read must produce at least one event.
    #[tokio::test]
    async fn test_progress_read_emits_events() {
        let id: ComponentId = "test-layer".into();
        let total: u64 = 1024;
        let data = vec![0u8; total as usize];
        let events = run_progress_read(data, id.clone(), Some(total)).await;

        let progress_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ProgressEvent::Progress { .. }))
            .collect();

        assert!(
            !progress_events.is_empty(),
            "expected at least one Progress event"
        );
        // All events must carry the correct id and total
        for event in &progress_events {
            if let ProgressEvent::Progress {
                id: eid,
                total: etot,
                ..
            } = event
            {
                assert_eq!(eid, &id);
                assert_eq!(*etot, Some(total));
            }
        }
        // The last Progress event must report fetched == total
        if let Some(ProgressEvent::Progress { fetched, .. }) = progress_events.last() {
            assert_eq!(
                *fetched, total,
                "last Progress event should have fetched == total"
            );
        }
    }

    /// `ProgressRead` with a zero-length source emits no `Progress` events
    /// since the watch value never changes from its initial state.
    #[tokio::test]
    async fn test_progress_read_empty_source_no_events() {
        let events = run_progress_read(vec![], "empty".into(), Some(0)).await;
        assert!(
            events.is_empty(),
            "no events should be emitted for an empty source"
        );
    }

    /// Every byte is sent through the watch channel, so even a single byte
    /// should produce exactly one `Progress` event.
    #[tokio::test]
    async fn test_progress_read_single_byte_one_event() {
        let events = run_progress_read(vec![42u8], "single".into(), Some(1)).await;
        let progress_count = events
            .iter()
            .filter(|e| matches!(e, ProgressEvent::Progress { .. }))
            .count();
        assert_eq!(
            progress_count, 1,
            "single byte should produce exactly one Progress event"
        );
    }
}

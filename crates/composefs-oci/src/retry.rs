//! Retrying transient failures when fetching from a registry.
//!
//! The containers-image-proxy (skopeo) does not retry failed requests
//! itself; in podman the retry loop lives in the caller (`c/common`), and
//! the same holds for us.  Registries such as quay.io intermittently return
//! 5xx errors or drop connections, so without retries a single blip fails
//! an entire pull.
//!
//! Which errors are transient is decided by the proxy, with the same
//! `IsErrorRetryable()` heuristic podman uses; see
//! [`containers_image_proxy::Error::is_retryable()`].  Proxies older than
//! skopeo 1.19 don't report that, so with them nothing is retried.
//!
//! Retries are done at the granularity of one proxy operation (opening the
//! image, fetching the manifest, or fetching and importing one blob), so a
//! failed layer does not force refetching the others.  Every blob attempt
//! starts from a fresh proxy request: data from a failed attempt is never
//! reused, and a layer is only registered once the proxy has verified the
//! size and digest of the complete blob.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use containers_image_proxy::Error as ProxyError;

use crate::progress::{ProgressEvent, ProgressReporter};

/// Default number of retries, matching podman's default in `containers.conf`.
const DEFAULT_MAX_RETRIES: u32 = 3;
/// Delay before the first retry when [`RetryPolicy::delay`] is unset; it
/// doubles for each further retry, as in podman.
const DEFAULT_INITIAL_DELAY: Duration = Duration::from_secs(1);

/// How to retry transient failures while fetching an image from a registry.
///
/// This mirrors podman's `--retry` and `--retry-delay` options.  Only
/// errors that the image proxy classifies as transient (network failures,
/// HTTP 502-504 responses and the like) are retried; others such as
/// authentication failures or a missing image fail immediately.
///
/// Start from [`RetryPolicy::default()`] or [`RetryPolicy::none()`] and
/// adjust the fields as needed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Maximum number of retries after the initial attempt; zero disables
    /// retrying.
    pub max_retries: u32,
    /// Fixed delay between attempts.  If unset, the delay starts at one
    /// second and doubles for each further retry.
    pub delay: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::with_max_retries(DEFAULT_MAX_RETRIES)
    }
}

impl RetryPolicy {
    /// A policy that never retries.
    pub const fn none() -> Self {
        Self::with_max_retries(0)
    }

    /// The default policy with a different number of retries.
    pub const fn with_max_retries(max_retries: u32) -> Self {
        Self {
            max_retries,
            delay: None,
        }
    }

    /// The delay before retry number `retry`, starting at zero.
    fn backoff_delay(&self, retry: u32) -> Duration {
        self.delay
            .unwrap_or_else(|| DEFAULT_INITIAL_DELAY.saturating_mul(2u32.saturating_pow(retry)))
    }
}

/// Whether `err` looks like a transient failure that is worth retrying.
///
/// Only errors reported by the image proxy are considered; local failures,
/// such as a malformed layer that the proxy verified as matching its digest,
/// are never retried.
pub(crate) fn is_transient(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<ProxyError>())
        .any(ProxyError::is_retryable)
}

/// Run `op` until it succeeds, fails with a non-transient error, or the
/// retries in `policy` are exhausted.
///
/// Each retry is reported as a [`ProgressEvent::Message`], which is how
/// callers such as `cfsctl` show it; it is only logged at debug level, so
/// it does not show up twice.
/// `what` describes the operation in those messages.
///
/// `op` must start from scratch every time it is called; nothing from a
/// failed attempt may leak into the next one.
pub(crate) async fn with_retry<T, F, Fut>(
    policy: &RetryPolicy,
    what: &str,
    reporter: &dyn ProgressReporter,
    mut op: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut retry = 0;
    loop {
        let err = match op().await {
            Ok(v) => return Ok(v),
            Err(err) => err,
        };
        if !is_transient(&err) {
            return Err(err);
        }
        if retry >= policy.max_retries {
            return if retry > 0 {
                let retries = if retry == 1 { "retry" } else { "retries" };
                Err(err).with_context(|| format!("Giving up after {retry} {retries}"))
            } else {
                Err(err)
            };
        }
        let delay = policy.backoff_delay(retry);
        retry += 1;
        let msg = format!(
            "{what}: transient error, retrying in {:.1}s ({retry}/{}): {err:#}",
            delay.as_secs_f64(),
            policy.max_retries
        );
        tracing::debug!("{msg}");
        reporter.report(ProgressEvent::Message(msg));
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use containers_image_proxy::GetBlobError;

    use super::*;
    use crate::progress::NullReporter;

    /// A progress reporter that records messages.
    #[derive(Debug, Default)]
    struct MessageLog(Mutex<Vec<String>>);

    impl ProgressReporter for MessageLog {
        fn report(&self, event: ProgressEvent) {
            if let ProgressEvent::Message(m) = event {
                self.0.lock().unwrap().push(m);
            }
        }
    }

    const FAST_RETRIES: RetryPolicy = RetryPolicy {
        max_retries: 3,
        delay: Some(Duration::ZERO),
    };
    const TRANSIENT: &str = "received unexpected HTTP status: 503 Service Unavailable";
    const PERMANENT: &str = "unauthorized: authentication required";

    /// A failed proxy request, as classified by the proxy.
    fn proxy_failure(msg: &str, retryable: bool) -> ProxyError {
        let (method, error) = ("GetBlob".into(), msg.into());
        if retryable {
            ProxyError::RetryableRequestFailure { method, error }
        } else {
            ProxyError::RequestInitiationFailure { method, error }
        }
    }

    #[test]
    fn test_is_transient() {
        let proxy = |e: ProxyError| anyhow::Error::from(e);
        let cases = [
            (proxy(proxy_failure(TRANSIENT, true)), true),
            (proxy(proxy_failure(PERMANENT, false)), false),
            // Only the proxy's classification counts, not the message
            (proxy(proxy_failure(TRANSIENT, false)), false),
            (
                proxy(GetBlobError::Retryable("connection reset".into()).into()),
                true,
            ),
            (
                proxy(GetBlobError::Other("connection reset".into()).into()),
                false,
            ),
            // Transient cause wrapped in context
            (
                proxy(proxy_failure(TRANSIENT, true)).context("Failed to import layer sha256:abcd"),
                true,
            ),
            // Both the proxy and the import failed: the proxy decides
            (
                proxy(proxy_failure("unexpected EOF", true))
                    .context("Import failed: unexpected EOF in tar stream")
                    .context("Fetching layer sha256:abcd"),
                true,
            ),
            (
                proxy(proxy_failure("manifest unknown", false))
                    .context("Import failed: unexpected EOF in tar stream"),
                false,
            ),
            // Local errors are never retried
            (anyhow::anyhow!("unexpected EOF in tar stream"), false),
        ];
        for (err, expected) in cases {
            assert_eq!(is_transient(&err), expected, "{err:#}");
        }
    }

    #[test]
    fn test_backoff_delay() {
        let default = RetryPolicy::default();
        let fixed = RetryPolicy {
            delay: Some(Duration::from_millis(500)),
            ..RetryPolicy::default()
        };
        // (policy, retry, expected)
        let cases = [
            (&default, 0, Duration::from_secs(1)),
            (&default, 1, Duration::from_secs(2)),
            (&default, 2, Duration::from_secs(4)),
            // Must not overflow
            (&default, u32::MAX, Duration::from_secs(u32::MAX.into())),
            (&fixed, 0, Duration::from_millis(500)),
            (&fixed, 5, Duration::from_millis(500)),
        ];
        for (policy, retry, expected) in cases {
            assert_eq!(
                policy.backoff_delay(retry),
                expected,
                "{policy:?} retry={retry}"
            );
        }
    }

    /// Drive [`with_retry`] with a fetcher that fails with the given errors
    /// in order and then succeeds.
    #[tokio::test]
    async fn test_with_retry() {
        const ONE_RETRY: RetryPolicy = RetryPolicy {
            max_retries: 1,
            ..FAST_RETRIES
        };
        const T: (&str, bool) = (TRANSIENT, true);
        const P: (&str, bool) = (PERMANENT, false);
        // (policy, errors before success, expected attempts, expected
        // success, expected context of the final error)
        type Case<'a> = (
            RetryPolicy,
            &'a [(&'a str, bool)],
            usize,
            bool,
            Option<&'a str>,
        );
        let cases: &[Case] = &[
            (FAST_RETRIES, &[], 1, true, None),
            (FAST_RETRIES, &[T], 2, true, None),
            (FAST_RETRIES, &[T; 3], 4, true, None),
            // Out of retries
            (
                FAST_RETRIES,
                &[T; 4],
                4,
                false,
                Some("Giving up after 3 retries"),
            ),
            (
                ONE_RETRY,
                &[T; 2],
                2,
                false,
                Some("Giving up after 1 retry"),
            ),
            // Permanent errors are not retried, even after transient ones
            (FAST_RETRIES, &[P], 1, false, None),
            (FAST_RETRIES, &[T, P], 2, false, None),
            // Retrying disabled
            (RetryPolicy::none(), &[T], 1, false, None),
        ];
        for (policy, errors, expected_attempts, expected_ok, expected_context) in cases {
            let log = MessageLog::default();
            let mut attempts = 0;
            let r = with_retry(policy, "Fetching thing", &log, || {
                let result = match errors.get(attempts) {
                    Some(&(msg, retryable)) => Err(proxy_failure(msg, retryable).into()),
                    None => Ok(attempts),
                };
                attempts += 1;
                std::future::ready(result)
            })
            .await;
            let ctx = format!("policy={policy:?} errors={errors:?}");
            assert_eq!(attempts, *expected_attempts, "{ctx}");
            assert_eq!(r.is_ok(), *expected_ok, "{ctx}: {r:?}");
            let messages = log.0.into_inner().unwrap();
            assert_eq!(messages.len(), expected_attempts - 1, "{ctx}");
            for (i, m) in messages.iter().enumerate() {
                let n = i + 1;
                let max = policy.max_retries;
                assert!(
                    m.starts_with("Fetching thing: transient error, retrying in ")
                        && m.contains(&format!("({n}/{max}): "))
                        && m.ends_with(TRANSIENT),
                    "{ctx}: {m}"
                );
            }
            if let Err(e) = r {
                let outer = e.to_string();
                match expected_context {
                    Some(c) => assert_eq!(outer, *c, "{ctx}"),
                    None => assert!(outer.starts_with("failed to invoke method"), "{ctx}: {e:#}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_with_retry_sleeps() {
        let policy = RetryPolicy {
            max_retries: 1,
            delay: Some(Duration::from_millis(50)),
        };
        let start = std::time::Instant::now();
        let mut failed = false;
        with_retry(&policy, "x", &NullReporter, || {
            let r = if failed {
                Ok(())
            } else {
                Err(proxy_failure("connection reset by peer", true).into())
            };
            failed = true;
            std::future::ready(r)
        })
        .await
        .unwrap();
        assert!(start.elapsed() >= Duration::from_millis(50));
    }
}

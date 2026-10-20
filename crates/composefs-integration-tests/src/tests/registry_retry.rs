//! Integration test for retrying transient registry failures.
//!
//! Serves the deterministic OCI layout from [`create_oci_layout`] from a
//! minimal in-process registry that answers the first manifest request with
//! `503 Service Unavailable` and hangs up on the first request for each
//! blob, and pulls it with `cfsctl oci pull docker://` through skopeo.
//! skopeo (i.e. containers/image) does not retry either itself, so any
//! recovery is ours.  Whether an error is worth retrying is decided by the
//! proxy, so this also checks that skopeo classifies both as retryable,
//! which needs skopeo 1.19 or newer.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use xshell::{Shell, cmd};

use crate::tests::cli::{OCI_LAYOUT_COMPOSEFS_ID, create_oci_layout, init_insecure_repo};
use crate::{SkopeoVersion, cfsctl, integration_test, skopeo_version};

/// The first skopeo whose image proxy reports which errors are retryable
/// (protocol 0.2.8); with older ones nothing is retried.
const MIN_SKOPEO_VERSION: SkopeoVersion = (1, 19, 0);
/// Repository name the image is served under.
const IMAGE_NAME: &str = "composefs/retry-test";
/// Requests that fail once: the manifest, plus the blobs of the image from
/// [`create_oci_layout`] (config and one layer).
const FAILURE_COUNT: usize = 3;
/// Key in [`FailedRequests`] for the manifest, which is fetched by tag or
/// digest.
const MANIFEST_KEY: &str = "manifest";
/// How long to wait for a request before giving up on a connection, so a
/// client that never sends one can't hang a handler thread.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// First byte of a TLS handshake record, as in a ClientHello.
const TLS_HANDSHAKE: u8 = 0x16;

/// The manifest ([`MANIFEST_KEY`]) and blob digests that have already
/// failed once.
type FailedRequests = Mutex<HashSet<String>>;

/// A read-only registry serving a single-image OCI layout over plain HTTP,
/// failing the first request for the manifest and for each blob.  Every
/// response closes the connection, so each request is seen separately.
struct FlakyRegistry {
    addr: SocketAddr,
    failed: Arc<FailedRequests>,
    shutdown: Arc<AtomicBool>,
}

impl FlakyRegistry {
    fn start(layout: &Path) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let failed = Arc::new(FailedRequests::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let layout = layout.to_owned();
        let (failures, stop) = (Arc::clone(&failed), Arc::clone(&shutdown));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let conn = match conn {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("flaky registry: accept: {e}");
                        continue;
                    }
                };
                let (layout, failures) = (layout.clone(), Arc::clone(&failures));
                std::thread::spawn(move || {
                    if let Err(e) = handle_request(conn, &layout, &failures) {
                        eprintln!("flaky registry: {e:#}");
                    }
                });
            }
        });
        Ok(Self {
            addr,
            failed,
            shutdown,
        })
    }

    fn failure_count(&self) -> usize {
        self.failed.lock().unwrap().len()
    }

    fn image_ref(&self) -> String {
        format!("docker://{}/{IMAGE_NAME}:latest", self.addr)
    }

    /// Create a home directory whose `registries.conf` allows plain HTTP to
    /// this registry.  skopeo only reads the per-user file from `$HOME`
    /// (it ignores `CONTAINERS_REGISTRIES_CONF`), and cfsctl has no flag
    /// for its `--tls-verify`.
    fn create_home(&self, parent: &Path) -> Result<PathBuf> {
        let home = parent.join("home");
        let config_dir = home.join(".config/containers");
        std::fs::create_dir_all(&config_dir)?;
        let conf = format!(
            "[[registry]]\nlocation = \"{}\"\ninsecure = true\n",
            self.addr
        );
        std::fs::write(config_dir.join("registries.conf"), conf)?;
        Ok(home)
    }
}

impl Drop for FlakyRegistry {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake up the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

fn respond(
    conn: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    send_body: bool,
) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    conn.write_all(head.as_bytes())?;
    if send_body {
        conn.write_all(body)?;
    }
    Ok(())
}

fn read_blob(layout: &Path, digest: &str) -> Result<Vec<u8>> {
    let (alg, hex) = digest
        .split_once(':')
        .with_context(|| format!("invalid digest {digest}"))?;
    Ok(std::fs::read(layout.join("blobs").join(alg).join(hex))?)
}

/// How [`fail_once`] fails a request.
#[derive(Debug, Clone, Copy)]
enum Fault {
    /// Respond with `503 Service Unavailable`.
    Unavailable,
    /// Close the connection without responding.
    HangUp,
}

/// Fail the first request for `key` as `fault` says; returns whether it did.
fn fail_once(
    conn: &mut TcpStream,
    failed: &FailedRequests,
    key: &str,
    fault: Fault,
    send_body: bool,
) -> Result<bool> {
    let first_request = failed.lock().unwrap().insert(key.to_owned());
    if first_request {
        match fault {
            Fault::Unavailable => respond(conn, "503 Service Unavailable", &[], b"", send_body)?,
            // The caller drops the connection.
            Fault::HangUp => {}
        }
    }
    Ok(first_request)
}

fn handle_request(mut conn: TcpStream, layout: &Path, failed: &FailedRequests) -> Result<()> {
    conn.set_read_timeout(Some(READ_TIMEOUT))?;
    // skopeo tries TLS before falling back to plain HTTP; just hang up on it,
    // rather than waiting for a request line that never comes.
    let mut first = [0u8];
    if conn.peek(&mut first)? == 0 || first[0] == TLS_HANDSHAKE {
        return Ok(());
    }
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("Reading request line")?;
    // Skip the headers; nothing in them matters here.
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 || line == b"\r\n" {
            break;
        }
    }
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return Ok(());
    };
    let send_body = method != "HEAD";
    let not_found = |conn: &mut TcpStream| respond(conn, "404 Not Found", &[], b"", send_body);

    if path == "/v2/" {
        return respond(
            &mut conn,
            "200 OK",
            &[("Content-Type", "application/json")],
            b"{}",
            send_body,
        );
    }
    let Some(rest) = path.strip_prefix(&format!("/v2/{IMAGE_NAME}/")) else {
        return not_found(&mut conn);
    };
    if let Some(reference) = rest.strip_prefix("manifests/") {
        if fail_once(
            &mut conn,
            failed,
            MANIFEST_KEY,
            Fault::Unavailable,
            send_body,
        )? {
            return Ok(());
        }
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(layout.join("index.json"))?)?;
        let desc = &index["manifests"][0];
        let (Some(digest), Some(media_type)) =
            (desc["digest"].as_str(), desc["mediaType"].as_str())
        else {
            anyhow::bail!("index.json has no manifest descriptor");
        };
        if reference.contains(':') && reference != digest {
            return not_found(&mut conn);
        }
        let manifest = read_blob(layout, digest)?;
        respond(
            &mut conn,
            "200 OK",
            &[
                ("Content-Type", media_type),
                ("Docker-Content-Digest", digest),
            ],
            &manifest,
            send_body,
        )
    } else if let Some(digest) = rest.strip_prefix("blobs/") {
        if fail_once(&mut conn, failed, digest, Fault::HangUp, send_body)? {
            return Ok(());
        }
        match read_blob(layout, digest) {
            Ok(blob) => respond(
                &mut conn,
                "200 OK",
                &[("Content-Type", "application/octet-stream")],
                &blob,
                send_body,
            ),
            Err(e) => {
                eprintln!("flaky registry: {e:#}");
                not_found(&mut conn)
            }
        }
    } else {
        not_found(&mut conn)
    }
}

/// A pull through skopeo survives a transient 503 on the manifest and
/// dropped connections on the config and layer fetches, and imports the
/// same image as a direct pull of the layout.  With retries disabled the
/// same faults fail the pull, which shows they were injected.
fn test_pull_retries_transient_registry_errors() -> Result<()> {
    let Some(version) = skopeo_version() else {
        eprintln!("skopeo not found, skipping registry retry test");
        return Ok(());
    };
    if version < MIN_SKOPEO_VERSION {
        eprintln!(
            "skopeo {version:?} does not classify retryable errors (needs {MIN_SKOPEO_VERSION:?}), \
             skipping registry retry test"
        );
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;
    let fixture_dir = tempfile::tempdir()?;
    let layout = create_oci_layout(fixture_dir.path())?;

    // (extra cfsctl args, expect success)
    let cases: &[(&[&str], bool)] = &[(&[], true), (&["--retry", "0"], false)];
    for &(args, expect_ok) in cases {
        let registry = FlakyRegistry::start(&layout)?;
        let home = registry.create_home(fixture_dir.path())?;
        let image = registry.image_ref();
        let repo_dir = init_insecure_repo(&sh, &cfsctl)?;
        let repo = repo_dir.path();

        let output = cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci pull {args...} {image} retry-image"
        )
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .ignore_status()
        .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let ctx = format!("args={args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");

        let failures = registry.failure_count();
        if !expect_ok {
            assert_eq!(failures, 1, "should give up at the first failure; {ctx}");
            assert!(!output.status.success(), "pull should fail; {ctx}");
            assert!(
                stderr.contains("503 Service Unavailable"),
                "error should report the 503; {ctx}"
            );
            continue;
        }

        assert!(output.status.success(), "pull should succeed; {ctx}");
        assert_eq!(failures, FAILURE_COUNT, "{ctx}");
        let combined = format!("{stdout}{stderr}");
        let retries = combined.matches("transient error, retrying").count();
        assert_eq!(
            retries, FAILURE_COUNT,
            "each injected failure should be retried once; {ctx}"
        );
        let config_digest = stdout
            .lines()
            .find_map(|l| l.strip_prefix("config").map(|s| s.trim().to_string()))
            .with_context(|| format!("config digest in pull output; {ctx}"))?;
        let at_config_digest = format!("@{config_digest}");
        let image_id = cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci compute-id {at_config_digest}"
        )
        .read()?;
        assert_eq!(image_id.trim(), OCI_LAYOUT_COMPOSEFS_ID);
    }
    Ok(())
}
integration_test!(test_pull_retries_transient_registry_errors);

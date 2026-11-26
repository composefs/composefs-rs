//! Storage lock acquisition and owned guards.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::time::Duration;

use cap_std::fs::Dir;
use composefs_ioctls::lock::ofd_lock;
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde::Serialize;

use super::{ImportError, Result, records};

// Short handoffs should be responsive; cap retries to avoid frequent polling
// during another process's long import while keeping cancellation asynchronous.
const RETRY_INITIAL: Duration = Duration::from_millis(10);
const RETRY_MAX: Duration = Duration::from_millis(250);
// containers/storage/pkg/lockfile/lastwrite.go:lastWriterIDSize.
const CHANGE_TOKEN_SIZE: usize = 64;

#[derive(Debug)]
pub(super) struct LockFile {
    file: File,
    path: String,
}

#[derive(Debug)]
pub(super) struct ReadLock {
    _file: File,
}

#[derive(Debug)]
pub(super) struct WriteLock(File);

impl LockFile {
    pub fn open(dir: &Dir, path: &str) -> Result<Self> {
        let fd = rustix::fs::openat(
            dir,
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(records::CONTROL_FILE_MODE),
        )?;
        if rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode)
            != rustix::fs::FileType::RegularFile
        {
            return Err(ImportError::RecoveryRequired(format!(
                "{path} is not a regular lockfile"
            )));
        }
        Ok(Self {
            file: fd.into(),
            path: path.into(),
        })
    }

    pub async fn read(self) -> Result<ReadLock> {
        Ok(ReadLock {
            _file: self.acquire(FlockOperation::NonBlockingLockShared).await?,
        })
    }

    pub async fn write(self) -> Result<WriteLock> {
        Ok(WriteLock(
            self.acquire(FlockOperation::NonBlockingLockExclusive)
                .await?,
        ))
    }

    async fn acquire(self, operation: FlockOperation) -> Result<File> {
        let mut retry = RETRY_INITIAL;
        loop {
            match ofd_lock(&self.file, operation) {
                Ok(()) => return Ok(self.file),
                Err(e) if matches!(e.raw_os_error(), Some(n) if n == rustix::io::Errno::AGAIN.raw_os_error() || n == rustix::io::Errno::ACCESS.raw_os_error()) =>
                {
                    if retry == RETRY_INITIAL {
                        tracing::debug!(
                            path = self.path,
                            ?operation,
                            "waiting for containers/storage lock"
                        );
                    }
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(RETRY_MAX);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl WriteLock {
    pub fn write_records<T: Serialize>(&self, dir: &Dir, name: &str, values: &[T]) -> Result<()> {
        let bytes = serde_json::to_vec(values)?;
        let mut token = [0u8; CHANGE_TOKEN_SIZE];
        openssl::rand::rand_bytes(&mut token).map_err(std::io::Error::other)?;
        self.0.write_all_at(&token, 0)?;
        self.0.sync_all()?;
        records::atomic_write(dir, name, &bytes, records::PRIVATE_FILE_MODE)
    }

    /// Retain the transaction and its locks through the complete durable update.
    pub async fn write_records_async<R: Serialize + Send + 'static, T: Send + 'static>(
        self,
        dir: Dir,
        name: String,
        values: Vec<R>,
        owner: T,
    ) -> Result<(Self, T)> {
        tokio::task::spawn_blocking(move || {
            self.write_records(&dir, &name, &values)?;
            Ok((self, owner))
        })
        .await?
    }
}

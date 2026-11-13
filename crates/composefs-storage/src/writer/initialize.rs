//! Creation of the directories needed by a writable overlay store.

use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, DirBuilder, DirBuilderExt};
use rustix::fs::{self, Mode};

use super::locking::LockFile;
use super::{OpenedStoreLocation, Result, StorageWriter, StoreLocation, records};

pub(super) async fn ensure(location: StoreLocation) -> Result<StorageWriter> {
    let (graphroot, graph_created) = root(
        &location.graphroot,
        location.graphroot_path.as_deref().unwrap_or(Path::new(".")),
    )?;
    // Keep readable handles to the actual roots before writing storage contents.
    let mut sync_dirs = vec![records::open_dir(&graphroot, Path::new("."))?];
    let (runroot, run_created) = match &location.runroot {
        Some(parent) => {
            let (dir, created) = root(
                parent,
                location.runroot_path.as_deref().unwrap_or(Path::new(".")),
            )?;
            sync_dirs.push(records::open_dir(&dir, Path::new("."))?);
            (Some(dir), created)
        }
        None => (None, false),
    };
    let new_lock = missing(&graphroot, "storage.lock")?;
    let request = LockFile::open(&graphroot, "storage.lock")?;
    let location = OpenedStoreLocation { graphroot, runroot };
    let mut changed = graph_created || run_created || new_lock;
    let guard = request.write().await?;
    // Parents precede their children.
    for (path, mode, lock) in [
        ("overlay", records::DEFAULT_DIR_MODE, None),
        ("overlay/l", records::DEFAULT_DIR_MODE, None),
        (
            "overlay-layers",
            records::PRIVATE_DIR_MODE,
            Some("layers.lock"),
        ),
        (
            "overlay-images",
            records::PRIVATE_DIR_MODE,
            Some("images.lock"),
        ),
    ] {
        let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
        let parent = records::open_dir(&location.graphroot, Path::new(parent))?;
        let dir = directory(&parent, name, mode, &mut changed)?;
        if let Some(file) = lock {
            changed |= missing(&dir, file)?;
            LockFile::open(&dir, file)?;
        }
    }
    if let Some(runroot) = &location.runroot {
        directory(
            runroot,
            "overlay-layers",
            records::PRIVATE_DIR_MODE,
            &mut changed,
        )?;
    }
    let writer = StorageWriter::open_inner(location)?;
    if changed {
        // Setup has already changed the store. Keep this job queued on
        // cancellation so the graph lock covers the full durability barrier.
        tokio::task::spawn_blocking(move || -> Result<()> {
            let _guard = guard;
            for dir in sync_dirs {
                fs::syncfs(&dir)?;
            }
            Ok(())
        })
        .await??;
    }
    Ok(writer)
}

fn root(parent: &Dir, path: &Path) -> Result<(Dir, bool)> {
    let mut dir = parent.try_clone()?;
    let mut prefix = PathBuf::new();
    let mut created = false;
    for component in path.components() {
        prefix.push(component.as_os_str());
        match records::allow_missing(parent.open_dir(&prefix))? {
            Some(next) => dir = next,
            None => {
                let mut builder = DirBuilder::new();
                builder.mode(records::PRIVATE_DIR_MODE);
                match dir.create_dir_with(component.as_os_str(), &builder) {
                    Ok(()) => created = true,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
                dir = parent.open_dir(&prefix)?;
            }
        }
    }
    Ok((dir, created))
}

fn directory(parent: &Dir, name: &str, mode: u32, changed: &mut bool) -> Result<Dir> {
    let created = match fs::mkdirat(parent, name, Mode::from_bits_truncate(mode)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.into()),
    };
    let dir = records::open_dir(parent, Path::new(name))?;
    if created {
        fs::fchmod(&dir, Mode::from_bits_truncate(mode))?;
    }
    *changed |= created;

    Ok(dir)
}

fn missing(dir: &Dir, path: &str) -> Result<bool> {
    Ok(records::allow_missing(dir.symlink_metadata(path))?.is_none())
}

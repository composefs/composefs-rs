//! FUSE mount support for cfsctl.
//!
//! This module is only compiled when the `fuse` feature is enabled.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::ValueEnum;
use rustix::fs::{CWD, Mode, OFlags};

use composefs::fsverity::FsVerityHashValue;
use composefs::mount::MountOptions;
use composefs::repository::Repository;

/// How to mount: kernel composefs driver, FUSE, or auto-detect.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub(crate) enum FuseMode {
    /// Auto-detect based on privileges
    #[default]
    Auto,
    /// Force FUSE mount
    Yes,
    /// Force kernel mount
    No,
}

#[derive(Debug)]
pub(crate) enum MountMode {
    Kernel,
    Fuse,
    FuseOverlay,
}

fn in_init_user_namespace() -> bool {
    std::fs::read_to_string("/proc/self/uid_map")
        .map(|s| s.trim() == "0          0 4294967295")
        .unwrap_or(false)
}

fn has_cap_sys_admin() -> bool {
    if let Ok(caps) = rustix::thread::capabilities(None) {
        caps.effective
            .contains(rustix::thread::CapabilitySet::SYS_ADMIN)
    } else {
        false
    }
}

/// Probe whether the kernel supports overlayfs with userxattr + data-only
/// layers. Kernels without the `5ef7bcde` backport reject this because
/// data-only layers require metacopy, which conflicts with userxattr.
///
/// The probe creates a temporary directory for the lower/data dirs, sets
/// up a dummy overlay with `userxattr` + data-only layer syntax, and
/// checks whether `fsconfig_create` succeeds.
fn supports_userxattr_data_layers() -> bool {
    use composefs::mount::FsHandle;
    use rustix::mount::{fsconfig_create, fsconfig_set_flag, fsconfig_set_string};
    use std::os::fd::{AsFd as _, AsRawFd as _};

    let Ok(tmpdir) = tempfile::tempdir() else {
        return false;
    };
    let lower = tmpdir.path().join("lower");
    let data = tmpdir.path().join("data");
    if std::fs::create_dir(&lower).is_err() || std::fs::create_dir(&data).is_err() {
        return false;
    }
    let Ok(lower_fd) = rustix::fs::open(
        &lower,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let Ok(data_fd) = rustix::fs::open(
        &data,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let lowerdir_arg = format!(
        "/proc/self/fd/{}::/proc/self/fd/{}",
        lower_fd.as_raw_fd(),
        data_fd.as_raw_fd()
    );

    let Ok(overlayfs) = FsHandle::open("overlay") else {
        return false;
    };
    let supported = fsconfig_set_flag(overlayfs.as_fd(), "userxattr").is_ok()
        && fsconfig_set_string(overlayfs.as_fd(), "lowerdir", &*lowerdir_arg).is_ok()
        && fsconfig_create(overlayfs.as_fd()).is_ok();
    log::debug!("supports_userxattr_data_layers: {supported}");
    supported
}

pub(crate) fn detect_mount_mode(fuse_mode: FuseMode, has_upper: bool) -> MountMode {
    let use_fuse = match fuse_mode {
        FuseMode::Yes => true,
        FuseMode::No => false,
        FuseMode::Auto => !(rustix::process::getuid().is_root() && in_init_user_namespace()),
    };

    if !use_fuse {
        return MountMode::Kernel;
    }

    let mode = if (has_upper || has_cap_sys_admin()) && supports_userxattr_data_layers() {
        MountMode::FuseOverlay
    } else {
        MountMode::Fuse
    };
    log::debug!("detect_mount_mode: {mode:?}");
    mode
}

pub(crate) fn run_fuse_foreground(
    image_fd: OwnedFd,
    objects_fd: Arc<OwnedFd>,
    mountpoint: &str,
    mode: MountMode,
    mount_options: MountOptions,
    enable_verity: bool,
    ready_fd: Option<OwnedFd>,
) -> Result<()> {
    match mode {
        MountMode::Kernel => unreachable!(),
        MountMode::Fuse => {
            let options = composefs_fuse::ServeFuseOptions::default();
            composefs_fuse::serve_fuse(mountpoint, image_fd, objects_fd, &options, ready_fd)
                .context("FUSE server error")?;
        }
        MountMode::FuseOverlay => {
            let dev_fuse = composefs_fuse::open_fuse()?;
            let fuse_options = composefs_fuse::FuseMountOptions::default();
            let fuse_mnt =
                composefs_fuse::mount_fuse(&dev_fuse, &fuse_options).context("FUSE mount")?;

            let mut serve_options = composefs_fuse::ServeFuseOptions::default();
            serve_options.set_overlay_xattr(Some(composefs_fuse::OverlayXattrMode::User));

            let serve_objects = Arc::clone(&objects_fd);
            let serve_dev = dev_fuse;
            let join_handle = std::thread::spawn(move || {
                composefs_fuse::serve_fuse_fd(serve_dev, image_fd, serve_objects, &serve_options)
            });

            let read_write = mount_options.read_write();
            let mut overlay_options = composefs_fuse::OverlayMountOptions::default();
            if let Some((upper_fd, work_fd)) = mount_options.into_overlay() {
                overlay_options.set_overlay(upper_fd, work_fd);
            }
            overlay_options.set_read_write(read_write);
            overlay_options.set_enable_verity(enable_verity);

            let overlay_mnt =
                composefs_fuse::mount_fuse_overlay(fuse_mnt, &*objects_fd, &overlay_options)
                    .context("overlay mount")?;
            composefs::mount::mount_at(overlay_mnt, CWD, mountpoint)?;

            if let Some(fd) = ready_fd {
                let _ = rustix::io::write(&fd, b"r");
            }

            join_handle
                .join()
                .map_err(|_| anyhow::anyhow!("FUSE server thread panicked"))?
                .context("FUSE server error")?;
        }
    }
    Ok(())
}

/// Re-exec ourselves as `--internal-fuse-serve` to run the FUSE server in a
/// clean process without the tokio runtime. File descriptors are passed via
/// the systemd socket activation protocol (LISTEN_FDS/LISTEN_FDNAMES) for
/// safe and easy fd transfer.
#[allow(unsafe_code)]
pub(crate) fn run_fuse_mount<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    name: &str,
    mountpoint: &str,
    mode: MountMode,
    mount_options: MountOptions,
    foreground: bool,
) -> Result<()> {
    if foreground {
        let (image_fd, enable_verity) = repo.open_image(name)?;
        let objects_fd = Arc::new(repo.objects_dir()?.try_clone()?);
        return run_fuse_foreground(
            image_fd,
            objects_fd,
            mountpoint,
            mode,
            mount_options,
            enable_verity,
            None,
        );
    }

    use cap_std_ext::cmdext::{CapStdExtCommandExt as _, CmdFds, SystemdFdName};
    use std::os::unix::process::CommandExt;

    let (image_fd, enable_verity) = repo.open_image(name)?;
    let (read_pipe, write_pipe) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let repo_fd = repo.repo_fd().try_clone_to_owned()?;

    let read_write = mount_options.read_write();
    let mut sd_fds: Vec<(Arc<OwnedFd>, SystemdFdName<'_>)> = vec![
        (Arc::new(image_fd), SystemdFdName::new("image")),
        (Arc::new(repo_fd), SystemdFdName::new("repo")),
        (Arc::new(write_pipe), SystemdFdName::new("ready")),
    ];

    if let Some((upper_fd, work_fd)) = mount_options.into_overlay() {
        sd_fds.push((Arc::new(upper_fd), SystemdFdName::new("upper")));
        sd_fds.push((Arc::new(work_fd), SystemdFdName::new("work")));
    }

    let fds = CmdFds::new_systemd_fds(sd_fds);

    let self_exe = std::env::current_exe().context("resolving own binary path")?;
    let mut cmd = std::process::Command::new(&self_exe);
    cmd.arg("--internal-fuse-serve");
    cmd.arg("--mountpoint").arg(mountpoint);

    match mode {
        MountMode::Kernel => unreachable!(),
        MountMode::Fuse => cmd.arg("--mode").arg("fuse"),
        MountMode::FuseOverlay => cmd.arg("--mode").arg("fuse-overlay"),
    };

    if enable_verity {
        cmd.arg("--enable-verity");
    }
    if read_write {
        cmd.arg("--read-write");
    }

    cmd.take_fds(fds);

    unsafe {
        cmd.pre_exec(|| {
            let _ = rustix::process::setsid();
            Ok(())
        });
    }

    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::inherit());

    let _child = cmd.spawn().context("spawning FUSE server process")?;

    let mut buf = [0u8; 1];
    let _ = rustix::io::read(&read_pipe, &mut buf);

    Ok(())
}

/// Arguments for the internal FUSE server process.
/// File descriptors are received via the systemd activation protocol
/// (LISTEN_FDS/LISTEN_FDNAMES), not via raw fd number arguments.
#[derive(Debug, clap::Parser)]
pub struct InternalFuseServeArgs {
    #[arg(long)]
    mountpoint: String,
    #[arg(long, value_parser = ["fuse", "fuse-overlay"])]
    mode: String,
    #[arg(long)]
    enable_verity: bool,
    #[arg(long)]
    read_write: bool,
}

/// Entry point for the internal FUSE server process, called from main()
/// before the tokio runtime is created.
#[allow(unsafe_code)]
pub fn run_internal_fuse_serve(args: InternalFuseServeArgs) -> Result<()> {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let fds = libsystemd::activation::receive_descriptors_with_names(true)
        .map_err(|e| anyhow::anyhow!("receiving activation fds: {e}"))?;

    let mut image_fd: Option<OwnedFd> = None;
    let mut repo_fd: Option<OwnedFd> = None;
    let mut ready_fd: Option<OwnedFd> = None;
    let mut upper_fd: Option<OwnedFd> = None;
    let mut work_fd: Option<OwnedFd> = None;

    for (fd, name) in fds {
        let owned = unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) };
        match name.as_str() {
            "image" => image_fd = Some(owned),
            "repo" => repo_fd = Some(owned),
            "ready" => ready_fd = Some(owned),
            "upper" => upper_fd = Some(owned),
            "work" => work_fd = Some(owned),
            other => log::warn!("unexpected activation fd name: {other}"),
        }
    }

    let image_fd = image_fd.context("missing 'image' activation fd")?;
    let repo_fd = repo_fd.context("missing 'repo' activation fd")?;
    let ready_fd = ready_fd.context("missing 'ready' activation fd")?;

    let objects_fd = Arc::new(
        rustix::fs::openat(
            &repo_fd,
            "objects",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("opening objects dir")?,
    );

    let mode = match args.mode.as_str() {
        "fuse" => MountMode::Fuse,
        "fuse-overlay" => MountMode::FuseOverlay,
        _ => unreachable!(),
    };

    let mut mount_options = MountOptions::default();
    if let (Some(upper), Some(work)) = (upper_fd, work_fd) {
        mount_options.set_overlay(upper, work);
    }
    mount_options.set_read_write(args.read_write);

    run_fuse_foreground(
        image_fd,
        objects_fd,
        &args.mountpoint,
        mode,
        mount_options,
        args.enable_verity,
        Some(ready_fd),
    )
}

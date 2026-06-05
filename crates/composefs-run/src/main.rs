//! Minimal container runner using composefs images and crun.

use std::fs;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::mount::MountOptions;
use composefs::repository::{Repository, read_repo_algorithm};
use composefs_oci::OciDigest;
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxNamespace, LinuxNamespaceType,
    MountBuilder, ProcessBuilder, RootBuilder, Spec, UserBuilder,
};
use rustix::fs::{CWD, Mode, OFlags};
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags, fsconfig_create, fsmount,
    fsopen,
};

/// Minimal container runner using composefs images and crun.
#[derive(Debug, Parser)]
#[clap(name = "composefs-run")]
struct Cli {
    /// Path to the composefs repository
    #[clap(long, default_value = "/sysroot/composefs")]
    repo: PathBuf,

    /// Mount the rootfs read-only
    #[clap(long)]
    read_only: bool,

    /// When --read-only is set, mount tmpfs on /dev/shm, /run, /tmp, /var/tmp
    #[clap(long, default_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    read_only_tmpfs: bool,

    /// Persistent upper layer directory for overlayfs (default: tmpfs)
    #[clap(long = "overlay-upperdir", requires = "overlay_workdir")]
    upperdir: Option<PathBuf>,

    /// Persistent work directory for overlayfs (required with --overlay-upperdir)
    #[clap(long = "overlay-workdir", requires = "upperdir")]
    overlay_workdir: Option<PathBuf>,

    /// Bind mount a host directory into the container (-v HOST:CONTAINER[:ro])
    #[clap(short = 'v', long = "volume")]
    volumes: Vec<String>,

    /// Allocate a pseudo-TTY
    #[clap(short = 't', long)]
    tty: bool,

    /// Keep stdin open
    #[clap(short = 'i', long)]
    interactive: bool,

    /// Write the container init PID to this file
    #[clap(long)]
    pidfile: Option<PathBuf>,

    /// Give extended privileges to the container (all caps, no seccomp, device access)
    #[clap(long)]
    privileged: bool,

    /// Add a Linux capability (e.g. SYS_ADMIN, NET_RAW, or ALL)
    #[clap(long)]
    cap_add: Vec<String>,

    /// Drop a Linux capability (e.g. NET_RAW, or ALL)
    #[clap(long)]
    cap_drop: Vec<String>,

    /// Set environment variables (KEY=VALUE)
    #[clap(short = 'e', long = "env")]
    envs: Vec<String>,

    /// Unset environment variables from the image config
    #[clap(long)]
    unsetenv: Vec<String>,

    /// Override the user (user, uid, user:group, uid:gid)
    #[clap(short = 'u', long)]
    user: Option<String>,

    /// Override the working directory
    #[clap(short = 'w', long = "workdir")]
    workdir_override: Option<String>,

    /// Expose a port (currently informational only, no network setup)
    #[clap(long)]
    expose: Vec<String>,

    /// Publish a port (HOST:CONTAINER or HOST:CONTAINER/PROTO)
    #[clap(short = 'p', long)]
    publish: Vec<String>,

    /// Network mode: host (share host network) or private (isolated, loopback only)
    #[clap(long, default_value = "host")]
    network: String,

    /// Systemd container mode: true (auto-detect), false, or always
    #[clap(long, default_value = "true")]
    systemd: String,

    /// OCI image ref name or @sha256:... digest
    image: String,

    /// Command to run (overrides image entrypoint+cmd)
    #[clap(last = true)]
    cmd: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let repo_path = &cli.repo;
    let repo_fd = rustix::fs::open(
        repo_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Opening repository at {}", repo_path.display()))?;

    let algorithm = read_repo_algorithm(&repo_fd)?
        .context("No meta.json found — is this a composefs repository?")?;

    match algorithm {
        composefs::fsverity::Algorithm::Sha256 { .. } => run::<Sha256HashValue>(&cli, repo_path),
        composefs::fsverity::Algorithm::Sha512 { .. } => run::<Sha512HashValue>(&cli, repo_path),
    }
}

fn run<ObjectID: FsVerityHashValue>(cli: &Cli, repo_path: &Path) -> Result<()> {
    let repo = Repository::<ObjectID>::open_path(CWD, repo_path)
        .context("Opening composefs repository")?;

    // Resolve the OCI image
    let (erofs_id, open_config) = resolve_image(&repo, &cli.image)?;

    // Extract container config from the OCI image
    let oci_config = open_config
        .config
        .config()
        .as_ref()
        .context("Image has no config section")?;

    let args = if cli.cmd.is_empty() {
        let mut args = oci_config.entrypoint().clone().unwrap_or_default();
        args.extend(oci_config.cmd().clone().unwrap_or_default());
        ensure!(
            !args.is_empty(),
            "No entrypoint or cmd in image config and no command specified"
        );
        args
    } else {
        cli.cmd.clone()
    };

    // Environment: start from image, remove --unsetenv, add --env
    let mut env: Vec<String> = oci_config.env().clone().unwrap_or_else(|| {
        vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()]
    });
    env.retain(|e| {
        let key = e.split('=').next().unwrap_or("");
        !cli.unsetenv.iter().any(|u| u == key)
    });
    for e in &cli.envs {
        // Replace existing key or append
        let key = e.split('=').next().unwrap_or("");
        env.retain(|existing| existing.split('=').next().unwrap_or("") != key);
        env.push(e.clone());
    }

    // Working directory: CLI override or image config
    let cwd = cli
        .workdir_override
        .clone()
        .or_else(|| oci_config.working_dir().clone())
        .unwrap_or_else(|| "/".into());

    // User: CLI override or image config
    let user = cli
        .user
        .clone()
        .or_else(|| oci_config.user().clone())
        .unwrap_or_default();

    // All detached mounts are created BEFORE unshare(NEWNS). The kernel's
    // clone_private_mount() (used internally by overlayfs fsconfig_set_fd)
    // rejects mounts inherited from a parent namespace. Creating everything
    // as detached fds in the original namespace avoids this.

    // Create a detached tmpfs for the bundle (config.json, rootfs mountpoint,
    // and optionally overlay upper/work dirs).
    let bundle_tmpfs = create_detached_tmpfs().context("Creating detached tmpfs for bundle")?;
    rustix::fs::mkdirat(&bundle_tmpfs, "rootfs", Mode::from_raw_mode(0o755))?;

    let mut mount_options = MountOptions::default();
    if !cli.read_only {
        if let (Some(u), Some(w)) = (&cli.upperdir, &cli.overlay_workdir) {
            let upper_fd = rustix::fs::open(
                u,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("Opening upperdir '{}'", u.display()))?;
            let work_fd = rustix::fs::open(
                w,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("Opening workdir '{}'", w.display()))?;
            mount_options.set_overlay(upper_fd, work_fd);
        } else {
            // Use dirs on the bundle tmpfs for ephemeral upper/work
            rustix::fs::mkdirat(&bundle_tmpfs, "upper", Mode::from_raw_mode(0o755))?;
            rustix::fs::mkdirat(&bundle_tmpfs, "work", Mode::from_raw_mode(0o755))?;

            let upper_fd = rustix::fs::openat(
                &bundle_tmpfs,
                "upper",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let work_fd = rustix::fs::openat(
                &bundle_tmpfs,
                "work",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            mount_options.set_overlay(upper_fd, work_fd);
        };
        mount_options.set_read_write(true);
    }

    // Get a detached composefs mount fd
    let mount_fd = repo
        .mount_with_options(&erofs_id.to_hex(), &mount_options)
        .context("Creating composefs mount")?;

    // Enter a new mount namespace so all attached mounts are cleaned up on exit.
    // Safety: we're single-threaded at this point.
    unsafe { rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::NEWNS) }
        .context("unshare(CLONE_NEWNS) — are you running as root?")?;

    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
    )
    .context("Making / recursively private")?;

    // Attach the bundle tmpfs and composefs rootfs mount
    let bundle_dir = "/run/composefs-run";
    std::fs::create_dir_all(bundle_dir)?;
    composefs::mount::mount_at(bundle_tmpfs, CWD, Path::new(bundle_dir))
        .context("Attaching bundle tmpfs")?;

    let rootfs_dir = format!("{bundle_dir}/rootfs");
    composefs::mount::mount_at(mount_fd, CWD, Path::new(&rootfs_dir))
        .context("Attaching composefs mount at rootfs")?;

    let tty = if cli.tty && !std::io::stdin().is_terminal() {
        eprintln!("warning: -t specified but stdin is not a terminal, ignoring");
        false
    } else {
        cli.tty
    };

    // Generate OCI runtime spec
    let container_id = format!("composefs-{}", std::process::id());
    let systemd_mode = match cli.systemd.as_str() {
        "always" => true,
        "false" => false,
        _ => is_systemd_command(&args),
    };
    let spec = build_runtime_spec(
        &args,
        &env,
        &cwd,
        &user,
        tty,
        cli.privileged,
        &cli.cap_add,
        &cli.cap_drop,
        &cli.network,
        cli.read_only,
        cli.read_only_tmpfs,
        &cli.volumes,
        &cli.publish,
        systemd_mode,
        &container_id,
    )?;

    let config_path = format!("{bundle_dir}/config.json");
    let config_json = serde_json::to_string_pretty(&spec)?;
    fs::write(&config_path, &config_json)?;

    if cli.interactive || tty {
        // Foreground: crun run (blocks until container exits)
        let err = Command::new("crun")
            .arg("run")
            .arg("--bundle")
            .arg(bundle_dir)
            .arg(&container_id)
            .exec();
        Err(err).context("Failed to exec crun")
    } else {
        // Detached: crun create + start, redirect stdio to journal
        run_detached(
            bundle_dir,
            &container_id,
            &cli.image,
            cli.pidfile.as_deref(),
        )
    }
}

/// Create a connected journal stream fd using the sd_journal_stream_fd protocol.
fn journal_stream_fd(identifier: &str) -> Result<std::os::fd::OwnedFd> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect("/run/systemd/journal/stdout")
        .context("Connecting to journal socket")?;

    // Header: identifier, unit_id, priority, level_prefix,
    //         forward_to_syslog, forward_to_kmsg, forward_to_console
    write!(stream, "{identifier}\n\n6\n0\n0\n0\n0\n")?;
    stream.flush()?;

    Ok(std::os::fd::OwnedFd::from(stream))
}

fn run_detached(
    bundle_dir: &str,
    container_id: &str,
    image_name: &str,
    pidfile: Option<&Path>,
) -> Result<()> {
    // Set up journal stream for container stdout/stderr
    let journal_fd = journal_stream_fd(&format!("composefs-run:{image_name}"))
        .context("Creating journal stream fd")?;
    let journal_fd2 = rustix::io::dup(&journal_fd)?;

    // Always use --pid-file so we reliably get the PID even for short-lived containers
    let tmp_pidfile;
    let pidfile_path = match pidfile {
        Some(pf) => pf.to_owned(),
        None => {
            tmp_pidfile = format!("{bundle_dir}/container.pid");
            PathBuf::from(&tmp_pidfile)
        }
    };

    // crun create: set up the container but don't start it yet
    let status = Command::new("crun")
        .arg("create")
        .arg("--bundle")
        .arg(bundle_dir)
        .arg("--pid-file")
        .arg(&pidfile_path)
        .arg(container_id)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(std::fs::File::from(journal_fd)))
        .stderr(std::process::Stdio::from(std::fs::File::from(journal_fd2)))
        .status()
        .context("Failed to run crun create")?;
    ensure!(status.success(), "crun create failed: {status}");

    // crun start: release the container's init process
    let status = Command::new("crun")
        .arg("start")
        .arg(container_id)
        .status()
        .context("Failed to run crun start")?;
    ensure!(status.success(), "crun start failed: {status}");

    // Print the PID from the pidfile
    let pid = fs::read_to_string(&pidfile_path).context("Reading PID file")?;
    println!("{}", pid.trim());

    Ok(())
}

fn resolve_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: &str,
) -> Result<(ObjectID, composefs_oci::OpenConfig<ObjectID>)> {
    let img = if let Some(digest_str) = image.strip_prefix('@') {
        let digest: OciDigest = digest_str.parse().context("Parsing manifest digest")?;
        composefs_oci::OciImage::open(repo, &digest, None)?
    } else {
        composefs_oci::OciImage::open_ref(repo, image)?
    };

    let erofs_id = img
        .image_ref()
        .context("Image has no EROFS — try re-pulling")?
        .clone();

    let config = composefs_oci::open_config(repo, img.config_digest(), Some(img.config_verity()))?;

    Ok((erofs_id, config))
}

fn is_systemd_command(args: &[String]) -> bool {
    const SYSTEMD_COMMANDS: &[&str] = &[
        "systemd",
        "/usr/sbin/init",
        "/sbin/init",
        "/usr/local/sbin/init",
    ];
    args.first()
        .map(|cmd| SYSTEMD_COMMANDS.iter().any(|s| cmd.ends_with(s)))
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn build_runtime_spec(
    args: &[String],
    env: &[String],
    cwd: &str,
    user: &str,
    tty: bool,
    privileged: bool,
    cap_add: &[String],
    cap_drop: &[String],
    network: &str,
    read_only: bool,
    read_only_tmpfs: bool,
    volumes: &[String],
    publish: &[String],
    systemd_mode: bool,
    container_id: &str,
) -> Result<Spec> {
    let mut spec = Spec::default();

    // Root
    spec.set_root(Some(
        RootBuilder::default()
            .path("rootfs")
            .readonly(read_only)
            .build()?,
    ));

    // Process
    let (uid, gid) = parse_user(user)?;
    let mut env = env.to_vec();
    if systemd_mode {
        env.push(format!(
            "container_uuid={}",
            &container_id[..container_id.len().min(32)]
        ));
    }
    spec.set_process(Some(
        ProcessBuilder::default()
            .args(args.to_vec())
            .env(env)
            .cwd(cwd)
            .terminal(tty)
            .user(UserBuilder::default().uid(uid).gid(gid).build()?)
            .build()?,
    ));

    // Linux: namespaces, and privileged mode adjustments
    if let Some(linux) = spec.linux().as_ref() {
        let host_network = network == "host";
        let namespaces: Vec<LinuxNamespace> = linux
            .namespaces()
            .as_ref()
            .map(|ns| {
                ns.iter()
                    .filter(|n| !(host_network && n.typ() == LinuxNamespaceType::Network))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        let linux_spec = LinuxBuilder::default()
            .namespaces(namespaces)
            .masked_paths(if privileged {
                vec![]
            } else {
                linux.masked_paths().clone().unwrap_or_default()
            })
            .readonly_paths(if privileged {
                vec![]
            } else {
                linux.readonly_paths().clone().unwrap_or_default()
            })
            .build()?;

        spec.set_linux(Some(linux_spec));
    }

    // Capabilities: --privileged gives all, --cap-add/--cap-drop modify the default set
    if privileged || !cap_add.is_empty() || !cap_drop.is_empty() {
        use std::collections::HashSet;

        let mut caps: HashSet<Capability> = if privileged {
            all_capabilities()
        } else {
            // Start from the default set
            spec.process()
                .as_ref()
                .and_then(|p| p.capabilities().as_ref())
                .and_then(|c| c.bounding().as_ref())
                .cloned()
                .unwrap_or_default()
        };

        for cap_str in cap_add {
            if cap_str.eq_ignore_ascii_case("ALL") {
                caps = all_capabilities();
            } else {
                caps.insert(parse_capability(cap_str)?);
            }
        }
        for cap_str in cap_drop {
            if cap_str.eq_ignore_ascii_case("ALL") {
                caps.clear();
            } else {
                caps.remove(&parse_capability(cap_str)?);
            }
        }

        let linux_caps = LinuxCapabilitiesBuilder::default()
            .bounding(caps.clone())
            .effective(caps.clone())
            .inheritable(caps.clone())
            .permitted(caps.clone())
            .ambient(caps)
            .build()?;

        if let Some(process) = spec.process_mut() {
            process.set_capabilities(Some(linux_caps));
        }
    }

    // Hostname
    spec.set_hostname(Some("composefs-container".into()));

    // Mounts
    let mut mounts: Vec<_> = spec.mounts().clone().unwrap_or_default();

    // Collect paths that need writable tmpfs mounts.
    // Systemd mode and --read-only overlap on /run and /tmp; systemd mode
    // adds additional paths. We deduplicate by collecting all paths first.
    let mut tmpfs_paths = Vec::new();

    if read_only && read_only_tmpfs {
        // Matches podman --read-only --read-only-tmpfs=true behavior
        tmpfs_paths.extend_from_slice(&["/dev/shm", "/run", "/tmp", "/var/tmp"]);
    }

    if systemd_mode {
        // Systemd needs these writable; extends/overlaps with --readonly
        for path in &["/run", "/run/lock", "/tmp", "/var/log/journal"] {
            if !tmpfs_paths.contains(path) {
                tmpfs_paths.push(path);
            }
        }
    }

    let tmpfs_opts: Vec<String> = if systemd_mode {
        vec![
            "rw".into(),
            "rprivate".into(),
            "nosuid".into(),
            "nodev".into(),
            "tmpcopyup".into(),
        ]
    } else {
        vec!["nosuid".into(), "nodev".into(), "mode=1777".into()]
    };

    for path in &tmpfs_paths {
        mounts.retain(|m| m.destination() != Path::new(path));
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(path))
                .typ("tmpfs")
                .source("tmpfs")
                .options(tmpfs_opts.clone())
                .build()?,
        );
    }

    if systemd_mode {
        // Replace /sys/fs/cgroup with a writable cgroup mount
        mounts.retain(|m| m.destination() != Path::new("/sys/fs/cgroup"));
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from("/sys/fs/cgroup"))
                .typ("cgroup")
                .source("cgroup")
                .options(vec!["private".into(), "rw".into()])
                .build()?,
        );
    }

    // Bind mount volumes
    for vol in volumes {
        let (host, container, options) = parse_volume(vol)?;
        let mut opts = vec!["rbind".into()];
        if options == "ro" {
            opts.push("ro".into());
        }
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(&container))
                .typ("none")
                .source(host)
                .options(opts)
                .build()?,
        );
    }
    spec.set_mounts(Some(mounts));

    // Port publishing (informational — with host networking ports are already accessible)
    if !publish.is_empty() && network == "host" {
        eprintln!(
            "note: --publish has no effect with --network=host (ports are already accessible)"
        );
    } else if !publish.is_empty() {
        eprintln!(
            "warning: --publish with --network=private requires port forwarding (not yet implemented)"
        );
    }

    Ok(spec)
}

fn parse_capability(s: &str) -> Result<Capability> {
    // Accept CAP_NET_RAW, NET_RAW, cap_net_raw, etc.
    let normalized = s
        .strip_prefix("CAP_")
        .or_else(|| s.strip_prefix("cap_"))
        .unwrap_or(s)
        .to_ascii_uppercase();
    normalized
        .parse()
        .with_context(|| format!("Unknown capability: {s}"))
}

fn all_capabilities() -> std::collections::HashSet<Capability> {
    [
        Capability::AuditControl,
        Capability::AuditRead,
        Capability::AuditWrite,
        Capability::BlockSuspend,
        Capability::Bpf,
        Capability::CheckpointRestore,
        Capability::Chown,
        Capability::DacOverride,
        Capability::DacReadSearch,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::IpcLock,
        Capability::IpcOwner,
        Capability::Kill,
        Capability::Lease,
        Capability::LinuxImmutable,
        Capability::MacAdmin,
        Capability::MacOverride,
        Capability::Mknod,
        Capability::NetAdmin,
        Capability::NetBindService,
        Capability::NetBroadcast,
        Capability::NetRaw,
        Capability::Perfmon,
        Capability::Setfcap,
        Capability::Setgid,
        Capability::Setpcap,
        Capability::Setuid,
        Capability::SysAdmin,
        Capability::SysBoot,
        Capability::SysChroot,
        Capability::SysModule,
        Capability::SysNice,
        Capability::SysPacct,
        Capability::SysPtrace,
        Capability::SysRawio,
        Capability::SysResource,
        Capability::SysTime,
        Capability::SysTtyConfig,
        Capability::Syslog,
        Capability::WakeAlarm,
    ]
    .into_iter()
    .collect()
}

fn parse_user(user: &str) -> Result<(u32, u32)> {
    if user.is_empty() {
        return Ok((0, 0));
    }
    let parts: Vec<&str> = user.splitn(2, ':').collect();
    let uid = parts[0].parse::<u32>().with_context(|| {
        format!(
            "Non-numeric user '{}' — only numeric UIDs are supported",
            parts[0]
        )
    })?;
    let gid = if let Some(g) = parts.get(1) {
        g.parse::<u32>()
            .with_context(|| format!("Non-numeric group '{g}' — only numeric GIDs are supported"))?
    } else {
        uid
    };
    Ok((uid, gid))
}

fn parse_volume(vol: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = vol.splitn(3, ':').collect();
    ensure!(
        parts.len() >= 2,
        "Volume must be HOST:CONTAINER[:OPTIONS], got: {vol}"
    );
    let host = parts[0].to_string();
    let container = parts[1].to_string();
    let options = parts.get(2).unwrap_or(&"rw").to_string();
    Ok((host, container, options))
}

/// Create a detached tmpfs mount.
/// Returns an fd that can be used with openat/mkdirat.
fn create_detached_tmpfs() -> Result<rustix::fd::OwnedFd> {
    let fs_fd = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).context("fsopen(tmpfs)")?;
    fsconfig_create(&fs_fd).context("fsconfig_create for tmpfs")?;
    let mnt_fd = fsmount(
        &fs_fd,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )
    .context("fsmount for tmpfs")?;
    Ok(mnt_fd)
}

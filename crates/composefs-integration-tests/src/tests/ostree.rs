//! Integration tests for ostree pull functionality.

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use anyhow::Result;
use tempfile::TempDir;
use xshell::{Shell, cmd};

use composefs_oci::composefs::fsverity::Sha256HashValue;
use composefs_oci::composefs::repository::Repository;

use crate::integration_test;
use composefs_integration_tests::create_test_repository;

/// Create test content for an ostree commit.
///
/// `version` controls what content is generated, allowing two versions
/// to differ in ways that exercise different delta code paths:
/// - Files unchanged between versions (inherited from base)
/// - Small files added/removed (OPEN_SPLICE_AND_CLOSE)
/// - Large files with minor edits (BSPATCH / rollsum)
/// - New large files (fallback candidates)
/// - Symlinks with changed targets
/// - Nested directory changes (new dirtree metadata)
fn create_ostree_test_content(parent: &Path, version: u32) -> Result<std::path::PathBuf> {
    let root = parent.join("content");
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(root.join("bin"))?;
    std::fs::create_dir_all(root.join("subdir"))?;
    std::fs::create_dir_all(root.join("lib"))?;
    std::fs::create_dir_all(root.join("share/locale"))?;
    std::fs::create_dir_all(root.join("share/icons"))?;

    // --- Files unchanged between versions ---

    // Small file (inlined by ostree)
    std::fs::write(root.join("README"), "This is a test application.\n")?;
    // Medium file
    std::fs::write(
        root.join("share/locale/messages.po"),
        "msgid \"hello\"\nmsgstr \"world\"\n".repeat(50),
    )?;
    // Large binary (external object, shared across versions)
    let mut shared_data = vec![0u8; 64 * 1024];
    for (i, b) in shared_data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    std::fs::write(root.join("lib/libshared.so"), &shared_data)?;
    // Duplicate (tests deduplication)
    std::fs::write(root.join("lib/libshared.so.1"), &shared_data)?;

    // File with xattr (unchanged across versions)
    let xattr_file = root.join("share/icons/app.png");
    std::fs::write(
        &xattr_file,
        vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    )?;
    rustix::fs::setxattr(
        &xattr_file,
        c"user.testxattr",
        b"testvalue",
        rustix::fs::XattrFlags::CREATE,
    )?;

    // Symlink (unchanged across versions)
    std::os::unix::fs::symlink("libshared.so.1", root.join("lib/libcompat.so"))?;

    // --- Files that vary by version ---

    // Small config file that changes between versions
    std::fs::write(
        root.join("config.ini"),
        format!("[app]\nversion={version}\nname=testapp\n"),
    )?;

    // Large binary with a minor edit (triggers bspatch in delta)
    let mut app_binary = vec![0u8; 256 * 1024];
    for (i, b) in app_binary.iter_mut().enumerate() {
        *b = ((i * 7 + 13) % 256) as u8;
    }
    // Embed version near the start so most of the file is unchanged
    let version_bytes = version.to_le_bytes();
    app_binary[100..104].copy_from_slice(&version_bytes);
    app_binary[200..204].copy_from_slice(&version_bytes);
    std::fs::write(root.join("bin/app"), &app_binary)?;

    // Another large file with version-dependent content
    let mut data_file = vec![0u8; 128 * 1024];
    for (i, b) in data_file.iter_mut().enumerate() {
        *b = ((i * 3 + version as usize) % 256) as u8;
    }
    std::fs::write(root.join("share/data.bin"), &data_file)?;

    // Symlink that changes target between versions
    std::os::unix::fs::symlink(
        format!("libshared.so.{version}"),
        root.join("lib/libcurrent.so"),
    )?;

    // Nested file that changes
    std::fs::write(
        root.join("subdir/nested.txt"),
        format!("nested content version {version}\n"),
    )?;

    // Version-specific files (v2 adds extra files, simulating a real update)
    if version >= 2 {
        std::fs::create_dir_all(root.join("share/new-feature"))?;
        std::fs::write(
            root.join("share/new-feature/data.json"),
            r#"{"feature": "new", "enabled": true}"#,
        )?;
        // A new large file (potential fallback in delta)
        let new_large = vec![0xCDu8; 192 * 1024];
        std::fs::write(root.join("share/new-feature/resource.bin"), &new_large)?;
    }

    Ok(root)
}

fn init_ostree_repo(sh: &Shell, path: &Path, mode: &str) -> Result<()> {
    let path = path.to_str().unwrap();
    cmd!(sh, "ostree init --repo={path} --mode={mode}").run()?;
    Ok(())
}

fn commit_to_ostree(sh: &Shell, repo: &Path, branch: &str, srcdir: &Path) -> Result<String> {
    let repo = repo.to_str().unwrap();
    let srcdir = srcdir.to_str().unwrap();
    let output = cmd!(sh, "ostree commit --repo={repo} --branch={branch} {srcdir}").read()?;
    Ok(output.trim().to_string())
}

fn pull_and_get_image_id(
    repo: &Arc<Repository<Sha256HashValue>>,
    ostree_repo_path: &Path,
    ostree_ref: &str,
    base_name: Option<&str>,
) -> Result<(Sha256HashValue, composefs_ostree::PullStats)> {
    let rt = tokio::runtime::Runtime::new()?;
    let ostree_repo =
        composefs_ostree::LocalRepo::open_path(repo, rustix::fs::CWD, ostree_repo_path)?;
    let opts = composefs_ostree::PullOptions {
        base_reference: base_name,
        ..Default::default()
    };
    let (_obj_id, stats) =
        rt.block_on(composefs_ostree::pull(repo, ostree_repo, ostree_ref, opts))?;

    let image_id = composefs_ostree::get_image_ref(repo, ostree_ref)?;

    Ok((image_id, stats))
}

fn test_ostree_pull_local_all_modes() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path(), 1)?;

    // Commit to archive-z2 first — some modes can't be committed to directly
    let archive_repo = tmpdir.path().join("ostree-archive-z2");
    init_ostree_repo(&sh, &archive_repo, "archive-z2")?;
    commit_to_ostree(&sh, &archive_repo, "test", &content)?;

    // bare-user-only needs a commit with uid=0, gid=0, no xattrs
    let buo_archive = tmpdir.path().join("ostree-buo-archive");
    init_ostree_repo(&sh, &buo_archive, "archive-z2")?;
    let buo_archive_str = buo_archive.to_str().unwrap();
    let content_str = content.to_str().unwrap();
    cmd!(
        sh,
        "ostree commit --repo={buo_archive_str} --branch=test --owner-uid=0 --owner-gid=0 --no-xattrs {content_str}"
    )
    .run()?;

    // bare-split-xattrs: ostree CLI doesn't support committing/pulling into this mode.
    let modes = ["archive-z2", "bare-user", "bare", "bare-user-only"];

    let mut image_ids: Vec<(String, Sha256HashValue)> = Vec::new();

    for mode in &modes {
        let ostree_repo_path = if *mode == "archive-z2" {
            archive_repo.clone()
        } else {
            let p = tmpdir.path().join(format!("ostree-{mode}"));
            init_ostree_repo(&sh, &p, mode)?;
            let source = if *mode == "bare-user-only" {
                &buo_archive
            } else {
                &archive_repo
            };
            let src = source.to_str().unwrap();
            let dst = p.to_str().unwrap();
            cmd!(sh, "ostree pull-local --repo={dst} {src} test").run()?;
            p
        };

        let composefs_dir = TempDir::new()?;
        let repo = create_test_repository(&composefs_dir)?;

        let (image_id, stats) = pull_and_get_image_id(&repo, &ostree_repo_path, "test", None)?;

        assert!(
            stats.metadata_fetched > 0,
            "{mode}: expected metadata_fetched > 0"
        );
        assert!(
            stats.files_fetched > 0,
            "{mode}: expected files_fetched > 0"
        );

        image_ids.push((mode.to_string(), image_id));
    }

    // bare-user-only uses a different commit (uid=0, gid=0, no xattrs),
    // so its image ID will differ from the others.
    let first_id = &image_ids[0].1;
    for (mode, id) in &image_ids[1..] {
        if mode == "bare-user-only" {
            continue;
        }
        assert_eq!(first_id, id, "image ID from {mode} differs from archive-z2");
    }

    Ok(())
}
integration_test!(test_ostree_pull_local_all_modes);

fn test_ostree_pull_remote_archive() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path(), 1)?;

    // Create archive-z2 repo and commit
    let ostree_repo_path = tmpdir.path().join("ostree-archive");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    commit_to_ostree(&sh, &ostree_repo_path, "test", &content)?;

    // Pull locally first to get reference image ID
    let composefs_dir_local = TempDir::new()?;
    let repo_local = create_test_repository(&composefs_dir_local)?;
    let (local_image_id, _) = pull_and_get_image_id(&repo_local, &ostree_repo_path, "test", None)?;

    // Pull via HTTP and compare
    let server = HttpServer::start(&ostree_repo_path)?;
    let composefs_dir_remote = TempDir::new()?;
    let repo_remote = create_test_repository(&composefs_dir_remote)?;

    let rt = tokio::runtime::Runtime::new()?;
    let ostree_repo = composefs_ostree::RemoteRepo::new(&repo_remote, &server.url())?;
    let (_obj_id, stats) = rt.block_on(composefs_ostree::pull(
        &repo_remote,
        ostree_repo,
        "test",
        Default::default(),
    ))?;

    assert!(stats.metadata_fetched > 0);
    assert!(stats.files_fetched > 0);

    let remote_image_id = composefs_ostree::get_image_ref(&repo_remote, "test")?;

    assert_eq!(
        local_image_id, remote_image_id,
        "remote pull image ID differs from local pull"
    );

    Ok(())
}
integration_test!(test_ostree_pull_remote_archive);

fn test_ostree_pull_with_base() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path(), 1)?;

    // Create archive-z2 repo with initial commit on branch "commit-a"
    let ostree_repo_path = tmpdir.path().join("ostree-repo");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    commit_to_ostree(&sh, &ostree_repo_path, "commit-a", &content)?;

    // Pull commit A
    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;

    let rt = tokio::runtime::Runtime::new()?;
    let ostree_repo =
        composefs_ostree::LocalRepo::open_path(&repo, rustix::fs::CWD, &ostree_repo_path)?;
    let (_, _stats_a) = rt.block_on(composefs_ostree::pull(
        &repo,
        ostree_repo,
        "commit-a",
        Default::default(),
    ))?;

    // Create version 2 content and commit as branch B
    let content_v2 = create_ostree_test_content(tmpdir.path(), 2)?;
    commit_to_ostree(&sh, &ostree_repo_path, "commit-b", &content_v2)?;

    // Pull commit B with base
    let ostree_repo =
        composefs_ostree::LocalRepo::open_path(&repo, rustix::fs::CWD, &ostree_repo_path)?;
    let opts = composefs_ostree::PullOptions {
        base_reference: Some("commit-a"),
        ..Default::default()
    };
    let (_, stats_with_base) =
        rt.block_on(composefs_ostree::pull(&repo, ostree_repo, "commit-b", opts))?;

    // Pull commit B without base into a fresh repo
    let composefs_dir2 = TempDir::new()?;
    let repo2 = create_test_repository(&composefs_dir2)?;
    let ostree_repo =
        composefs_ostree::LocalRepo::open_path(&repo2, rustix::fs::CWD, &ostree_repo_path)?;
    let (_, stats_without_base) = rt.block_on(composefs_ostree::pull(
        &repo2,
        ostree_repo,
        "commit-b",
        Default::default(),
    ))?;

    assert!(
        stats_with_base.files_fetched < stats_without_base.files_fetched,
        "expected base pull to fetch fewer files: with_base={} vs without_base={}",
        stats_with_base.files_fetched,
        stats_without_base.files_fetched,
    );

    // Both should produce the same image
    let image_id1 = composefs_ostree::get_image_ref(&repo, "commit-b")?;
    let image_id2 = composefs_ostree::get_image_ref(&repo2, "commit-b")?;

    assert_eq!(
        image_id1, image_id2,
        "image IDs should match with and without base"
    );

    Ok(())
}
integration_test!(test_ostree_pull_with_base);

struct HttpServer {
    child: std::process::Child,
    port: u16,
}

impl HttpServer {
    fn start(directory: &Path) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let child = Command::new("python3")
            .args([
                "-m",
                "http.server",
                &port.to_string(),
                "--directory",
                directory.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        std::thread::sleep(std::time::Duration::from_millis(500));
        Ok(HttpServer { child, port })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn generate_delta(sh: &Shell, repo: &Path, from: Option<&str>, to: &str) -> Result<()> {
    let repo = repo.to_str().unwrap();
    if let Some(from) = from {
        cmd!(
            sh,
            "ostree static-delta generate --repo={repo} --from={from} --to={to}"
        )
        .run()?;
    } else {
        cmd!(
            sh,
            "ostree static-delta generate --repo={repo} --empty --to={to}"
        )
        .run()?;
    }
    Ok(())
}

fn update_summary(sh: &Shell, repo: &Path) -> Result<()> {
    let repo = repo.to_str().unwrap();
    cmd!(sh, "ostree summary --repo={repo} --update").run()?;
    Ok(())
}

fn test_ostree_pull_remote_scratch_delta() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path(), 1)?;

    let ostree_repo_path = tmpdir.path().join("ostree-archive");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    let commit_id = commit_to_ostree(&sh, &ostree_repo_path, "test", &content)?;

    generate_delta(&sh, &ostree_repo_path, None, &commit_id)?;
    update_summary(&sh, &ostree_repo_path)?;

    // Pull via direct object fetch for reference
    let composefs_dir_ref = TempDir::new()?;
    let repo_ref = create_test_repository(&composefs_dir_ref)?;
    let (ref_image_id, _) = pull_and_get_image_id(&repo_ref, &ostree_repo_path, "test", None)?;

    // Pull via HTTP with delta
    let server = HttpServer::start(&ostree_repo_path)?;
    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;

    let rt = tokio::runtime::Runtime::new()?;
    let ostree_repo = composefs_ostree::RemoteRepo::new(&repo, &server.url())?;
    let (_, stats) = rt.block_on(composefs_ostree::pull(
        &repo,
        ostree_repo,
        "test",
        Default::default(),
    ))?;

    assert!(
        stats.delta_parts_applied > 0,
        "expected delta to be used, but delta_parts_applied=0"
    );

    let delta_image_id = composefs_ostree::get_image_ref(&repo, "test")?;
    assert_eq!(
        ref_image_id, delta_image_id,
        "scratch delta image ID differs from local pull"
    );

    Ok(())
}
integration_test!(test_ostree_pull_remote_scratch_delta);

fn test_ostree_pull_remote_diff_delta() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;

    let ostree_repo_path = tmpdir.path().join("ostree-archive");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;

    let content_v1 = create_ostree_test_content(tmpdir.path(), 1)?;
    let commit_a = commit_to_ostree(&sh, &ostree_repo_path, "branch-a", &content_v1)?;

    let content_v2 = create_ostree_test_content(tmpdir.path(), 2)?;
    let commit_b = commit_to_ostree(&sh, &ostree_repo_path, "branch-b", &content_v2)?;

    generate_delta(&sh, &ostree_repo_path, Some(&commit_a), &commit_b)?;
    update_summary(&sh, &ostree_repo_path)?;

    // Pull commit B via direct local pull for reference image ID
    let composefs_dir_ref = TempDir::new()?;
    let repo_ref = create_test_repository(&composefs_dir_ref)?;
    let (ref_image_id, _) = pull_and_get_image_id(&repo_ref, &ostree_repo_path, "branch-b", None)?;

    // Pull over HTTP: first commit A (no delta), then commit B (should use diff delta)
    let server = HttpServer::start(&ostree_repo_path)?;
    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;

    let rt = tokio::runtime::Runtime::new()?;

    let ostree_repo = composefs_ostree::RemoteRepo::new(&repo, &server.url())?;
    rt.block_on(composefs_ostree::pull(
        &repo,
        ostree_repo,
        "branch-a",
        Default::default(),
    ))?;

    let ostree_repo = composefs_ostree::RemoteRepo::new(&repo, &server.url())?;
    let (_, stats_b) = rt.block_on(composefs_ostree::pull(
        &repo,
        ostree_repo,
        "branch-b",
        Default::default(),
    ))?;

    assert!(
        stats_b.delta_parts_applied > 0,
        "expected differential delta to be used, but delta_parts_applied=0"
    );

    let delta_image_id = composefs_ostree::get_image_ref(&repo, "branch-b")?;
    assert_eq!(
        ref_image_id, delta_image_id,
        "differential delta image ID differs from local pull"
    );

    Ok(())
}
integration_test!(test_ostree_pull_remote_diff_delta);

fn test_ostree_commit_roundtrip() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path(), 1)?;

    let ostree_repo_path = tmpdir.path().join("ostree-repo");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    let original_commit_id = commit_to_ostree(&sh, &ostree_repo_path, "original", &content)?;

    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;
    pull_and_get_image_id(&repo, &ostree_repo_path, "original", None)?;

    // Read the original commit's metadata and filesystem
    let fs = composefs_ostree::create_filesystem(&repo, "original")?;
    let commit = composefs_ostree::read_commit(&repo, "original")?;
    let commit_meta = commit.commit_metadata();

    // Recreate the commit — should produce the same commit ID
    let (_, roundtrip_commit_id) =
        composefs_ostree::commit_filesystem(&repo, &fs, commit_meta, None)?;

    assert_eq!(
        original_commit_id, roundtrip_commit_id,
        "roundtrip commit ID differs from original"
    );

    Ok(())
}
integration_test!(test_ostree_commit_roundtrip);

fn test_ostree_apply_delta_offline() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;

    let ostree_repo_path = tmpdir.path().join("ostree-archive");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;

    let content_v1 = create_ostree_test_content(tmpdir.path(), 1)?;
    let commit_a = commit_to_ostree(&sh, &ostree_repo_path, "branch-a", &content_v1)?;

    let content_v2 = create_ostree_test_content(tmpdir.path(), 2)?;
    let commit_b = commit_to_ostree(&sh, &ostree_repo_path, "branch-b", &content_v2)?;

    // Generate an inline delta file
    let delta_file = tmpdir.path().join("delta.bin");
    let repo_str = ostree_repo_path.to_str().unwrap();
    let delta_str = delta_file.to_str().unwrap();
    cmd!(
        sh,
        "ostree static-delta generate --repo={repo_str} --from={commit_a} --to={commit_b} --inline --filename={delta_str}"
    )
    .run()?;

    // Pull commit A, then apply delta
    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;

    let ostree_repo =
        composefs_ostree::LocalRepo::open_path(&repo, rustix::fs::CWD, &ostree_repo_path)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(composefs_ostree::pull(
        &repo,
        ostree_repo,
        "branch-a",
        Default::default(),
    ))?;

    let (_, delta_stats) = composefs_ostree::apply_delta_offline(&repo, &delta_file)?;
    assert!(delta_stats.metadata_fetched > 0);

    // Pull commit B directly for reference
    let composefs_dir_ref = TempDir::new()?;
    let repo_ref = create_test_repository(&composefs_dir_ref)?;
    let (ref_image_id, _) = pull_and_get_image_id(&repo_ref, &ostree_repo_path, "branch-b", None)?;

    let delta_image_id = composefs_ostree::get_image_ref(&repo, &delta_stats.commit_id)?;
    assert_eq!(
        ref_image_id, delta_image_id,
        "offline delta image ID differs from local pull"
    );

    Ok(())
}
integration_test!(test_ostree_apply_delta_offline);

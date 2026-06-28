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

fn create_ostree_test_content(parent: &Path) -> Result<std::path::PathBuf> {
    let root = parent.join("content");
    std::fs::create_dir_all(root.join("subdir"))?;

    // Small file (will be inlined by ostree)
    std::fs::write(root.join("small.txt"), "hello")?;
    // Large file (external object)
    std::fs::write(root.join("large.bin"), vec![0xABu8; 128 * 1024])?;
    // Duplicate of large file (shared object)
    std::fs::write(root.join("large-dup.bin"), vec![0xABu8; 128 * 1024])?;
    // Symlink
    std::os::unix::fs::symlink("small.txt", root.join("link.txt"))?;
    // Nested file
    std::fs::write(root.join("subdir/nested.txt"), "nested content")?;

    // File with xattr
    let xattr_file = root.join("with-xattr.txt");
    std::fs::write(&xattr_file, "has xattr")?;
    rustix::fs::setxattr(
        &xattr_file,
        c"user.testxattr",
        b"testvalue",
        rustix::fs::XattrFlags::CREATE,
    )?;

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
    let (_obj_id, stats) = rt.block_on(composefs_ostree::pull_local(
        repo,
        ostree_repo_path,
        ostree_ref,
        base_name,
    ))?;

    let image_id = composefs_ostree::get_image_ref(repo, ostree_ref)?;

    Ok((image_id, stats))
}

fn test_ostree_pull_local_all_modes() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path())?;

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
    let content = create_ostree_test_content(tmpdir.path())?;

    // Create archive-z2 repo and commit
    let ostree_repo_path = tmpdir.path().join("ostree-archive");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    commit_to_ostree(&sh, &ostree_repo_path, "test", &content)?;

    // Pull locally first to get reference image ID
    let composefs_dir_local = TempDir::new()?;
    let repo_local = create_test_repository(&composefs_dir_local)?;
    let (local_image_id, _) = pull_and_get_image_id(&repo_local, &ostree_repo_path, "test", None)?;

    // Find a free port and start HTTP server
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let repo_path_str = ostree_repo_path.to_str().unwrap().to_string();
    let mut server = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--directory",
            &repo_path_str,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let result = (|| -> Result<()> {
        // Poll the server until it is ready
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);
        let delay = std::time::Duration::from_millis(50);
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse()?;

        loop {
            if std::net::TcpStream::connect_timeout(&addr, delay).is_ok() {
                break;
            }
            if start_time.elapsed() >= timeout {
                anyhow::bail!("python3 http.server did not become ready on port {port} within 10s");
            }
            std::thread::sleep(delay);
        }

        let composefs_dir_remote = TempDir::new()?;
        let repo_remote = create_test_repository(&composefs_dir_remote)?;

        let rt = tokio::runtime::Runtime::new()?;
        let url = format!("http://127.0.0.1:{port}");
        let (_obj_id, stats) =
            rt.block_on(composefs_ostree::pull(&repo_remote, &url, "test", None))?;

        assert!(stats.metadata_fetched > 0);
        assert!(stats.files_fetched > 0);

        let remote_image_id = composefs_ostree::get_image_ref(&repo_remote, "test")?;

        assert_eq!(
            local_image_id, remote_image_id,
            "remote pull image ID differs from local pull"
        );

        Ok(())
    })();

    server.kill().ok();
    server.wait().ok();

    result
}
integration_test!(test_ostree_pull_remote_archive);

fn test_ostree_pull_with_base() -> Result<()> {
    let sh = Shell::new()?;
    let tmpdir = TempDir::new()?;
    let content = create_ostree_test_content(tmpdir.path())?;

    // Create archive-z2 repo with initial commit on branch "commit-a"
    let ostree_repo_path = tmpdir.path().join("ostree-repo");
    init_ostree_repo(&sh, &ostree_repo_path, "archive-z2")?;
    commit_to_ostree(&sh, &ostree_repo_path, "commit-a", &content)?;

    // Pull commit A
    let composefs_dir = TempDir::new()?;
    let repo = create_test_repository(&composefs_dir)?;

    let rt = tokio::runtime::Runtime::new()?;
    let (_, _stats_a) = rt.block_on(composefs_ostree::pull_local(
        &repo,
        &ostree_repo_path,
        "commit-a",
        None,
    ))?;

    // Modify content slightly and make commit B on branch "commit-b"
    std::fs::write(content.join("new-file.txt"), "new content for commit B")?;
    commit_to_ostree(&sh, &ostree_repo_path, "commit-b", &content)?;

    // Pull commit B with base
    let (_, stats_with_base) = rt.block_on(composefs_ostree::pull_local(
        &repo,
        &ostree_repo_path,
        "commit-b",
        Some("commit-a"),
    ))?;

    // Pull commit B without base into a fresh repo
    let composefs_dir2 = TempDir::new()?;
    let repo2 = create_test_repository(&composefs_dir2)?;
    let (_, stats_without_base) = rt.block_on(composefs_ostree::pull_local(
        &repo2,
        &ostree_repo_path,
        "commit-b",
        None,
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

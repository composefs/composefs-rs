//! Bootloader entry parsing and manipulation.
//!
//! This module provides functionality to parse and manipulate Boot Loader Specification
//! entries and Unified Kernel Images (UKIs). It supports Type 1 BLS entries with separate
//! kernel and initrd files, Type 2 UKI files, traditional vmlinuz/initramfs pairs,
//! and aboot payloads. Key types include `BootLoaderEntryFile` for parsing BLS
//! configuration files and `BootEntry` for representing boot entry types.

use core::ops::Range;
use std::{
    collections::HashMap, ffi::OsStr, io::Cursor, os::unix::ffi::OsStrExt, path::Path,
    path::PathBuf, str::from_utf8,
};

use anyhow::{Context, Result, bail};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    tree::{DirectoryRef, FileSystem, ImageError, Inode, LeafContent, RegularFile},
};

use crate::{android_boot::AndroidBootImage, cmdline::split_cmdline, uki};

/// Strips the key (if it matches) plus the following whitespace from a single line in a "Type #1
/// Boot Loader Specification Entry" file.
///
/// The line needs to start with the name of the key, followed by at least one whitespace
/// character.  The whitespace is consumed.  If the current line doesn't match the key, None is
/// returned.
fn strip_ble_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    if !rest.chars().next()?.is_ascii_whitespace() {
        return None;
    }
    Some(rest.trim_start())
}

// https://doc.rust-lang.org/std/primitive.str.html#method.substr_range
fn substr_range(parent: &str, substr: &str) -> Option<Range<usize>> {
    let parent_start = parent as *const str as *const u8 as usize;
    let parent_end = parent_start + parent.len();
    let substr_start = substr as *const str as *const u8 as usize;
    let substr_end = substr_start + substr.len();

    if parent_start <= substr_start && substr_end <= parent_end {
        Some((substr_start - parent_start)..(substr_end - parent_start))
    } else {
        None
    }
}

/// Represents a parsed Boot Loader Specification entry file.
///
/// Contains the lines of a BLS .conf file and provides methods to query and modify
/// entries like kernel paths, initrd files, and command-line options.
#[derive(Debug)]
pub struct BootLoaderEntryFile {
    /// Lines from the bootloader entry configuration file
    pub lines: Vec<String>,
}

impl BootLoaderEntryFile {
    /// Creates a new bootloader entry file by parsing the content.
    ///
    /// # Arguments
    ///
    /// * `content` - The text content of the BLS entry file
    ///
    /// # Returns
    ///
    /// A new `BootLoaderEntryFile` with lines split on newlines
    pub fn new(content: &str) -> Self {
        Self {
            lines: content.split_terminator('\n').map(String::from).collect(),
        }
    }

    /// Returns an iterator over all values for a given key in the entry file.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to search for (e.g., "initrd", "options")
    ///
    /// # Returns
    ///
    /// An iterator yielding the value portion of each matching line
    pub fn get_values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.lines
            .iter()
            .filter_map(|line| strip_ble_key(line, key))
    }

    /// Returns the first value for a given key in the entry file.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to search for (e.g., "linux", "title")
    ///
    /// # Returns
    ///
    /// The value portion of the first matching line, or None if not found
    pub fn get_value(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| strip_ble_key(line, key))
    }

    /// Adds a kernel command-line argument, possibly replacing a previous value.
    ///
    /// arg can be something like "composefs=xyz" but it can also be something like "rw".  In
    /// either case, if the argument already existed, it will be replaced.
    pub fn add_cmdline(&mut self, arg: &str) {
        let key = match arg.find('=') {
            Some(pos) => &arg[..=pos], // include the '='
            None => arg,
        };

        // There are three possible paths in this function:
        //   1. options line with key= already in it (replace it)
        //   2. options line with no key= in it (append key=value)
        //   3. no options line (append the entire thing)
        for line in &mut self.lines {
            if let Some(cmdline) = strip_ble_key(line, "options") {
                let segment = split_cmdline(cmdline).find(|s| s.starts_with(key));

                if let Some(old) = segment {
                    // 1. Replace existing key
                    let range = substr_range(line, old).unwrap();
                    line.replace_range(range, arg);
                } else {
                    // 2. Append new argument
                    line.push(' ');
                    line.push_str(arg);
                }

                return;
            }
        }

        // 3. Append new "options" line with our argument
        self.lines.push(format!("options {arg}"));
    }

    /// Adjusts the kernel command-line arguments by adding a composefs karg (if provided)
    /// and adding additional arguments.
    ///
    /// `karg` should be a complete kernel argument string such as
    /// `"composefs.digest=v1-sha256-12:abc123"` or `"composefs=abc123"` as produced by
    /// [`composefs_boot::cmdline::ComposefsCmdline::to_cmdline_arg`].
    pub fn adjust_cmdline(&mut self, karg: Option<&str>, extra: &[&str]) {
        if let Some(k) = karg {
            self.add_cmdline(k);
        }

        for item in extra {
            self.add_cmdline(item);
        }
    }
}

/// Represents a Boot Loader Specification Type 1 entry.
///
/// Type 1 entries have separate kernel and initrd files referenced from a .conf file.
/// This structure contains both the parsed configuration and the actual file objects.
#[derive(Debug)]
pub struct Type1Entry<ObjectID: FsVerityHashValue> {
    /// The basename of the bootloader entry .conf file
    pub filename: Box<OsStr>,
    /// The parsed bootloader entry configuration
    pub entry: BootLoaderEntryFile,
    /// Map of file paths to their corresponding file objects (kernel, initrd, etc.)
    pub files: HashMap<Box<str>, RegularFile<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> Type1Entry<ObjectID> {
    /// Relocates boot resources to a new entry ID directory.
    ///
    /// This moves all referenced files (kernel, initrd, etc.) into a directory named after
    /// the entry_id and updates the entry configuration to match. The entry file itself is
    /// renamed to "{entry_id}.conf".
    ///
    /// # Arguments
    ///
    /// * `boot_subdir` - Optional subdirectory to prepend to paths in the entry file
    /// * `entry_id` - The new entry identifier to use for the directory and filename
    pub fn relocate(&mut self, boot_subdir: Option<&str>, entry_id: &str) {
        self.filename = Box::from(format!("{entry_id}.conf").as_ref());
        for line in &mut self.entry.lines {
            for key in ["linux", "initrd", "efi"] {
                let Some(value) = strip_ble_key(line, key) else {
                    continue;
                };
                let Some((_dir, basename)) = value.rsplit_once("/") else {
                    continue;
                };

                let file = self.files.remove(value);

                let new = format!("/{entry_id}/{basename}");
                let range = substr_range(line, value).unwrap();

                let final_entry_path = if let Some(boot_subdir) = boot_subdir {
                    format!("/{boot_subdir}{new}")
                } else {
                    new.clone()
                };

                line.replace_range(range, &final_entry_path);

                if let Some(file) = file {
                    self.files.insert(new.into_boxed_str(), file);
                }
            }
        }
    }

    /// Loads a Type 1 boot entry from a BLS .conf file.
    ///
    /// Parses the configuration file and loads all referenced boot resources (kernel, initrd, etc.)
    /// from the filesystem.
    ///
    /// # Arguments
    ///
    /// * `filename` - Name of the .conf file
    /// * `file` - The configuration file object
    /// * `root` - Root directory of the filesystem
    /// * `repo` - The composefs repository
    ///
    /// # Returns
    ///
    /// A fully loaded Type1Entry with all referenced files
    pub fn load(
        filename: &OsStr,
        file: &RegularFile<ObjectID>,
        root: DirectoryRef<'_, ObjectID>,
        repo: &Repository<ObjectID>,
    ) -> Result<Self> {
        let entry = BootLoaderEntryFile::new(from_utf8(&composefs::fs::read_file(file, repo)?)?);

        let mut files = HashMap::new();
        for key in ["linux", "initrd", "efi"] {
            for pathname in entry.get_values(key) {
                let (dir, filename) = root.split_ref(pathname.as_ref())?;
                files.insert(Box::from(pathname), dir.get_file(filename)?.clone());
            }
        }

        Ok(Self {
            filename: Box::from(filename),
            entry,
            files,
        })
    }

    /// Loads all Type 1 boot entries from /boot/loader/entries.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the filesystem
    /// * `repo` - The composefs repository
    ///
    /// # Returns
    ///
    /// A vector of all Type1Entry objects found in /boot/loader/entries
    pub fn load_all(fs: &FileSystem<ObjectID>, repo: &Repository<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];
        let root = fs.as_dir();

        match root.get_directory_ref("/boot/loader/entries".as_ref()) {
            Ok(entries_dir) => {
                for (filename, inode) in entries_dir.entries() {
                    if !filename.as_bytes().ends_with(b".conf") {
                        continue;
                    }

                    let Inode::Leaf(leaf_id, _) = inode else {
                        bail!("/boot/loader/entries/{filename:?} is a directory");
                    };

                    let leaf = fs.leaf(*leaf_id);
                    let LeafContent::Regular(file) = &leaf.content else {
                        bail!("/boot/loader/entries/{filename:?} is not a regular file");
                    };

                    entries.push(Self::load(filename, file, root, repo)?);
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

/// File extension for EFI executables
pub const EFI_EXT: &str = ".efi";
/// Directory extension for UKI addon directories
pub const EFI_ADDON_DIR_EXT: &str = ".efi.extra.d";
/// File extension for UKI addon files
pub const EFI_ADDON_FILE_EXT: &str = ".addon.efi";

/// Type of Portable Executable (PE) file for boot.
#[derive(Debug)]
pub enum PEType {
    /// A Unified Kernel Image
    Uki,
    /// A UKI addon scoped to the found UKI
    UkiAddon,
    /// A global UKI addon applicable for all UKIs
    GlobalUkiAddon,
}

/// Represents a Boot Loader Specification Type 2 entry (Unified Kernel Image).
///
/// Type 2 entries are UKI files that bundle the kernel, initrd, and other components
/// into a single EFI executable.
#[derive(Debug)]
pub struct Type2Entry<ObjectID: FsVerityHashValue> {
    /// Kernel version string, if found in /usr/lib/modules
    pub kver: Option<Box<OsStr>>,
    /// Path to the file (relative to /boot/EFI/Linux)
    pub file_path: PathBuf,
    /// The Portable Executable binary
    pub file: RegularFile<ObjectID>,
    /// Type of PE file (UKI or UKI addon)
    pub pe_type: PEType,
}

impl<ObjectID: FsVerityHashValue> Type2Entry<ObjectID> {
    /// Renames the UKI file to a new name.
    ///
    /// # Arguments
    ///
    /// * `name` - New base name (without .efi extension)
    pub fn rename(&mut self, name: &str) {
        let new_name = format!("{name}.efi");

        if let Some(parent) = self.file_path.parent() {
            self.file_path = parent.join(new_name);
        } else {
            self.file_path = new_name.into();
        }
    }

    // Find UKI components, the UKI PE binary and other UKI addons,
    // if any, in the provided directory
    fn find_uki_components(
        dir: DirectoryRef<'_, ObjectID>,
        entries: &mut Vec<Self>,
        path: &mut PathBuf,
        kver: &Option<Box<OsStr>>,
        global_addons: bool,
    ) -> Result<()> {
        for (filename, inode) in dir.entries() {
            path.push(filename);

            if let Inode::Directory(subdir) = inode {
                let subdir_ref = DirectoryRef::from_parts(subdir, dir.leaves());
                Self::find_uki_components(subdir_ref, entries, path, kver, global_addons)?;
                path.pop();
                continue;
            }

            if !filename.as_bytes().ends_with(EFI_EXT.as_bytes()) {
                path.pop();
                continue;
            }

            let Inode::Leaf(leaf_id, _) = inode else {
                bail!("{filename:?} is a directory");
            };

            let leaf = dir.leaf(*leaf_id);
            let LeafContent::Regular(file) = &leaf.content else {
                bail!("{filename:?} is not a regular file");
            };

            let pe_type = if filename.as_bytes().ends_with(EFI_ADDON_FILE_EXT.as_bytes()) {
                if global_addons {
                    PEType::GlobalUkiAddon
                } else {
                    PEType::UkiAddon
                }
            } else {
                // We already filter by .efi extension
                PEType::Uki
            };

            entries.push(Self {
                kver: kver.clone(),
                file_path: path.clone(),
                file: file.clone(),
                pe_type,
            });

            path.pop();
        }

        Ok(())
    }

    /// Loads all Type 2 boot entries from /boot/EFI/Linux and /usr/lib/modules.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the filesystem
    ///
    /// # Returns
    ///
    /// A vector of all Type2Entry objects found
    pub fn load_all(fs: &FileSystem<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];
        let root = fs.as_dir();

        // Collect all UKI extensions as well
        // Usually we'll find them in the root with directories ending in `.efi.extra.d` for kernel
        // specific addons. Global addons are found in `loader/addons`
        let paths = [
            // Gather UKI and deployment specific UKI Addons
            ("/boot/EFI/Linux", false),
            // Gather global UKI Addons if any
            ("/boot/loader/addons", true),
        ];

        for (p, global_addons) in paths {
            match root.get_directory_ref(p.as_ref()) {
                Ok(entries_dir) => Self::find_uki_components(
                    entries_dir,
                    &mut entries,
                    &mut PathBuf::new(),
                    &None,
                    global_addons,
                )?,
                Err(ImageError::NotFound(..)) => {}
                Err(other) => Err(other)?,
            };
        }

        match root.get_directory_ref("/usr/lib/modules".as_ref()) {
            Ok(modules_dir) => {
                for (kver, inode) in modules_dir.entries() {
                    let Inode::Directory(dir) = inode else {
                        continue;
                    };

                    let dir_ref = DirectoryRef::from_parts(dir, root.leaves());
                    Self::find_uki_components(
                        dir_ref,
                        &mut entries,
                        &mut PathBuf::new(),
                        &Some(Box::from(kver)),
                        false,
                    )?;
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

/// Represents a traditional vmlinuz/initramfs pair from /usr/lib/modules.
///
/// This is for kernels found in /usr/lib/modules/{kver}/ that have a vmlinuz
/// and optionally an initramfs.img file.
#[derive(Debug)]
pub struct UsrLibModulesVmlinuz<ObjectID: FsVerityHashValue> {
    /// Kernel version string (directory name in /usr/lib/modules)
    pub kver: Box<str>,
    /// The kernel image file
    pub vmlinuz: RegularFile<ObjectID>,
    /// Optional initramfs image
    pub initramfs: Option<RegularFile<ObjectID>>,
    /// Optional os-release file from /usr/lib/os-release
    pub os_release: Option<RegularFile<ObjectID>>,
}

impl<ObjectID: FsVerityHashValue> UsrLibModulesVmlinuz<ObjectID> {
    /// Converts this vmlinuz entry into a Type 1 BLS entry.
    ///
    /// # Arguments
    ///
    /// * `entry_id` - Optional entry ID to use; defaults to kernel version
    ///
    /// # Returns
    ///
    /// A Type1Entry with generated BLS configuration, or an error if initramfs is missing.
    pub fn into_type1(self, entry_id: Option<&str>) -> Result<Type1Entry<ObjectID>> {
        let id = entry_id.unwrap_or(&self.kver);

        let initramfs = self.initramfs.ok_or_else(|| {
            anyhow::anyhow!(
                "kernel {} has no initramfs.img in /usr/lib/modules/{}",
                self.kver,
                self.kver
            )
        })?;

        let title = "todoOS";
        let version = "0-todo";
        let entry = BootLoaderEntryFile::new(&format!(
            r#"# File created by composefs
title {title}
version {version}
linux /{id}/vmlinuz
initrd /{id}/initramfs.img
"#
        ));

        let filename = Box::from(format!("{id}.conf").as_ref());

        Ok(Type1Entry {
            filename,
            entry,
            files: HashMap::from([
                (Box::from(format!("/{id}/vmlinuz")), self.vmlinuz),
                (Box::from(format!("/{id}/initramfs.img")), initramfs),
            ]),
        })
    }

    /// Loads all vmlinuz entries from /usr/lib/modules.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the filesystem
    ///
    /// # Returns
    ///
    /// A vector of all UsrLibModulesVmlinuz entries found
    pub fn load_all(fs: &FileSystem<ObjectID>) -> Result<Vec<Self>> {
        let mut entries = vec![];
        let root = fs.as_dir();

        match root.get_directory_ref("/usr/lib/modules".as_ref()) {
            Ok(modules_dir) => {
                for (kver, inode) in modules_dir.entries() {
                    let Inode::Directory(dir) = inode else {
                        continue;
                    };

                    let dir_ref = DirectoryRef::from_parts(dir, root.leaves());
                    if let Ok(vmlinuz) = dir_ref.get_file("vmlinuz".as_ref()) {
                        // TODO: maybe initramfs should be mandatory: the kernel isn't useful
                        // without it
                        let initramfs = dir_ref.get_file("initramfs.img".as_ref()).ok();
                        let os_release = root.get_file("/usr/lib/os-release".as_ref()).ok();
                        entries.push(Self {
                            kver: Box::from(std::str::from_utf8(kver.as_bytes())?),
                            vmlinuz: vmlinuz.clone(),
                            initramfs: initramfs.cloned(),
                            os_release: os_release.cloned(),
                        });
                    }
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(other) => Err(other)?,
        };

        Ok(entries)
    }
}

/// Encoding of an aboot partition payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbootEncoding {
    /// Android boot image version 2.
    AndroidV2,
    /// Unified Kernel Image written to a ukiboot partition.
    Uki,
}

/// File backing an aboot artifact.
#[derive(Debug, Clone)]
pub struct AbootArtifact<ObjectID: FsVerityHashValue> {
    /// Source path in the image.
    pub path: PathBuf,
    /// Artifact contents.
    pub file: RegularFile<ObjectID>,
}

/// An aboot payload and its optional matching vbmeta image.
#[derive(Debug)]
pub struct AbootEntry<ObjectID: FsVerityHashValue> {
    /// Kernel version associated with the payload.
    pub kver: Box<str>,
    /// Payload encoding.
    pub encoding: AbootEncoding,
    /// Android boot image or ukiboot UKI.
    pub payload: AbootArtifact<ObjectID>,
    /// Matching vbmeta image for Android boot payloads.
    pub vbmeta: Option<AbootArtifact<ObjectID>>,
}

fn aboot_encoding<ObjectID: FsVerityHashValue>(
    file: &RegularFile<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<AbootEncoding> {
    let data = composefs::fs::read_file(file, repo)?;
    if data.starts_with(b"ANDROID!") {
        let mut image = Cursor::new(&data);
        AndroidBootImage::parse(&mut image).context("Parsing Android boot image")?;
        return Ok(AbootEncoding::AndroidV2);
    }

    uki::get_section(&data, ".linux")
        .ok_or(uki::UkiError::PortableExecutableError)?
        .context("Parsing aboot payload as UKI")?;
    uki::get_section(&data, ".initrd")
        .ok_or(uki::UkiError::PortableExecutableError)?
        .context("Parsing aboot payload as UKI")?;
    Ok(AbootEncoding::Uki)
}

fn optional_file<'a, ObjectID: FsVerityHashValue>(
    dir: DirectoryRef<'a, ObjectID>,
    name: &OsStr,
) -> Result<Option<&'a RegularFile<ObjectID>>> {
    match dir.get_file(name) {
        Ok(file) => Ok(Some(file)),
        Err(ImageError::NotFound(..)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl<ObjectID: FsVerityHashValue> AbootEntry<ObjectID> {
    fn load(
        kver: Box<str>,
        payload_path: &Path,
        payload: &RegularFile<ObjectID>,
        vbmeta_path: &Path,
        vbmeta: Option<&RegularFile<ObjectID>>,
        repo: &Repository<ObjectID>,
    ) -> Result<Self> {
        let encoding = aboot_encoding(payload, repo)
            .with_context(|| format!("Identifying aboot payload {payload_path:?}"))?;
        if encoding == AbootEncoding::Uki && vbmeta.is_some() {
            bail!("ukiboot payload {payload_path:?} must not have a vbmeta image");
        }
        Ok(Self {
            kver,
            encoding,
            payload: AbootArtifact {
                path: payload_path.to_path_buf(),
                file: payload.clone(),
            },
            vbmeta: vbmeta.map(|file| AbootArtifact {
                path: vbmeta_path.to_path_buf(),
                file: file.clone(),
            }),
        })
    }

    /// Discover aboot artifacts in `/boot` and `/usr/lib/modules`.
    pub fn load_all(fs: &FileSystem<ObjectID>, repo: &Repository<ObjectID>) -> Result<Vec<Self>> {
        let root = fs.as_dir();
        let mut entries = Vec::new();

        match root.get_directory_ref("/boot".as_ref()) {
            Ok(boot) => {
                for (filename, inode) in boot.entries() {
                    let name = filename.as_bytes();
                    let Some(kver) = name
                        .strip_prefix(b"aboot-")
                        .and_then(|name| name.strip_suffix(b".img"))
                    else {
                        continue;
                    };
                    if kver.is_empty() {
                        bail!("aboot payload has no kernel version");
                    }
                    let Inode::Leaf(leaf_id, _) = inode else {
                        bail!("/boot/{filename:?} is a directory");
                    };
                    let LeafContent::Regular(payload) = &fs.leaf(*leaf_id).content else {
                        bail!("/boot/{filename:?} is not a regular file");
                    };
                    let kver = from_utf8(kver)?;
                    let vbmeta_name = format!("vbmeta-{kver}.img");
                    let vbmeta = optional_file(boot, vbmeta_name.as_ref())?;
                    entries.push(Self::load(
                        kver.into(),
                        &PathBuf::from("/boot").join(filename),
                        payload,
                        &PathBuf::from("/boot").join(&vbmeta_name),
                        vbmeta,
                        repo,
                    )?);
                }
                for (filename, _) in boot.entries() {
                    let name = filename.as_bytes();
                    let Some(kver) = name
                        .strip_prefix(b"vbmeta-")
                        .and_then(|name| name.strip_suffix(b".img"))
                    else {
                        continue;
                    };
                    let payload_name = format!("aboot-{}.img", from_utf8(kver)?);
                    if optional_file(boot, payload_name.as_ref())?.is_none() {
                        bail!("vbmeta image /boot/{filename:?} has no matching aboot payload");
                    }
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(error) => Err(error)?,
        }

        match root.get_directory_ref("/usr/lib/modules".as_ref()) {
            Ok(modules) => {
                for (kver, inode) in modules.entries() {
                    let Inode::Directory(dir) = inode else {
                        continue;
                    };
                    let dir = DirectoryRef::from_parts(dir, root.leaves());
                    let payload = optional_file(dir, "aboot.img".as_ref())?;
                    let vbmeta = optional_file(dir, "vbmeta.img".as_ref())?;
                    let Some(payload) = payload else {
                        if vbmeta.is_some() {
                            bail!(
                                "vbmeta image /usr/lib/modules/{kver:?}/vbmeta.img has no matching aboot payload"
                            );
                        }
                        continue;
                    };
                    let kver = from_utf8(kver.as_bytes())?;
                    let base = PathBuf::from("/usr/lib/modules").join(kver);
                    entries.push(Self::load(
                        kver.into(),
                        &base.join("aboot.img"),
                        payload,
                        &base.join("vbmeta.img"),
                        vbmeta,
                        repo,
                    )?);
                }
            }
            Err(ImageError::NotFound(..)) => {}
            Err(error) => Err(error)?,
        }

        if entries.len() > 1 {
            bail!("multiple aboot payloads found");
        }
        Ok(entries)
    }
}

/// Represents any type of boot entry found in the filesystem.
///
/// This enum unifies Type 1 BLS entries, Type 2 UKIs, traditional
/// vmlinuz/initramfs pairs, and aboot payloads.
#[derive(Debug)]
pub enum BootEntry<ObjectID: FsVerityHashValue> {
    /// Boot Loader Specification Type 1 entry
    Type1(Type1Entry<ObjectID>),
    /// Boot Loader Specification Type 2 entry (UKI)
    Type2(Type2Entry<ObjectID>),
    /// Traditional vmlinuz from /usr/lib/modules
    UsrLibModulesVmLinuz(UsrLibModulesVmlinuz<ObjectID>),
    /// Android boot or ukiboot partition payload.
    Aboot(AbootEntry<ObjectID>),
}

/// Extracts all boot resources from a filesystem image.
///
/// Scans the filesystem for Type 1 BLS entries, Type 2 UKIs, traditional
/// vmlinuz files, and aboot payloads.
///
/// # Arguments
///
/// * `image` - The filesystem to scan
/// * `repo` - The composefs repository
///
/// # Returns
///
/// A vector containing all boot entries found in the filesystem
pub fn get_boot_resources<ObjectID: FsVerityHashValue>(
    image: &FileSystem<ObjectID>,
    repo: &Repository<ObjectID>,
) -> Result<Vec<BootEntry<ObjectID>>> {
    let mut entries = vec![];

    for e in Type1Entry::load_all(image, repo)? {
        entries.push(BootEntry::Type1(e));
    }
    for e in Type2Entry::load_all(image)? {
        entries.push(BootEntry::Type2(e));
    }
    for e in UsrLibModulesVmlinuz::load_all(image)? {
        entries.push(BootEntry::UsrLibModulesVmLinuz(e));
    }
    let aboot_entries = AbootEntry::load_all(image, repo)?;
    let has_other_primary = entries.iter().any(|entry| match entry {
        BootEntry::Type1(_) | BootEntry::UsrLibModulesVmLinuz(_) => true,
        BootEntry::Type2(entry) => matches!(entry.pe_type, PEType::Uki),
        BootEntry::Aboot(_) => unreachable!(),
    });
    if !aboot_entries.is_empty() && has_other_primary {
        bail!("aboot payload cannot be combined with other boot artifacts");
    }
    for entry in aboot_entries {
        entries.push(BootEntry::Aboot(entry));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::{
        fsverity::Sha256HashValue,
        test::TestRepo,
        tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
    };

    fn fake_file() -> RegularFile<Sha256HashValue> {
        RegularFile::Inline(Default::default())
    }

    fn boot_filesystem() -> FileSystem<Sha256HashValue> {
        let mut fs = FileSystem::new(Stat::uninitialized());
        fs.root.insert(
            "boot".as_ref(),
            Inode::Directory(Box::new(Directory::new(Stat::uninitialized()))),
        );
        fs
    }

    fn add_external(
        fs: &mut FileSystem<Sha256HashValue>,
        repo: &Repository<Sha256HashValue>,
        directory: &str,
        name: &str,
        data: &[u8],
    ) {
        let object_id = repo.ensure_object(data).unwrap();
        let leaf = fs.push_leaf(
            Stat::uninitialized(),
            LeafContent::Regular(RegularFile::External(object_id, data.len() as u64)),
        );
        fs.root
            .get_directory_mut(directory.as_ref())
            .unwrap()
            .insert(name.as_ref(), Inode::leaf(leaf));
    }

    fn add_modules_vmlinuz(fs: &mut FileSystem<Sha256HashValue>) {
        let leaf = fs.push_leaf(
            Stat::uninitialized(),
            LeafContent::Regular(RegularFile::Inline(Box::from(&b"kernel"[..]))),
        );
        let mut kver = Directory::new(Stat::uninitialized());
        kver.insert("vmlinuz".as_ref(), Inode::leaf(leaf));
        let mut modules = Directory::new(Stat::uninitialized());
        modules.insert("1.0".as_ref(), Inode::Directory(Box::new(kver)));
        let mut lib = Directory::new(Stat::uninitialized());
        lib.insert("modules".as_ref(), Inode::Directory(Box::new(modules)));
        let mut usr = Directory::new(Stat::uninitialized());
        usr.insert("lib".as_ref(), Inode::Directory(Box::new(lib)));
        fs.root
            .insert("usr".as_ref(), Inode::Directory(Box::new(usr)));
    }

    #[test]
    fn test_aboot_android_discovery() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        let image = crate::android_boot::tests::image(b"kernel", b"initrd", b"dtb");
        add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);
        add_external(&mut fs, &repo.repo, "/boot", "vbmeta-1.0.img", b"vbmeta");

        let entries = get_boot_resources(&fs, &repo.repo).unwrap();
        let [BootEntry::Aboot(entry)] = entries.as_slice() else {
            panic!("unexpected entries: {entries:?}");
        };
        assert_eq!(entry.kver.as_ref(), "1.0");
        assert_eq!(entry.encoding, AbootEncoding::AndroidV2);
        assert_eq!(entry.payload.path, PathBuf::from("/boot/aboot-1.0.img"));
        assert!(entry.vbmeta.is_some());
    }

    #[test]
    fn test_aboot_uki_discovery() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        let image = crate::uki::test::uki_with_linux_initrd();
        add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);

        let entries = get_boot_resources(&fs, &repo.repo).unwrap();
        let [BootEntry::Aboot(entry)] = entries.as_slice() else {
            panic!("unexpected entries: {entries:?}");
        };
        assert_eq!(entry.encoding, AbootEncoding::Uki);
        assert!(entry.vbmeta.is_none());
    }

    #[test]
    fn test_aboot_rejects_multiple_payloads() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        let image = crate::android_boot::tests::image(b"kernel", b"initrd", b"");
        add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);
        add_external(&mut fs, &repo.repo, "/boot", "aboot-2.0.img", &image);

        let error = get_boot_resources(&fs, &repo.repo).unwrap_err();
        assert!(error.to_string().contains("multiple aboot payloads"));
    }

    #[test]
    fn test_aboot_rejects_mixed_artifacts() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        let image = crate::android_boot::tests::image(b"kernel", b"initrd", b"");
        add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);
        add_modules_vmlinuz(&mut fs);

        let error = get_boot_resources(&fs, &repo.repo).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("aboot payload cannot be combined")
        );
    }

    #[test]
    fn test_ukiboot_rejects_vbmeta() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        let image = crate::uki::test::uki_with_linux_initrd();
        add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);
        add_external(&mut fs, &repo.repo, "/boot", "vbmeta-1.0.img", b"vbmeta");

        let error = get_boot_resources(&fs, &repo.repo).unwrap_err();
        assert!(error.to_string().contains("must not have a vbmeta image"));
    }

    #[test]
    fn test_aboot_inline_artifacts() {
        for external_payload in [false, true] {
            let repo = TestRepo::<Sha256HashValue>::new();
            let mut fs = boot_filesystem();
            let image = crate::android_boot::tests::image(b"kernel", b"initrd", b"");
            if external_payload {
                add_external(&mut fs, &repo.repo, "/boot", "aboot-1.0.img", &image);
            } else {
                let leaf = fs.push_leaf(
                    Stat::uninitialized(),
                    LeafContent::Regular(RegularFile::Inline(image.clone().into_boxed_slice())),
                );
                fs.root
                    .get_directory_mut("/boot".as_ref())
                    .unwrap()
                    .insert("aboot-1.0.img".as_ref(), Inode::leaf(leaf));
            }
            let leaf = fs.push_leaf(
                Stat::uninitialized(),
                LeafContent::Regular(RegularFile::Inline(b"vbmeta".as_slice().into())),
            );
            fs.root
                .get_directory_mut("/boot".as_ref())
                .unwrap()
                .insert("vbmeta-1.0.img".as_ref(), Inode::leaf(leaf));

            let entries = get_boot_resources(&fs, &repo.repo).unwrap();
            let [BootEntry::Aboot(entry)] = entries.as_slice() else {
                panic!("unexpected entries: {entries:?}");
            };
            assert_eq!(entry.encoding, AbootEncoding::AndroidV2);
            assert_eq!(
                composefs::fs::read_file(&entry.payload.file, &repo.repo)
                    .unwrap()
                    .as_ref(),
                image.as_slice(),
            );
            let vbmeta = entry.vbmeta.as_ref().unwrap();
            assert_eq!(vbmeta.path, PathBuf::from("/boot/vbmeta-1.0.img"));
            assert!(matches!(vbmeta.file, RegularFile::Inline(_)));
            assert_eq!(
                composefs::fs::read_file(&vbmeta.file, &repo.repo)
                    .unwrap()
                    .as_ref(),
                b"vbmeta",
            );
        }
    }

    #[test]
    fn test_aboot_rejects_orphan_vbmeta() {
        let repo = TestRepo::<Sha256HashValue>::new();
        let mut fs = boot_filesystem();
        add_external(&mut fs, &repo.repo, "/boot", "vbmeta-1.0.img", b"vbmeta");

        let error = get_boot_resources(&fs, &repo.repo).unwrap_err();
        assert!(error.to_string().contains("has no matching aboot payload"));
    }

    #[test]
    fn test_into_type1_with_initramfs() {
        let entry = UsrLibModulesVmlinuz::<Sha256HashValue> {
            kver: "6.9.0-arch1-1".into(),
            vmlinuz: fake_file(),
            initramfs: Some(fake_file()),
            os_release: None,
        };
        let t1 = entry
            .into_type1(None)
            .expect("should succeed with initramfs");
        let keys: Vec<&str> = t1.files.keys().map(|k| k.as_ref()).collect();
        assert!(
            keys.contains(&"/6.9.0-arch1-1/vmlinuz"),
            "missing vmlinuz key, got: {keys:?}"
        );
        assert!(
            keys.contains(&"/6.9.0-arch1-1/initramfs.img"),
            "missing initramfs key, got: {keys:?}"
        );
    }

    #[test]
    fn test_into_type1_without_initramfs_returns_error() {
        let entry = UsrLibModulesVmlinuz::<Sha256HashValue> {
            kver: "6.9.0-arch1-1".into(),
            vmlinuz: fake_file(),
            initramfs: None,
            os_release: None,
        };
        let err = entry.into_type1(None).unwrap_err();
        assert!(
            err.to_string().contains("no initramfs"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_bootloader_entry_file_new() {
        let content = "title Test Entry\nversion 1.0\nlinux /vmlinuz\ninitrd /initramfs.img\noptions quiet splash\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.lines.len(), 5);
        assert_eq!(entry.lines[0], "title Test Entry");
        assert_eq!(entry.lines[1], "version 1.0");
        assert_eq!(entry.lines[2], "linux /vmlinuz");
        assert_eq!(entry.lines[3], "initrd /initramfs.img");
        assert_eq!(entry.lines[4], "options quiet splash");
    }

    #[test]
    fn test_bootloader_entry_file_new_empty() {
        let entry = BootLoaderEntryFile::new("");
        assert_eq!(entry.lines.len(), 0);
    }

    #[test]
    fn test_bootloader_entry_file_new_single_line() {
        let entry = BootLoaderEntryFile::new("title Test");
        assert_eq!(entry.lines.len(), 1);
        assert_eq!(entry.lines[0], "title Test");
    }

    #[test]
    fn test_bootloader_entry_file_new_trailing_newline() {
        let content = "title Test\nversion 1.0\n";
        let entry = BootLoaderEntryFile::new(content);
        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[0], "title Test");
        assert_eq!(entry.lines[1], "version 1.0");
    }

    #[test]
    fn test_get_value() {
        let content = "title Test Entry\nversion 1.0\nlinux /vmlinuz\ninitrd /initramfs.img\noptions quiet splash\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), Some("Test Entry"));
        assert_eq!(entry.get_value("version"), Some("1.0"));
        assert_eq!(entry.get_value("linux"), Some("/vmlinuz"));
        assert_eq!(entry.get_value("initrd"), Some("/initramfs.img"));
        assert_eq!(entry.get_value("options"), Some("quiet splash"));
        assert_eq!(entry.get_value("nonexistent"), None);
    }

    #[test]
    fn test_get_value_whitespace_handling() {
        let content = "title\t\tTest Entry\nversion   1.0\nlinux\t/vmlinuz\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), Some("Test Entry"));
        assert_eq!(entry.get_value("version"), Some("1.0"));
        assert_eq!(entry.get_value("linux"), Some("/vmlinuz"));
    }

    #[test]
    fn test_get_value_no_whitespace_after_key() {
        let content = "titleTest Entry\nversionno_space\n";
        let entry = BootLoaderEntryFile::new(content);

        assert_eq!(entry.get_value("title"), None);
        assert_eq!(entry.get_value("version"), None);
    }

    #[test]
    fn test_get_values_multiple() {
        let content = "title Test Entry\ninitrd /initramfs1.img\ninitrd /initramfs2.img\noptions quiet\noptions splash\n";
        let entry = BootLoaderEntryFile::new(content);

        let initrd_values: Vec<_> = entry.get_values("initrd").collect();
        assert_eq!(initrd_values, vec!["/initramfs1.img", "/initramfs2.img"]);

        let options_values: Vec<_> = entry.get_values("options").collect();
        assert_eq!(options_values, vec!["quiet", "splash"]);

        let title_values: Vec<_> = entry.get_values("title").collect();
        assert_eq!(title_values, vec!["Test Entry"]);

        let nonexistent_values: Vec<_> = entry.get_values("nonexistent").collect();
        assert_eq!(nonexistent_values, Vec::<&str>::new());
    }

    #[test]
    fn test_add_cmdline_new_options_line() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.add_cmdline("quiet");

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options quiet");
    }

    #[test]
    fn test_add_cmdline_append_to_existing_options() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions splash\n");
        entry.add_cmdline("quiet");

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options splash quiet");
    }

    #[test]
    fn test_add_cmdline_replace_existing_key_value() {
        let mut entry =
            BootLoaderEntryFile::new("title Test Entry\noptions quiet splash root=/dev/sda1\n");
        entry.add_cmdline("root=/dev/sda2");

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet splash root=/dev/sda2");
    }

    #[test]
    fn test_add_cmdline_replace_existing_key_only() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions quiet rw splash\n");
        entry.add_cmdline("rw"); // Same key, should replace itself (no-op in this case)

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet rw splash");

        // Test replacing with different key
        entry.add_cmdline("ro");
        assert_eq!(entry.lines[1], "options quiet rw splash ro");
    }

    #[test]
    fn test_add_cmdline_key_with_equals() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions quiet\n");
        entry.add_cmdline("composefs=abc123");

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet composefs=abc123");
    }

    #[test]
    fn test_add_cmdline_replace_key_with_equals() {
        let mut entry =
            BootLoaderEntryFile::new("title Test Entry\noptions quiet composefs=old123\n");
        entry.add_cmdline("composefs=new456");

        assert_eq!(entry.lines.len(), 2);
        assert_eq!(entry.lines[1], "options quiet composefs=new456");
    }

    #[test]
    fn test_adjust_cmdline_with_composefs() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(Some("composefs=abc123"), &["quiet", "splash"]);

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options composefs=abc123 quiet splash");
    }

    #[test]
    fn test_adjust_cmdline_with_composefs_insecure() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(Some("composefs=?abc123"), &[]);

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options composefs=?abc123");
    }

    #[test]
    fn test_adjust_cmdline_no_composefs() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\nlinux /vmlinuz\n");
        entry.adjust_cmdline(None, &["quiet", "splash"]);

        assert_eq!(entry.lines.len(), 3);
        assert_eq!(entry.lines[2], "options quiet splash");
    }

    #[test]
    fn test_adjust_cmdline_existing_options() {
        let mut entry = BootLoaderEntryFile::new("title Test Entry\noptions root=/dev/sda1\n");
        entry.adjust_cmdline(Some("composefs=abc123"), &["quiet"]);

        assert_eq!(entry.lines.len(), 2);
        assert!(entry.lines[1].contains("root=/dev/sda1"));
        assert!(entry.lines[1].contains("abc123"));
        assert!(entry.lines[1].contains("quiet"));
    }

    #[test]
    fn test_strip_ble_key_helper() {
        assert_eq!(
            strip_ble_key("title Test Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(
            strip_ble_key("title\tTest Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(
            strip_ble_key("title  Test Entry", "title"),
            Some("Test Entry")
        );
        assert_eq!(strip_ble_key("titleTest Entry", "title"), None);
        assert_eq!(strip_ble_key("other Test Entry", "title"), None);
        assert_eq!(strip_ble_key("title", "title"), None); // No whitespace after key
    }

    #[test]
    fn test_substr_range_helper() {
        let parent = "hello world test";
        let substr = &parent[6..11]; // "world" - actual substring slice
        let range = substr_range(parent, substr).unwrap();
        assert_eq!(range, 6..11);
        assert_eq!(&parent[range], "world");

        // Test with different substring
        let other_substr = &parent[0..5]; // "hello"
        let range2 = substr_range(parent, other_substr).unwrap();
        assert_eq!(range2, 0..5);
        assert_eq!(&parent[range2], "hello");

        // Test non-substring (separate string with same content)
        let separate_string = String::from("world");
        assert_eq!(substr_range(parent, &separate_string), None);
    }
}

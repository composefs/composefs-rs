//! A generic metadata-only filesystem tree where regular files can be stored
//! however the caller wants.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    path::{Component, Path},
    rc::Rc,
};

use thiserror::Error;

/// File metadata similar to `struct stat` from POSIX.
#[derive(Debug)]
pub struct Stat {
    /// File mode and permissions bits.
    pub st_mode: u32,
    /// User ID of owner.
    pub st_uid: u32,
    /// Group ID of owner.
    pub st_gid: u32,
    /// Modification time in seconds since Unix epoch.
    pub st_mtim_sec: i64,
    /// Extended attributes as key-value pairs.
    pub xattrs: RefCell<BTreeMap<Box<OsStr>, Box<[u8]>>>,
}

impl Clone for Stat {
    fn clone(&self) -> Self {
        Self {
            st_mode: self.st_mode,
            st_uid: self.st_uid,
            st_gid: self.st_gid,
            st_mtim_sec: self.st_mtim_sec,
            xattrs: RefCell::new(self.xattrs.borrow().clone()),
        }
    }
}

impl Stat {
    /// Creates a placeholder stat for uninitialized root directories.
    ///
    /// This stat has obviously invalid metadata (mode 0) that must be overwritten
    /// before computing digests. It is intended for use when building a filesystem
    /// incrementally (e.g., from OCI layers) where the final root metadata will be
    /// set via `copy_root_metadata_from_usr()`.
    ///
    /// NOTE: If changing this, also update `doc/oci.md`.
    pub fn uninitialized() -> Self {
        Self {
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: RefCell::new(BTreeMap::new()),
        }
    }
}

/// Content types for leaf nodes (non-directory files).
#[derive(Debug)]
pub enum LeafContent<T> {
    /// A regular file with content of type `T`.
    Regular(T),
    /// A block device with the given device number.
    BlockDevice(u64),
    /// A character device with the given device number.
    CharacterDevice(u64),
    /// A named pipe (FIFO).
    Fifo,
    /// A Unix domain socket.
    Socket,
    /// A symbolic link pointing to the given target path.
    Symlink(Box<OsStr>),
}

/// A leaf node representing a non-directory file.
#[derive(Debug)]
pub struct Leaf<T> {
    /// Metadata for this leaf node.
    pub stat: Stat,
    /// The content and type of this leaf node.
    pub content: LeafContent<T>,
}

/// A directory node containing named entries.
#[derive(Debug, Clone)]
pub struct Directory<T> {
    /// Metadata for this directory.
    pub stat: Stat,
    /// Map of filenames to inodes within this directory.
    pub(crate) entries: BTreeMap<Box<OsStr>, Inode<T>>,
}

/// A filesystem inode representing either a directory or a leaf node.
#[derive(Debug, Clone)]
pub enum Inode<T> {
    /// A directory inode.
    Directory(Box<Directory<T>>),
    /// A leaf inode (reference-counted to support hardlinks).
    Leaf(Rc<Leaf<T>>),
}

/// Errors that can occur when working with filesystem images.
#[derive(Error, Debug)]
pub enum ImageError {
    /// The filename contains invalid components (e.g., "..", ".", or Windows prefixes).
    #[error("Invalid filename {0:?}")]
    InvalidFilename(Box<OsStr>),
    /// The specified directory entry does not exist.
    #[error("Directory entry {0:?} does not exist")]
    NotFound(Box<OsStr>),
    /// The entry exists but is not a directory when a directory was expected.
    #[error("Directory entry {0:?} is not a subdirectory")]
    NotADirectory(Box<OsStr>),
    /// The entry is a directory when a non-directory was expected.
    #[error("Directory entry {0:?} is a directory")]
    IsADirectory(Box<OsStr>),
    /// The entry exists but is not a regular file when a regular file was expected.
    #[error("Directory entry {0:?} is not a regular file")]
    IsNotRegular(Box<OsStr>),
}

impl<T> Inode<T> {
    /// Returns a reference to the metadata for this inode.
    pub fn stat(&self) -> &Stat {
        match self {
            Inode::Directory(dir) => &dir.stat,
            Inode::Leaf(leaf) => &leaf.stat,
        }
    }
}

impl<T> Directory<T> {
    /// Creates a new directory with the given metadata.
    pub fn new(stat: Stat) -> Self {
        Self {
            stat,
            entries: BTreeMap::new(),
        }
    }

    /// Iterates over all inodes in the current directory, in no particular order.
    pub fn inodes(&self) -> impl Iterator<Item = &Inode<T>> + use<'_, T> {
        self.entries.values()
    }

    /// Iterates over all entries in the current directory, in no particular order.  The iterator
    /// returns pairs of `(&OsStr, &Inode)` and is probably used like so:
    ///
    /// Currently this is equivalent to `Directory::sorted_entries()` but that might change at some
    /// point.
    ///
    /// ```
    /// use composefs::{tree::{FileSystem, Stat}, fsverity::Sha256HashValue};
    /// let fs = FileSystem::<Sha256HashValue>::new(Stat::uninitialized());
    ///
    /// // populate the fs...
    ///
    /// for (name, inode) in fs.root.entries() {
    ///   // name: &OsStr, inode: &Inode
    /// }
    /// ```
    pub fn entries(&self) -> impl Iterator<Item = (&OsStr, &Inode<T>)> + use<'_, T> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Iterates over all entries in the current directory, in asciibetical order of name.  The
    /// iterator returns pairs of `(&OsStr, &Inode)`.
    pub fn sorted_entries(&self) -> impl Iterator<Item = (&OsStr, &Inode<T>)> + use<'_, T> {
        self.entries.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Gets a reference to a subdirectory of this directory.
    ///
    /// The given path may be absolute or relative and it makes no difference.  It may not contain
    /// any Windows-like prefixes, or "." or ".." components.  It may or may not end in "/" and it
    /// makes no difference.
    ///
    /// See `Directory::get_directory_mut()` for the mutable verison of this function.
    ///
    /// # Arguments
    ///
    ///  * `pathname`: the full pathname of the directory to fetch, taken as being relative to the
    ///    current directory even if it starts with '/'
    ///
    /// # Return value
    ///
    /// On success, this returns a reference to the named directory.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn get_directory(&self, pathname: &OsStr) -> Result<&Directory<T>, ImageError> {
        match self.get_directory_opt(pathname)? {
            Some(r) => Ok(r),
            None => Err(ImageError::NotFound(Box::from(pathname))),
        }
    }

    /// Like [`Self::get_directory()`] but maps [`ImageError::NotFound`] to [`Option`].
    pub fn get_directory_opt(&self, pathname: &OsStr) -> Result<Option<&Directory<T>>, ImageError> {
        let path = Path::new(pathname);
        let mut dir = self;

        for component in path.components() {
            dir = match component {
                Component::RootDir => dir,
                Component::Prefix(..) | Component::CurDir | Component::ParentDir => {
                    return Err(ImageError::InvalidFilename(pathname.into()));
                }
                Component::Normal(filename) => match dir.entries.get(filename) {
                    Some(Inode::Directory(subdir)) => subdir,
                    Some(_) => return Err(ImageError::NotADirectory(filename.into())),
                    None => return Ok(None),
                },
            }
        }

        Ok(Some(dir))
    }

    /// Gets a mutable reference to a subdirectory of this directory.
    ///
    /// This is the mutable version of `Directory::get_directory()`.
    pub fn get_directory_mut(&mut self, pathname: &OsStr) -> Result<&mut Directory<T>, ImageError> {
        let path = Path::new(pathname);
        let mut dir = self;

        for component in path.components() {
            dir = match component {
                Component::RootDir => dir,
                Component::Prefix(..) | Component::CurDir | Component::ParentDir => {
                    return Err(ImageError::InvalidFilename(pathname.into()));
                }
                Component::Normal(filename) => match dir.entries.get_mut(filename) {
                    Some(Inode::Directory(subdir)) => subdir,
                    Some(_) => return Err(ImageError::NotADirectory(filename.into())),
                    None => return Err(ImageError::NotFound(filename.into())),
                },
            };
        }

        Ok(dir)
    }

    /// Splits a pathname into a directory and the filename within that directory.  The directory
    /// must already exist.  The filename within the directory may or may not exist.
    ///
    /// This is the main entry point for most operations based on pathname.  The expectation is
    /// that the returned filename will be used to perform a more concrete operation on the
    /// returned directory.
    ///
    /// See `Directory::get_directory()` for more information about path traversal.  See
    /// `Directory::split_mut()` for the mutable version of this function.
    ///
    /// # Arguments
    ///
    ///  * `pathname`: the full pathname to the file of interest
    ///
    /// # Return value
    ///
    /// On success (the pathname is not invalid and the directory exists), returns a tuple of the
    /// `Directory` containing the file at the given path, and the basename of that file.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn split<'d, 'n>(
        &'d self,
        pathname: &'n OsStr,
    ) -> Result<(&'d Directory<T>, &'n OsStr), ImageError> {
        let path = Path::new(pathname);

        let Some(filename) = path.file_name() else {
            return Err(ImageError::InvalidFilename(Box::from(pathname)));
        };

        let dir = match path.parent() {
            Some(parent) => self.get_directory(parent.as_os_str())?,
            None => self,
        };

        Ok((dir, filename))
    }

    /// Splits a pathname into a directory and the filename within that directory.  The directory
    /// must already exist.  The filename within the directory may or may not exist.
    ///
    /// This is the `_mut` version of `Directory::split()`.
    pub fn split_mut<'d, 'n>(
        &'d mut self,
        pathname: &'n OsStr,
    ) -> Result<(&'d mut Directory<T>, &'n OsStr), ImageError> {
        let path = Path::new(pathname);

        let Some(filename) = path.file_name() else {
            return Err(ImageError::InvalidFilename(Box::from(pathname)));
        };

        let dir = match path.parent() {
            Some(parent) => self.get_directory_mut(parent.as_os_str())?,
            None => self,
        };

        Ok((dir, filename))
    }

    /// Takes a reference to the "leaf" file (not directory) with the given filename directly
    /// contained in this directory.  This is usually done in preparation for creating a hardlink
    /// or in order to avoid issues with the borrow checker when mutating the tree.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is not a directory) the Rc is cloned and a new reference
    /// is returned.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn ref_leaf(&self, filename: &OsStr) -> Result<Rc<Leaf<T>>, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(leaf)) => Ok(Rc::clone(leaf)),
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(Box::from(filename))),
            None => Err(ImageError::NotFound(Box::from(filename))),
        }
    }

    /// Obtains information about the regular file with the given filename directly contained in
    /// this directory.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is a regular file) then the return value is either:
    ///  * the inline data
    ///  * an external reference, with size information
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn get_file<'a>(&'a self, filename: &OsStr) -> Result<&'a T, ImageError> {
        self.get_file_opt(filename)?
            .ok_or_else(|| ImageError::NotFound(Box::from(filename)))
    }

    /// Like [`Self::get_file()`] but maps [`ImageError::NotFound`] to [`Option`].
    pub fn get_file_opt<'a>(&'a self, filename: &OsStr) -> Result<Option<&'a T>, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(leaf)) => match &leaf.content {
                LeafContent::Regular(file) => Ok(Some(file)),
                _ => Err(ImageError::IsNotRegular(filename.into())),
            },
            Some(Inode::Directory(..)) => Err(ImageError::IsADirectory(filename.into())),
            None => Ok(None),
        }
    }

    /// Inserts the given inode into the directory with special handling for directories.  In case
    /// the inode is a directory and there is already a subdirectory with the given filename, the
    /// `stat` field will be updated with the value from the provided `inode` but the old directory
    /// entries will be left in place.
    ///
    /// In all other cases, this function is equivalent to `Directory::insert()`.
    ///
    /// This is something like extracting an archive or an overlay: directories are merged with
    /// existing directories, but otherwise the new content replaces what was there before.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn merge(&mut self, filename: &OsStr, inode: Inode<T>) {
        // If we're putting a directory on top of a directory, then update the stat information but
        // keep the old entries in place.
        if let Inode::Directory(new_dir) = inode {
            if let Some(Inode::Directory(old_dir)) = self.entries.get_mut(filename) {
                old_dir.stat = new_dir.stat;
            } else {
                // Unfortunately we already deconstructed the original inode and we can't get it
                // back again.  This is necessary because we wanted to move the stat field (above)
                // without cloning it which can't be done through a reference (mutable or not).
                self.insert(filename, Inode::Directory(new_dir));
            }
        } else {
            self.insert(filename, inode);
        }
    }

    /// Inserts the given inode into the directory.
    ///
    /// If the `filename` existed previously, the content is completely overwritten, including the
    /// case that it was a directory.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn insert(&mut self, filename: &OsStr, inode: Inode<T>) {
        self.entries.insert(Box::from(filename), inode);
    }

    /// Removes the named file from the directory, if it exists.  If it doesn't exist, this is a
    /// no-op.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    pub fn remove(&mut self, filename: &OsStr) {
        self.entries.remove(filename);
    }

    /// Does a directory lookup on the given filename, returning the Inode if it exists.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    pub fn lookup(&self, filename: &OsStr) -> Option<&Inode<T>> {
        self.entries.get(filename)
    }

    /// Removes an item from the directory, if it exists, returning the Inode value.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split_mut()` first.
    pub fn pop(&mut self, filename: &OsStr) -> Option<Inode<T>> {
        self.entries.remove(filename)
    }

    /// Removes all content from this directory, making the directory empty.  The `stat` data
    /// remains unmodified.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Recursively finds the newest modification time in this directory tree.
    ///
    /// Returns the maximum modification time among this directory's metadata
    /// and all files and subdirectories it contains.
    pub fn newest_file(&self) -> i64 {
        let mut newest = self.stat.st_mtim_sec;
        for inode in self.entries.values() {
            let mtime = match inode {
                Inode::Leaf(ref leaf) => leaf.stat.st_mtim_sec,
                Inode::Directory(ref dir) => dir.newest_file(),
            };
            if mtime > newest {
                newest = mtime;
            }
        }
        newest
    }
}

/// A complete filesystem tree with a root directory.
#[derive(Debug, Clone)]
pub struct FileSystem<T> {
    /// The root directory of the filesystem.
    pub root: Directory<T>,
}

impl<T> FileSystem<T> {
    /// Add 256 overlay whiteout stub entries to the root directory.
    ///
    /// This is required for Format 1.0 compatibility with the C mkcomposefs.
    /// Each whiteout is a character device named "00" through "ff" with rdev=0.
    /// They inherit uid/gid/mtime and xattrs from the root directory.
    ///
    /// These entries allow overlay filesystems to efficiently represent
    /// deleted files using device stubs that match the naming convention.
    pub fn add_overlay_whiteouts(&mut self) {
        use std::ffi::OsString;
        use std::rc::Rc;

        // Copy root's stat for the whiteout entries (inherit uid/gid/mtime)
        // Mode is set to 0o644 (rw-r--r--) as per C mkcomposefs
        let whiteout_stat = Stat {
            st_mode: 0o644,
            st_uid: self.root.stat.st_uid,
            st_gid: self.root.stat.st_gid,
            st_mtim_sec: self.root.stat.st_mtim_sec,
            xattrs: self.root.stat.xattrs.clone(),
        };

        for i in 0..=255u8 {
            let name = OsString::from(format!("{:02x}", i));

            // Skip if entry already exists
            if self.root.entries.contains_key(name.as_os_str()) {
                continue;
            }

            let leaf = Leaf {
                stat: Stat {
                    st_mode: whiteout_stat.st_mode,
                    st_uid: whiteout_stat.st_uid,
                    st_gid: whiteout_stat.st_gid,
                    st_mtim_sec: whiteout_stat.st_mtim_sec,
                    xattrs: whiteout_stat.xattrs.clone(),
                },
                content: LeafContent::CharacterDevice(0), // rdev=0
            };

            self.root
                .entries
                .insert(name.into_boxed_os_str(), Inode::Leaf(Rc::new(leaf)));
        }
    }

    /// Add trusted.overlay.opaque="y" xattr to root directory.
    ///
    /// This is required for Format 1.0 when whiteout entries are present,
    /// marking the directory as opaque for the overlay filesystem.
    pub fn set_overlay_opaque(&mut self) {
        self.root.stat.xattrs.borrow_mut().insert(
            Box::from(std::ffi::OsStr::new("trusted.overlay.opaque")),
            Box::from(*b"y"),
        );
    }

    /// Creates a new filesystem with a root directory having the given metadata.
    pub fn new(root_stat: Stat) -> Self {
        Self {
            root: Directory::new(root_stat),
        }
    }

    /// Sets the metadata for the root directory.
    pub fn set_root_stat(&mut self, stat: Stat) {
        self.root.stat = stat;
    }

    /// Copies metadata from `/usr` to the root directory.
    ///
    /// OCI container layer tars often don't include a root directory entry,
    /// and when they do, container runtimes typically ignore it. This makes
    /// root metadata non-deterministic. This method provides a way to derive
    /// consistent root metadata by copying it from `/usr`, which is always
    /// present in standard filesystem layouts.
    ///
    /// The copied metadata includes:
    /// - Mode (permissions)
    /// - Modification time
    /// - User ID (uid)
    /// - Group ID (gid)
    /// - Extended attributes (xattrs)
    ///
    /// NOTE: If changing this behavior, also update `doc/oci.md`.
    ///
    /// # Errors
    ///
    /// Returns an error if `/usr` does not exist or is not a directory.
    pub fn copy_root_metadata_from_usr(&mut self) -> Result<(), ImageError> {
        let usr = self.root.get_directory(OsStr::new("usr"))?;

        // Copy values to local variables to avoid borrow conflicts
        let st_mode = usr.stat.st_mode;
        let st_uid = usr.stat.st_uid;
        let st_gid = usr.stat.st_gid;
        let st_mtim_sec = usr.stat.st_mtim_sec;
        let xattrs = usr.stat.xattrs.clone();

        // Apply copied metadata to root
        self.root.stat.st_mode = st_mode;
        self.root.stat.st_uid = st_uid;
        self.root.stat.st_gid = st_gid;
        self.root.stat.st_mtim_sec = st_mtim_sec;
        self.root.stat.xattrs = xattrs;

        Ok(())
    }

    /// Applies a function to every [`Stat`] in the filesystem tree.
    ///
    /// This visits the root directory and all descendants (directories and leaves),
    /// calling the provided function with each node's `Stat`.
    pub fn for_each_stat<F>(&self, f: F)
    where
        F: Fn(&Stat),
    {
        fn visit_inode<T, F: Fn(&Stat)>(inode: &Inode<T>, f: &F) {
            match inode {
                Inode::Directory(ref dir) => visit_dir(dir, f),
                Inode::Leaf(ref leaf) => f(&leaf.stat),
            }
        }

        fn visit_dir<T, F: Fn(&Stat)>(dir: &Directory<T>, f: &F) {
            f(&dir.stat);
            for (_name, inode) in dir.entries.iter() {
                visit_inode(inode, f);
            }
        }

        visit_dir(&self.root, &f);
    }

    /// Filters extended attributes across the entire filesystem tree.
    ///
    /// Retains only xattrs whose names match the given predicate.
    /// This is useful for stripping build-time xattrs that shouldn't
    /// leak into the final image (e.g., `security.selinux` labels from
    /// the build host).
    pub fn filter_xattrs<F>(&self, predicate: F)
    where
        F: Fn(&OsStr) -> bool,
    {
        self.for_each_stat(|stat| {
            stat.xattrs.borrow_mut().retain(|k, _| predicate(k));
        });
    }

    /// Empties the `/run` directory if present, using `/usr`'s mtime.
    ///
    /// `/run` is a tmpfs at runtime and should always be empty in container images.
    /// This also works around podman/buildah's `RUN --mount` behavior where bind
    /// mount targets leave directory stubs in the filesystem that shouldn't be
    /// part of the image content.
    ///
    /// The mtime is set to match `/usr` for consistency with [`Self::copy_root_metadata_from_usr`].
    ///
    /// NOTE: If changing this behavior, also update `doc/oci.md`.
    ///
    /// # Errors
    ///
    /// Returns an error if `/usr` does not exist (needed to get the mtime).
    pub fn canonicalize_run(&mut self) -> Result<(), ImageError> {
        if self.root.get_directory_opt(OsStr::new("run"))?.is_some() {
            let usr_mtime = self.root.get_directory(OsStr::new("usr"))?.stat.st_mtim_sec;
            let run_dir = self.root.get_directory_mut(OsStr::new("run"))?;
            run_dir.stat.st_mtim_sec = usr_mtime;
            run_dir.clear();
        }
        Ok(())
    }

    /// Transforms the filesystem for OCI container image consistency.
    ///
    /// This applies the standard transformations needed to ensure consistent
    /// composefs digests between build-time (mounted filesystem) and install-time
    /// (OCI tar layers) views:
    ///
    /// 1. [`Self::copy_root_metadata_from_usr`] - copies `/usr` metadata to root directory
    /// 2. [`Self::canonicalize_run`] - empties `/run` directory
    ///
    /// This is the recommended single entry point for OCI container processing.
    ///
    /// NOTE: If changing this behavior, also update `doc/oci.md`.
    ///
    /// # Errors
    ///
    /// Returns an error if `/usr` does not exist.
    pub fn transform_for_oci(&mut self) -> Result<(), ImageError> {
        self.copy_root_metadata_from_usr()?;
        self.canonicalize_run()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::rc::Rc;

    // We never store any actual data here
    #[derive(Debug, Default)]
    struct FileContents {}

    // Helper to create a default stat for tests
    fn default_stat() -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: RefCell::new(BTreeMap::new()),
        }
    }

    // Helper to create a Stat with a specific mtime
    fn stat_with_mtime(mtime: i64) -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 1000,
            st_mtim_sec: mtime,
            xattrs: RefCell::new(BTreeMap::new()),
        }
    }

    // Helper to create a simple Leaf (e.g., an empty inline file)
    fn new_leaf_file(mtime: i64) -> Rc<Leaf<FileContents>> {
        Rc::new(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Regular(FileContents::default()),
        })
    }

    // Helper to create a simple Leaf (symlink)
    fn new_leaf_symlink(target: &str, mtime: i64) -> Rc<Leaf<FileContents>> {
        Rc::new(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Symlink(OsString::from(target).into_boxed_os_str()),
        })
    }

    // Helper to create an empty Directory Inode with a specific mtime
    fn new_dir_inode<T>(mtime: i64) -> Inode<T> {
        Inode::Directory(Box::new(Directory {
            stat: stat_with_mtime(mtime),
            entries: BTreeMap::new(),
        }))
    }

    // Helper to create a Directory Inode with specific stat
    fn new_dir_inode_with_stat<T>(stat: Stat) -> Inode<T> {
        Inode::Directory(Box::new(Directory {
            stat,
            entries: BTreeMap::new(),
        }))
    }

    #[test]
    fn test_directory_new() {
        let stat = stat_with_mtime(123);
        let dir = Directory::<()>::new(stat);
        assert_eq!(dir.stat.st_mtim_sec, 123);
        assert!(dir.entries.is_empty());
    }

    #[test]
    fn test_insert_and_get_leaf() {
        let mut dir = Directory::<FileContents>::new(default_stat());
        let leaf = new_leaf_file(10);
        dir.insert(OsStr::new("file.txt"), Inode::Leaf(Rc::clone(&leaf)));
        assert_eq!(dir.entries.len(), 1);

        let retrieved_leaf_rc = dir.ref_leaf(OsStr::new("file.txt")).unwrap();
        assert!(Rc::ptr_eq(&retrieved_leaf_rc, &leaf));

        let regular_file_content = dir.get_file(OsStr::new("file.txt")).unwrap();
        assert!(matches!(regular_file_content, FileContents {}));
    }

    #[test]
    fn test_insert_and_get_directory() {
        let mut dir = Directory::<()>::new(default_stat());
        let sub_dir_inode = new_dir_inode(20);
        dir.insert(OsStr::new("subdir"), sub_dir_inode);
        assert_eq!(dir.entries.len(), 1);

        let retrieved_subdir = dir.get_directory(OsStr::new("subdir")).unwrap();
        assert_eq!(retrieved_subdir.stat.st_mtim_sec, 20);

        let retrieved_subdir_opt = dir
            .get_directory_opt(OsStr::new("subdir"))
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_subdir_opt.stat.st_mtim_sec, 20);
    }

    #[test]
    fn test_get_directory_errors() {
        let mut root = Directory::new(default_stat());
        root.insert(OsStr::new("dir1"), new_dir_inode(10));
        root.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(30)));

        match root.get_directory(OsStr::new("nonexistent")) {
            Err(ImageError::NotFound(name)) => assert_eq!(name.to_str().unwrap(), "nonexistent"),
            _ => panic!("Expected NotFound"),
        }
        assert!(root
            .get_directory_opt(OsStr::new("nonexistent"))
            .unwrap()
            .is_none());

        match root.get_directory(OsStr::new("file1")) {
            Err(ImageError::NotADirectory(name)) => assert_eq!(name.to_str().unwrap(), "file1"),
            _ => panic!("Expected NotADirectory"),
        }
    }

    #[test]
    fn test_get_file_errors() {
        let mut dir = Directory::new(default_stat());
        dir.insert(OsStr::new("subdir"), new_dir_inode(10));
        dir.insert(
            OsStr::new("link.txt"),
            Inode::Leaf(new_leaf_symlink("target", 20)),
        );

        match dir.get_file(OsStr::new("nonexistent.txt")) {
            Err(ImageError::NotFound(name)) => {
                assert_eq!(name.to_str().unwrap(), "nonexistent.txt")
            }
            _ => panic!("Expected NotFound"),
        }
        assert!(dir
            .get_file_opt(OsStr::new("nonexistent.txt"))
            .unwrap()
            .is_none());

        match dir.get_file(OsStr::new("subdir")) {
            Err(ImageError::IsADirectory(name)) => assert_eq!(name.to_str().unwrap(), "subdir"),
            _ => panic!("Expected IsADirectory"),
        }
        match dir.get_file(OsStr::new("link.txt")) {
            Err(ImageError::IsNotRegular(name)) => assert_eq!(name.to_str().unwrap(), "link.txt"),
            res => panic!("Expected IsNotRegular, got {res:?}"),
        }
    }

    #[test]
    fn test_remove() {
        let mut dir = Directory::new(default_stat());
        dir.insert(OsStr::new("file1.txt"), Inode::Leaf(new_leaf_file(10)));
        dir.insert(OsStr::new("subdir"), new_dir_inode(20));
        assert_eq!(dir.entries.len(), 2);

        dir.remove(OsStr::new("file1.txt"));
        assert_eq!(dir.entries.len(), 1);
        assert!(!dir.entries.contains_key(OsStr::new("file1.txt")));

        dir.remove(OsStr::new("nonexistent")); // Should be no-op
        assert_eq!(dir.entries.len(), 1);
    }

    #[test]
    fn test_merge() {
        let mut dir = Directory::new(default_stat());

        // Merge Leaf onto empty
        dir.merge(OsStr::new("item"), Inode::Leaf(new_leaf_file(10)));
        assert_eq!(
            dir.entries
                .get(OsStr::new("item"))
                .unwrap()
                .stat()
                .st_mtim_sec,
            10
        );

        // Merge Directory onto existing Directory
        let mut existing_dir_inode = new_dir_inode_with_stat(stat_with_mtime(80));
        if let Inode::Directory(ref mut ed_box) = existing_dir_inode {
            ed_box.insert(OsStr::new("inner_file"), Inode::Leaf(new_leaf_file(85)));
        }
        dir.insert(OsStr::new("merged_dir"), existing_dir_inode);

        let new_merging_dir_inode = new_dir_inode_with_stat(stat_with_mtime(90));
        dir.merge(OsStr::new("merged_dir"), new_merging_dir_inode);

        match dir.entries.get(OsStr::new("merged_dir")) {
            Some(Inode::Directory(d)) => {
                assert_eq!(d.stat.st_mtim_sec, 90); // Stat updated
                assert_eq!(d.entries.len(), 1); // Inner file preserved
                assert!(d.entries.contains_key(OsStr::new("inner_file")));
            }
            _ => panic!("Expected directory after merge"),
        }

        // Merge Leaf onto Directory (replaces)
        dir.merge(OsStr::new("merged_dir"), Inode::Leaf(new_leaf_file(100)));
        assert!(matches!(
            dir.entries.get(OsStr::new("merged_dir")),
            Some(Inode::Leaf(_))
        ));
        assert_eq!(
            dir.entries
                .get(OsStr::new("merged_dir"))
                .unwrap()
                .stat()
                .st_mtim_sec,
            100
        );
    }

    #[test]
    fn test_clear() {
        let mut dir = Directory::new(default_stat());
        dir.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(10)));
        dir.stat.st_mtim_sec = 100;

        dir.clear();
        assert!(dir.entries.is_empty());
        assert_eq!(dir.stat.st_mtim_sec, 100); // Stat should be unmodified
    }

    #[test]
    fn test_newest_file() {
        let mut root = Directory::new(stat_with_mtime(5));
        assert_eq!(root.newest_file(), 5);

        root.insert(OsStr::new("file1"), Inode::Leaf(new_leaf_file(10)));
        assert_eq!(root.newest_file(), 10);

        let subdir_stat = stat_with_mtime(15);
        let mut subdir = Box::new(Directory::new(subdir_stat));
        subdir.insert(OsStr::new("subfile1"), Inode::Leaf(new_leaf_file(12)));
        root.insert(OsStr::new("subdir"), Inode::Directory(subdir));
        assert_eq!(root.newest_file(), 15);

        if let Some(Inode::Directory(sd)) = root.entries.get_mut(OsStr::new("subdir")) {
            sd.insert(OsStr::new("subfile2"), Inode::Leaf(new_leaf_file(20)));
        }
        assert_eq!(root.newest_file(), 20);

        root.stat.st_mtim_sec = 25;
        assert_eq!(root.newest_file(), 25);
    }

    #[test]
    fn test_iteration_entries_sorted_inodes() {
        let mut dir = Directory::new(default_stat());
        dir.insert(OsStr::new("b_file"), Inode::Leaf(new_leaf_file(10)));
        dir.insert(OsStr::new("a_dir"), new_dir_inode(20));
        dir.insert(
            OsStr::new("c_link"),
            Inode::Leaf(new_leaf_symlink("target", 30)),
        );

        let names_from_entries: Vec<&OsStr> = dir.entries().map(|(name, _)| name).collect();
        assert_eq!(names_from_entries.len(), 3); // BTreeMap iter is sorted
        assert!(names_from_entries.contains(&OsStr::new("a_dir")));
        assert!(names_from_entries.contains(&OsStr::new("b_file")));
        assert!(names_from_entries.contains(&OsStr::new("c_link")));

        let sorted_names: Vec<&OsStr> = dir.sorted_entries().map(|(name, _)| name).collect();
        assert_eq!(
            sorted_names,
            vec![
                OsStr::new("a_dir"),
                OsStr::new("b_file"),
                OsStr::new("c_link")
            ]
        );

        let mut inode_types = vec![];
        for inode in dir.inodes() {
            match inode {
                Inode::Directory(_) => inode_types.push("dir"),
                Inode::Leaf(_) => inode_types.push("leaf"),
            }
        }
        assert_eq!(inode_types.len(), 3);
        assert_eq!(inode_types.iter().filter(|&&t| t == "dir").count(), 1);
        assert_eq!(inode_types.iter().filter(|&&t| t == "leaf").count(), 2);
    }

    #[test]
    fn test_copy_root_metadata_from_usr() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr with specific metadata
        let usr_stat = Stat {
            st_mode: 0o755,
            st_uid: 42,
            st_gid: 43,
            st_mtim_sec: 1234567890,
            xattrs: RefCell::new(BTreeMap::from([(
                Box::from(OsStr::new("security.selinux")),
                Box::from(b"system_u:object_r:usr_t:s0".as_slice()),
            )])),
        };
        let usr_dir = Directory {
            stat: usr_stat,
            entries: BTreeMap::new(),
        };
        fs.root.entries.insert(
            Box::from(OsStr::new("usr")),
            Inode::Directory(Box::new(usr_dir)),
        );

        fs.copy_root_metadata_from_usr().unwrap();

        assert_eq!(fs.root.stat.st_mode, 0o755);
        assert_eq!(fs.root.stat.st_uid, 42);
        assert_eq!(fs.root.stat.st_gid, 43);
        assert_eq!(fs.root.stat.st_mtim_sec, 1234567890);
        assert!(fs
            .root
            .stat
            .xattrs
            .borrow()
            .contains_key(OsStr::new("security.selinux")));
    }

    #[test]
    fn test_copy_root_metadata_from_usr_missing() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        match fs.copy_root_metadata_from_usr() {
            Err(ImageError::NotFound(name)) => assert_eq!(name.to_str().unwrap(), "usr"),
            other => panic!("Expected NotFound error, got {:?}", other),
        }
    }

    #[test]
    fn test_filter_xattrs() {
        let root_stat = Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: 0,
            xattrs: RefCell::new(BTreeMap::from([
                (
                    Box::from(OsStr::new("security.selinux")),
                    Box::from(b"label".as_slice()),
                ),
                (
                    Box::from(OsStr::new("security.capability")),
                    Box::from(b"cap".as_slice()),
                ),
                (
                    Box::from(OsStr::new("user.custom")),
                    Box::from(b"value".as_slice()),
                ),
            ])),
        };
        let fs = FileSystem::<FileContents>::new(root_stat);

        // Filter to keep only xattrs starting with "user."
        fs.filter_xattrs(|name| name.as_encoded_bytes().starts_with(b"user."));

        let root_xattrs = fs.root.stat.xattrs.borrow();
        assert_eq!(root_xattrs.len(), 1);
        assert!(root_xattrs.contains_key(OsStr::new("user.custom")));
    }

    #[test]
    fn test_canonicalize_run() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr with specific mtime
        let usr_dir = Directory::new(stat_with_mtime(12345));
        fs.root
            .insert(OsStr::new("usr"), Inode::Directory(Box::new(usr_dir)));

        // Create /run with content and different mtime
        let mut run_dir = Directory::new(stat_with_mtime(99999));
        run_dir.insert(OsStr::new("somefile"), Inode::Leaf(new_leaf_file(11111)));
        let mut subdir = Directory::new(stat_with_mtime(22222));
        subdir.insert(OsStr::new("nested"), Inode::Leaf(new_leaf_file(33333)));
        run_dir.insert(OsStr::new("subdir"), Inode::Directory(Box::new(subdir)));
        fs.root
            .insert(OsStr::new("run"), Inode::Directory(Box::new(run_dir)));

        // Verify /run has content before
        assert_eq!(
            fs.root
                .get_directory(OsStr::new("run"))
                .unwrap()
                .entries
                .len(),
            2
        );

        // Canonicalize
        fs.canonicalize_run().unwrap();

        // Verify /run is now empty with /usr's mtime
        let run = fs.root.get_directory(OsStr::new("run")).unwrap();
        assert!(run.entries.is_empty());
        assert_eq!(run.stat.st_mtim_sec, 12345);
    }

    #[test]
    fn test_canonicalize_run_no_run_dir() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr but no /run
        let usr_dir = Directory::new(stat_with_mtime(12345));
        fs.root
            .insert(OsStr::new("usr"), Inode::Directory(Box::new(usr_dir)));

        // Should succeed without error
        fs.canonicalize_run().unwrap();
    }

    #[test]
    fn test_transform_for_oci() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr with specific metadata
        let usr_stat = Stat {
            st_mode: 0o750,
            st_uid: 100,
            st_gid: 200,
            st_mtim_sec: 54321,
            xattrs: RefCell::new(BTreeMap::from([(
                Box::from(OsStr::new("user.test")),
                Box::from(b"val".as_slice()),
            )])),
        };
        fs.root
            .insert(OsStr::new("usr"), new_dir_inode_with_stat(usr_stat));

        // Create /run with content
        let mut run_dir = Directory::new(stat_with_mtime(99999));
        run_dir.insert(OsStr::new("file"), Inode::Leaf(new_leaf_file(11111)));
        fs.root
            .insert(OsStr::new("run"), Inode::Directory(Box::new(run_dir)));

        // Transform for OCI
        fs.transform_for_oci().unwrap();

        // Verify root metadata copied from /usr
        assert_eq!(fs.root.stat.st_mode, 0o750);
        assert_eq!(fs.root.stat.st_uid, 100);
        assert_eq!(fs.root.stat.st_gid, 200);
        assert_eq!(fs.root.stat.st_mtim_sec, 54321);

        // Verify /run is emptied with /usr's mtime
        let run = fs.root.get_directory(OsStr::new("run")).unwrap();
        assert!(run.entries.is_empty());
        assert_eq!(run.stat.st_mtim_sec, 54321);
    }

    #[test]
    fn test_add_overlay_whiteouts() {
        let root_stat = Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 2000,
            st_mtim_sec: 12345,
            xattrs: RefCell::new(BTreeMap::from([(
                Box::from(OsStr::new("security.selinux")),
                Box::from(b"system_u:object_r:root_t:s0".as_slice()),
            )])),
        };
        let mut fs = FileSystem::<FileContents>::new(root_stat);

        // Add a pre-existing entry that should not be overwritten
        fs.root
            .insert(OsStr::new("00"), Inode::Leaf(new_leaf_file(99999)));

        fs.add_overlay_whiteouts();

        // Should have 256 whiteout entries (255 new + 1 pre-existing)
        assert_eq!(fs.root.entries.len(), 256);

        // The pre-existing "00" should still have its original mtime
        if let Some(Inode::Leaf(leaf)) = fs.root.entries.get(OsStr::new("00")) {
            assert_eq!(leaf.stat.st_mtim_sec, 99999);
        } else {
            panic!("Expected '00' to remain a leaf");
        }

        // Check a newly created whiteout entry
        if let Some(Inode::Leaf(leaf)) = fs.root.entries.get(OsStr::new("ff")) {
            // Should be a character device with rdev=0
            assert!(matches!(leaf.content, LeafContent::CharacterDevice(0)));
            // Should have mode 0o644
            assert_eq!(leaf.stat.st_mode, 0o644);
            // Should inherit uid/gid/mtime from root
            assert_eq!(leaf.stat.st_uid, 1000);
            assert_eq!(leaf.stat.st_gid, 2000);
            assert_eq!(leaf.stat.st_mtim_sec, 12345);
            // Should have copied xattrs from root
            assert!(leaf
                .stat
                .xattrs
                .borrow()
                .contains_key(OsStr::new("security.selinux")));
        } else {
            panic!("Expected 'ff' to be a leaf");
        }

        // Check some middle entries exist
        assert!(fs.root.entries.contains_key(OsStr::new("7f")));
        assert!(fs.root.entries.contains_key(OsStr::new("a0")));
    }

    #[test]
    fn test_set_overlay_opaque() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        fs.set_overlay_opaque();

        let xattrs = fs.root.stat.xattrs.borrow();
        let opaque = xattrs.get(OsStr::new("trusted.overlay.opaque"));
        assert!(opaque.is_some());
        assert_eq!(opaque.unwrap().as_ref(), b"y");
    }

    #[test]
    fn test_add_overlay_whiteouts_empty_fs() {
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        fs.add_overlay_whiteouts();

        // Should have exactly 256 entries
        assert_eq!(fs.root.entries.len(), 256);

        // Check first and last entries
        assert!(fs.root.entries.contains_key(OsStr::new("00")));
        assert!(fs.root.entries.contains_key(OsStr::new("ff")));
    }
}

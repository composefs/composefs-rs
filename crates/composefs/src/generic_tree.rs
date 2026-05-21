//! A generic metadata-only filesystem tree where regular files can be stored
//! however the caller wants.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    marker::PhantomData,
    path::{Component, Path},
};

use thiserror::Error;

/// File metadata similar to `struct stat` from POSIX.
#[derive(Debug, Clone)]
pub struct Stat {
    /// File mode and permissions bits.
    pub st_mode: u32,
    /// User ID of owner.
    pub st_uid: u32,
    /// Group ID of owner.
    pub st_gid: u32,
    /// Modification time in seconds since Unix epoch.
    pub st_mtim_sec: i64,
    /// Modification time nanosecond component (0..999_999_999).
    pub st_mtim_nsec: u32,
    /// Extended attributes as key-value pairs.
    pub xattrs: BTreeMap<Box<OsStr>, Box<[u8]>>,
}

impl Default for Stat {
    fn default() -> Self {
        Self::uninitialized()
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
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }
}

/// Index into [`FileSystem`]'s leaves table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafId(pub usize);

/// Content types for leaf nodes (non-directory files).
#[derive(Debug, Clone)]
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

impl<T> LeafContent<T> {
    /// Maps `Regular(&T)` to `Regular(U)` via a fallible function,
    /// passing all other variants through unchanged.
    pub fn try_map_ref<U, E>(
        &self,
        f: impl FnOnce(&T) -> Result<U, E>,
    ) -> Result<LeafContent<U>, E> {
        match self {
            LeafContent::Regular(t) => Ok(LeafContent::Regular(f(t)?)),
            LeafContent::BlockDevice(rdev) => Ok(LeafContent::BlockDevice(*rdev)),
            LeafContent::CharacterDevice(rdev) => Ok(LeafContent::CharacterDevice(*rdev)),
            LeafContent::Fifo => Ok(LeafContent::Fifo),
            LeafContent::Socket => Ok(LeafContent::Socket),
            LeafContent::Symlink(target) => Ok(LeafContent::Symlink(target.clone())),
        }
    }
}

/// A leaf node representing a non-directory file.
#[derive(Debug, Clone)]
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
    /// A leaf inode, referencing an entry in the leaves table by index.
    ///
    /// The `PhantomData` ties the type parameter `T` to the enum without
    /// requiring it to appear directly (since `LeafId` is type-erased).
    /// Use [`Inode::leaf`] to construct this variant.
    Leaf(LeafId, PhantomData<T>),
}

impl<T> Inode<T> {
    /// Create a leaf inode referencing the given leaf table index.
    pub fn leaf(id: LeafId) -> Self {
        Inode::Leaf(id, PhantomData)
    }
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
    /// A LeafId in the directory tree is out of bounds.
    #[error("LeafId {0} is out of bounds (leaves table has {1} entries)")]
    LeafIdOutOfBounds(usize, usize),
    /// Leaves in the table are not referenced by any directory entry.
    #[error("Orphaned leaves at indices {0:?}")]
    OrphanedLeaves(Vec<usize>),
}

impl<T> Inode<T> {
    /// Returns a reference to the metadata for this inode.
    ///
    /// For leaf inodes, the `leaves` table is needed to resolve the `LeafId`.
    pub fn stat<'a>(&'a self, leaves: &'a [Leaf<T>]) -> &'a Stat {
        match self {
            Inode::Directory(dir) => &dir.stat,
            Inode::Leaf(id, _) => &leaves[id.0].stat,
        }
    }

    /// Recursively changes the type parameter of an inode tree.
    ///
    /// [`LeafId`] indices pass through unchanged — only the phantom type
    /// parameter on [`Inode::Leaf`] is updated.
    fn retype<U>(self) -> Inode<U> {
        match self {
            Inode::Directory(dir) => Inode::Directory(Box::new(dir.retype::<U>())),
            Inode::Leaf(id, _) => Inode::leaf(id),
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

    /// Returns the `LeafId` for the named non-directory entry.
    ///
    /// This is typically used to create hardlinks: directory entries sharing
    /// the same `LeafId` are hardlinks to the same underlying leaf.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is not a directory) the LeafId is returned.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn leaf_id(&self, filename: &OsStr) -> Result<LeafId, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(id, _)) => Ok(*id),
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
    ///  * `leaves`: the leaves table from the containing [`FileSystem`].
    ///
    /// # Return value
    ///
    /// On success (the entry exists and is a regular file) then a reference to the file
    /// content `T` is returned.
    ///
    /// On failure, can return any number of errors from ImageError.
    pub fn get_file<'a>(
        &'a self,
        filename: &OsStr,
        leaves: &'a [Leaf<T>],
    ) -> Result<&'a T, ImageError> {
        self.get_file_opt(filename, leaves)?
            .ok_or_else(|| ImageError::NotFound(Box::from(filename)))
    }

    /// Like [`Self::get_file()`] but maps [`ImageError::NotFound`] to [`Option`].
    pub fn get_file_opt<'a>(
        &'a self,
        filename: &OsStr,
        leaves: &'a [Leaf<T>],
    ) -> Result<Option<&'a T>, ImageError> {
        match self.entries.get(filename) {
            Some(Inode::Leaf(id, _)) => match &leaves[id.0].content {
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
    /// Returns `true` if the entry is new, `false` if it replaced an existing entry.
    ///
    /// # Arguments
    ///
    ///  * `filename`: the filename in the current directory.  If you need to support full
    ///    pathnames then you should call `Directory::split()` first.
    ///  * `inode`: the inode to store under the `filename`
    pub fn insert(&mut self, filename: &OsStr, inode: Inode<T>) -> bool {
        self.entries.insert(Box::from(filename), inode).is_none()
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

    /// Updates a leaf entry in this directory to point to a different [`LeafId`].
    ///
    /// Used when breaking a hardlink: after cloning a leaf into a new slot, call
    /// this to redirect the directory entry to the clone.  Panics if `filename`
    /// does not exist or is not a leaf.
    pub fn remap_leaf(&mut self, filename: &OsStr, new_id: LeafId) {
        match self.entries.get_mut(filename) {
            Some(Inode::Leaf(id, _)) => *id = new_id,
            _ => panic!("remap_leaf: {filename:?} is not a leaf entry"),
        }
    }

    /// Retains only top-level entries whose names satisfy the predicate.
    /// This is used for filtering dump output to specific entries.
    pub fn retain_top_level(&mut self, mut f: impl FnMut(&str) -> bool) {
        self.entries.retain(|name, _| {
            // Convert OsStr to str for comparison; non-UTF8 names never match
            name.to_str().is_some_and(&mut f)
        });
    }

    /// Recursively finds the newest modification time in this directory tree.
    ///
    /// Returns the maximum modification time among this directory's metadata
    /// and all files and subdirectories it contains, as a `(sec, nsec)` tuple
    /// for full nanosecond precision.
    ///
    /// The `leaves` table is needed to resolve leaf mtimes.
    pub fn newest_file(&self, leaves: &[Leaf<T>]) -> (i64, u32) {
        let mut newest = (self.stat.st_mtim_sec, self.stat.st_mtim_nsec);
        for inode in self.entries.values() {
            let mtime = match inode {
                Inode::Leaf(id, _) => {
                    let s = &leaves[id.0].stat;
                    (s.st_mtim_sec, s.st_mtim_nsec)
                }
                Inode::Directory(dir) => dir.newest_file(leaves),
            };
            if mtime > newest {
                newest = mtime;
            }
        }
        newest
    }

    /// Recursively changes the type parameter of the directory tree.
    ///
    /// [`LeafId`] indices pass through unchanged — only the phantom type
    /// parameter on [`Inode::Leaf`] is updated.
    fn retype<U>(self) -> Directory<U> {
        let entries = self
            .entries
            .into_iter()
            .map(|(name, inode)| (name, inode.retype::<U>()))
            .collect();
        Directory {
            stat: self.stat,
            entries,
        }
    }

    /// Counts how many times each LeafId is referenced in this directory tree.
    fn count_leaf_refs(&self, refcount: &mut [u32]) {
        for inode in self.entries.values() {
            match inode {
                Inode::Directory(dir) => dir.count_leaf_refs(refcount),
                Inode::Leaf(id, _) => refcount[id.0] += 1,
            }
        }
    }

    /// Validates that all LeafIds are in bounds and counts references.
    fn fsck_refs(&self, num_leaves: usize, refcount: &mut [u32]) -> Result<(), ImageError> {
        for inode in self.entries.values() {
            match inode {
                Inode::Directory(dir) => dir.fsck_refs(num_leaves, refcount)?,
                Inode::Leaf(id, _) => {
                    if id.0 >= num_leaves {
                        return Err(ImageError::LeafIdOutOfBounds(id.0, num_leaves));
                    }
                    refcount[id.0] += 1;
                }
            }
        }
        Ok(())
    }

    /// Remaps all LeafIds in this directory tree using the given mapping.
    fn remap_leaf_ids(&mut self, id_map: &[LeafId]) {
        for inode in self.entries.values_mut() {
            match inode {
                Inode::Directory(dir) => dir.remap_leaf_ids(id_map),
                Inode::Leaf(id, _) => *id = id_map[id.0],
            }
        }
    }
}

/// A complete filesystem tree with a root directory and a flat table of leaves.
///
/// Leaf nodes (non-directory files) are stored in a flat `Vec` and referenced
/// by [`LeafId`] indices from the directory tree. This design is `Send + Sync`,
/// supports hardlinks via shared `LeafId`, and avoids reference counting.
#[derive(Debug)]
pub struct FileSystem<T> {
    /// The root directory of the filesystem.
    pub root: Directory<T>,
    /// Table of all leaf nodes; [`LeafId`] indexes into this vector.
    pub leaves: Vec<Leaf<T>>,
}

impl<T> FileSystem<T> {
    /// Add 256 overlay whiteout stub entries to the root directory.
    ///
    /// This is required for Format 1.0 compatibility with the C mkcomposefs.
    /// Each whiteout is a character device named "00" through "ff" with rdev=0.
    /// They inherit uid/gid/mtime from the root directory but have empty xattrs.
    ///
    /// These entries allow overlay filesystems to efficiently represent
    /// deleted files using device stubs that match the naming convention.
    ///
    /// Adds the 256 two-character hex-named whiteout stub entries (`00`..`ff`) to
    /// the root directory, skipping any that already exist.
    ///
    /// Matches C mkcomposefs v1.0.8 `add_overlay_whiteouts()`: each stub inherits
    /// `uid`, `gid`, and `mtime` from root, gets mode `S_IFCHR|0644` with `rdev=0`,
    /// and **only** the `security.selinux` xattr from root (if present).  No other
    /// xattrs are propagated — copying all root xattrs would make them appear on 257
    /// inodes instead of 1, causing the xattr-sharing pass to turn them into shared
    /// references and bloating the inode body in a way C does not.
    pub(crate) fn add_overlay_whiteouts(&mut self) {
        use std::ffi::OsString;

        // C mkcomposefs only inherits security.selinux from root for the stubs.
        // Copying all root xattrs would change shared-vs-local xattr storage and
        // produce a binary-incompatible image.
        let selinux_key = std::ffi::OsStr::new("security.selinux");
        let mut whiteout_xattrs = std::collections::BTreeMap::new();
        if let Some(val) = self.root.stat.xattrs.get(selinux_key) {
            whiteout_xattrs.insert(Box::from(selinux_key), val.clone());
        }

        let whiteout_stat = Stat {
            st_mode: 0o644,
            st_uid: self.root.stat.st_uid,
            st_gid: self.root.stat.st_gid,
            st_mtim_sec: self.root.stat.st_mtim_sec,
            st_mtim_nsec: self.root.stat.st_mtim_nsec,
            xattrs: whiteout_xattrs,
        };

        for i in 0..=255u8 {
            let name = OsString::from(format!("{:02x}", i));

            // Skip if entry already exists
            if self.root.entries.contains_key(name.as_os_str()) {
                continue;
            }

            let leaf_id = self.push_leaf(whiteout_stat.clone(), LeafContent::CharacterDevice(0));
            self.root
                .entries
                .insert(name.into_boxed_os_str(), Inode::leaf(leaf_id));
        }
    }

    /// Creates a new filesystem with a root directory having the given metadata.
    pub fn new(root_stat: Stat) -> Self {
        Self {
            root: Directory::new(root_stat),
            leaves: Vec::new(),
        }
    }

    /// Sets the metadata for the root directory.
    pub fn set_root_stat(&mut self, stat: Stat) {
        self.root.stat = stat;
    }

    /// Pushes a new leaf into the leaves table and returns its [`LeafId`].
    pub fn push_leaf(&mut self, stat: Stat, content: LeafContent<T>) -> LeafId {
        let id = LeafId(self.leaves.len());
        self.leaves.push(Leaf { stat, content });
        id
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
        let st_mtim_nsec = usr.stat.st_mtim_nsec;
        let xattrs = usr.stat.xattrs.clone();

        // Apply copied metadata to root
        self.root.stat.st_mode = st_mode;
        self.root.stat.st_uid = st_uid;
        self.root.stat.st_gid = st_gid;
        self.root.stat.st_mtim_sec = st_mtim_sec;
        self.root.stat.st_mtim_nsec = st_mtim_nsec;
        self.root.stat.xattrs = xattrs;

        Ok(())
    }

    /// Applies a function to every [`Stat`] in the filesystem tree.
    ///
    /// This visits the root directory and all descendant directories via the tree,
    /// and each leaf stat exactly once via the flat leaves table.
    pub fn for_each_stat<F>(&self, f: F)
    where
        F: Fn(&Stat),
    {
        fn visit_dir<T, F: Fn(&Stat)>(dir: &Directory<T>, f: &F) {
            f(&dir.stat);
            for inode in dir.entries.values() {
                if let Inode::Directory(subdir) = inode {
                    visit_dir(subdir, f);
                }
            }
        }

        visit_dir(&self.root, &f);
        for leaf in &self.leaves {
            f(&leaf.stat);
        }
    }

    /// Applies a function to every [`Stat`] in the filesystem tree, mutably.
    ///
    /// This visits each directory stat via the tree, and each leaf stat exactly
    /// once via the flat leaves table. No dedup needed since each leaf appears
    /// exactly once in the table regardless of how many directory entries
    /// reference it.
    pub fn for_each_stat_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Stat),
    {
        fn visit_dir_mut<T, F: FnMut(&mut Stat)>(dir: &mut Directory<T>, f: &mut F) {
            f(&mut dir.stat);
            for inode in dir.entries.values_mut() {
                if let Inode::Directory(subdir) = inode {
                    visit_dir_mut(subdir, f);
                }
            }
        }

        visit_dir_mut(&mut self.root, &mut f);
        for leaf in &mut self.leaves {
            f(&mut leaf.stat);
        }
    }

    /// Filters extended attributes across the entire filesystem tree.
    ///
    /// Retains only xattrs whose names match the given predicate.
    /// This is useful for stripping build-time xattrs that shouldn't
    /// leak into the final image (e.g., `security.selinux` labels from
    /// the build host).
    pub fn filter_xattrs<F>(&mut self, predicate: F)
    where
        F: Fn(&OsStr) -> bool,
    {
        self.for_each_stat_mut(|stat| {
            stat.xattrs.retain(|k, _| predicate(k));
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
            let usr = self.root.get_directory(OsStr::new("usr"))?.stat.clone();
            let run_dir = self.root.get_directory_mut(OsStr::new("run"))?;
            run_dir.stat.st_mtim_sec = usr.st_mtim_sec;
            run_dir.stat.st_mtim_nsec = usr.st_mtim_nsec;
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

    /// Converts `FileSystem<T>` to `FileSystem<U>` by mapping regular file content.
    ///
    /// Applies `f` to each `LeafContent::Regular(T)` to produce `LeafContent::Regular(U)`.
    /// All other leaf content variants (symlinks, devices, etc.) are passed through unchanged.
    ///
    /// Because hardlinks are index-based, directory tree indices pass through unchanged.
    /// The mapping function is called exactly once per unique leaf.
    pub fn try_map_regular<U, E>(
        self,
        mut f: impl FnMut(&T) -> Result<U, E>,
    ) -> Result<FileSystem<U>, E> {
        let new_leaves = self
            .leaves
            .into_iter()
            .map(|leaf| {
                let new_content = leaf.content.try_map_ref(&mut f)?;
                Ok(Leaf {
                    stat: leaf.stat,
                    content: new_content,
                })
            })
            .collect::<Result<_, E>>()?;
        let root = self.root.retype::<U>();
        Ok(FileSystem {
            root,
            leaves: new_leaves,
        })
    }

    /// Removes unreferenced leaves and remaps all LeafIds.
    ///
    /// After removing entries from the tree, some leaves may become
    /// unreferenced. This method compacts the leaves table by removing
    /// dead entries and updating all LeafIds in the tree accordingly.
    pub fn compact(&mut self) {
        // 1. Count references to each LeafId
        let mut refcount = vec![0u32; self.leaves.len()];
        self.root.count_leaf_refs(&mut refcount);

        // 2. Build old_id → new_id mapping, skipping dead entries
        let mut id_map = vec![LeafId(0); self.leaves.len()];
        let mut write_pos = 0;
        for (old_id, &count) in refcount.iter().enumerate() {
            if count > 0 {
                id_map[old_id] = LeafId(write_pos);
                write_pos += 1;
            }
        }

        // 3. Compact the leaves vec (keep only live entries)
        let mut new_leaves = Vec::with_capacity(write_pos);
        for (old_id, leaf) in self.leaves.drain(..).enumerate() {
            if refcount[old_id] > 0 {
                new_leaves.push(leaf);
            }
        }
        self.leaves = new_leaves;

        // 4. Remap all LeafIds in the tree
        self.root.remap_leaf_ids(&id_map);

        debug_assert!(self.fsck().is_ok(), "compact() produced invalid filesystem");
    }

    /// Compute nlink counts for all leaves at once.
    ///
    /// Returns a `Vec` indexed by [`LeafId`] where each entry is the
    /// number of directory entries referencing that leaf (i.e. the
    /// hard link count).
    pub fn nlinks(&self) -> Vec<u32> {
        let mut refcount = vec![0u32; self.leaves.len()];
        self.root.count_leaf_refs(&mut refcount);
        refcount
    }

    /// Verify internal consistency of the filesystem.
    ///
    /// Checks that:
    /// - All [`LeafId`] indices in the directory tree are within bounds
    ///   of the leaves table
    /// - All leaves in the table are referenced by at least one
    ///   directory entry (no orphans)
    ///
    /// Returns `Ok(())` if the filesystem is consistent, or an error
    /// describing the first inconsistency found.
    pub fn fsck(&self) -> Result<(), ImageError> {
        // Validate bounds and count references in one pass.
        let mut refcount = vec![0u32; self.leaves.len()];
        self.root.fsck_refs(self.leaves.len(), &mut refcount)?;

        let orphans: Vec<usize> = refcount
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(i, _)| i)
            .collect();
        if !orphans.is_empty() {
            return Err(ImageError::OrphanedLeaves(orphans));
        }

        Ok(())
    }

    /// Returns a [`DirectoryRef`] for the root directory.
    pub fn as_dir(&self) -> DirectoryRef<'_, T> {
        DirectoryRef {
            dir: &self.root,
            leaves: &self.leaves,
        }
    }

    /// Returns a reference to the leaf with the given id.
    pub fn leaf(&self, id: LeafId) -> &Leaf<T> {
        &self.leaves[id.0]
    }

    /// Returns a mutable reference to the leaf with the given id.
    pub fn leaf_mut(&mut self, id: LeafId) -> &mut Leaf<T> {
        &mut self.leaves[id.0]
    }
}

/// A read-only view of a [`Directory`] paired with the [`FileSystem`]'s
/// leaves table, so that leaf-resolving methods don't need a separate
/// `leaves` parameter.
///
/// Obtained via [`FileSystem::as_dir`] or [`DirectoryRef::get_directory`].
#[derive(Debug)]
pub struct DirectoryRef<'a, T> {
    dir: &'a Directory<T>,
    leaves: &'a [Leaf<T>],
}

// Manual Clone/Copy implementations to avoid requiring T: Clone/Copy,
// since the struct only holds references.
impl<T> Clone for DirectoryRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for DirectoryRef<'_, T> {}

impl<T> std::ops::Deref for DirectoryRef<'_, T> {
    type Target = Directory<T>;

    fn deref(&self) -> &Self::Target {
        self.dir
    }
}

impl<'a, T> DirectoryRef<'a, T> {
    /// Constructs a [`DirectoryRef`] from a directory reference and a leaves table.
    ///
    /// This is useful when you have a `&Directory<T>` obtained from tree
    /// traversal (e.g., pattern matching on [`Inode::Directory`]) and want
    /// to wrap it with its leaves table for convenient leaf resolution.
    pub fn from_parts(dir: &'a Directory<T>, leaves: &'a [Leaf<T>]) -> Self {
        DirectoryRef { dir, leaves }
    }

    /// Returns the underlying leaves table.
    pub fn leaves(&self) -> &'a [Leaf<T>] {
        self.leaves
    }

    /// Looks up a subdirectory by path, returning a new [`DirectoryRef`].
    ///
    /// Like [`Directory::get_directory`] but wraps the result in a
    /// [`DirectoryRef`] that carries the leaves table.
    pub fn get_directory_ref(&self, pathname: &OsStr) -> Result<DirectoryRef<'a, T>, ImageError> {
        self.dir.get_directory(pathname).map(|dir| DirectoryRef {
            dir,
            leaves: self.leaves,
        })
    }

    /// Looks up a subdirectory by path, returning `None` if not found.
    ///
    /// Like [`Directory::get_directory_opt`] but wraps the result in a
    /// [`DirectoryRef`].
    pub fn get_directory_ref_opt(
        &self,
        pathname: &OsStr,
    ) -> Result<Option<DirectoryRef<'a, T>>, ImageError> {
        self.dir.get_directory_opt(pathname).map(|opt| {
            opt.map(|dir| DirectoryRef {
                dir,
                leaves: self.leaves,
            })
        })
    }

    /// Returns a reference to the leaf with the given id.
    pub fn leaf(&self, id: LeafId) -> &'a Leaf<T> {
        &self.leaves[id.0]
    }

    /// Splits a pathname into a [`DirectoryRef`] and the filename within it.
    ///
    /// Like [`Directory::split`] but wraps the resulting directory in a
    /// [`DirectoryRef`].
    pub fn split_ref<'n>(
        &self,
        pathname: &'n OsStr,
    ) -> Result<(DirectoryRef<'a, T>, &'n OsStr), ImageError> {
        let (dir, filename) = self.dir.split(pathname)?;
        Ok((
            DirectoryRef {
                dir,
                leaves: self.leaves,
            },
            filename,
        ))
    }

    /// Returns the regular file content `T` for the named entry.
    pub fn get_file(&self, filename: &OsStr) -> Result<&'a T, ImageError> {
        self.dir.get_file(filename, self.leaves)
    }

    /// Like [`Self::get_file`] but maps not-found to `None`.
    pub fn get_file_opt(&self, filename: &OsStr) -> Result<Option<&'a T>, ImageError> {
        self.dir.get_file_opt(filename, self.leaves)
    }

    /// Recursively finds the newest modification time in this directory tree.
    ///
    /// Returns a `(sec, nsec)` tuple for full nanosecond precision.
    pub fn newest_file(&self) -> (i64, u32) {
        self.dir.newest_file(self.leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

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
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    // Helper to create a Stat with a specific mtime
    fn stat_with_mtime(mtime: i64) -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 1000,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::new(),
        }
    }

    // Helper to create a leaf in the leaves vec and return the LeafId
    fn push_leaf_file(leaves: &mut Vec<Leaf<FileContents>>, mtime: i64) -> LeafId {
        let id = LeafId(leaves.len());
        leaves.push(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Regular(FileContents::default()),
        });
        id
    }

    // Helper to create a symlink leaf in the leaves vec and return the LeafId
    fn push_leaf_symlink(leaves: &mut Vec<Leaf<FileContents>>, target: &str, mtime: i64) -> LeafId {
        let id = LeafId(leaves.len());
        leaves.push(Leaf {
            stat: stat_with_mtime(mtime),
            content: LeafContent::Symlink(OsString::from(target).into_boxed_os_str()),
        });
        id
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
        let mut leaves = Vec::new();
        let leaf_id = push_leaf_file(&mut leaves, 10);

        let mut dir = Directory::<FileContents>::new(default_stat());
        dir.insert(OsStr::new("file.txt"), Inode::leaf(leaf_id));
        assert_eq!(dir.entries.len(), 1);

        let retrieved_id = dir.leaf_id(OsStr::new("file.txt")).unwrap();
        assert_eq!(retrieved_id, leaf_id);

        let regular_file_content = dir.get_file(OsStr::new("file.txt"), &leaves).unwrap();
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
        let mut leaves = Vec::new();
        let leaf_id = push_leaf_file(&mut leaves, 30);

        let mut root = Directory::<FileContents>::new(default_stat());
        root.insert(OsStr::new("dir1"), new_dir_inode(10));
        root.insert(OsStr::new("file1"), Inode::leaf(leaf_id));

        match root.get_directory(OsStr::new("nonexistent")) {
            Err(ImageError::NotFound(name)) => assert_eq!(name.to_str().unwrap(), "nonexistent"),
            _ => panic!("Expected NotFound"),
        }
        assert!(
            root.get_directory_opt(OsStr::new("nonexistent"))
                .unwrap()
                .is_none()
        );

        match root.get_directory(OsStr::new("file1")) {
            Err(ImageError::NotADirectory(name)) => assert_eq!(name.to_str().unwrap(), "file1"),
            _ => panic!("Expected NotADirectory"),
        }
    }

    #[test]
    fn test_get_file_errors() {
        let mut leaves = Vec::new();
        let symlink_id = push_leaf_symlink(&mut leaves, "target", 20);

        let mut dir = Directory::<FileContents>::new(default_stat());
        dir.insert(OsStr::new("subdir"), new_dir_inode(10));
        dir.insert(OsStr::new("link.txt"), Inode::leaf(symlink_id));

        match dir.get_file(OsStr::new("nonexistent.txt"), &leaves) {
            Err(ImageError::NotFound(name)) => {
                assert_eq!(name.to_str().unwrap(), "nonexistent.txt")
            }
            _ => panic!("Expected NotFound"),
        }
        assert!(
            dir.get_file_opt(OsStr::new("nonexistent.txt"), &leaves)
                .unwrap()
                .is_none()
        );

        match dir.get_file(OsStr::new("subdir"), &leaves) {
            Err(ImageError::IsADirectory(name)) => assert_eq!(name.to_str().unwrap(), "subdir"),
            _ => panic!("Expected IsADirectory"),
        }
        match dir.get_file(OsStr::new("link.txt"), &leaves) {
            Err(ImageError::IsNotRegular(name)) => assert_eq!(name.to_str().unwrap(), "link.txt"),
            res => panic!("Expected IsNotRegular, got {res:?}"),
        }
    }

    #[test]
    fn test_remove() {
        let mut leaves = Vec::new();
        let leaf_id = push_leaf_file(&mut leaves, 10);

        let mut dir = Directory::<FileContents>::new(default_stat());
        dir.insert(OsStr::new("file1.txt"), Inode::leaf(leaf_id));
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
        let mut leaves = Vec::new();

        let mut dir = Directory::<FileContents>::new(default_stat());

        // Merge Leaf onto empty
        let leaf_id = push_leaf_file(&mut leaves, 10);
        dir.merge(OsStr::new("item"), Inode::leaf(leaf_id));
        assert_eq!(
            dir.entries
                .get(OsStr::new("item"))
                .unwrap()
                .stat(&leaves)
                .st_mtim_sec,
            10
        );

        // Merge Directory onto existing Directory
        let inner_leaf_id = push_leaf_file(&mut leaves, 85);
        let mut existing_dir_inode = new_dir_inode_with_stat(stat_with_mtime(80));
        if let Inode::Directory(ref mut ed_box) = existing_dir_inode {
            ed_box.insert(OsStr::new("inner_file"), Inode::leaf(inner_leaf_id));
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
        let replace_leaf_id = push_leaf_file(&mut leaves, 100);
        dir.merge(OsStr::new("merged_dir"), Inode::leaf(replace_leaf_id));
        assert!(matches!(
            dir.entries.get(OsStr::new("merged_dir")),
            Some(Inode::Leaf(..))
        ));
        assert_eq!(
            dir.entries
                .get(OsStr::new("merged_dir"))
                .unwrap()
                .stat(&leaves)
                .st_mtim_sec,
            100
        );
    }

    #[test]
    fn test_clear() {
        let mut leaves = Vec::new();
        let leaf_id = push_leaf_file(&mut leaves, 10);

        let mut dir = Directory::<FileContents>::new(default_stat());
        dir.insert(OsStr::new("file1"), Inode::leaf(leaf_id));
        dir.stat.st_mtim_sec = 100;

        dir.clear();
        assert!(dir.entries.is_empty());
        assert_eq!(dir.stat.st_mtim_sec, 100); // Stat should be unmodified
    }

    #[test]
    fn test_newest_file() {
        let mut leaves = Vec::new();

        let mut root = Directory::new(stat_with_mtime(5));
        assert_eq!(root.newest_file(&leaves), (5, 0));

        let leaf_id_10 = push_leaf_file(&mut leaves, 10);
        root.insert(OsStr::new("file1"), Inode::leaf(leaf_id_10));
        assert_eq!(root.newest_file(&leaves), (10, 0));

        let subdir_stat = stat_with_mtime(15);
        let mut subdir = Box::new(Directory::new(subdir_stat));
        let leaf_id_12 = push_leaf_file(&mut leaves, 12);
        subdir.insert(OsStr::new("subfile1"), Inode::leaf(leaf_id_12));
        root.insert(OsStr::new("subdir"), Inode::Directory(subdir));
        assert_eq!(root.newest_file(&leaves), (15, 0));

        if let Some(Inode::Directory(sd)) = root.entries.get_mut(OsStr::new("subdir")) {
            let leaf_id_20 = push_leaf_file(&mut leaves, 20);
            sd.insert(OsStr::new("subfile2"), Inode::leaf(leaf_id_20));
        }
        assert_eq!(root.newest_file(&leaves), (20, 0));

        root.stat.st_mtim_sec = 25;
        assert_eq!(root.newest_file(&leaves), (25, 0));
    }

    #[test]
    fn test_iteration_entries_sorted_inodes() {
        let mut leaves = Vec::new();
        let file_id = push_leaf_file(&mut leaves, 10);
        let link_id = push_leaf_symlink(&mut leaves, "target", 30);

        let mut dir = Directory::<FileContents>::new(default_stat());
        dir.insert(OsStr::new("b_file"), Inode::leaf(file_id));
        dir.insert(OsStr::new("a_dir"), new_dir_inode(20));
        dir.insert(OsStr::new("c_link"), Inode::leaf(link_id));

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
                Inode::Leaf(..) => inode_types.push("leaf"),
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
            st_mtim_nsec: 0,
            xattrs: BTreeMap::from([(
                Box::from(OsStr::new("security.selinux")),
                Box::from(b"system_u:object_r:usr_t:s0".as_slice()),
            )]),
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
        assert!(
            fs.root
                .stat
                .xattrs
                .contains_key(OsStr::new("security.selinux"))
        );
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
            st_mtim_nsec: 0,
            xattrs: BTreeMap::from([
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
            ]),
        };
        let mut fs = FileSystem::<FileContents>::new(root_stat);

        // Filter to keep only xattrs starting with "user."
        fs.filter_xattrs(|name| name.as_encoded_bytes().starts_with(b"user."));

        assert_eq!(fs.root.stat.xattrs.len(), 1);
        assert!(fs.root.stat.xattrs.contains_key(OsStr::new("user.custom")));
    }

    #[test]
    fn test_canonicalize_run() {
        let mut leaves = Vec::new();
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr with specific mtime
        let usr_dir = Directory::new(stat_with_mtime(12345));
        fs.root
            .insert(OsStr::new("usr"), Inode::Directory(Box::new(usr_dir)));

        // Create /run with content and different mtime
        let mut run_dir = Directory::new(stat_with_mtime(99999));
        let file_id = push_leaf_file(&mut leaves, 11111);
        run_dir.insert(OsStr::new("somefile"), Inode::leaf(file_id));
        let mut subdir = Directory::new(stat_with_mtime(22222));
        let nested_id = push_leaf_file(&mut leaves, 33333);
        subdir.insert(OsStr::new("nested"), Inode::leaf(nested_id));
        run_dir.insert(OsStr::new("subdir"), Inode::Directory(Box::new(subdir)));
        fs.root
            .insert(OsStr::new("run"), Inode::Directory(Box::new(run_dir)));
        fs.leaves = leaves;

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
    fn test_try_map_regular_basic() {
        let mut fs = FileSystem::<u32>::new(stat_with_mtime(1));
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(42u32),
        });
        fs.root
            .insert(OsStr::new("file.txt"), Inode::Leaf(LeafId(0), PhantomData));

        let mapped = fs
            .try_map_regular(|v: &u32| Ok::<String, std::fmt::Error>(format!("val={v}")))
            .unwrap();

        let content = mapped.as_dir().get_file(OsStr::new("file.txt")).unwrap();
        assert_eq!(content, "val=42");
        assert_eq!(mapped.root.stat.st_mtim_sec, 1);
    }

    #[test]
    fn test_try_map_regular_non_regular_passthrough() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(1),
            content: LeafContent::Symlink(OsString::from("/target").into_boxed_os_str()),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(2),
            content: LeafContent::Fifo,
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(3),
            content: LeafContent::Socket,
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(4),
            content: LeafContent::BlockDevice(0x0801),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(5),
            content: LeafContent::CharacterDevice(0x0501),
        });

        fs.root
            .insert(OsStr::new("link"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("fifo"), Inode::Leaf(LeafId(1), PhantomData));
        fs.root
            .insert(OsStr::new("sock"), Inode::Leaf(LeafId(2), PhantomData));
        fs.root
            .insert(OsStr::new("blk"), Inode::Leaf(LeafId(3), PhantomData));
        fs.root
            .insert(OsStr::new("chr"), Inode::Leaf(LeafId(4), PhantomData));

        let mapped = fs
            .try_map_regular(|_: &u32| Ok::<String, std::fmt::Error>("unused".into()))
            .unwrap();

        // Verify each non-regular variant is preserved
        match mapped.root.lookup(OsStr::new("link")) {
            Some(Inode::Leaf(id, _)) => match &mapped.leaf(*id).content {
                LeafContent::Symlink(t) => assert_eq!(t.as_ref(), OsStr::new("/target")),
                other => panic!("Expected Symlink, got {other:?}"),
            },
            other => panic!("Expected Leaf, got {other:?}"),
        }
        match mapped.root.lookup(OsStr::new("fifo")) {
            Some(Inode::Leaf(id, _)) => {
                assert!(matches!(mapped.leaf(*id).content, LeafContent::Fifo))
            }
            other => panic!("Expected Leaf/Fifo, got {other:?}"),
        }
        match mapped.root.lookup(OsStr::new("sock")) {
            Some(Inode::Leaf(id, _)) => {
                assert!(matches!(mapped.leaf(*id).content, LeafContent::Socket))
            }
            other => panic!("Expected Leaf/Socket, got {other:?}"),
        }
        match mapped.root.lookup(OsStr::new("blk")) {
            Some(Inode::Leaf(id, _)) => match &mapped.leaf(*id).content {
                LeafContent::BlockDevice(rdev) => assert_eq!(*rdev, 0x0801),
                other => panic!("Expected BlockDevice, got {other:?}"),
            },
            other => panic!("Expected Leaf, got {other:?}"),
        }
        match mapped.root.lookup(OsStr::new("chr")) {
            Some(Inode::Leaf(id, _)) => match &mapped.leaf(*id).content {
                LeafContent::CharacterDevice(rdev) => assert_eq!(*rdev, 0x0501),
                other => panic!("Expected CharacterDevice, got {other:?}"),
            },
            other => panic!("Expected Leaf, got {other:?}"),
        }
    }

    #[test]
    fn test_try_map_regular_hardlink_sharing() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        // One leaf, two directory entries (hardlink)
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(99u32),
        });
        fs.root
            .insert(OsStr::new("a"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("b"), Inode::Leaf(LeafId(0), PhantomData));

        // Track how many times the mapping function is called
        let mut call_count = 0u32;
        let mapped = fs
            .try_map_regular(|v: &u32| {
                call_count += 1;
                Ok::<String, std::fmt::Error>(format!("mapped={v}"))
            })
            .unwrap();

        // The mapping function should be called exactly once for the single leaf
        assert_eq!(call_count, 1);

        // Both entries should point to the same LeafId
        let id_a = match mapped.root.lookup(OsStr::new("a")) {
            Some(Inode::Leaf(id, _)) => *id,
            other => panic!("Expected Leaf, got {other:?}"),
        };
        let id_b = match mapped.root.lookup(OsStr::new("b")) {
            Some(Inode::Leaf(id, _)) => *id,
            other => panic!("Expected Leaf, got {other:?}"),
        };
        assert_eq!(id_a, id_b);
        assert_eq!(
            mapped.as_dir().get_file(OsStr::new("a")).unwrap(),
            "mapped=99"
        );
    }

    #[test]
    fn test_try_map_regular_error_propagation() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(1),
            content: LeafContent::Regular(1u32),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(2),
            content: LeafContent::Regular(0u32),
        });
        fs.root
            .insert(OsStr::new("ok"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("fail"), Inode::Leaf(LeafId(1), PhantomData));

        let result = fs.try_map_regular(|v: &u32| {
            if *v == 0 {
                Err("cannot map zero")
            } else {
                Ok(v * 10)
            }
        });

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "cannot map zero");
    }

    #[test]
    fn test_transform_for_oci() {
        let mut leaves = Vec::new();
        let mut fs = FileSystem::<FileContents>::new(default_stat());

        // Create /usr with specific metadata
        let usr_stat = Stat {
            st_mode: 0o750,
            st_uid: 100,
            st_gid: 200,
            st_mtim_sec: 54321,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::from([(
                Box::from(OsStr::new("user.test")),
                Box::from(b"val".as_slice()),
            )]),
        };
        fs.root
            .insert(OsStr::new("usr"), new_dir_inode_with_stat(usr_stat));

        // Create /run with content
        let mut run_dir = Directory::new(stat_with_mtime(99999));
        let file_id = push_leaf_file(&mut leaves, 11111);
        run_dir.insert(OsStr::new("file"), Inode::leaf(file_id));
        fs.root
            .insert(OsStr::new("run"), Inode::Directory(Box::new(run_dir)));
        fs.leaves = leaves;

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
    fn test_filesystem_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FileSystem<u32>>();
        assert_send_sync::<FileSystem<String>>();
    }

    #[test]
    fn test_filesystem_hardlink_sharing() {
        // Two directory entries pointing to the same LeafId
        let mut fs = FileSystem::<u32>::new(default_stat());
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(99u32),
        });
        fs.root
            .insert(OsStr::new("a"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("b"), Inode::Leaf(LeafId(0), PhantomData));

        let id_a = fs.root.leaf_id(OsStr::new("a")).unwrap();
        let id_b = fs.root.leaf_id(OsStr::new("b")).unwrap();
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn test_try_map_regular_on_flat_fs() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(42u32),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(20),
            content: LeafContent::Symlink(OsString::from("/x").into_boxed_os_str()),
        });
        fs.root
            .insert(OsStr::new("file"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("link"), Inode::Leaf(LeafId(1), PhantomData));

        let mapped = fs
            .try_map_regular(|v: &u32| Ok::<String, std::fmt::Error>(format!("val={v}")))
            .unwrap();

        // Check mapped leaf
        match &mapped.leaf(LeafId(0)).content {
            LeafContent::Regular(s) => assert_eq!(s, "val=42"),
            other => panic!("Expected Regular, got {other:?}"),
        }
        // Non-regular passthrough
        match &mapped.leaf(LeafId(1)).content {
            LeafContent::Symlink(t) => assert_eq!(t.as_ref(), OsStr::new("/x")),
            other => panic!("Expected Symlink, got {other:?}"),
        }
    }

    #[test]
    fn test_compact() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        // Push 3 leaves; only reference 0 and 2
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(1u32),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(20),
            content: LeafContent::Regular(2u32),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(30),
            content: LeafContent::Regular(3u32),
        });
        fs.root
            .insert(OsStr::new("a"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("c"), Inode::Leaf(LeafId(2), PhantomData));

        fs.compact();

        assert_eq!(fs.leaves.len(), 2);
        // "a" should now be LeafId(0) and "c" should be LeafId(1)
        let id_a = fs.root.leaf_id(OsStr::new("a")).unwrap();
        let id_c = fs.root.leaf_id(OsStr::new("c")).unwrap();
        assert_eq!(id_a, LeafId(0));
        assert_eq!(id_c, LeafId(1));
        // Verify content is correct after compaction
        match &fs.leaf(id_a).content {
            LeafContent::Regular(v) => assert_eq!(*v, 1),
            _ => panic!("Wrong content"),
        }
        match &fs.leaf(id_c).content {
            LeafContent::Regular(v) => assert_eq!(*v, 3),
            _ => panic!("Wrong content"),
        }
    }

    #[test]
    fn test_nlink() {
        let mut fs = FileSystem::<u32>::new(default_stat());
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(10),
            content: LeafContent::Regular(42u32),
        });
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(20),
            content: LeafContent::Regular(99u32),
        });
        // Leaf 0 referenced twice (hardlink), leaf 1 referenced once
        fs.root
            .insert(OsStr::new("a"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("b"), Inode::Leaf(LeafId(0), PhantomData));
        fs.root
            .insert(OsStr::new("c"), Inode::Leaf(LeafId(1), PhantomData));

        assert_eq!(fs.nlinks()[LeafId(0).0], 2);
        assert_eq!(fs.nlinks()[LeafId(1).0], 1);

        let nlinks = fs.nlinks();
        assert_eq!(nlinks, vec![2, 1]);
    }

    #[test]
    fn test_for_each_stat_mut() {
        let mut fs = FileSystem::<u32>::new(stat_with_mtime(100));
        fs.leaves.push(Leaf {
            stat: stat_with_mtime(200),
            content: LeafContent::Regular(1u32),
        });
        fs.root
            .insert(OsStr::new("f"), Inode::Leaf(LeafId(0), PhantomData));

        // Double all mtimes
        fs.for_each_stat_mut(|stat| {
            stat.st_mtim_sec *= 2;
        });

        assert_eq!(fs.root.stat.st_mtim_sec, 200);
        assert_eq!(fs.leaves[0].stat.st_mtim_sec, 400);
    }

    #[test]
    fn test_add_overlay_whiteouts() {
        let root_stat = Stat {
            st_mode: 0o755,
            st_uid: 1000,
            st_gid: 2000,
            st_mtim_sec: 12345,
            st_mtim_nsec: 0,
            xattrs: BTreeMap::from([(
                Box::from(OsStr::new("security.selinux")),
                Box::from(b"system_u:object_r:root_t:s0".as_slice()),
            )]),
        };
        let mut fs = FileSystem::<FileContents>::new(root_stat);

        // Add a pre-existing entry that should not be overwritten
        let pre_id = fs.push_leaf(
            stat_with_mtime(99999),
            LeafContent::Regular(FileContents {}),
        );
        fs.root.insert(OsStr::new("00"), Inode::leaf(pre_id));

        fs.add_overlay_whiteouts();

        // Should have 256 whiteout entries (255 new + 1 pre-existing)
        assert_eq!(fs.root.entries.len(), 256);

        // The pre-existing "00" should still have its original mtime
        if let Some(Inode::Leaf(id, _)) = fs.root.entries.get(OsStr::new("00")) {
            assert_eq!(fs.leaf(*id).stat.st_mtim_sec, 99999);
        } else {
            panic!("Expected '00' to remain a leaf");
        }

        // Check a newly created whiteout entry
        if let Some(Inode::Leaf(id, _)) = fs.root.entries.get(OsStr::new("ff")) {
            let leaf = fs.leaf(*id);
            // Should be a character device with rdev=0
            assert!(matches!(leaf.content, LeafContent::CharacterDevice(0)));
            // Should have mode 0o644
            assert_eq!(leaf.stat.st_mode, 0o644);
            // Should inherit uid/gid/mtime from root
            assert_eq!(leaf.stat.st_uid, 1000);
            assert_eq!(leaf.stat.st_gid, 2000);
            assert_eq!(leaf.stat.st_mtim_sec, 12345);
            // Should inherit xattrs from root (e.g. SELinux label) — matching
            // C mkcomposefs behaviour where whiteout entries copy root metadata.
            assert_eq!(
                leaf.stat
                    .xattrs
                    .get(OsStr::new("security.selinux"))
                    .map(|v| v.as_ref()),
                Some(b"system_u:object_r:root_t:s0".as_slice())
            );
        } else {
            panic!("Expected 'ff' to be a leaf");
        }

        // Check some middle entries exist
        assert!(fs.root.entries.contains_key(OsStr::new("7f")));
        assert!(fs.root.entries.contains_key(OsStr::new("a0")));
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

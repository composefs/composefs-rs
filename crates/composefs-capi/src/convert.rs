use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use zerocopy::{FromBytes, IntoBytes};

use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{self, LeafId};
use composefs::tree::{self, RegularFile};

use crate::node::lcfs_node_ref;
use crate::{FfiNode, FfiXattr};

fn stat_from_ffi(node: &FfiNode) -> generic_tree::Stat {
    let mut xattrs = std::collections::BTreeMap::new();
    for xattr in unsafe { node.xattrs_slice() } {
        let key = OsStr::from_bytes(unsafe { xattr.key_cstr() }.to_bytes());
        xattrs.insert(Box::from(key), Box::from(unsafe { xattr.value_bytes() }));
    }
    generic_tree::Stat {
        st_mode: node.inode.st_mode,
        st_uid: node.inode.st_uid,
        st_gid: node.inode.st_gid,
        st_mtim_sec: node.inode.st_mtim_sec,
        st_mtim_nsec: node.inode.st_mtim_nsec,
        xattrs,
    }
}

fn stat_to_ffi(stat: &generic_tree::Stat, node: &mut FfiNode) {
    node.inode.st_mode = stat.st_mode;
    node.inode.st_uid = stat.st_uid;
    node.inode.st_gid = stat.st_gid;
    node.inode.st_mtim_sec = stat.st_mtim_sec;
    node.inode.st_mtim_nsec = stat.st_mtim_nsec;
    let xattr_vec: Vec<FfiXattr> = stat
        .xattrs
        .iter()
        .map(|(k, v)| {
            let key = CString::new(k.as_bytes()).unwrap_or_else(|_| {
                CString::new(
                    k.as_bytes()
                        .iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            });
            unsafe { FfiXattr::new(&key, v) }
        })
        .collect();
    unsafe {
        node.xattrs_put_back(xattr_vec);
    }
}

/// Convert an FfiNode tree into a composefs FileSystem.
///
/// Hardlinked nodes (those with link_to set) will share the same LeafId.
pub(crate) fn ffi_tree_to_filesystem(
    root: &FfiNode,
) -> anyhow::Result<tree::FileSystem<Sha256HashValue>> {
    let root_stat = stat_from_ffi(root);
    let mut fs = tree::FileSystem::new(root_stat);
    let mut hardlink_map: HashMap<usize, LeafId> = HashMap::new();

    ffi_dir_to_fs(root, &mut fs.root, &mut fs.leaves, &mut hardlink_map)?;
    Ok(fs)
}

fn ffi_dir_to_fs(
    ffi_dir: &FfiNode,
    dir: &mut tree::Directory<Sha256HashValue>,
    leaves: &mut Vec<tree::Leaf<Sha256HashValue>>,
    hardlink_map: &mut HashMap<usize, LeafId>,
) -> anyhow::Result<()> {
    for &child_ptr in unsafe { ffi_dir.children_slice() } {
        let child = unsafe { &*child_ptr };
        let child_name = if !child.name.is_null() {
            OsStr::from_bytes(unsafe { CStr::from_ptr(child.name) }.to_bytes())
        } else {
            OsStr::new("")
        };

        let file_type = child.inode.st_mode & libc::S_IFMT;

        if file_type == libc::S_IFDIR {
            let child_stat = stat_from_ffi(child);
            let mut subdir = tree::Directory::new(child_stat);
            ffi_dir_to_fs(child, &mut subdir, leaves, hardlink_map)?;
            dir.insert(child_name, generic_tree::Inode::Directory(Box::new(subdir)));
        } else {
            let target_ptr = if !child.link_to.is_null() {
                child.link_to as usize
            } else {
                child_ptr as usize
            };

            if let Some(&existing_id) = hardlink_map.get(&target_ptr) {
                dir.insert(child_name, generic_tree::Inode::leaf(existing_id));
                continue;
            }

            let actual = if !child.link_to.is_null() {
                unsafe { &*child.link_to }
            } else {
                child
            };

            let leaf_content = ffi_node_to_leaf_content(actual)?;
            let leaf_stat = stat_from_ffi(actual);
            let leaf_id = LeafId(leaves.len());
            leaves.push(tree::Leaf {
                stat: leaf_stat,
                content: leaf_content,
            });
            hardlink_map.insert(target_ptr, leaf_id);
            dir.insert(child_name, generic_tree::Inode::leaf(leaf_id));
        }
    }
    Ok(())
}

fn ffi_node_to_leaf_content(node: &FfiNode) -> anyhow::Result<tree::LeafContent<Sha256HashValue>> {
    let file_type = node.inode.st_mode & libc::S_IFMT;
    match file_type {
        t if t == libc::S_IFREG => {
            if !node.content.is_null() {
                let data = unsafe {
                    std::slice::from_raw_parts(node.content, node.inode.st_size as usize)
                };
                Ok(generic_tree::LeafContent::Regular(RegularFile::Inline(
                    Box::from(data),
                )))
            } else if node.digest_set {
                let digest =
                    Sha256HashValue::read_from_bytes(&node.digest).expect("digest size mismatch");
                Ok(generic_tree::LeafContent::Regular(RegularFile::External(
                    digest,
                    node.inode.st_size,
                )))
            } else if !node.payload.is_null() {
                let payload = unsafe { CStr::from_ptr(node.payload) };
                let raw = payload.to_bytes();
                let path = raw.strip_suffix(b".file").unwrap_or(raw);
                let digest = Sha256HashValue::from_object_pathname(path)
                    .map_err(|e| anyhow::anyhow!("invalid digest path: {e}"))?;
                Ok(generic_tree::LeafContent::Regular(
                    RegularFile::ExternalNoVerity(digest, node.inode.st_size),
                ))
            } else if node.inode.st_size > 0 {
                Ok(generic_tree::LeafContent::Regular(RegularFile::Sparse(
                    node.inode.st_size,
                )))
            } else {
                Ok(generic_tree::LeafContent::Regular(RegularFile::Inline(
                    Box::new([]),
                )))
            }
        }
        t if t == libc::S_IFLNK => {
            let target = if !node.payload.is_null() {
                let p = unsafe { CStr::from_ptr(node.payload) };
                OsString::from(OsStr::from_bytes(p.to_bytes()))
            } else {
                OsString::new()
            };
            Ok(generic_tree::LeafContent::Symlink(
                target.into_boxed_os_str(),
            ))
        }
        t if t == libc::S_IFBLK => Ok(generic_tree::LeafContent::BlockDevice(
            node.inode.st_rdev as u64,
        )),
        t if t == libc::S_IFCHR => Ok(generic_tree::LeafContent::CharacterDevice(
            node.inode.st_rdev as u64,
        )),
        t if t == libc::S_IFIFO => Ok(generic_tree::LeafContent::Fifo),
        t if t == libc::S_IFSOCK => Ok(generic_tree::LeafContent::Socket),
        _ => anyhow::bail!("unknown file type: {:#o}", file_type),
    }
}

/// Convert a composefs FileSystem into an FfiNode tree.
///
/// The returned pointer is a newly allocated root node with ref_count=1.
/// The caller is responsible for calling lcfs_node_unref on it.
pub(crate) fn filesystem_to_ffi_tree(fs: &tree::FileSystem<Sha256HashValue>) -> *mut FfiNode {
    let mut root = Box::new(FfiNode::default());
    stat_to_ffi(&fs.root.stat, &mut root);
    root.inode.st_mode |= libc::S_IFDIR;

    // Map LeafId -> *mut FfiNode for hardlink tracking
    let mut leaf_node_map: HashMap<usize, *mut FfiNode> = HashMap::new();
    let nlinks = fs.nlinks();

    let root_ptr = Box::into_raw(root);

    fs_dir_to_ffi(&fs.root, &fs.leaves, &nlinks, root_ptr, &mut leaf_node_map);

    root_ptr
}

fn fs_dir_to_ffi(
    dir: &tree::Directory<Sha256HashValue>,
    leaves: &[tree::Leaf<Sha256HashValue>],
    nlinks: &[u32],
    parent: *mut FfiNode,
    leaf_node_map: &mut HashMap<usize, *mut FfiNode>,
) {
    for (name, inode) in dir.sorted_entries() {
        match inode {
            generic_tree::Inode::Directory(subdir) => {
                let mut child = Box::new(FfiNode::default());
                stat_to_ffi(&subdir.stat, &mut child);
                child.inode.st_mode = (child.inode.st_mode & !libc::S_IFMT) | libc::S_IFDIR;
                let name_bytes = name.as_bytes();
                child.name = CString::new(name_bytes).map_or(ptr::null_mut(), CString::into_raw);
                child.parent = parent;

                let child_ptr = Box::into_raw(child);
                fs_dir_to_ffi(subdir, leaves, nlinks, child_ptr, leaf_node_map);
                unsafe {
                    let mut children = (*parent).children_as_vec();
                    children.push(child_ptr);
                    (*parent).children_put_back(children);
                }
            }
            generic_tree::Inode::Leaf(leaf_id, _) => {
                let leaf = &leaves[leaf_id.0];
                let is_hardlink = nlinks[leaf_id.0] > 1;

                if is_hardlink && let Some(&existing_ptr) = leaf_node_map.get(&leaf_id.0) {
                    let mut link_node = Box::new(FfiNode::default());
                    let name_bytes = name.as_bytes();
                    link_node.name =
                        CString::new(name_bytes).map_or(ptr::null_mut(), CString::into_raw);
                    link_node.parent = parent;
                    link_node.link_to = unsafe { lcfs_node_ref(existing_ptr) };

                    let link_ptr = Box::into_raw(link_node);
                    unsafe {
                        let mut children = (*parent).children_as_vec();
                        children.push(link_ptr);
                        (*parent).children_put_back(children);
                    }
                    continue;
                }

                let mut child = Box::new(FfiNode::default());
                stat_to_ffi(&leaf.stat, &mut child);
                leaf_content_to_ffi(&leaf.content, &mut child);
                let name_bytes = name.as_bytes();
                child.name = CString::new(name_bytes).map_or(ptr::null_mut(), CString::into_raw);
                child.parent = parent;
                child.inode.st_nlink = nlinks[leaf_id.0];

                let child_ptr = Box::into_raw(child);

                if is_hardlink {
                    leaf_node_map.insert(leaf_id.0, child_ptr);
                }

                unsafe {
                    let mut children = (*parent).children_as_vec();
                    children.push(child_ptr);
                    (*parent).children_put_back(children);
                }
            }
        }
    }
}

fn leaf_content_to_ffi(content: &tree::LeafContent<Sha256HashValue>, node: &mut FfiNode) {
    match content {
        generic_tree::LeafContent::Regular(reg) => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFREG;
            match reg {
                RegularFile::Inline(data) => {
                    node.inode.st_size = data.len() as u64;
                    unsafe {
                        node.set_content_buf(data);
                    }
                }
                RegularFile::External(digest, size) => {
                    node.inode.st_size = *size;
                    node.digest.copy_from_slice(digest.as_bytes());
                    node.digest_set = true;
                    let path = digest.to_object_pathname();
                    node.payload = CString::new(path).map_or(ptr::null_mut(), CString::into_raw);
                }
                RegularFile::ExternalNoVerity(digest, size) => {
                    node.inode.st_size = *size;
                    let path = digest.to_object_pathname();
                    node.payload = CString::new(path).map_or(ptr::null_mut(), CString::into_raw);
                }
                RegularFile::Sparse(size) => {
                    node.inode.st_size = *size;
                }
            }
        }
        generic_tree::LeafContent::Symlink(target) => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFLNK;
            node.inode.st_size = target.len() as u64;
            node.payload =
                CString::new(target.as_bytes()).map_or(ptr::null_mut(), CString::into_raw);
        }
        generic_tree::LeafContent::BlockDevice(rdev) => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFBLK;
            node.inode.st_rdev = *rdev as u32;
        }
        generic_tree::LeafContent::CharacterDevice(rdev) => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFCHR;
            node.inode.st_rdev = *rdev as u32;
        }
        generic_tree::LeafContent::Fifo => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFIFO;
        }
        generic_tree::LeafContent::Socket => {
            node.inode.st_mode = (node.inode.st_mode & !libc::S_IFMT) | libc::S_IFSOCK;
        }
    }
}

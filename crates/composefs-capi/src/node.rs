use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;

use libc::{self, size_t, timespec};

use crate::errno::set_errno;
use crate::{FfiNode, FfiXattr, LCFS_DIGEST_SIZE};

// EROFS xattr on-disk overhead constants, matching the C library.
const LCFS_INODE_XATTRMETA_SIZE: usize = 4;
const LCFS_XATTR_HEADER_SIZE: usize = 12;
const LCFS_INODE_EXTERNAL_XATTR_MAX: usize = u16::MAX as usize / 2; // 32767
const XATTR_NAME_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Node lifecycle
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_new() -> *mut FfiNode {
    let node = Box::new(FfiNode::default());
    Box::into_raw(node)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_ref(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*node).ref_count += 1;
    }
    node
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_unref(node: *mut FfiNode) {
    if node.is_null() {
        return;
    }
    unsafe {
        (*node).ref_count -= 1;
        if (*node).ref_count > 0 {
            return;
        }

        // Unref all children
        for i in 0..(*node).children_size {
            let child = *(*node).children.add(i);
            (*child).parent = ptr::null_mut();
            lcfs_node_unref(child);
        }
        (*node).children_size = 0;

        if !(*node).link_to.is_null() {
            let target = (*node).link_to;
            (*node).link_to = ptr::null_mut();
            lcfs_node_unref(target);
        }

        drop(Box::from_raw(node));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_clone(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    unsafe {
        let src = &*node;
        let mut cloned = FfiNode::default();

        cloned.inode.st_mode = src.inode.st_mode;
        cloned.inode.st_nlink = src.inode.st_nlink;
        cloned.inode.st_uid = src.inode.st_uid;
        cloned.inode.st_gid = src.inode.st_gid;
        cloned.inode.st_rdev = src.inode.st_rdev;
        cloned.inode.st_size = src.inode.st_size;
        cloned.inode.st_mtim_sec = src.inode.st_mtim_sec;
        cloned.inode.st_mtim_nsec = src.inode.st_mtim_nsec;
        cloned.xattr_size = src.xattr_size;
        cloned.digest = src.digest;
        cloned.digest_set = src.digest_set;

        // Deep-copy payload
        if !src.payload.is_null() {
            cloned.payload = CString::new(CStr::from_ptr(src.payload).to_bytes())
                .unwrap()
                .into_raw();
        }

        // Deep-copy content
        if !src.content.is_null() && src.inode.st_size > 0 {
            let data = std::slice::from_raw_parts(src.content, src.inode.st_size as usize);
            cloned.set_content_buf(data);
        }

        // Deep-copy xattrs
        if !src.xattrs.is_null() && src.n_xattrs > 0 {
            let src_xattrs = std::slice::from_raw_parts(src.xattrs, src.n_xattrs);
            let cloned_xattrs: Vec<FfiXattr> = src_xattrs
                .iter()
                .map(|x| FfiXattr::new(x.key_cstr(), x.value_bytes()))
                .collect();
            cloned.xattrs_put_back(cloned_xattrs);
        }

        // Clone link_to
        if !src.link_to.is_null() {
            cloned.link_to = lcfs_node_ref(src.link_to);
        }

        Box::into_raw(Box::new(cloned))
    }
}

/// Mapping of (old node pointer -> new cloned node pointer) used during deep clone
/// to rewrite hardlink targets after cloning.
struct CloneMapping {
    entries: Vec<(*mut FfiNode, *mut FfiNode)>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_clone_deep(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    let mut mapping = CloneMapping {
        entries: Vec::new(),
    };

    unsafe {
        let cloned = clone_deep_inner(node, &mut mapping);
        if !cloned.is_null() {
            clone_rewrite_links(cloned, &mapping);
        }
        cloned
    }
}

unsafe fn clone_deep_inner(node: *mut FfiNode, mapping: &mut CloneMapping) -> *mut FfiNode {
    unsafe {
        let cloned = lcfs_node_clone(node);
        if cloned.is_null() {
            return ptr::null_mut();
        }

        mapping.entries.push((node, cloned));

        // Deep-clone all children
        for &child_ptr in (*node).children_slice() {
            let child_clone = clone_deep_inner(child_ptr, mapping);
            if child_clone.is_null() {
                lcfs_node_unref(cloned);
                return ptr::null_mut();
            }
            let child_name = (*child_ptr).name as *const c_char;
            if lcfs_node_add_child(cloned, child_clone, child_name) < 0 {
                lcfs_node_unref(child_clone);
                lcfs_node_unref(cloned);
                return ptr::null_mut();
            }
        }

        cloned
    }
}

/// Walk the cloned tree and rewrite any link_to pointers that refer to
/// nodes in the old tree so they point to the corresponding cloned nodes.
unsafe fn clone_rewrite_links(node: *mut FfiNode, mapping: &CloneMapping) {
    unsafe {
        for &child in (*node).children_slice() {
            clone_rewrite_links(child, mapping);
        }

        if !(*node).link_to.is_null() {
            let old_target = (*node).link_to;
            for &(old, new) in &mapping.entries {
                if old == old_target {
                    lcfs_node_unref(old_target);
                    (*node).link_to = lcfs_node_ref(new);
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata getters/setters
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_dirp(node: *mut FfiNode) -> bool {
    if node.is_null() {
        return false;
    }
    unsafe { ((*node).inode.st_mode & libc::S_IFMT) == libc::S_IFDIR }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_mode(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_mode }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_mode(node: *mut FfiNode, mode: u32) {
    if node.is_null() {
        return;
    }
    unsafe {
        (*node).inode.st_mode = mode;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_try_set_mode(node: *mut FfiNode, mode: u32) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let file_type = mode & libc::S_IFMT;
    if file_type != libc::S_IFREG
        && file_type != libc::S_IFDIR
        && file_type != libc::S_IFCHR
        && file_type != libc::S_IFBLK
        && file_type != libc::S_IFIFO
        && file_type != libc::S_IFLNK
        && file_type != libc::S_IFSOCK
    {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        (*node).inode.st_mode = mode;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_uid(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_uid }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_uid(node: *mut FfiNode, uid: u32) {
    if !node.is_null() {
        unsafe {
            (*node).inode.st_uid = uid;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_gid(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_gid }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_gid(node: *mut FfiNode, gid: u32) {
    if !node.is_null() {
        unsafe {
            (*node).inode.st_gid = gid;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_nlink(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_nlink }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_nlink(node: *mut FfiNode, nlink: u32) {
    if !node.is_null() {
        unsafe {
            (*node).inode.st_nlink = nlink;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_size(node: *mut FfiNode) -> u64 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_size }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_size(node: *mut FfiNode, size: u64) {
    if !node.is_null() {
        unsafe {
            if (*node).inode.st_size != size {
                (*node).free_content();
            }
            (*node).inode.st_size = size;
        }
    }
}

#[unsafe(no_mangle)]
#[deprecated]
pub unsafe extern "C" fn lcfs_node_get_rdev(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_rdev }
}

#[unsafe(no_mangle)]
#[deprecated]
pub unsafe extern "C" fn lcfs_node_set_rdev(node: *mut FfiNode, rdev: u32) {
    if !node.is_null() {
        unsafe {
            (*node).inode.st_rdev = rdev;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_rdev64(node: *mut FfiNode) -> u64 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).inode.st_rdev as u64 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_rdev64(node: *mut FfiNode, rdev: u64) {
    if !node.is_null() {
        unsafe {
            (*node).inode.st_rdev = rdev as u32;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_mtime(node: *mut FfiNode, time: *mut timespec) {
    if node.is_null() || time.is_null() {
        return;
    }
    unsafe {
        (*time).tv_sec = (*node).inode.st_mtim_sec;
        (*time).tv_nsec = (*node).inode.st_mtim_nsec as i64;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_mtime(node: *mut FfiNode, time: *mut timespec) {
    if node.is_null() || time.is_null() {
        return;
    }
    unsafe {
        (*node).inode.st_mtim_sec = (*time).tv_sec;
        (*node).inode.st_mtim_nsec = (*time).tv_nsec as u32;
    }
}

// ---------------------------------------------------------------------------
// Extended attributes
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_xattr(
    node: *mut FfiNode,
    name: *const c_char,
    length: *mut size_t,
) -> *const c_char {
    if node.is_null() || name.is_null() {
        return ptr::null();
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        for xattr in (*node).xattrs_slice() {
            if xattr.key_cstr() == name_cstr {
                if !length.is_null() {
                    *length = xattr.value_len as usize;
                }
                return xattr.value as *const c_char;
            }
        }
    }
    ptr::null()
}

/// Compute the EROFS on-disk overhead for an xattr entry.
fn xattr_entry_size(namelen: usize, value_len: usize, is_first: bool) -> usize {
    let mut size = (2 * LCFS_INODE_XATTRMETA_SIZE) - 1 + namelen + value_len;
    if is_first {
        size += LCFS_XATTR_HEADER_SIZE;
    }
    size
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_xattr(
    node: *mut FfiNode,
    name: *const c_char,
    value: *const c_char,
    value_len: size_t,
) -> c_int {
    if node.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        let namelen = name_cstr.to_bytes().len();

        if namelen == 0 || namelen > XATTR_NAME_MAX {
            set_errno(libc::ERANGE);
            return -1;
        }

        if value_len > u16::MAX as usize {
            set_errno(libc::EINVAL);
            return -1;
        }

        let val_slice: &[u8] = if value.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(value as *const u8, value_len)
        };

        // Update existing — adjust tracked xattr_size for the value change
        for xattr in (*node).xattrs_slice_mut() {
            if xattr.key_cstr() == name_cstr {
                let is_only = (*node).n_xattrs == 1;
                let old_entry = xattr_entry_size(namelen, xattr.value_len as usize, is_only);
                let new_entry = xattr_entry_size(namelen, val_slice.len(), is_only);
                let new_total = (*node).xattr_size - old_entry + new_entry;
                if new_total > LCFS_INODE_EXTERNAL_XATTR_MAX {
                    set_errno(libc::ERANGE);
                    return -1;
                }
                (*node).xattr_size = new_total;
                xattr.set_value(val_slice);
                return 0;
            }
        }

        // Inserting new — check cumulative size limit
        let is_first = (*node).n_xattrs == 0;
        let entry_size = xattr_entry_size(namelen, value_len, is_first);
        if (*node).xattr_size + entry_size > LCFS_INODE_EXTERNAL_XATTR_MAX {
            set_errno(libc::ERANGE);
            return -1;
        }

        (*node).xattr_size += entry_size;
        let new_xattr = FfiXattr::new(name_cstr, val_slice);
        let mut xattrs = (*node).xattrs_as_vec();
        xattrs.push(new_xattr);
        (*node).xattrs_put_back(xattrs);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_unset_xattr(node: *mut FfiNode, name: *const c_char) -> c_int {
    if node.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        let pos = (*node)
            .xattrs_slice()
            .iter()
            .position(|x| x.key_cstr() == name_cstr);
        match pos {
            Some(idx) => {
                let mut xattrs = (*node).xattrs_as_vec();
                let removed = xattrs.remove(idx);
                let namelen = removed.key_cstr().to_bytes().len();
                let was_last = xattrs.is_empty();
                let mut entry_size = xattr_entry_size(namelen, removed.value_len as usize, false);
                if was_last {
                    entry_size += LCFS_XATTR_HEADER_SIZE;
                }
                (*node).xattr_size = (*node).xattr_size.saturating_sub(entry_size);
                drop(removed);
                (*node).xattrs_put_back(xattrs);
            }
            None => {
                set_errno(libc::ENODATA);
                return -1;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_n_xattr(node: *mut FfiNode) -> size_t {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).n_xattrs }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_xattr_name(
    node: *mut FfiNode,
    index: size_t,
) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        if index >= (*node).n_xattrs {
            return ptr::null();
        }
        (*node).xattrs_slice()[index].key
    }
}

// ---------------------------------------------------------------------------
// Content and payload
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_payload(
    node: *mut FfiNode,
    payload: *const c_char,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        if payload.is_null() {
            (*node).free_payload();
        } else {
            let cstr = CStr::from_ptr(payload);
            if cstr.to_bytes().len() >= libc::PATH_MAX as usize {
                set_errno(libc::ENAMETOOLONG);
                return -1;
            }
            (*node).free_payload();
            (*node).payload = cstr.to_owned().into_raw();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_symlink_payload(
    node: *mut FfiNode,
    payload: *const c_char,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        if payload.is_null() || *payload == 0 {
            set_errno(libc::EINVAL);
            return -1;
        }
        let ret = lcfs_node_set_payload(node, payload);
        if ret < 0 {
            return ret;
        }
        if !(*node).payload.is_null() {
            (*node).inode.st_size = CStr::from_ptr((*node).payload).to_bytes().len() as u64;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_payload(node: *mut FfiNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe { (*node).payload }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_content(
    node: *mut FfiNode,
    data: *const u8,
    data_size: size_t,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        if data.is_null() || data_size == 0 {
            (*node).free_content();
            (*node).inode.st_size = 0;
        } else {
            let content_slice = std::slice::from_raw_parts(data, data_size);
            (*node).inode.st_size = data_size as u64;
            (*node).set_content_buf(content_slice);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_content(node: *mut FfiNode) -> *const u8 {
    if node.is_null() {
        return ptr::null();
    }
    unsafe { (*node).content }
}

// ---------------------------------------------------------------------------
// Tree structure
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_name(node: *mut FfiNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe { (*node).name }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_parent(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*node).parent }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_n_children(node: *mut FfiNode) -> size_t {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).children_size }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_child(node: *mut FfiNode, i: size_t) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        if i >= (*node).children_size {
            return ptr::null_mut();
        }
        (*node).children_slice()[i]
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_lookup_child(
    node: *mut FfiNode,
    name: *const c_char,
) -> *mut FfiNode {
    if node.is_null() || name.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        for &child_ptr in (*node).children_slice() {
            if !(*child_ptr).name.is_null() && CStr::from_ptr((*child_ptr).name) == name_cstr {
                return child_ptr;
            }
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_add_child(
    parent: *mut FfiNode,
    child: *mut FfiNode,
    name: *const c_char,
) -> c_int {
    if parent.is_null() || child.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe {
        if ((*parent).inode.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            set_errno(libc::ENOTDIR);
            return -1;
        }

        let name_cstr = CStr::from_ptr(name);
        let name_bytes = name_cstr.to_bytes();

        if name_bytes.is_empty() {
            set_errno(libc::EINVAL);
            return -1;
        }

        if name_bytes.len() > 255 {
            set_errno(libc::ENAMETOOLONG);
            return -1;
        }

        // Child already has a name (already in a tree)
        if !(*child).name.is_null() {
            set_errno(libc::EMLINK);
            return -1;
        }

        // Check for duplicate name
        for &existing in (*parent).children_slice() {
            if !(*existing).name.is_null() && CStr::from_ptr((*existing).name) == name_cstr {
                set_errno(libc::EEXIST);
                return -1;
            }
        }

        // Set name and parent on child
        (*child).name = CString::new(name_bytes).unwrap().into_raw();
        (*child).parent = parent;

        // Insert sorted by name
        let mut children = (*parent).children_as_vec();
        let insert_pos = children
            .binary_search_by(|probe| {
                let probe_name = CStr::from_ptr((**probe).name);
                probe_name.to_bytes().cmp(name_bytes)
            })
            .unwrap_or_else(|pos| pos);
        children.insert(insert_pos, child);
        (*parent).children_put_back(children);
    }
    0
}

// ---------------------------------------------------------------------------
// Hardlinks
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_make_hardlink(node: *mut FfiNode, target: *mut FfiNode) {
    if node.is_null() || target.is_null() {
        return;
    }
    unsafe {
        if !(*node).link_to.is_null() {
            let old = (*node).link_to;
            (*node).link_to = ptr::null_mut();
            lcfs_node_unref(old);
        }
        (*node).link_to = lcfs_node_ref(target);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_hardlink_target(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*node).link_to }
}

// ---------------------------------------------------------------------------
// fs-verity digest on node
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_fsverity_digest(node: *mut FfiNode) -> *const u8 {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        if (*node).digest_set {
            (*node).digest.as_ptr()
        } else {
            ptr::null()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_fsverity_digest(node: *mut FfiNode, digest: *const u8) {
    if node.is_null() || digest.is_null() {
        return;
    }
    unsafe {
        (*node)
            .digest
            .copy_from_slice(std::slice::from_raw_parts(digest, LCFS_DIGEST_SIZE));
        (*node).digest_set = true;
    }
}

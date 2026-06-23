#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

mod convert;
mod errno;
mod fsverity;
mod image;
mod mount;
mod node;

use std::ffi::{CStr, CString, c_char};
use std::mem;
use std::ptr;

use libc::c_int;

const LCFS_DIGEST_SIZE: usize = 32;

#[repr(C)]
pub(crate) struct FfiXattr {
    key: *mut c_char,
    value: *mut c_char,
    value_len: u16,
    erofs_shared_xattr_offset: i64,
}

impl FfiXattr {
    pub(crate) unsafe fn new(key: &CStr, value: &[u8]) -> Self {
        let key_ptr = CString::new(key.to_bytes()).unwrap().into_raw();
        let (value_ptr, value_len) = if value.is_empty() {
            (ptr::null_mut(), 0u16)
        } else {
            let boxed: Box<[u8]> = value.into();
            (Box::into_raw(boxed) as *mut c_char, value.len() as u16)
        };
        FfiXattr {
            key: key_ptr,
            value: value_ptr,
            value_len,
            erofs_shared_xattr_offset: -1,
        }
    }

    pub(crate) unsafe fn key_cstr(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.key) }
    }

    pub(crate) unsafe fn value_bytes(&self) -> &[u8] {
        if self.value.is_null() || self.value_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.value as *const u8, self.value_len as usize) }
        }
    }

    pub(crate) unsafe fn set_value(&mut self, value: &[u8]) {
        unsafe {
            self.free_value();
        }
        if value.is_empty() {
            self.value = ptr::null_mut();
            self.value_len = 0;
        } else {
            let boxed: Box<[u8]> = value.into();
            self.value = Box::into_raw(boxed) as *mut c_char;
            self.value_len = value.len() as u16;
        }
    }

    unsafe fn free_value(&mut self) {
        if !self.value.is_null() && self.value_len > 0 {
            unsafe {
                let p =
                    ptr::slice_from_raw_parts_mut(self.value as *mut u8, self.value_len as usize);
                drop(Box::from_raw(p));
            }
            self.value = ptr::null_mut();
            self.value_len = 0;
        }
    }
}

impl Drop for FfiXattr {
    fn drop(&mut self) {
        unsafe {
            if !self.key.is_null() {
                drop(CString::from_raw(self.key));
            }
            self.free_value();
        }
    }
}

#[repr(C)]
pub(crate) struct FfiInode {
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u32,
    pub st_size: u64,
    pub st_mtim_sec: i64,
    pub st_mtim_nsec: u32,
}

#[repr(C)]
pub(crate) struct FfiNode {
    pub(crate) ref_count: c_int,
    pub(crate) parent: *mut FfiNode,
    pub(crate) children: *mut *mut FfiNode,
    pub(crate) children_capacity: usize,
    pub(crate) children_size: usize,
    pub(crate) link_to: *mut FfiNode,
    pub(crate) link_to_invalid: bool,
    pub(crate) name: *mut c_char,
    pub(crate) payload: *mut c_char,
    pub(crate) content: *mut u8,
    pub(crate) xattrs: *mut FfiXattr,
    pub(crate) n_xattrs: usize,
    pub(crate) xattr_size: usize,
    pub(crate) digest_set: bool,
    pub(crate) digest: [u8; LCFS_DIGEST_SIZE],
    pub(crate) inode: FfiInode,
    next: *mut FfiNode,
    in_tree: bool,
    inode_num: u32,
    erofs_compact: bool,
    erofs_ipad: u32,
    erofs_xattr_size_field: u32,
    erofs_isize: u32,
    erofs_nid: u64,
    erofs_n_blocks: u32,
    erofs_tailsize: u32,
}

impl FfiNode {
    pub(crate) unsafe fn children_as_vec(&mut self) -> Vec<*mut FfiNode> {
        if self.children.is_null() {
            Vec::new()
        } else {
            unsafe {
                Vec::from_raw_parts(self.children, self.children_size, self.children_capacity)
            }
        }
    }

    pub(crate) unsafe fn children_put_back(&mut self, mut v: Vec<*mut FfiNode>) {
        self.children = v.as_mut_ptr();
        self.children_size = v.len();
        self.children_capacity = v.capacity();
        mem::forget(v);
    }

    pub(crate) unsafe fn children_slice(&self) -> &[*mut FfiNode] {
        if self.children.is_null() || self.children_size == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.children, self.children_size) }
        }
    }

    pub(crate) unsafe fn set_content_buf(&mut self, data: &[u8]) {
        unsafe {
            self.free_content();
        }
        if !data.is_empty() {
            let boxed: Box<[u8]> = data.into();
            self.content = Box::into_raw(boxed) as *mut u8;
        }
    }

    pub(crate) unsafe fn free_content(&mut self) {
        if !self.content.is_null() {
            let len = self.inode.st_size as usize;
            if len > 0 {
                unsafe {
                    let p = ptr::slice_from_raw_parts_mut(self.content, len);
                    drop(Box::from_raw(p));
                }
            }
            self.content = ptr::null_mut();
        }
    }

    pub(crate) unsafe fn free_name(&mut self) {
        if !self.name.is_null() {
            unsafe {
                drop(CString::from_raw(self.name));
            }
            self.name = ptr::null_mut();
        }
    }

    pub(crate) unsafe fn free_payload(&mut self) {
        if !self.payload.is_null() {
            unsafe {
                drop(CString::from_raw(self.payload));
            }
            self.payload = ptr::null_mut();
        }
    }

    pub(crate) unsafe fn xattrs_as_vec(&mut self) -> Vec<FfiXattr> {
        if self.xattrs.is_null() || self.n_xattrs == 0 {
            Vec::new()
        } else {
            unsafe { Vec::from_raw_parts(self.xattrs, self.n_xattrs, self.n_xattrs) }
        }
    }

    pub(crate) unsafe fn xattrs_put_back(&mut self, mut v: Vec<FfiXattr>) {
        v.shrink_to_fit();
        if v.is_empty() {
            self.xattrs = ptr::null_mut();
            self.n_xattrs = 0;
            mem::forget(v);
        } else {
            self.xattrs = v.as_mut_ptr();
            self.n_xattrs = v.len();
            mem::forget(v);
        }
    }

    pub(crate) unsafe fn xattrs_slice(&self) -> &[FfiXattr] {
        if self.xattrs.is_null() || self.n_xattrs == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.xattrs, self.n_xattrs) }
        }
    }

    pub(crate) unsafe fn xattrs_slice_mut(&mut self) -> &mut [FfiXattr] {
        if self.xattrs.is_null() || self.n_xattrs == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(self.xattrs, self.n_xattrs) }
        }
    }
}

impl Default for FfiNode {
    fn default() -> Self {
        FfiNode {
            ref_count: 1,
            parent: ptr::null_mut(),
            children: ptr::null_mut(),
            children_capacity: 0,
            children_size: 0,
            link_to: ptr::null_mut(),
            link_to_invalid: false,
            name: ptr::null_mut(),
            payload: ptr::null_mut(),
            content: ptr::null_mut(),
            xattrs: ptr::null_mut(),
            n_xattrs: 0,
            xattr_size: 0,
            digest_set: false,
            digest: [0u8; LCFS_DIGEST_SIZE],
            inode: FfiInode {
                st_mode: 0,
                st_nlink: 1,
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_mtim_sec: 0,
                st_mtim_nsec: 0,
            },
            next: ptr::null_mut(),
            in_tree: false,
            inode_num: 0,
            erofs_compact: false,
            erofs_ipad: 0,
            erofs_xattr_size_field: 0,
            erofs_isize: 0,
            erofs_nid: 0,
            erofs_n_blocks: 0,
            erofs_tailsize: 0,
        }
    }
}

impl Drop for FfiNode {
    fn drop(&mut self) {
        unsafe {
            if !self.children.is_null() {
                // children_size should be 0 after lcfs_node_unref drains them
                let v =
                    Vec::from_raw_parts(self.children, self.children_size, self.children_capacity);
                drop(v);
            }
            self.free_name();
            self.free_payload();
            self.free_content();
            if !self.xattrs.is_null() && self.n_xattrs > 0 {
                let v = Vec::from_raw_parts(self.xattrs, self.n_xattrs, self.n_xattrs);
                drop(v);
            }
        }
    }
}

const _: () = {
    assert!(size_of::<FfiXattr>() == 32);
    assert!(size_of::<FfiInode>() == 48);
    assert!(size_of::<FfiNode>() == 240);
};

#[cfg(test)]
mod tests;

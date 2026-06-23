pub(crate) fn set_errno(err: i32) {
    unsafe { *libc::__errno_location() = err };
}

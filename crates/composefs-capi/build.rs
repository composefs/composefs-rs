fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libcomposefs.so.1");

    cc::Build::new()
        .file("tests/test_lcfs.c")
        .file("tests/ostree-image.c")
        .include("include/libcomposefs")
        .warnings(false)
        .compile("test_lcfs_c");
}

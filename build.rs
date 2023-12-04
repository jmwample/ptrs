fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/common/elligator2/");

    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file("src/common/elligator2/elligator2.c")
        .file("src/common/elligator2/curve25519-donna-c64.c")
        .include("/usr/include/x86_64-linux-gnu/")
        .compile("elligator2");

    // inform the compiler that we need libgmp -- MUST COME AFTER elligator2 lib OR LINKING BREAKS
    pkg_config::Config::new().probe("gmp").unwrap(); // also working for compile / bin but not test
}

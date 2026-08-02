fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/chkstk.c");

    // On iOS targets, compile the __chkstk_darwin stub needed by the PQ implementation.
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target == "ios" {
        cc::Build::new().file("src/chkstk.c").compile("chkstk");
    }
}

fn main() {
    // On iOS targets, compile the __chkstk_darwin stub needed by blst/pqcrypto
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target == "ios" {
        cc::Build::new().file("src/chkstk.c").compile("chkstk");
    }
}

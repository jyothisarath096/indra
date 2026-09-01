use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let production = manifest.join("../../../indra-core/src/sortition.rs");
    println!("cargo:rerun-if-changed={}", production.display());
    let source = fs::read_to_string(&production).expect("read production sortition source");
    let executable_source = source
        .strip_prefix(
            "//! Praos/Minotaur sortition with deterministic outward-rounded Q768 arithmetic.\n",
        )
        .expect("production source must retain its expected module-doc line");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"))
        .join("instrumented_sortition.rs");
    fs::write(output, executable_source).expect("write instrumented production source");
}

fn main() {
    cc::Build::new()
        .file("csrc/dilithium2_seeded.c")
        .include("csrc")
        .compile("indra_dilithium2_seeded");
}

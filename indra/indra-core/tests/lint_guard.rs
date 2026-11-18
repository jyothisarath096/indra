#[test]
fn source_lint_suppression_guard_passes() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/check_no_lint_allows.sh");
    let status = std::process::Command::new("bash")
        .arg(script)
        .status()
        .expect("lint guard process must start");
    assert!(status.success(), "lint suppression guard failed: {status}");
}

#[test]
fn canonical_lint_policy_guard_passes() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/check_lint_policy.sh");
    let status = std::process::Command::new("bash")
        .arg(script)
        .status()
        .expect("lint policy process must start");
    assert!(status.success(), "lint policy guard failed: {status}");
}

use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use hvm::samples::first_runnable_sample;
use predicates::str::contains;

#[test]
fn inspect_prints_expected_fields_for_sample_pe() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let sample = first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample");
    let mut cmd = cargo_bin_cmd!("hvm-hikari-virtual-engine");

    cmd.current_dir(&repo_root)
        .arg("inspect")
        .arg(sample.path.strip_prefix(&repo_root).unwrap());

    cmd.assert()
        .success()
        .stdout(contains(format!("name: {}", sample.name)));
    cmd.assert().stdout(contains("imports:"));
    cmd.assert().stdout(contains("has_tls:"));
}

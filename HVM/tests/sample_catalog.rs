use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use hvm::samples::discover_default_samples;
use predicates::str::contains;

#[test]
fn sample_catalog_discovers_current_sample_set() {
    let samples = discover_default_samples().unwrap();

    assert!(!samples.is_empty());
    assert!(samples.iter().any(|sample| sample.arch == "x86"));
    assert!(samples.iter().any(|sample| sample.arch == "x64"));
    assert!(samples.iter().all(|sample| sample.path.exists()));
}

#[test]
fn samples_cli_lists_catalog_entries() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let samples = discover_default_samples().unwrap();
    let first = samples.first().unwrap();
    let mut cmd = cargo_bin_cmd!("hvm-hikari-virtual-engine");

    cmd.current_dir(&repo_root)
        .args(["samples", "--dir", "Sample"]);

    cmd.assert()
        .success()
        .stdout(contains(first.name.as_str()))
        .stdout(contains("arch="))
        .stdout(contains("kind="));
}

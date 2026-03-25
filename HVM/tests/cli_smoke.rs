use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

#[test]
fn help_lists_inspect_and_run_subcommands() {
    let mut cmd = cargo_bin_cmd!("hvm-hikari-virtual-engine");
    cmd.arg("--help");
    cmd.assert().success().stdout(contains("inspect"));
    cmd.assert().stdout(contains("run"));
}

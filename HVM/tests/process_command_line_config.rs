use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::samples::first_runnable_sample;

fn runtime_sample() -> hvm::samples::SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
}

fn temp_config_path(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-{name}-{timestamp}.json"))
}

#[test]
fn load_config_accepts_process_command_line_alias() {
    let sample = runtime_sample();
    let config_path = temp_config_path("process-command-line-config");

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"command_line\":\"legacy.exe\",",
                "\"process_command_line\":\"C:\\\\Users\\\\Admin\\\\Desktop\\\\sample.ex_\"",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert_eq!(config.command_line, r"C:\Users\Admin\Desktop\sample.ex_");

    fs::remove_file(config_path).unwrap();
}

#[test]
fn process_command_line_alias_drives_get_command_linew() {
    let sample = runtime_sample();
    let config_path = temp_config_path("process-command-line-runtime");

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"process_command_line\":\"C:\\\\Users\\\\Admin\\\\Desktop\\\\sample.ex_\"",
                "}}"
            ),
            sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let retval = engine.dispatch_bound_stub(stub, &[]).unwrap();
    let mirrored = engine.process_env().read_wide_string(retval).unwrap();

    assert_eq!(mirrored, r"C:\Users\Admin\Desktop\sample.ex_");
    assert_eq!(engine.command_line(), r"C:\Users\Admin\Desktop\sample.ex_");

    fs::remove_file(config_path).unwrap();
}

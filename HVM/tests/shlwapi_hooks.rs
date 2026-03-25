use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

#[test]
fn str_trim_a_trims_in_place_and_returns_python_style_success() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let text = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    let trim = engine.allocate_executable_test_page(0x6310_1000).unwrap();
    engine
        .write_test_bytes(text, b"  GenuineIntel  \0")
        .unwrap();
    engine.write_test_bytes(trim, b" \0").unwrap();

    let stub = engine.bind_hook_for_test("shlwapi.dll", "StrTrimA");
    let retval = engine.dispatch_bound_stub(stub, &[text, trim]).unwrap();

    assert_eq!(retval, 1);
    let bytes = engine.modules().memory().read(text, 13).unwrap();
    assert_eq!(&bytes, b"GenuineIntel\0");
}

#[test]
fn path_file_exists_w_denies_blocked_host_paths() {
    let blocked_dir = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-shlwapi-blocked-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&blocked_dir).unwrap();
    let blocked_file = blocked_dir.join("exists.bin");
    fs::write(&blocked_file, b"blocked").unwrap();

    let mut config = sample_config();
    config.blocked_read_dirs = vec![blocked_dir.clone()];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path = engine.allocate_executable_test_page(0x6310_2000).unwrap();
    engine
        .write_test_bytes(
            path,
            &blocked_file
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let stub = engine.bind_hook_for_test("shlwapi.dll", "PathFileExistsW");
    let retval = engine.dispatch_bound_stub(stub, &[path]).unwrap();

    assert_eq!(retval, 0);
    assert_eq!(engine.last_error(), 5);

    fs::remove_file(blocked_file).unwrap();
    fs::remove_dir_all(blocked_dir).unwrap();
}

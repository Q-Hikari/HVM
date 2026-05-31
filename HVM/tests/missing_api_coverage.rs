use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::{load_config, EngineConfig};
use hvm::runtime::engine::VirtualExecutionEngine;

const HKEY_CURRENT_USER: u64 = 0x8000_0001;
const REG_DWORD: u32 = 4;

fn unique_root(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-missing-api-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn trace_config(root: &Path) -> (EngineConfig, PathBuf) {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs")
        .join("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    let human_path = root.join("trace.api.human.log");
    config.api_human_log_path = Some(human_path.clone());
    config.api_jsonl_path = Some(root.join("trace.api.jsonl"));
    config.api_log_path = None;
    (config, human_path)
}

fn alloc_page(engine: &mut VirtualExecutionEngine, preferred: u64) -> u64 {
    let address = engine.allocate_executable_test_page(preferred).unwrap();
    engine.write_test_bytes(address, &[0u8; 0x1000]).unwrap();
    address
}

fn write_ansi(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn read_c_string(engine: &VirtualExecutionEngine, address: u64, max_len: usize) -> String {
    let bytes = engine.modules().memory().read(address, max_len).unwrap();
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).to_string()
}

fn read_u32(engine: &VirtualExecutionEngine, address: u64) -> u32 {
    u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

#[test]
fn ansi_registry_variants_are_supported_without_unsupported_markers() {
    let root = unique_root("ansi-registry");
    let (config, human_path) = trace_config(&root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let create_key = engine.bind_hook_for_test("advapi32.dll", "RegCreateKeyA");
    let set_value = engine.bind_hook_for_test("advapi32.dll", "RegSetValueExA");
    let enum_value = engine.bind_hook_for_test("advapi32.dll", "RegEnumValueA");
    let delete_value = engine.bind_hook_for_test("advapi32.dll", "RegDeleteValueA");

    let page = alloc_page(&mut engine, 0x7900_0000);
    let subkey_ptr = page;
    let value_name_ptr = page + 0x100;
    let data_ptr = page + 0x200;
    let out_handle_ptr = page + 0x300;
    let enum_name_ptr = page + 0x320;
    let enum_name_len_ptr = page + 0x360;
    let enum_type_ptr = page + 0x364;
    let enum_data_ptr = page + 0x368;
    let enum_data_len_ptr = page + 0x390;

    write_ansi(&mut engine, subkey_ptr, r"Software\MissingApiCoverage");
    write_ansi(&mut engine, value_name_ptr, "BeaconState");
    engine
        .write_test_bytes(data_ptr, &1u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(enum_name_len_ptr, &32u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(enum_data_len_ptr, &64u32.to_le_bytes())
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(create_key, &[HKEY_CURRENT_USER, subkey_ptr, out_handle_ptr])
            .unwrap(),
        0
    );
    let handle = read_u32(&engine, out_handle_ptr) as u64;
    assert_ne!(handle, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                set_value,
                &[handle, value_name_ptr, 0, REG_DWORD as u64, data_ptr, 4,],
            )
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                enum_value,
                &[
                    handle,
                    0,
                    enum_name_ptr,
                    enum_name_len_ptr,
                    0,
                    enum_type_ptr,
                    enum_data_ptr,
                    enum_data_len_ptr,
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_c_string(&engine, enum_name_ptr, 64), "BeaconState");
    assert_eq!(read_u32(&engine, enum_type_ptr), REG_DWORD);
    assert_eq!(read_u32(&engine, enum_data_ptr), 1);

    assert_eq!(
        engine
            .dispatch_bound_stub(delete_value, &[handle, value_name_ptr])
            .unwrap(),
        0
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(!human_log.contains("target_function=\"RegSetValueExA\""));
    assert!(!human_log.contains("target_function=\"RegDeleteValueA\""));
    assert!(!human_log.contains("target_function=\"regcreatekeya\""));
    assert!(!human_log.contains("target_function=\"regenumvaluea\""));
}

#[test]
fn ansi_kernel32_and_sfc_stubs_are_supported_without_unsupported_markers() {
    let root = unique_root("ansi-kernel32");
    let (config, human_path) = trace_config(&root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_profile = engine.bind_hook_for_test("kernel32.dll", "GetPrivateProfileStringA");
    let write_profile = engine.bind_hook_for_test("kernel32.dll", "WritePrivateProfileStringA");
    let set_attributes = engine.bind_hook_for_test("kernel32.dll", "SetFileAttributesA");
    let lstrcmpi = engine.bind_hook_for_test("kernel32.dll", "lstrcmpiA");
    let lstrcpyn = engine.bind_hook_for_test("kernel32.dll", "lstrcpynA");
    let sfc = engine.bind_hook_for_test("sfc_os.dll", "SfcIsFileProtected");

    let page = alloc_page(&mut engine, 0x7A00_0000);
    let app_ptr = page;
    let key_ptr = page + 0x40;
    let default_ptr = page + 0x80;
    let buffer_ptr = page + 0x100;
    let file_ptr = page + 0x200;
    let win_path_ptr = page + 0x300;
    let wide_path_ptr = page + 0x400;
    let left_ptr = page + 0x500;
    let right_ptr = page + 0x540;
    let copy_dst_ptr = page + 0x580;

    write_ansi(&mut engine, app_ptr, "beacon");
    write_ansi(&mut engine, key_ptr, "path");
    write_ansi(&mut engine, default_ptr, "fallback");
    write_ansi(&mut engine, file_ptr, "config.ini");
    write_ansi(
        &mut engine,
        win_path_ptr,
        "Sample/567dbfa9f7d29702a70feb934ec08e54",
    );
    write_wide(
        &mut engine,
        wide_path_ptr,
        r"C:\Windows\SysWOW64\kernel32.dll",
    );
    write_ansi(&mut engine, left_ptr, "Beacon.EXE");
    write_ansi(&mut engine, right_ptr, "beacon.exe");
    write_ansi(&mut engine, copy_dst_ptr, "xxxxxxxx");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_profile,
                &[app_ptr, key_ptr, default_ptr, buffer_ptr, 64, file_ptr],
            )
            .unwrap(),
        "fallback".len() as u64
    );
    assert_eq!(read_c_string(&engine, buffer_ptr, 64), "fallback");

    assert_eq!(
        engine
            .dispatch_bound_stub(write_profile, &[app_ptr, key_ptr, default_ptr, file_ptr])
            .unwrap(),
        1
    );
    engine
        .dispatch_bound_stub(set_attributes, &[win_path_ptr, 0x20])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(lstrcmpi, &[left_ptr, right_ptr])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(lstrcpyn, &[copy_dst_ptr, left_ptr, 7])
            .unwrap(),
        copy_dst_ptr
    );
    assert_eq!(read_c_string(&engine, copy_dst_ptr, 16), "Beacon");
    assert_eq!(
        engine
            .dispatch_bound_stub(sfc, &[0, wide_path_ptr])
            .unwrap(),
        0
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(!human_log.contains("target_function=\"getprivateprofilestringa\""));
    assert!(!human_log.contains("target_function=\"writeprivateprofilestringa\""));
    assert!(!human_log.contains("target_function=\"setfileattributesa\""));
    assert!(!human_log.contains("target_function=\"lstrcmpia\""));
    assert!(!human_log.contains("target_function=\"lstrcpyna\""));
    assert!(!human_log.contains("target_function=\"sfcisfileprotected\""));
}

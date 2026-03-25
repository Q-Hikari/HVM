use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::{load_config, VolumeMount};
use hvm::environment_profile::{
    EnvironmentOverrides, MachineIdentityOverrides, VolumeProfileOverrides,
};
use hvm::memory::manager::{PROT_EXEC, PROT_READ, PROT_WRITE};
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::runtime::scheduler::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use hvm::samples::{
    discover_default_samples, first_runnable_exported_sample, first_runnable_sample, SampleKind,
};
use hvm::tests_support::build_loaded_engine;

const INVALID_HANDLE_VALUE: u64 = u32::MAX as u64;
const PAGE_READONLY: u64 = 0x02;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_GUARD: u64 = 0x100;
const PAGE_EXECUTE_READ: u64 = 0x20;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u64 = 0x0000_4000;
const FILE_MAP_COPY: u64 = 0x0001;
const FILE_MAP_WRITE: u64 = 0x0002;
const FILE_MAP_READ: u64 = 0x0004;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_IMAGE: u32 = 0x0100_0000;
const MEM_RELEASE: u64 = 0x0000_8000;
const ERROR_INVALID_ADDRESS: u32 = 487;

fn runtime_sample() -> hvm::samples::SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
}

fn runtime_sample_for_arch(arch: &str) -> hvm::samples::SampleDescriptor {
    discover_default_samples()
        .unwrap()
        .into_iter()
        .find(|sample| {
            sample.run_supported
                && sample.arch.eq_ignore_ascii_case(arch)
                && sample.kind == SampleKind::Executable
        })
        .unwrap_or_else(|| panic!("expected at least one runnable {arch} executable sample"))
}

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn sample_58ac_dllregister_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_58ac2f65e335922be3f60e57099dc8a3_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.trace_api_calls = false;
    config.api_log_to_console = false;
    config.console_output_to_console = false;
    config
}

fn dll_sample_config() -> Option<hvm::config::EngineConfig> {
    let dll_sample = first_runnable_exported_sample().unwrap()?;
    let host_sample = runtime_sample_for_arch(&dll_sample.arch);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-kernel32-dll-{timestamp}.json"
    ));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"process_image\":\"{}\"",
                "}}"
            ),
            host_sample.path.to_string_lossy().replace('\\', "\\\\"),
            host_sample.path.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    fs::remove_file(config_path).unwrap();
    Some(config)
}

fn sample_config_with_parent() -> hvm::config::EngineConfig {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let parent_image = repo_root.join("Sample").join("parent_toolhelp.exe");
    let mut config = sample_config();
    config.parent_process_image = Some(parent_image.clone());
    config.parent_process_pid = Some(0x4321);
    config.parent_process_command_line =
        Some(format!("\"{}\" /parent", parent_image.to_string_lossy()));
    config
}

fn runtime_pointer_size(engine: &VirtualExecutionEngine) -> usize {
    if engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        8
    } else {
        4
    }
}

fn read_runtime_pointer(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    let pointer_size = runtime_pointer_size(engine);
    let bytes = engine
        .modules()
        .memory()
        .read(address, pointer_size)
        .unwrap();
    if pointer_size == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn runtime_win32_handle_value(engine: &VirtualExecutionEngine, value: u32) -> u64 {
    if runtime_pointer_size(engine) == 8 && value & 0x8000_0000 != 0 {
        0xFFFF_FFFF_0000_0000 | value as u64
    } else {
        value as u64
    }
}

fn runtime_invalid_handle_value(engine: &VirtualExecutionEngine) -> u64 {
    runtime_win32_handle_value(engine, u32::MAX)
}

fn read_wide_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine
        .modules()
        .memory()
        .read(address, capacity * 2)
        .unwrap();
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&words).unwrap()
}

fn read_wide_multi_sz(
    engine: &VirtualExecutionEngine,
    address: u64,
    capacity: usize,
) -> Vec<String> {
    let bytes = engine
        .modules()
        .memory()
        .read(address, capacity * 2)
        .unwrap();
    let mut current = Vec::new();
    let mut entries = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            if current.is_empty() {
                break;
            }
            entries.push(String::from_utf16_lossy(&current));
            current.clear();
        } else {
            current.push(word);
        }
    }
    entries
}

fn page_protect_from_region_perms(perms: u32) -> u32 {
    match perms & (PROT_READ | PROT_WRITE | PROT_EXEC) {
        bits if bits & PROT_EXEC != 0 && bits & PROT_WRITE != 0 => 0x40,
        bits if bits & PROT_EXEC != 0 && bits & PROT_READ != 0 => 0x20,
        bits if bits & PROT_EXEC != 0 => 0x10,
        bits if bits & PROT_WRITE != 0 => 0x04,
        bits if bits & PROT_READ != 0 => 0x02,
        _ => 0x01,
    }
}

fn read_wide_process_entry(
    engine: &VirtualExecutionEngine,
    address: u64,
) -> (u32, u32, u32, String) {
    let pid = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address + 8, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let thread_count = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address + 20, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let parent_pid = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address + 24, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let bytes = engine.modules().memory().read(address + 36, 520).unwrap();
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    let image_name = String::from_utf16_lossy(&words);
    (pid, parent_pid, thread_count, image_name)
}

#[test]
fn create_thread_hook_registers_ready_thread_and_returns_tid() {
    let mut engine = build_loaded_engine();

    assert!(engine
        .registry()
        .definition("kernel32.dll", "CreateThread")
        .is_some());

    let (handle, tid) = engine
        .kernel32()
        .create_thread_for_test(0x401000, 0x4141, false)
        .unwrap();

    assert!(handle != 0);
    assert!(tid != 0);
    assert_eq!(engine.scheduler().thread_state(tid).unwrap(), "ready");
}

#[test]
fn kernel32_get_command_linew_dispatches_through_hook_stub() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let retval = engine.call_native_for_test(stub, &[]).unwrap();
    let mirrored = engine.process_env().read_wide_string(retval).unwrap();

    assert_eq!(mirrored, engine.command_line());
}

#[test]
fn kernel32_get_command_linew_intercepts_relative_call_stub() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "GetCommandLineW");
    let code = engine.allocate_executable_test_page(0x6300_0000).unwrap();
    let next = code + 5;
    let rel = (stub as i64 - next as i64) as i32;
    let mut bytes = vec![0xE8];
    bytes.extend_from_slice(&rel.to_le_bytes());
    bytes.push(0xC3);
    engine.write_test_bytes(code, &bytes).unwrap();

    let retval = engine.call_native_for_test(code, &[]).unwrap();
    let mirrored = engine.process_env().read_wide_string(retval).unwrap();

    assert_eq!(mirrored, engine.command_line());
}

#[test]
fn startup_baseline_preloads_common_system_modules_and_keeps_them_loaded() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let loader_names = engine.process_env().loader_module_names().unwrap();
    for module in ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll"] {
        assert!(
            loader_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(module)),
            "missing {module} in loader names: {loader_names:?}"
        );
    }

    let get_module_handle = engine.bind_hook_for_test("kernel32.dll", "GetModuleHandleW");
    let free_library = engine.bind_hook_for_test("kernel32.dll", "FreeLibrary");
    let name_buffer = engine.allocate_executable_test_page(0x6300_0800).unwrap();
    engine
        .write_test_bytes(
            name_buffer,
            &"kernel32.dll\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let handle = engine
        .dispatch_bound_stub(get_module_handle, &[name_buffer])
        .unwrap();
    assert_ne!(handle, 0);
    assert_eq!(
        engine.dispatch_bound_stub(free_library, &[handle]).unwrap(),
        1
    );
    assert!(engine.modules().get_by_base(handle).is_some());
}

#[test]
fn wide_char_to_multi_byte_uses_gbk_and_includes_trailing_nul() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6301_0000).unwrap();
    let dest = engine.allocate_executable_test_page(0x6302_0000).unwrap();
    let encoded = "中文\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    engine.write_test_bytes(source, &encoded).unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "WideCharToMultiByte");
    let required = engine
        .dispatch_bound_stub(stub, &[936, 0, source, u32::MAX as u64, 0, 0, 0, 0])
        .unwrap();
    let written = engine
        .dispatch_bound_stub(stub, &[936, 0, source, u32::MAX as u64, dest, 5, 0, 0])
        .unwrap();

    assert_eq!(required, 5);
    assert_eq!(written, 5);
    assert_eq!(
        engine.modules().memory().read(dest, 5).unwrap(),
        [0xD6, 0xD0, 0xCE, 0xC4, 0x00]
    );
}

#[test]
fn wide_char_to_multi_byte_ignores_unmappable_characters_like_python() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6302_1000).unwrap();
    let dest = engine.allocate_executable_test_page(0x6302_2000).unwrap();
    let encoded = "A😀中\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    engine.write_test_bytes(source, &encoded).unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "WideCharToMultiByte");
    let required = engine
        .dispatch_bound_stub(stub, &[936, 0, source, u32::MAX as u64, 0, 0, 0, 0])
        .unwrap();
    let written = engine
        .dispatch_bound_stub(stub, &[936, 0, source, u32::MAX as u64, dest, 4, 0, 0])
        .unwrap();

    assert_eq!(required, 4);
    assert_eq!(written, 4);
    assert_eq!(
        engine.modules().memory().read(dest, 4).unwrap(),
        [0x41, 0xD6, 0xD0, 0x00]
    );
}

#[test]
fn multi_byte_to_wide_char_uses_gbk_and_includes_trailing_nul() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6303_0000).unwrap();
    let dest = engine.allocate_executable_test_page(0x6304_0000).unwrap();
    engine
        .write_test_bytes(source, &[0xD6, 0xD0, 0xCE, 0xC4])
        .unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "MultiByteToWideChar");
    let required = engine
        .dispatch_bound_stub(stub, &[936, 0, source, 4, 0, 0])
        .unwrap();
    let written = engine
        .dispatch_bound_stub(stub, &[936, 0, source, 4, dest, 3])
        .unwrap();
    let expected = "中文\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();

    assert_eq!(required, 3);
    assert_eq!(written, 3);
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(dest, expected.len())
            .unwrap(),
        expected
    );
}

#[test]
fn multi_byte_to_wide_char_ignores_invalid_gbk_bytes_like_python() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6304_1000).unwrap();
    let dest = engine.allocate_executable_test_page(0x6304_2000).unwrap();
    engine
        .write_test_bytes(source, &[0x41, 0xFF, 0xD6, 0xD0])
        .unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "MultiByteToWideChar");
    let required = engine
        .dispatch_bound_stub(stub, &[936, 0, source, 4, 0, 0])
        .unwrap();
    let written = engine
        .dispatch_bound_stub(stub, &[936, 0, source, 4, dest, 3])
        .unwrap();
    let expected = "A中\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();

    assert_eq!(required, 3);
    assert_eq!(written, 3);
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(dest, expected.len())
            .unwrap(),
        expected
    );
}

#[test]
fn multi_byte_to_wide_char_matches_python_gbk_length_for_full_byte_sweep() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6304_2800).unwrap();
    let mut bytes = vec![0x20];
    bytes.extend(1u8..=255u8);
    engine.write_test_bytes(source, &bytes).unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "MultiByteToWideChar");
    let required = engine
        .dispatch_bound_stub(stub, &[936, 0, source, 0x100, 0, 0])
        .unwrap();

    assert_eq!(required, 186);
}

#[test]
fn lcmap_string_a_uses_python_ascii_ignore_and_count_rules() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6304_3000).unwrap();
    let dest = engine.allocate_executable_test_page(0x6304_4000).unwrap();
    engine
        .write_test_bytes(source, &[0x41, 0x80, 0x42, 0x00])
        .unwrap();

    let stub = engine.bind_hook_for_test("kernel32.dll", "LCMapStringA");
    let required = engine
        .dispatch_bound_stub(stub, &[0, 0, source, 0, 0, 0])
        .unwrap();
    let written = engine
        .dispatch_bound_stub(stub, &[0, 0, source, 2, dest, 3])
        .unwrap();

    assert_eq!(required, 3);
    assert_eq!(written, 3);
    assert_eq!(engine.modules().memory().read(dest, 3).unwrap(), b"AB\0");
}

#[test]
fn lcmap_string_w_and_ex_treat_zero_length_as_full_string_like_python() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let source = engine.allocate_executable_test_page(0x6304_5000).unwrap();
    let dest_w = engine.allocate_executable_test_page(0x6304_6000).unwrap();
    let dest_ex = engine.allocate_executable_test_page(0x6304_7000).unwrap();
    let encoded = "AB\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let expected = encoded.clone();
    engine.write_test_bytes(source, &encoded).unwrap();

    let lcmap_w = engine.bind_hook_for_test("kernel32.dll", "LCMapStringW");
    let lcmap_ex = engine.bind_hook_for_test("kernel32.dll", "LCMapStringEx");

    assert_eq!(
        engine
            .dispatch_bound_stub(lcmap_w, &[0, 0, source, 0, 0, 0])
            .unwrap(),
        3
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(lcmap_ex, &[0, 0, source, 0, 0, 0, 0, 0, 0])
            .unwrap(),
        3
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(lcmap_w, &[0, 0, source, 0, dest_w, 3])
            .unwrap(),
        3
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(lcmap_ex, &[0, 0, source, 0, dest_ex, 3, 0, 0, 0])
            .unwrap(),
        3
    );
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(dest_w, expected.len())
            .unwrap(),
        expected
    );
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(dest_ex, expected.len())
            .unwrap(),
        encoded
    );
}

#[test]
fn get_locale_info_returns_python_style_code_page_strings() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let ascii = engine.allocate_executable_test_page(0x6305_0000).unwrap();
    let wide = engine.allocate_executable_test_page(0x6306_0000).unwrap();
    let get_locale_info_a = engine.bind_hook_for_test("kernel32.dll", "GetLocaleInfoA");
    let get_locale_info_w = engine.bind_hook_for_test("kernel32.dll", "GetLocaleInfoW");

    assert_eq!(
        engine
            .dispatch_bound_stub(get_locale_info_a, &[0, 0, 0, 0])
            .unwrap(),
        4
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(get_locale_info_a, &[0, 0, ascii, 4])
            .unwrap(),
        4
    );
    assert_eq!(engine.modules().memory().read(ascii, 4).unwrap(), b"936\0");

    assert_eq!(
        engine
            .dispatch_bound_stub(get_locale_info_w, &[0, 0, 0, 0])
            .unwrap(),
        4
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(get_locale_info_w, &[0, 0, wide, 4])
            .unwrap(),
        4
    );
    assert_eq!(
        engine.modules().memory().read(wide, 8).unwrap(),
        "936\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn tls_and_fls_hooks_preserve_last_error_and_free_slots() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let tls_alloc = engine.bind_hook_for_test("kernel32.dll", "TlsAlloc");
    let tls_set = engine.bind_hook_for_test("kernel32.dll", "TlsSetValue");
    let tls_get = engine.bind_hook_for_test("kernel32.dll", "TlsGetValue");
    let tls_free = engine.bind_hook_for_test("kernel32.dll", "TlsFree");
    let fls_alloc = engine.bind_hook_for_test("kernel32.dll", "FlsAlloc");
    let fls_set = engine.bind_hook_for_test("kernel32.dll", "FlsSetValue");
    let fls_get = engine.bind_hook_for_test("kernel32.dll", "FlsGetValue");
    let fls_free = engine.bind_hook_for_test("kernel32.dll", "FlsFree");

    let tls_slot = engine.dispatch_bound_stub(tls_alloc, &[]).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(tls_set, &[tls_slot, 0x1111_2222])
            .unwrap(),
        1
    );
    engine.set_last_error(0xAABB_CCDD);
    assert_eq!(
        engine.dispatch_bound_stub(tls_get, &[tls_slot]).unwrap(),
        0x1111_2222
    );
    assert_eq!(engine.last_error(), 0xAABB_CCDD);
    assert_eq!(
        engine.dispatch_bound_stub(tls_free, &[tls_slot]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(tls_get, &[tls_slot]).unwrap(), 0);
    assert_eq!(
        engine.dispatch_bound_stub(tls_free, &[tls_slot]).unwrap(),
        0
    );

    let fls_slot = engine.dispatch_bound_stub(fls_alloc, &[0]).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(fls_set, &[fls_slot, 0x3333_4444])
            .unwrap(),
        1
    );
    engine.set_last_error(0x1122_3344);
    assert_eq!(
        engine.dispatch_bound_stub(fls_get, &[fls_slot]).unwrap(),
        0x3333_4444
    );
    assert_eq!(engine.last_error(), 0x1122_3344);
    assert_eq!(
        engine.dispatch_bound_stub(fls_free, &[fls_slot]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(fls_get, &[fls_slot]).unwrap(), 0);
    assert_eq!(
        engine.dispatch_bound_stub(fls_free, &[fls_slot]).unwrap(),
        0
    );
}

#[test]
fn critical_section_hooks_match_python_return_values() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let cs = engine.allocate_executable_test_page(0x6307_0000).unwrap();
    let initialize = engine.bind_hook_for_test("kernel32.dll", "InitializeCriticalSection");
    let initialize_ex = engine.bind_hook_for_test("kernel32.dll", "InitializeCriticalSectionEx");
    let initialize_spin =
        engine.bind_hook_for_test("kernel32.dll", "InitializeCriticalSectionAndSpinCount");
    let enter = engine.bind_hook_for_test("kernel32.dll", "EnterCriticalSection");
    let leave = engine.bind_hook_for_test("kernel32.dll", "LeaveCriticalSection");
    let delete = engine.bind_hook_for_test("kernel32.dll", "DeleteCriticalSection");

    assert_eq!(engine.dispatch_bound_stub(initialize, &[cs]).unwrap(), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(initialize_ex, &[cs, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(initialize_spin, &[cs, 0])
            .unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(enter, &[cs]).unwrap(), 0);
    assert_eq!(engine.dispatch_bound_stub(leave, &[cs]).unwrap(), 0);
    assert_eq!(engine.dispatch_bound_stub(delete, &[cs]).unwrap(), 0);
}

#[test]
fn get_startup_info_hooks_write_python_style_zeroed_structs() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let page = engine.allocate_executable_test_page(0x6307_0800).unwrap();
    engine.write_test_bytes(page, &[0xCC; 68]).unwrap();

    let get_startup_info_a = engine.bind_hook_for_test("kernel32.dll", "GetStartupInfoA");
    let get_startup_info_w = engine.bind_hook_for_test("kernel32.dll", "GetStartupInfoW");

    assert_eq!(
        engine
            .dispatch_bound_stub(get_startup_info_a, &[page])
            .unwrap(),
        0
    );
    assert_eq!(engine.modules().memory().read(page, 68).unwrap(), {
        let mut expected = vec![0u8; 68];
        expected[0..4].copy_from_slice(&68u32.to_le_bytes());
        expected
    });

    engine.write_test_bytes(page, &[0xCC; 68]).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_startup_info_w, &[page])
            .unwrap(),
        0
    );
    assert_eq!(engine.modules().memory().read(page, 68).unwrap(), {
        let mut expected = vec![0u8; 68];
        expected[0..4].copy_from_slice(&68u32.to_le_bytes());
        expected
    });
}

#[test]
fn get_string_type_hooks_zero_fill_python_style_output_buffers() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let page = engine.allocate_executable_test_page(0x6307_1000).unwrap();
    let ansi = page;
    let wide = page + 0x100;
    let out_a = page + 0x200;
    let out_w = page + 0x300;
    engine.write_test_bytes(ansi, b"ab\0").unwrap();
    engine
        .write_test_bytes(
            wide,
            &"ab\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(out_a, &[0xCC; 8]).unwrap();
    engine.write_test_bytes(out_w, &[0xCC; 8]).unwrap();

    let get_string_type_a = engine.bind_hook_for_test("kernel32.dll", "GetStringTypeA");
    let get_string_type_w = engine.bind_hook_for_test("kernel32.dll", "GetStringTypeW");

    assert_eq!(
        engine
            .dispatch_bound_stub(get_string_type_a, &[0, 0, ansi, 2, out_a])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(get_string_type_w, &[0, wide, 2, out_w])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.modules().memory().read(out_a, 4).unwrap(),
        vec![0; 4]
    );
    assert_eq!(
        engine.modules().memory().read(out_w, 4).unwrap(),
        vec![0; 4]
    );
}

#[test]
fn create_mutex_w_sets_already_exists_for_repeated_named_mutexes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let name = engine.allocate_executable_test_page(0x6308_0000).unwrap();
    engine
        .write_test_bytes(
            name,
            &"Global\\RustParity\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_mutex = engine.bind_hook_for_test("kernel32.dll", "CreateMutexW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    let first = engine
        .dispatch_bound_stub(create_mutex, &[0, 1, name])
        .unwrap();
    let first_error = engine.last_error();
    let second = engine
        .dispatch_bound_stub(create_mutex, &[0, 1, name])
        .unwrap();

    assert_ne!(first, 0);
    assert_eq!(first_error, 0);
    assert_ne!(second, 0);
    assert_ne!(second, first);
    assert_eq!(engine.last_error(), 183);
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[second, u32::MAX as u64])
            .unwrap(),
        0
    );
}

#[test]
fn open_mutex_w_returns_alias_for_existing_named_mutex() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let name = engine.allocate_executable_test_page(0x6308_4000).unwrap();
    engine
        .write_test_bytes(
            name,
            &"Global\\RustOpenMutex\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_mutex = engine.bind_hook_for_test("kernel32.dll", "CreateMutexW");
    let open_mutex = engine.bind_hook_for_test("kernel32.dll", "OpenMutexW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    let created = engine
        .dispatch_bound_stub(create_mutex, &[0, 1, name])
        .unwrap();
    let opened = engine
        .dispatch_bound_stub(open_mutex, &[0, 0, name])
        .unwrap();

    assert_ne!(created, 0);
    assert_ne!(opened, 0);
    assert_ne!(opened, created);
    assert_eq!(engine.last_error(), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[opened, u32::MAX as u64])
            .unwrap(),
        0
    );
}

#[test]
fn wait_for_multiple_objects_returns_first_signaled_index_and_consumes_auto_reset_event() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let wait_single = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let wait_multiple = engine.bind_hook_for_test("kernel32.dll", "WaitForMultipleObjects");
    let handles = engine.allocate_executable_test_page(0x6308_1000).unwrap();

    let first = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();
    let second = engine
        .dispatch_bound_stub(create_event, &[0, 0, 1, 0])
        .unwrap();
    let mut handle_bytes = Vec::new();
    handle_bytes.extend_from_slice(&(first as u32).to_le_bytes());
    handle_bytes.extend_from_slice(&(second as u32).to_le_bytes());
    engine.write_test_bytes(handles, &handle_bytes).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(wait_multiple, &[2, handles, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(wait_single, &[second, 0])
            .unwrap(),
        0x102
    );
}

#[test]
fn wait_for_single_object_resumes_after_set_event_signals_waiter() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let set_event = engine.bind_hook_for_test("kernel32.dll", "SetEvent");
    let wait_single = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let main_tid = engine.main_thread_tid().unwrap();

    let event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(wait_single, &[event, u32::MAX as u64])
            .unwrap(),
        WAIT_TIMEOUT as u64
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("waiting"));

    assert_eq!(engine.dispatch_bound_stub(set_event, &[event]).unwrap(), 1);
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("ready"));

    assert_eq!(
        engine
            .dispatch_bound_stub(wait_single, &[event, u32::MAX as u64])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
}

#[test]
fn wait_for_single_object_reports_wait_failed_for_invalid_handle() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let wait_single = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    assert_eq!(
        engine
            .dispatch_bound_stub(wait_single, &[0xDEAD_BEEF, 0])
            .unwrap(),
        WAIT_FAILED as u64
    );
    assert_eq!(engine.last_error(), 6);
}

#[test]
fn signal_object_and_wait_signals_source_and_resumes_after_target_is_set() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let set_event = engine.bind_hook_for_test("kernel32.dll", "SetEvent");
    let wait_single = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let signal_and_wait = engine.bind_hook_for_test("kernel32.dll", "SignalObjectAndWait");
    let main_tid = engine.main_thread_tid().unwrap();

    let signal_event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();
    let wait_event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                signal_and_wait,
                &[signal_event, wait_event, u32::MAX as u64, 0],
            )
            .unwrap(),
        WAIT_TIMEOUT as u64
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("waiting"));
    assert_eq!(
        engine
            .dispatch_bound_stub(wait_single, &[signal_event, 0])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(set_event, &[wait_event])
            .unwrap(),
        1
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("ready"));
    assert_eq!(
        engine
            .dispatch_bound_stub(
                signal_and_wait,
                &[signal_event, wait_event, u32::MAX as u64, 0],
            )
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
}

#[test]
fn create_mutex_wait_tracks_reentrant_owner_and_release() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_mutex = engine.bind_hook_for_test("kernel32.dll", "CreateMutexW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let release = engine.bind_hook_for_test("kernel32.dll", "ReleaseMutex");

    let mutex = engine
        .dispatch_bound_stub(create_mutex, &[0, 1, 0])
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[mutex, u32::MAX as u64])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
    assert_eq!(engine.dispatch_bound_stub(release, &[mutex]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(release, &[mutex]).unwrap(), 1);
    assert_eq!(
        engine.dispatch_bound_stub(wait, &[mutex, 0]).unwrap(),
        WAIT_OBJECT_0 as u64
    );
    assert_eq!(engine.dispatch_bound_stub(release, &[mutex]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(release, &[mutex]).unwrap(), 0);
}

#[test]
fn create_file_w_accepts_dos_device_paths_without_resetting_last_error() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let physical_drive = engine.allocate_executable_test_page(0x6309_0000).unwrap();
    let scsi = engine.allocate_executable_test_page(0x630A_0000).unwrap();
    engine
        .write_test_bytes(
            physical_drive,
            &"\\\\.\\PhysicalDrive0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            scsi,
            &"\\\\.\\Scsi0:\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let device_io = engine.bind_hook_for_test("kernel32.dll", "DeviceIoControl");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let out_bytes = engine.allocate_executable_test_page(0x630B_0000).unwrap();
    engine.set_last_error(183);

    let handle = engine
        .dispatch_bound_stub(create_file, &[physical_drive, 0xC000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    let scsi_handle = engine
        .dispatch_bound_stub(create_file, &[scsi, 0xC000_0000, 3, 0, 3, 0, 0])
        .unwrap();

    assert_eq!(handle, 0x1000);
    assert_eq!(scsi_handle, 0x1004);
    assert_eq!(engine.last_error(), 183);
    assert_eq!(
        engine
            .dispatch_bound_stub(device_io, &[handle, 0, 0, 0, 0, 0, out_bytes, 0])
            .unwrap(),
        0
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[handle]).unwrap(), 1);
    assert_eq!(
        engine
            .dispatch_bound_stub(device_io, &[scsi_handle, 0, 0, 0, 0, 0, out_bytes, 0])
            .unwrap(),
        0
    );
    assert_eq!(
        engine.dispatch_bound_stub(close, &[scsi_handle]).unwrap(),
        1
    );
}

#[test]
fn device_io_control_on_primary_disk_matches_python_failure_path() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let physical_drive = engine.allocate_executable_test_page(0x630C_0000).unwrap();
    let query = engine.allocate_executable_test_page(0x630D_0000).unwrap();
    let descriptor = engine.allocate_executable_test_page(0x630E_0000).unwrap();
    let returned = engine.allocate_executable_test_page(0x630F_0000).unwrap();
    engine
        .write_test_bytes(
            physical_drive,
            &"\\\\.\\PhysicalDrive0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(query, &[0u8; 12]).unwrap();
    engine.write_test_bytes(descriptor, &[0xAA; 0x40]).unwrap();
    engine.write_test_bytes(returned, &[0xCC; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let device_io = engine.bind_hook_for_test("kernel32.dll", "DeviceIoControl");
    let handle = engine
        .dispatch_bound_stub(create_file, &[physical_drive, 0xC000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    engine.set_last_error(183);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                device_io,
                &[handle, 0x2D14_00, query, 12, descriptor, 0x100, returned, 0]
            )
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), 183);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(returned, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        engine.modules().memory().read(descriptor, 0x40).unwrap(),
        vec![0xAA; 0x40]
    );
}

#[test]
fn create_file_w_rejects_missing_physical_drive_with_file_not_found() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let physical_drive = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    engine
        .write_test_bytes(
            physical_drive,
            &"\\\\.\\PhysicalDrive7\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    engine.set_last_error(183);

    assert_eq!(
        engine
            .dispatch_bound_stub(create_file, &[physical_drive, 0xC000_0000, 3, 0, 3, 0, 0])
            .unwrap(),
        INVALID_HANDLE_VALUE
    );
    assert_eq!(engine.last_error(), 2);
}

#[test]
fn create_file_w_accepts_volume_guid_root_and_find_first_file_w_maps_volume_guid_paths() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let volume_root = engine.allocate_executable_test_page(0x6310_8000).unwrap();
    let volume_glob = engine.allocate_executable_test_page(0x6310_9000).unwrap();
    let find_data = engine.allocate_executable_test_page(0x6310_A000).unwrap();
    engine
        .write_test_bytes(
            volume_root,
            &"\\\\?\\Volume{54a1f3c2-9f4a-48d2-8c71-112233445566}\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            volume_glob,
            &"\\\\?\\Volume{54a1f3c2-9f4a-48d2-8c71-112233445566}\\*.*\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(find_data, &[0u8; 0x250]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let find_first_file = engine.bind_hook_for_test("kernel32.dll", "FindFirstFileW");
    let find_close = engine.bind_hook_for_test("kernel32.dll", "FindClose");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let handle = engine
        .dispatch_bound_stub(create_file, &[volume_root, 0x100, 3, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    assert_eq!(engine.dispatch_bound_stub(close, &[handle]).unwrap(), 1);

    let find_handle = engine
        .dispatch_bound_stub(find_first_file, &[volume_glob, find_data])
        .unwrap();
    assert_ne!(find_handle, INVALID_HANDLE_VALUE);
    assert!(!read_wide_c_string(&engine, find_data + 0x2C, 260).is_empty());
    assert_eq!(
        engine
            .dispatch_bound_stub(find_close, &[find_handle])
            .unwrap(),
        1
    );
}

#[test]
fn device_io_control_returns_geometry_for_primary_disk() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let physical_drive = engine.allocate_executable_test_page(0x6311_0000).unwrap();
    let geometry = engine.allocate_executable_test_page(0x6312_0000).unwrap();
    let returned = engine.allocate_executable_test_page(0x6313_0000).unwrap();
    engine
        .write_test_bytes(
            physical_drive,
            &"\\\\.\\PhysicalDrive0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(geometry, &[0u8; 0x40]).unwrap();
    engine.write_test_bytes(returned, &[0u8; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let device_io = engine.bind_hook_for_test("kernel32.dll", "DeviceIoControl");
    let handle = engine
        .dispatch_bound_stub(create_file, &[physical_drive, 0x8000_0000, 3, 0, 3, 0, 0])
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                device_io,
                &[handle, 0x0007_00A0, 0, 0, geometry, 0x40, returned, 0]
            )
            .unwrap(),
        1
    );
    assert_eq!(engine.last_error(), 0);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(returned, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        32
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(geometry + 8, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        12
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(geometry + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        512
    );
}

#[test]
fn physical_drive_handle_supports_seek_write_and_flush() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let physical_drive = engine.allocate_executable_test_page(0x6313_1000).unwrap();
    let new_position = engine.allocate_executable_test_page(0x6313_3000).unwrap();
    let buffer = engine.allocate_executable_test_page(0x6313_4000).unwrap();
    let written = engine.allocate_executable_test_page(0x6313_5000).unwrap();
    engine
        .write_test_bytes(
            physical_drive,
            &"\\\\.\\PhysicalDrive0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(new_position, &[0u8; 8]).unwrap();
    engine.write_test_bytes(buffer, &[0u8; 512]).unwrap();
    engine.write_test_bytes(written, &[0u8; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let set_file_pointer_ex = engine.bind_hook_for_test("kernel32.dll", "SetFilePointerEx");
    let write_file = engine.bind_hook_for_test("kernel32.dll", "WriteFile");
    let flush = engine.bind_hook_for_test("kernel32.dll", "FlushFileBuffers");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let handle = engine
        .dispatch_bound_stub(create_file, &[physical_drive, 0xC000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    assert_eq!(handle, 0x1000);
    assert_eq!(
        engine
            .dispatch_bound_stub(set_file_pointer_ex, &[handle, 0, 0, new_position, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(new_position, 8)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(write_file, &[handle, buffer, 512, written, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(written, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        512
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(set_file_pointer_ex, &[handle, 0, 0, new_position, 1])
            .unwrap(),
        1
    );
    assert_eq!(
        u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(new_position, 8)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        512
    );
    assert_eq!(engine.dispatch_bound_stub(flush, &[handle]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[handle]).unwrap(), 1);
}

#[test]
fn volume_enumeration_advances_across_multiple_logical_roots() {
    let extra_root = std::env::temp_dir().join(format!(
        "hikari-kernel32-volume-enum-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&extra_root).unwrap();

    let mut config = sample_config();
    config.volumes.push(VolumeMount {
        host_path: extra_root.clone(),
        guest_path: r"D:\".to_string(),
        recursive: true,
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let find_first_volume = engine.bind_hook_for_test("kernel32.dll", "FindFirstVolumeW");
    let find_next_volume = engine.bind_hook_for_test("kernel32.dll", "FindNextVolumeW");
    let find_volume_close = engine.bind_hook_for_test("kernel32.dll", "FindVolumeClose");
    let first_buffer = engine.allocate_executable_test_page(0x6313_6000).unwrap();
    let next_buffer = engine.allocate_executable_test_page(0x6313_7000).unwrap();
    engine.write_test_bytes(first_buffer, &[0u8; 256]).unwrap();
    engine.write_test_bytes(next_buffer, &[0u8; 256]).unwrap();

    let handle = engine
        .dispatch_bound_stub(find_first_volume, &[first_buffer, 128])
        .unwrap();
    assert_ne!(handle, 0);
    let first = read_wide_c_string(&engine, first_buffer, 128);
    assert_eq!(first, r"\\?\Volume{54a1f3c2-9f4a-48d2-8c71-112233445566}\");

    assert_eq!(
        engine
            .dispatch_bound_stub(find_next_volume, &[handle, next_buffer, 128])
            .unwrap(),
        1
    );
    let next = read_wide_c_string(&engine, next_buffer, 128);
    assert!(next.starts_with(r"\\?\Volume{"));
    assert_ne!(next, first);

    assert_eq!(
        engine
            .dispatch_bound_stub(find_volume_close, &[handle])
            .unwrap(),
        1
    );
}

#[test]
fn query_dos_device_w_maps_drive_and_physical_drive_names() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let query_dos_device = engine.bind_hook_for_test("kernel32.dll", "QueryDosDeviceW");
    let drive_name = engine.allocate_executable_test_page(0x6313_1000).unwrap();
    let physical_name = engine.allocate_executable_test_page(0x6313_2000).unwrap();
    let drive_target = engine.allocate_executable_test_page(0x6313_3000).unwrap();
    let physical_target = engine.allocate_executable_test_page(0x6313_4000).unwrap();
    engine
        .write_test_bytes(
            drive_name,
            &"C:\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            physical_name,
            &"PhysicalDrive0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(drive_target, &[0u8; 128]).unwrap();
    engine
        .write_test_bytes(physical_target, &[0u8; 128])
        .unwrap();

    assert!(
        engine
            .dispatch_bound_stub(query_dos_device, &[drive_name, drive_target, 128])
            .unwrap()
            > 0
    );
    assert_eq!(
        read_wide_multi_sz(&engine, drive_target, 128),
        vec![r"\Device\HarddiskVolume1".to_string()]
    );

    assert!(
        engine
            .dispatch_bound_stub(query_dos_device, &[physical_name, physical_target, 128])
            .unwrap()
            > 0
    );
    assert_eq!(
        read_wide_multi_sz(&engine, physical_target, 128),
        vec![r"\Device\Harddisk0\DR0".to_string()]
    );
}

#[test]
fn physical_drive_count_override_exposes_additional_drive_names() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        volume: Some(VolumeProfileOverrides {
            physical_drive_count: Some(3),
            ..Default::default()
        }),
        ..Default::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let query_dos_device = engine.bind_hook_for_test("kernel32.dll", "QueryDosDeviceW");
    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let names_output = engine.allocate_executable_test_page(0x6313_8000).unwrap();
    let physical_name = engine.allocate_executable_test_page(0x6313_9000).unwrap();
    engine.write_test_bytes(names_output, &[0u8; 512]).unwrap();
    engine
        .write_test_bytes(
            physical_name,
            &"\\\\.\\PhysicalDrive2\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    assert!(
        engine
            .dispatch_bound_stub(query_dos_device, &[0, names_output, 256])
            .unwrap()
            > 0
    );
    let entries = read_wide_multi_sz(&engine, names_output, 256);
    assert!(entries.iter().any(|entry| entry == "PhysicalDrive0"));
    assert!(entries.iter().any(|entry| entry == "PhysicalDrive1"));
    assert!(entries.iter().any(|entry| entry == "PhysicalDrive2"));

    let handle = engine
        .dispatch_bound_stub(create_file, &[physical_name, 0x8000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);
}

#[test]
fn query_dos_device_w_enumerates_known_device_names_when_name_is_null() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let query_dos_device = engine.bind_hook_for_test("kernel32.dll", "QueryDosDeviceW");
    let output = engine.allocate_executable_test_page(0x6313_5000).unwrap();
    engine.write_test_bytes(output, &[0u8; 256]).unwrap();

    assert!(
        engine
            .dispatch_bound_stub(query_dos_device, &[0, output, 256])
            .unwrap()
            > 0
    );

    let entries = read_wide_multi_sz(&engine, output, 256);
    assert!(entries.iter().any(|entry| entry == "C:"));
    assert!(entries.iter().any(|entry| entry == "PhysicalDrive0"));
    assert!(entries.iter().any(|entry| entry == "NUL"));
}

#[test]
fn file_mapping_hooks_share_named_backing_and_persist_view_content() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let name = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    engine
        .write_test_bytes(
            name,
            &"Local\\VmEngineMapping\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let open_mapping = engine.bind_hook_for_test("kernel32.dll", "OpenFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let flush_view = engine.bind_hook_for_test("kernel32.dll", "FlushViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let first = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, name],
        )
        .unwrap();
    assert_ne!(first, 0);
    assert_eq!(engine.last_error(), 0);

    let second = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, name],
        )
        .unwrap();
    assert_ne!(second, 0);
    assert_ne!(second, first);
    assert_eq!(engine.last_error(), 183);

    let third = engine
        .dispatch_bound_stub(open_mapping, &[FILE_MAP_READ, 0, name])
        .unwrap();
    assert_ne!(third, 0);
    assert_eq!(engine.last_error(), 0);

    let first_view = engine
        .dispatch_bound_stub(map_view, &[first, FILE_MAP_WRITE, 0, 0, 0x1000])
        .unwrap();
    assert_ne!(first_view, 0);
    engine.write_test_bytes(first_view, b"HELLO").unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(flush_view, &[first_view, 5])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(unmap_view, &[first_view])
            .unwrap(),
        1
    );

    let second_view = engine
        .dispatch_bound_stub(map_view, &[third, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();
    assert_eq!(
        engine.modules().memory().read(second_view, 5).unwrap(),
        b"HELLO"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(unmap_view, &[second_view])
            .unwrap(),
        1
    );

    assert_eq!(engine.dispatch_bound_stub(close, &[first]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[second]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[third]).unwrap(), 1);
}

#[test]
fn file_mapping_flush_writes_back_to_underlying_file() {
    let path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-mapping-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&path, b"abcdef").unwrap();

    let mut config = sample_config();
    config
        .allowed_read_dirs
        .push(path.parent().unwrap().to_path_buf());

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6311_0000).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let flush_view = engine.bind_hook_for_test("kernel32.dll", "FlushViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let file = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0xC000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(file, INVALID_HANDLE_VALUE);

    let mapping = engine
        .dispatch_bound_stub(create_mapping, &[file, 0, PAGE_READWRITE, 0, 0, 0])
        .unwrap();
    assert_ne!(mapping, 0);

    let view = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_WRITE, 0, 0, 0])
        .unwrap();
    assert_ne!(view, 0);
    engine.write_test_bytes(view + 2, b"XYZ").unwrap();

    assert_eq!(
        engine.dispatch_bound_stub(flush_view, &[view, 5]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(unmap_view, &[view]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[file]).unwrap(), 1);

    assert_eq!(fs::read(&path).unwrap(), b"abXYZf");
    fs::remove_file(path).unwrap();
}

#[test]
fn find_first_file_a_enumerates_virtual_system32_executable() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let pattern = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    let find_data = engine.allocate_executable_test_page(0x6310_1000).unwrap();
    engine
        .write_test_bytes(pattern, b"C:\\Windows\\System32\\*.exe\0")
        .unwrap();
    engine.write_test_bytes(find_data, &[0u8; 0x140]).unwrap();

    let find_first = engine.bind_hook_for_test("kernel32.dll", "FindFirstFileA");
    let find_close = engine.bind_hook_for_test("kernel32.dll", "FindClose");

    let handle = engine
        .dispatch_bound_stub(find_first, &[pattern, find_data])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);

    let bytes = engine
        .modules()
        .memory()
        .read(find_data + 0x2C, 32)
        .unwrap();
    let end = bytes.iter().position(|byte| *byte == 0).unwrap();
    let file_name = String::from_utf8_lossy(&bytes[..end]).into_owned();
    assert_eq!(file_name, "cmd.exe");

    assert_eq!(
        engine.dispatch_bound_stub(find_close, &[handle]).unwrap(),
        1
    );
}

#[test]
fn create_file_a_reads_virtual_system32_pe_header() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_2000).unwrap();
    let read_buffer = engine.allocate_executable_test_page(0x6310_3000).unwrap();
    let read_count = engine.allocate_executable_test_page(0x6310_4000).unwrap();
    engine
        .write_test_bytes(path_ptr, b"C:\\Windows\\System32\\cmd.exe\0")
        .unwrap();
    engine.write_test_bytes(read_buffer, &[0u8; 0x200]).unwrap();
    engine.write_test_bytes(read_count, &[0u8; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileA");
    let read_file = engine.bind_hook_for_test("kernel32.dll", "ReadFile");
    let set_file_pointer = engine.bind_hook_for_test("kernel32.dll", "SetFilePointer");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0x80, 0])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);

    assert_eq!(
        engine
            .dispatch_bound_stub(read_file, &[handle, read_buffer, 0x40, read_count, 0])
            .unwrap(),
        1
    );
    let dos_header = engine.modules().memory().read(read_buffer, 0x40).unwrap();
    assert_eq!(&dos_header[..2], b"MZ");
    let e_lfanew = u32::from_le_bytes(dos_header[0x3C..0x40].try_into().unwrap());
    let first_read = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(read_count, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(first_read, 0x40);

    assert_eq!(
        engine
            .dispatch_bound_stub(set_file_pointer, &[handle, e_lfanew as u64, 0, 0])
            .unwrap(),
        e_lfanew as u64
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(read_file, &[handle, read_buffer, 0xF8, read_count, 0])
            .unwrap(),
        1
    );
    let nt_headers = engine.modules().memory().read(read_buffer, 0xF8).unwrap();
    assert_eq!(&nt_headers[..4], b"PE\0\0");
    assert_eq!(
        u16::from_le_bytes(nt_headers[0x14..0x16].try_into().unwrap()),
        0xE0
    );
    assert_eq!(
        u16::from_le_bytes(nt_headers[0x5C..0x5E].try_into().unwrap()),
        3
    );

    assert_eq!(engine.dispatch_bound_stub(close, &[handle]).unwrap(), 1);
}

#[test]
fn create_file_w_denies_blocked_host_paths() {
    let blocked_dir = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-blocked-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&blocked_dir).unwrap();
    let blocked_file = blocked_dir.join("blocked.bin");
    fs::write(&blocked_file, b"blocked").unwrap();

    let mut config = sample_config();
    config.blocked_read_dirs = vec![blocked_dir.clone()];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_5000).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &blocked_file
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();

    assert_eq!(handle, INVALID_HANDLE_VALUE);
    assert_eq!(engine.last_error(), 5);

    fs::remove_file(blocked_file).unwrap();
    fs::remove_dir_all(blocked_dir).unwrap();
}

#[test]
fn create_file_w_allows_blocked_host_path_when_exposed_via_guest_volume() {
    let blocked_dir = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-volume-blocked-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&blocked_dir).unwrap();
    let blocked_file = blocked_dir.join("mapped.bin");
    fs::write(&blocked_file, b"volume-data").unwrap();

    let mut config = sample_config();
    config.blocked_read_dirs = vec![blocked_dir.clone()];
    config.volumes = vec![VolumeMount {
        host_path: blocked_dir.clone(),
        guest_path: r"C:\Mounted\Samples".to_string(),
        recursive: true,
    }];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_5800).unwrap();
    let read_buffer = engine.allocate_executable_test_page(0x6310_5900).unwrap();
    let read_count = engine.allocate_executable_test_page(0x6310_5A00).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &r"C:\Mounted\Samples\mapped.bin"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(read_buffer, &[0u8; 16]).unwrap();
    engine.write_test_bytes(read_count, &[0u8; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let read_file = engine.bind_hook_for_test("kernel32.dll", "ReadFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);

    assert_eq!(
        engine
            .dispatch_bound_stub(read_file, &[handle, read_buffer, 11, read_count, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.modules().memory().read(read_buffer, 11).unwrap(),
        b"volume-data"
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(read_count, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        11
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[handle]).unwrap(), 1);

    fs::remove_file(blocked_file).unwrap();
    fs::remove_dir_all(blocked_dir).unwrap();
}

#[test]
fn create_file_w_auto_mounts_sample_directory_into_guest_current_directory() {
    let runtime = runtime_sample();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-auto-mount-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let host_sample = root.join(&runtime.name);
    let sibling = root.join("stage2.dat");
    fs::copy(&runtime.path, &host_sample).unwrap();
    fs::write(&sibling, b"auto-mounted").unwrap();

    let mut config = sample_config();
    config.main_module = host_sample.clone();
    config.process_image = Some(host_sample);
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            current_directory: Some(r"C:\Lab\Drop".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_5B00).unwrap();
    let read_buffer = engine.allocate_executable_test_page(0x6310_5C00).unwrap();
    let read_count = engine.allocate_executable_test_page(0x6310_5D00).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &r"C:\Lab\Drop\stage2.dat"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(read_buffer, &[0u8; 16]).unwrap();
    engine.write_test_bytes(read_count, &[0u8; 4]).unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let read_file = engine.bind_hook_for_test("kernel32.dll", "ReadFile");

    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    assert_eq!(
        engine
            .dispatch_bound_stub(read_file, &[handle, read_buffer, 12, read_count, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.modules().memory().read(read_buffer, 12).unwrap(),
        b"auto-mounted"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn create_file_w_respects_auto_mount_disable_flag() {
    let runtime = runtime_sample();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-auto-mount-off-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let host_sample = root.join(&runtime.name);
    let sibling = root.join("stage2.dat");
    fs::copy(&runtime.path, &host_sample).unwrap();
    fs::write(&sibling, b"auto-mounted").unwrap();

    let mut config = sample_config();
    config.main_module = host_sample.clone();
    config.process_image = Some(host_sample);
    config.auto_mount_module_dirs = false;
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            current_directory: Some(r"C:\Lab\Drop".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_5E00).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &r"C:\Lab\Drop\stage2.dat"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    assert_eq!(
        engine
            .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
            .unwrap(),
        INVALID_HANDLE_VALUE
    );
    assert_eq!(engine.last_error(), 2);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn create_file_w_only_allows_host_paths_from_allowlist() {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let allowed_dir =
        std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-allowed-{timestamp}"));
    let other_dir =
        std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-other-{timestamp}"));
    fs::create_dir_all(&allowed_dir).unwrap();
    fs::create_dir_all(&other_dir).unwrap();
    let allowed_file = allowed_dir.join("allowed.bin");
    let other_file = other_dir.join("other.bin");
    fs::write(&allowed_file, b"allowed").unwrap();
    fs::write(&other_file, b"other").unwrap();

    let mut config = sample_config();
    config.allowed_read_dirs = vec![allowed_dir.clone()];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let allowed_ptr = engine.allocate_executable_test_page(0x6310_6000).unwrap();
    let other_ptr = engine.allocate_executable_test_page(0x6310_7000).unwrap();
    engine
        .write_test_bytes(
            allowed_ptr,
            &allowed_file
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            other_ptr,
            &other_file
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let allowed_handle = engine
        .dispatch_bound_stub(create_file, &[allowed_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();
    assert_ne!(allowed_handle, INVALID_HANDLE_VALUE);

    let denied_handle = engine
        .dispatch_bound_stub(create_file, &[other_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();
    assert_eq!(denied_handle, INVALID_HANDLE_VALUE);
    assert_eq!(engine.last_error(), 5);
    assert_eq!(
        engine
            .dispatch_bound_stub(close, &[allowed_handle])
            .unwrap(),
        1
    );

    fs::remove_file(allowed_file).unwrap();
    fs::remove_file(other_file).unwrap();
    fs::remove_dir_all(allowed_dir).unwrap();
    fs::remove_dir_all(other_dir).unwrap();
}

#[test]
fn create_file_w_hides_configured_device_path() {
    let mut config = sample_config();
    config.hidden_device_paths = vec![String::from(r"\\.\VBoxMiniRdrDN")];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6310_8000).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &r"\\.\VBoxMiniRdrDN"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();

    assert_eq!(handle, INVALID_HANDLE_VALUE);
    assert_eq!(engine.last_error(), 2);
}

#[test]
fn create_file_w_hides_configured_device_path_with_x64_invalid_handle_value() {
    let mut engine = VirtualExecutionEngine::new(sample_58ac_dllregister_config()).unwrap();
    engine.load().unwrap();
    assert_eq!(runtime_pointer_size(&engine), 8);

    let path_ptr = engine.allocate_executable_test_page(0x6310_8000).unwrap();
    engine
        .write_test_bytes(
            path_ptr,
            &r"\\.\VBoxMiniRdrDN"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 1, 0, 3, 0, 0])
        .unwrap();

    assert_eq!(handle, runtime_invalid_handle_value(&engine));
    assert_eq!(handle, u64::MAX);
    assert_eq!(engine.last_error(), 2);
}

#[test]
fn get_current_process_returns_sign_extended_pseudo_handle_on_x64() {
    let mut engine = VirtualExecutionEngine::new(sample_58ac_dllregister_config()).unwrap();
    engine.load().unwrap();
    assert_eq!(runtime_pointer_size(&engine), 8);

    let get_current_process = engine.bind_hook_for_test("kernel32.dll", "GetCurrentProcess");
    let handle = engine
        .dispatch_bound_stub(get_current_process, &[])
        .unwrap();

    assert_eq!(handle, runtime_invalid_handle_value(&engine));
    assert_eq!(handle, u64::MAX);
}

#[test]
fn close_handle_rejects_invalid_handle_value_on_x64() {
    let mut engine = VirtualExecutionEngine::new(sample_58ac_dllregister_config()).unwrap();
    engine.load().unwrap();
    assert_eq!(runtime_pointer_size(&engine), 8);

    let close_handle = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let invalid = runtime_invalid_handle_value(&engine);
    let result = engine
        .dispatch_bound_stub(close_handle, &[invalid])
        .unwrap();

    assert_eq!(result, 0);
    assert_eq!(engine.last_error(), 6);
}

#[test]
fn create_file_mapping_accepts_sign_extended_invalid_handle_value_on_x64() {
    let mut engine = VirtualExecutionEngine::new(sample_58ac_dllregister_config()).unwrap();
    engine.load().unwrap();
    assert_eq!(runtime_pointer_size(&engine), 8);

    let name = engine.allocate_executable_test_page(0x6310_9000).unwrap();
    engine
        .write_test_bytes(
            name,
            &"Local\\VmEngineX64Mapping\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let handle = engine
        .dispatch_bound_stub(
            create_mapping,
            &[
                runtime_invalid_handle_value(&engine),
                0,
                PAGE_READWRITE,
                0,
                0x1000,
                name,
            ],
        )
        .unwrap();

    assert_ne!(handle, 0);
    assert_eq!(engine.last_error(), 0);
}

#[test]
fn find_first_file_a_denies_blocked_host_directory_enumeration() {
    let blocked_dir = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-find-blocked-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&blocked_dir).unwrap();
    let blocked_file = blocked_dir.join("a.txt");
    fs::write(&blocked_file, b"sample").unwrap();

    let mut config = sample_config();
    config.blocked_read_dirs = vec![blocked_dir.clone()];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let pattern_ptr = engine.allocate_executable_test_page(0x6310_8000).unwrap();
    let find_data = engine.allocate_executable_test_page(0x6310_9000).unwrap();
    engine
        .write_test_bytes(
            pattern_ptr,
            format!("{}/*.txt\0", blocked_dir.to_string_lossy()).as_bytes(),
        )
        .unwrap();
    engine.write_test_bytes(find_data, &[0u8; 0x140]).unwrap();

    let find_first = engine.bind_hook_for_test("kernel32.dll", "FindFirstFileA");
    let handle = engine
        .dispatch_bound_stub(find_first, &[pattern_ptr, find_data])
        .unwrap();

    assert_eq!(handle, INVALID_HANDLE_VALUE);
    assert_eq!(engine.last_error(), 5);

    fs::remove_file(blocked_file).unwrap();
    fs::remove_dir_all(blocked_dir).unwrap();
}

#[test]
fn cxizka_alias_zeroes_optional_outputs() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let out1 = engine.allocate_executable_test_page(0x6310_5000).unwrap();
    let out2 = engine.allocate_executable_test_page(0x6310_6000).unwrap();
    let out3 = engine.allocate_executable_test_page(0x6310_7000).unwrap();
    engine
        .write_test_bytes(out1, &0x1122_3344u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(out2, &0x5566_7788u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(out3, &0x99AA_BBCCu32.to_le_bytes())
        .unwrap();

    let alias = engine.bind_hook_for_test("kernel32.dll", "CxIZKa");
    assert_eq!(
        engine
            .dispatch_bound_stub(alias, &[0, out1, 0, out2, out3])
            .unwrap(),
        0
    );

    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(out1, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(out2, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(out3, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
}

#[test]
fn shared_file_mapping_views_observe_live_writes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    let shared = engine
        .dispatch_bound_stub(
            map_view,
            &[mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x1000],
        )
        .unwrap();
    let readonly = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();
    assert_ne!(shared, 0);
    assert_ne!(readonly, 0);

    engine.write_test_bytes(shared, b"SYNC!").unwrap();
    assert_eq!(
        engine.modules().memory().read(readonly, 5).unwrap(),
        b"SYNC!"
    );

    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[readonly]).unwrap(),
        1
    );
    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[shared]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
}

#[test]
fn file_map_copy_view_keeps_private_writes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    let shared = engine
        .dispatch_bound_stub(
            map_view,
            &[mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x1000],
        )
        .unwrap();
    assert_ne!(shared, 0);
    engine.write_test_bytes(shared, b"BASE!").unwrap();

    let private = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_COPY, 0, 0, 0x1000])
        .unwrap();
    assert_ne!(private, 0);
    assert_eq!(
        engine.modules().memory().read(private, 5).unwrap(),
        b"BASE!"
    );

    engine.write_test_bytes(private, b"COPY!").unwrap();
    assert_eq!(
        engine.modules().memory().read(private, 5).unwrap(),
        b"COPY!"
    );
    assert_eq!(engine.modules().memory().read(shared, 5).unwrap(), b"BASE!");

    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[private]).unwrap(),
        1
    );
    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[shared]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
}

#[test]
fn native_unicorn_writes_propagate_across_shared_views() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();
    if !engine.has_native_unicorn() || runtime_pointer_size(&engine) != 4 {
        return;
    }

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    let shared = engine
        .dispatch_bound_stub(
            map_view,
            &[mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x1000],
        )
        .unwrap();
    let observer = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();
    let code = engine.allocate_executable_test_page(0x631D_0000).unwrap();

    let mut bytes = vec![0xB8];
    bytes.extend_from_slice(b"NATI");
    bytes.push(0xC7);
    bytes.push(0x05);
    bytes.extend_from_slice(&(shared as u32).to_le_bytes());
    bytes.extend_from_slice(b"NATI");
    bytes.push(0xC3);
    engine.write_test_bytes(code, &bytes).unwrap();

    assert_eq!(
        engine.call_native_for_test(code, &[]).unwrap(),
        0x4954414Eu64
    );
    assert_eq!(engine.modules().memory().read(shared, 4).unwrap(), b"NATI");
    assert_eq!(
        engine.modules().memory().read(observer, 4).unwrap(),
        b"NATI"
    );

    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[observer]).unwrap(),
        1
    );
    assert_eq!(
        engine.dispatch_bound_stub(unmap_view, &[shared]).unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
}

#[test]
fn native_unicorn_guard_page_access_fails_once_then_clears_guard() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();
    if !engine.has_native_unicorn() || runtime_pointer_size(&engine) != 4 {
        return;
    }

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x631E_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x631F_0000).unwrap();

    let guarded = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_READWRITE])
        .unwrap();
    assert_ne!(guarded, 0);
    engine
        .write_test_bytes(guarded, &0x1122_3344u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[guarded, 0x1000, PAGE_READWRITE | PAGE_GUARD, old_protect]
            )
            .unwrap(),
        1
    );

    let code = engine.allocate_executable_test_page(0x6320_0000).unwrap();
    let mut bytes = vec![0xA1];
    bytes.extend_from_slice(&(guarded as u32).to_le_bytes());
    bytes.push(0xC3);
    engine.write_test_bytes(code, &bytes).unwrap();

    let first = engine.call_native_for_test(code, &[]).err().unwrap();
    assert!(first.to_string().contains("guard page"));

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[guarded, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );

    assert_eq!(engine.call_native_for_test(code, &[]).unwrap(), 0x1122_3344);
}

#[test]
fn virtual_query_reports_image_and_mapped_memory_types() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let info = engine.allocate_executable_test_page(0x6312_0000).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_query,
                &[engine.entry_module().unwrap().base, info, 28]
            )
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 24, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_IMAGE
    );

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    let view = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();
    assert_ne!(view, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[view, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 24, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_MAPPED
    );

    assert_eq!(engine.dispatch_bound_stub(unmap_view, &[view]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[0x1234, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_FREE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 24, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0
    );
}

#[test]
fn virtual_alloc_tracks_reserved_and_committed_regions() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let virtual_free = engine.bind_hook_for_test("kernel32.dll", "VirtualFree");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6312_1000).unwrap();

    let reserved = engine
        .dispatch_bound_stub(
            virtual_alloc,
            &[0, 0x2000, MEM_RESERVE as u64, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(reserved, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[reserved + 0x100, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(read_runtime_pointer(&engine, info), reserved);
    assert_eq!(read_runtime_pointer(&engine, info + 4), reserved);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 8, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_RESERVE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        0
    );

    let committed = engine
        .dispatch_bound_stub(
            virtual_alloc,
            &[reserved + 0x1000, 0x1000, MEM_COMMIT as u64, PAGE_READONLY],
        )
        .unwrap();
    assert_eq!(committed, reserved + 0x1000);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[committed + 0x100, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(read_runtime_pointer(&engine, info), committed);
    assert_eq!(read_runtime_pointer(&engine, info + 4), reserved);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 8, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_COMMIT
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_free, &[committed, 0x1000, MEM_DECOMMIT])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[committed + 0x100, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_RESERVE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_free, &[reserved, 0, MEM_RELEASE])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[reserved + 0x100, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_FREE
    );
}

#[test]
fn virtual_alloc_commit_without_reserved_range_reports_invalid_address() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_alloc,
                &[0, 0x400, MEM_COMMIT as u64, PAGE_EXECUTE_READWRITE]
            )
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_INVALID_ADDRESS);
}

#[test]
fn initial_x86_thread_stack_virtual_query_uses_guarded_window() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6312_6000).unwrap();
    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    let guard_base = thread.stack_limit - 0x1000;

    assert_eq!(thread.stack_limit, thread.stack_top - 0x1000);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[thread.stack_top - 8, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(read_runtime_pointer(&engine, info), thread.stack_limit);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_COMMIT
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[guard_base, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(read_runtime_pointer(&engine, info), guard_base);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_COMMIT
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE | PAGE_GUARD
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[guard_base - 1, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_RESERVE
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        0
    );
}

#[test]
fn virtual_query_preserves_image_allocation_metadata_after_protect_split() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6313_0000).unwrap();
    let before_info = engine.allocate_executable_test_page(0x6314_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x631D_0000).unwrap();
    let module = engine
        .entry_module()
        .or_else(|| engine.main_module())
        .cloned()
        .unwrap();
    let protected_page = module.base + 0x1000;
    let struct_size = if runtime_pointer_size(&engine) == 8 {
        48usize
    } else {
        28usize
    };
    let allocation_protect_offset = if runtime_pointer_size(&engine) == 8 {
        16u64
    } else {
        8u64
    };
    let protect_offset = if runtime_pointer_size(&engine) == 8 {
        36u64
    } else {
        20u64
    };
    let type_offset = if runtime_pointer_size(&engine) == 8 {
        40u64
    } else {
        24u64
    };

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_query,
                &[protected_page + 0x100, before_info, struct_size as u64]
            )
            .unwrap(),
        struct_size as u64
    );
    let allocation_protect_before = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(before_info + allocation_protect_offset, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[protected_page, 0x1000, PAGE_READONLY, old_protect]
            )
            .unwrap(),
        1
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_query,
                &[protected_page + 0x100, info, struct_size as u64]
            )
            .unwrap(),
        struct_size as u64
    );
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        module.base
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + allocation_protect_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        allocation_protect_before
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + protect_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + type_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_IMAGE
    );
}

#[test]
fn virtual_query_preserves_mapped_allocation_metadata_after_protect_split() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6315_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x6316_0000).unwrap();
    let struct_size = if runtime_pointer_size(&engine) == 8 {
        48usize
    } else {
        28usize
    };
    let allocation_protect_offset = if runtime_pointer_size(&engine) == 8 {
        16u64
    } else {
        8u64
    };
    let protect_offset = if runtime_pointer_size(&engine) == 8 {
        36u64
    } else {
        20u64
    };
    let type_offset = if runtime_pointer_size(&engine) == 8 {
        40u64
    } else {
        24u64
    };

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x2000, 0],
        )
        .unwrap();
    let view = engine
        .dispatch_bound_stub(
            map_view,
            &[mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x2000],
        )
        .unwrap();
    assert_ne!(view, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[view + 0x1000, 0x1000, PAGE_READONLY, old_protect]
            )
            .unwrap(),
        1
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[view + 0x1100, info, struct_size as u64])
            .unwrap(),
        struct_size as u64
    );
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        view
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(old_protect, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + allocation_protect_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        )
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + protect_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + type_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_MAPPED
    );

    assert_eq!(engine.dispatch_bound_stub(unmap_view, &[view]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
}

#[test]
fn virtual_query_reports_pe_section_level_image_permissions() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6317_0000).unwrap();
    let module = engine
        .entry_module()
        .or_else(|| engine.main_module())
        .cloned()
        .unwrap();
    let module_end = module.base + module.size;
    let image_regions = engine
        .modules()
        .memory()
        .regions
        .iter()
        .filter(|region| module.base < region.end() && region.base < module_end)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        image_regions.len() >= 2,
        "expected section-split image regions, got {image_regions:?}"
    );
    let code_region = image_regions
        .iter()
        .find(|region| region.perms & PROT_EXEC != 0)
        .cloned()
        .expect("expected executable image section");
    let data_region = image_regions
        .iter()
        .find(|region| region.perms & PROT_EXEC == 0)
        .cloned()
        .expect("expected non-executable image section");

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[code_region.base, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        page_protect_from_region_perms(code_region.perms)
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 24, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_IMAGE
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[data_region.base, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        page_protect_from_region_perms(data_region.perms)
    );
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        module.base
    );
}

#[test]
fn read_process_memory_consumes_guard_pages_once() {
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_protect_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualProtectEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let read_process_memory = engine.bind_hook_for_test("kernel32.dll", "ReadProcessMemory");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let input = engine.allocate_executable_test_page(0x6318_0000).unwrap();
    let output = engine.allocate_executable_test_page(0x6319_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x631A_0000).unwrap();
    let count = engine.allocate_executable_test_page(0x631B_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x631C_0000).unwrap();
    engine.write_test_bytes(input, b"GUARD").unwrap();
    engine.write_test_bytes(output, &[0u8; 5]).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 0x4321])
        .unwrap();
    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);

    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    assert_eq!(
        engine
            .dispatch_bound_stub(write_process_memory, &[process, remote, input, 5, count])
            .unwrap(),
        1
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect_ex,
                &[
                    process,
                    remote,
                    0x1000,
                    PAGE_READONLY | PAGE_GUARD,
                    old_protect
                ]
            )
            .unwrap(),
        1
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, remote, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY | PAGE_GUARD
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(read_process_memory, &[process, remote, output, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, remote, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(read_process_memory, &[process, remote, output, 5, count])
            .unwrap(),
        1
    );
    assert_eq!(read_runtime_pointer(&engine, count), 5);
    assert_eq!(engine.modules().memory().read(output, 5).unwrap(), b"GUARD");
    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn remote_process_memory_respects_reserved_and_readonly_pages() {
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let read_process_memory = engine.bind_hook_for_test("kernel32.dll", "ReadProcessMemory");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 0x4321])
        .unwrap();
    assert_ne!(process, 0);

    let input = engine.allocate_executable_test_page(0x6312_2000).unwrap();
    let output = engine.allocate_executable_test_page(0x6312_3000).unwrap();
    let info = engine.allocate_executable_test_page(0x6312_4000).unwrap();
    let count = engine.allocate_executable_test_page(0x6312_5000).unwrap();
    engine.write_test_bytes(input, b"BLOCK").unwrap();
    engine.write_test_bytes(output, &[0xAA; 5]).unwrap();

    let reserved = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x2000, MEM_RESERVE as u64, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(reserved, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, reserved + 0x100, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        MEM_RESERVE
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(write_process_memory, &[process, reserved, input, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(read_process_memory, &[process, reserved, output, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);

    let committed = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, reserved, 0x1000, MEM_COMMIT as u64, PAGE_READONLY],
        )
        .unwrap();
    assert_eq!(committed, reserved);
    assert_eq!(
        engine
            .dispatch_bound_stub(write_process_memory, &[process, committed, input, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(read_process_memory, &[process, committed, output, 5, count])
            .unwrap(),
        1
    );
    assert_eq!(read_runtime_pointer(&engine, count), 5);
    assert_eq!(
        engine.modules().memory().read(output, 5).unwrap(),
        &[0u8; 5]
    );
}

#[test]
fn remote_process_memory_hooks_use_separate_address_spaces() {
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_free_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualFreeEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let read_process_memory = engine.bind_hook_for_test("kernel32.dll", "ReadProcessMemory");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let input = engine.allocate_executable_test_page(0x6313_0000).unwrap();
    let output = engine.allocate_executable_test_page(0x6314_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x6315_0000).unwrap();
    let count = engine.allocate_executable_test_page(0x6316_0000).unwrap();
    engine.write_test_bytes(input, b"REMOTE").unwrap();
    engine.write_test_bytes(output, &[0u8; 6]).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 0x4321])
        .unwrap();
    assert_ne!(process, 0);

    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(write_process_memory, &[process, remote, input, 6, count])
            .unwrap(),
        1
    );
    assert_eq!(read_runtime_pointer(&engine, count), 6);

    assert_eq!(
        engine
            .dispatch_bound_stub(read_process_memory, &[process, remote, output, 6, count])
            .unwrap(),
        1
    );
    assert_eq!(read_runtime_pointer(&engine, count), 6);
    assert_eq!(
        engine.modules().memory().read(output, 6).unwrap(),
        b"REMOTE"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, remote, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0x1000
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 24, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_PRIVATE
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_free_ex, &[process, remote, 0, MEM_RELEASE])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, remote, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 16, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_FREE
    );

    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn virtual_protect_hooks_update_current_and_remote_region_permissions() {
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_protect_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualProtectEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let info = engine.allocate_executable_test_page(0x6317_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x6318_0000).unwrap();

    let local = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_READWRITE])
        .unwrap();
    assert_ne!(local, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[local + 0x123, 0x20, PAGE_READONLY, old_protect]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(old_protect, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[local + 0x321, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 0x4321])
        .unwrap();
    assert_ne!(process, 0);
    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect_ex,
                &[process, remote + 0x40, 0x10, PAGE_EXECUTE_READ, old_protect]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(old_protect, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READWRITE
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query_ex, &[process, remote + 0x80, info, 28])
            .unwrap(),
        28
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_EXECUTE_READ
    );

    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn free_library_matches_python_last_error_behavior() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let main_module = engine.main_module().map(|record| record.base);
    let dependency = engine
        .modules()
        .loaded_modules()
        .into_iter()
        .find(|module| Some(module.base) != main_module && !module.synthetic)
        .map(|module| module.base);
    let free_library = engine.bind_hook_for_test("kernel32.dll", "FreeLibrary");

    if let Some(dependency) = dependency {
        engine.set_last_error(1813);
        assert_eq!(
            engine
                .dispatch_bound_stub(free_library, &[dependency])
                .unwrap(),
            1
        );
        assert_eq!(engine.last_error(), 0);
    }

    if let Some(main_base) = main_module {
        engine.set_last_error(1813);
        assert_eq!(
            engine
                .dispatch_bound_stub(free_library, &[main_base])
                .unwrap(),
            0
        );
        assert_eq!(engine.last_error(), 6);
    }
}

#[test]
fn load_library_w_initializes_real_sample_dll_and_honors_dynamic_refcounts() {
    let Some(dll_sample) = first_runnable_exported_sample().unwrap() else {
        return;
    };
    let Some(mut config) = dll_sample_config() else {
        return;
    };
    config.preload_modules.clear();
    config.whitelist_modules = [dll_sample.name.to_ascii_lowercase()].into_iter().collect();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.modules().get_loaded(&dll_sample.name).is_none());
    let expected_loader_name = format!("{}.dll", dll_sample.name);
    assert!(!engine
        .process_env()
        .loader_module_names()
        .unwrap()
        .iter()
        .any(|name| name.eq_ignore_ascii_case(&expected_loader_name)));

    let name = engine.allocate_executable_test_page(0x6311_0000).unwrap();
    engine
        .write_test_bytes(
            name,
            &format!("{}\0", dll_sample.name)
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let load_library = engine.bind_hook_for_test("kernel32.dll", "LoadLibraryW");
    let free_library = engine.bind_hook_for_test("kernel32.dll", "FreeLibrary");
    let virtual_query = engine.bind_hook_for_test("kernel32.dll", "VirtualQuery");
    let info = engine.allocate_executable_test_page(0x6312_0000).unwrap();
    let struct_size = if runtime_pointer_size(&engine) == 8 {
        48usize
    } else {
        28usize
    };
    let state_offset = if runtime_pointer_size(&engine) == 8 {
        32u64
    } else {
        16u64
    };

    let first = engine.dispatch_bound_stub(load_library, &[name]).unwrap();
    let second = engine.dispatch_bound_stub(load_library, &[name]).unwrap();

    assert_eq!(first, second);
    assert_eq!(engine.last_error(), 0);
    assert!(
        engine
            .modules()
            .get_loaded(&dll_sample.name)
            .unwrap()
            .initialized
    );
    let loader_names = engine.process_env().loader_module_names().unwrap();
    assert!(
        loader_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&expected_loader_name)),
        "loader names after load: {loader_names:?}"
    );

    assert_eq!(
        engine.dispatch_bound_stub(free_library, &[first]).unwrap(),
        1
    );
    assert!(engine.modules().get_loaded(&dll_sample.name).is_some());
    assert_eq!(
        engine.dispatch_bound_stub(free_library, &[second]).unwrap(),
        1
    );
    assert!(engine.modules().get_loaded(&dll_sample.name).is_none());
    let loader_names = engine.process_env().loader_module_names().unwrap();
    assert!(
        !loader_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&expected_loader_name)),
        "loader names after unload: {loader_names:?}"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(virtual_query, &[first, info, struct_size as u64])
            .unwrap(),
        struct_size as u64
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(info + state_offset, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_FREE
    );
}

#[test]
fn create_thread_and_resume_thread_initialize_virtual_thread_context() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let tid_ptr = engine.allocate_executable_test_page(0x6312_0000).unwrap();
    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let resume_thread = engine.bind_hook_for_test("kernel32.dll", "ResumeThread");

    let handle = engine
        .dispatch_bound_stub(create_thread, &[0, 0, 0x401000, 0x4141, 0x4, tid_ptr])
        .unwrap();
    let tid = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(tid_ptr, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let snapshot = engine.scheduler().thread_snapshot(tid).unwrap();

    assert_ne!(handle, 0);
    assert_eq!(snapshot.handle as u64, handle);
    assert_eq!(snapshot.start_address, 0x401000);
    assert_eq!(snapshot.parameter, 0x4141);
    assert_eq!(snapshot.state, "suspended");
    assert_ne!(snapshot.teb_base, 0);
    assert!(snapshot.stack_limit < snapshot.stack_top);
    assert_eq!(snapshot.registers.get("eip"), Some(&0x401000));
    let esp = *snapshot.registers.get("esp").unwrap();
    let frame = engine.modules().memory().read(esp, 8).unwrap();
    assert_eq!(
        u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64,
        engine.main_thread_exit_sentinel()
    );
    assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 0x4141);

    assert_eq!(
        engine
            .dispatch_bound_stub(resume_thread, &[handle])
            .unwrap(),
        1
    );
    assert_eq!(engine.scheduler().thread_state(tid).unwrap(), "ready");
    assert_eq!(
        engine
            .dispatch_bound_stub(resume_thread, &[handle])
            .unwrap(),
        0
    );
}

#[test]
fn toolhelp_process_snapshot_enumerates_parent_process_and_ppid() {
    let sample = runtime_sample();
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let create_snapshot = engine.bind_hook_for_test("kernel32.dll", "CreateToolhelp32Snapshot");
    let process32_first = engine.bind_hook_for_test("kernel32.dll", "Process32FirstW");
    let process32_next = engine.bind_hook_for_test("kernel32.dll", "Process32NextW");
    let entry = engine.allocate_executable_test_page(0x6313_0000).unwrap();
    let mut entry_seed = vec![0u8; 556];
    entry_seed[0..4].copy_from_slice(&556u32.to_le_bytes());
    engine.write_test_bytes(entry, &entry_seed).unwrap();

    let snapshot = engine
        .dispatch_bound_stub(create_snapshot, &[0x0000_0002, 0])
        .unwrap();

    assert_ne!(snapshot, u32::MAX as u64);
    assert_eq!(
        engine
            .dispatch_bound_stub(process32_first, &[snapshot, entry])
            .unwrap(),
        1
    );

    let mut entries = vec![read_wide_process_entry(&engine, entry)];
    loop {
        let result = engine
            .dispatch_bound_stub(process32_next, &[snapshot, entry])
            .unwrap();
        if result == 0 {
            break;
        }
        entries.push(read_wide_process_entry(&engine, entry));
    }

    assert_eq!(engine.last_error(), 18);
    assert!(entries.iter().any(|(pid, ppid, thread_count, image_name)| {
        *pid == 0x1337
            && *ppid == 0x4321
            && *thread_count >= 1
            && image_name.eq_ignore_ascii_case(&sample.name)
    }));
    assert!(entries.iter().any(|(pid, ppid, thread_count, image_name)| {
        *pid == 0x4321
            && *ppid == 0
            && *thread_count == 0
            && image_name.eq_ignore_ascii_case("parent_toolhelp.exe")
    }));
    assert!(entries.iter().all(|(_, ppid, _, image_name)| !image_name
        .eq_ignore_ascii_case(&sample.name)
        || *ppid == 0x4321));
}

#[test]
fn search_path_w_returns_zero_for_missing_file() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let directory_ptr = engine.allocate_executable_test_page(0x6310_A000).unwrap();
    let file_ptr = engine.allocate_executable_test_page(0x6310_B000).unwrap();
    let output_ptr = engine.allocate_executable_test_page(0x6310_C000).unwrap();
    engine
        .write_test_bytes(
            directory_ptr,
            &r"C:\Windows\System32"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            file_ptr,
            &"definitely_missing_binary"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(output_ptr, &[0u8; 520]).unwrap();

    let search_path = engine.bind_hook_for_test("kernel32.dll", "SearchPathW");
    let result = engine
        .dispatch_bound_stub(
            search_path,
            &[directory_ptr, file_ptr, 0, 260, output_ptr, 0],
        )
        .unwrap();

    assert_eq!(result, 0);
    assert_eq!(engine.last_error(), 2);
}

#[test]
fn get_temp_file_name_w_returns_guest_visible_temp_path() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let prefix_ptr = engine.allocate_executable_test_page(0x6310_D000).unwrap();
    let output_ptr = engine.allocate_executable_test_page(0x6310_E000).unwrap();
    engine
        .write_test_bytes(
            prefix_ptr,
            &"TMP"
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine.write_test_bytes(output_ptr, &[0u8; 520]).unwrap();

    let get_temp_file_name = engine.bind_hook_for_test("kernel32.dll", "GetTempFileNameW");
    let unique = engine
        .dispatch_bound_stub(get_temp_file_name, &[0, prefix_ptr, 0x1234, output_ptr])
        .unwrap();

    assert_eq!(unique, 0x1234);
    let output = read_wide_c_string(&engine, output_ptr, 260);
    assert!(output.starts_with("C:\\"));
    assert!(output.ends_with(r"\TMP1234.tmp"));
}

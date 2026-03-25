use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::samples::{first_runnable_exported_sample, first_runnable_sample};

const PAGE_READWRITE: u64 = 0x04;
const FILE_MAP_READ: u64 = 0x0004;

fn dll_entry_config() -> Option<hvm::config::EngineConfig> {
    let dll_sample = first_runnable_exported_sample().unwrap()?;
    let host_sample = first_runnable_sample().unwrap()?;
    let export_name = dll_sample.first_export()?.to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path =
        std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-psapi-{timestamp}.json"));

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"process_image\":\"{}\",",
                "\"entry_module\":\"{}\",",
                "\"entry_export\":\"{}\"",
                "}}"
            ),
            dll_sample.path.to_string_lossy().replace('\\', "\\\\"),
            host_sample.path.to_string_lossy().replace('\\', "\\\\"),
            dll_sample.path.to_string_lossy().replace('\\', "\\\\"),
            export_name,
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    fs::remove_file(config_path).unwrap();
    Some(config)
}

fn read_wide_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine
        .modules()
        .memory()
        .read(address, capacity.saturating_mul(2))
        .unwrap();
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16_lossy(&words)
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

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
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

#[test]
fn psapi_queries_follow_process_image_identity_for_dll_config() {
    let Some(config) = dll_entry_config() else {
        return;
    };
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let enum_modules = engine.bind_hook_for_test("psapi.dll", "EnumProcessModules");
    let get_process_image = engine.bind_hook_for_test("psapi.dll", "GetProcessImageFileNameW");
    let get_module_file_name = engine.bind_hook_for_test("kernel32.dll", "K32GetModuleFileNameExW");
    let get_module_base_name = engine.bind_hook_for_test("psapi.dll", "GetModuleBaseNameW");
    let entry_module_base = engine.entry_module().unwrap().base;

    let module_array = engine.allocate_executable_test_page(0x6330_0000).unwrap();
    let needed_ptr = engine.allocate_executable_test_page(0x6331_0000).unwrap();
    let image_buffer = engine.allocate_executable_test_page(0x6332_0000).unwrap();
    let file_name_buffer = engine.allocate_executable_test_page(0x6333_0000).unwrap();
    let base_name_buffer = engine.allocate_executable_test_page(0x6334_0000).unwrap();
    let pointer_size = runtime_pointer_size(&engine);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                enum_modules,
                &[u32::MAX as u64, module_array, 0x40, needed_ptr]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(needed_ptr, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as usize,
        engine.modules().loaded_modules().len().max(1) * pointer_size
    );
    assert_eq!(
        read_runtime_pointer(&engine, module_array),
        engine.main_module().unwrap().base
    );

    assert!(
        engine
            .dispatch_bound_stub(get_process_image, &[u32::MAX as u64, image_buffer, 260])
            .unwrap()
            > 0
    );
    let process_image = engine.main_module().unwrap().clone();
    assert!(
        PathBuf::from(read_wide_c_string(&engine, image_buffer, 260))
            .ends_with(Path::new("Sample").join(&process_image.name))
    );

    assert!(
        engine
            .dispatch_bound_stub(
                get_module_file_name,
                &[u32::MAX as u64, 0, file_name_buffer, 260]
            )
            .unwrap()
            > 0
    );
    assert!(
        PathBuf::from(read_wide_c_string(&engine, file_name_buffer, 260))
            .ends_with(Path::new("Sample").join(&process_image.name))
    );

    assert!(
        engine
            .dispatch_bound_stub(
                get_module_base_name,
                &[u32::MAX as u64, entry_module_base, base_name_buffer, 260]
            )
            .unwrap()
            > 0
    );
    assert!(read_wide_c_string(&engine, base_name_buffer, 260)
        .eq_ignore_ascii_case(&engine.entry_module().unwrap().name));
}

#[test]
fn psapi_module_information_reports_runtime_module_layout() {
    let Some(config) = dll_entry_config() else {
        return;
    };
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let entry_module = engine.entry_module().unwrap().clone();
    let get_module_information = engine.bind_hook_for_test("psapi.dll", "GetModuleInformation");
    let get_mapped_file_name = engine.bind_hook_for_test("psapi.dll", "GetMappedFileNameW");
    let module_info = engine.allocate_executable_test_page(0x6335_0000).unwrap();
    let mapped_name = engine.allocate_executable_test_page(0x6336_0000).unwrap();
    let pointer_size = runtime_pointer_size(&engine);
    let module_info_size = if pointer_size == 8 { 24 } else { 12 };

    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_module_information,
                &[
                    u32::MAX as u64,
                    entry_module.base,
                    module_info,
                    module_info_size as u64,
                ]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        read_runtime_pointer(&engine, module_info),
        entry_module.base
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(module_info + pointer_size as u64, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        entry_module.size
    );
    assert_eq!(
        read_runtime_pointer(
            &engine,
            module_info + if pointer_size == 8 { 16 } else { 8 }
        ),
        entry_module.entrypoint
    );

    assert!(
        engine
            .dispatch_bound_stub(
                get_mapped_file_name,
                &[u32::MAX as u64, entry_module.base, mapped_name, 260]
            )
            .unwrap()
            > 0
    );
    assert!(PathBuf::from(read_wide_c_string(&engine, mapped_name, 260))
        .ends_with(Path::new("Sample").join(&entry_module.name)));
}

#[test]
fn psapi_get_mapped_file_name_reports_backing_file_for_mapped_view() {
    let path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-psapi-map-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&path, b"mapped-file").unwrap();

    let mut config = sample_config();
    config
        .allowed_read_dirs
        .push(path.parent().unwrap().to_path_buf());
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let path_ptr = engine.allocate_executable_test_page(0x6337_0000).unwrap();
    let mapped_name = engine.allocate_executable_test_page(0x6338_0000).unwrap();
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
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let get_mapped_file_name = engine.bind_hook_for_test("psapi.dll", "GetMappedFileNameW");

    let file = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x8000_0000, 3, 0, 3, 0, 0])
        .unwrap();
    let mapping = engine
        .dispatch_bound_stub(create_mapping, &[file, 0, PAGE_READWRITE, 0, 0, 0])
        .unwrap();
    let view = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_READ, 0, 0, 0])
        .unwrap();

    assert!(
        engine
            .dispatch_bound_stub(
                get_mapped_file_name,
                &[u32::MAX as u64, view, mapped_name, 260]
            )
            .unwrap()
            > 0
    );
    assert_eq!(
        PathBuf::from(read_wide_c_string(&engine, mapped_name, 260)),
        path
    );

    assert_eq!(engine.dispatch_bound_stub(unmap_view, &[view]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[file]).unwrap(), 1);
    fs::remove_file(path).unwrap();
}

#[test]
fn psapi_remote_process_module_queries_use_remote_module_state() {
    let mut engine = VirtualExecutionEngine::new(sample_config_with_parent()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let enum_modules = engine.bind_hook_for_test("psapi.dll", "EnumProcessModules");
    let get_module_file_name = engine.bind_hook_for_test("kernel32.dll", "K32GetModuleFileNameExW");
    let get_module_base_name = engine.bind_hook_for_test("psapi.dll", "GetModuleBaseNameW");

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 0x4321])
        .unwrap();
    assert_ne!(process, 0);

    let module_array = engine.allocate_executable_test_page(0x6339_0000).unwrap();
    let needed_ptr = engine.allocate_executable_test_page(0x633A_0000).unwrap();
    let file_name_buffer = engine.allocate_executable_test_page(0x633B_0000).unwrap();
    let base_name_buffer = engine.allocate_executable_test_page(0x633C_0000).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(enum_modules, &[process, module_array, 0x40, needed_ptr])
            .unwrap(),
        1
    );
    assert!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(needed_ptr, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as usize
            >= runtime_pointer_size(&engine)
    );

    let module = read_runtime_pointer(&engine, module_array);
    assert_ne!(module, 0);
    assert!(
        engine
            .dispatch_bound_stub(get_module_file_name, &[process, 0, file_name_buffer, 260])
            .unwrap()
            > 0
    );
    assert!(
        PathBuf::from(read_wide_c_string(&engine, file_name_buffer, 260))
            .ends_with(Path::new("Sample").join("parent_toolhelp.exe"))
    );

    assert!(
        engine
            .dispatch_bound_stub(
                get_module_base_name,
                &[process, module, base_name_buffer, 260]
            )
            .unwrap()
            > 0
    );
    assert!(read_wide_c_string(&engine, base_name_buffer, 260)
        .eq_ignore_ascii_case("parent_toolhelp.exe"));
}

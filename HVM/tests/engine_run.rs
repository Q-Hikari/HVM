use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use hvm::config::load_config;
use hvm::models::RunStopReason;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::samples::{
    discover_default_samples, first_runnable_exported_sample, first_runnable_sample,
    SampleDescriptor, SampleKind,
};
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn runtime_sample() -> SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
}

fn runtime_sample_name() -> String {
    runtime_sample().name
}

fn native_dll_sample() -> SampleDescriptor {
    discover_default_samples()
        .unwrap()
        .into_iter()
        .find(|sample| sample.run_supported && sample.kind == SampleKind::DynamicLibrary)
        .expect("expected at least one runnable dll sample")
}

fn default_export_entry_args(dll_sample: &SampleDescriptor) -> &'static str {
    if dll_sample.arch.eq_ignore_ascii_case("x64") {
        r#"[{"type":"wstring","value":""}]"#
    } else {
        "[]"
    }
}

fn write_temp_config(contents: String) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("hvm-hikari-virtual-engine-engine-run-{stamp}.json"));
    fs::write(&path, contents).unwrap();
    path
}

fn write_temp_trace_path(suffix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-engine-run-{suffix}-{stamp}.jsonl"
    ))
}

fn write_temp_dll_export_config(
    dll_sample: &SampleDescriptor,
    entry_args: &str,
) -> (PathBuf, PathBuf, PathBuf, String) {
    let host_path = runtime_sample().path;
    let dll_path = dll_sample.path.clone();
    let export_name = dll_sample
        .first_export()
        .expect("expected exported sample to expose at least one export")
        .to_string();
    let config_path = write_temp_config(format!(
        concat!(
            "{{",
            "\"main_module\":\"{}\",",
            "\"process_image\":\"{}\",",
            "\"entry_module\":\"{}\",",
            "\"entry_export\":\"{}\",",
            "\"entry_args\":{}",
            "}}"
        ),
        dll_path.to_string_lossy().replace('\\', "\\\\"),
        host_path.to_string_lossy().replace('\\', "\\\\"),
        dll_path.to_string_lossy().replace('\\', "\\\\"),
        export_name,
        entry_args,
    ));
    (config_path, dll_path, host_path, export_name)
}

fn read_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine.modules().memory().read(address, capacity).unwrap();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
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

fn read_runtime_u16(engine: &VirtualExecutionEngine, address: u64) -> u16 {
    u16::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address, 2)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn read_runtime_u32(engine: &VirtualExecutionEngine, address: u64) -> u32 {
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

fn read_runtime_loader_wide_string(
    engine: &VirtualExecutionEngine,
    descriptor_address: u64,
) -> String {
    let byte_len = read_runtime_u16(engine, descriptor_address) as usize;
    let buffer = read_runtime_pointer(engine, descriptor_address + 4);
    let bytes = engine.modules().memory().read(buffer, byte_len).unwrap();
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn ror32(value: u32, count: u32) -> u32 {
    value.rotate_right(count)
}

fn shell_module_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for ch in name.chars() {
        let mut value = ch as u32;
        if value > 0x60 {
            value = value.saturating_sub(0x20);
        }
        hash = ror32(hash.wrapping_add(value), 13);
    }
    hash
}

fn shell_export_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for byte in name.bytes() {
        hash = ror32(hash.wrapping_add(byte as u32), 13);
    }
    hash
}

fn resolve_shell_hash_from_process_memory(
    engine: &VirtualExecutionEngine,
    target_hash: u32,
) -> Option<u64> {
    let peb = engine.process_env().current_peb();
    let ldr = read_runtime_pointer(engine, peb + engine.process_env().offsets().peb_ldr as u64);
    let load_head = ldr + 0x0C;
    let mut cursor = read_runtime_pointer(engine, load_head);
    let mut remaining = 64usize;

    while cursor != load_head && remaining > 0 {
        let entry_base = cursor;
        let module_base = read_runtime_pointer(engine, entry_base + 0x18);
        let module_name = read_runtime_loader_wide_string(engine, entry_base + 0x2C);
        let module_hash = shell_module_hash(&module_name);
        let pe_offset = read_runtime_u32(engine, module_base + 0x3C) as u64;
        let export_directory_rva = read_runtime_u32(engine, module_base + pe_offset + 0x78);
        if export_directory_rva != 0 {
            let export_directory = module_base + export_directory_rva as u64;
            let name_count = read_runtime_u32(engine, export_directory + 24);
            let function_table_rva = read_runtime_u32(engine, export_directory + 28);
            let name_pointer_table_rva = read_runtime_u32(engine, export_directory + 32);
            let ordinal_table_rva = read_runtime_u32(engine, export_directory + 36);
            for index in 0..name_count {
                let name_rva = read_runtime_u32(
                    engine,
                    module_base + name_pointer_table_rva as u64 + index as u64 * 4,
                );
                let export_name = read_c_string(engine, module_base + name_rva as u64, 512);
                let ordinal = read_runtime_u16(
                    engine,
                    module_base + ordinal_table_rva as u64 + index as u64 * 2,
                );
                let function_rva = read_runtime_u32(
                    engine,
                    module_base + function_table_rva as u64 + ordinal as u64 * 4,
                );
                if shell_export_hash(&export_name) ^ module_hash == target_hash {
                    return Some(module_base + function_rva as u64);
                }
            }
        }

        cursor = read_runtime_pointer(engine, cursor);
        remaining -= 1;
    }

    None
}

#[test]
fn run_config_executes_sample_and_returns_exit_fields() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let result = engine.run().unwrap();
    let main_tid = engine.main_thread_tid().unwrap();

    assert!(result.entrypoint > 0);
    assert!(result.instructions > 0);
    assert!(result.stopped);
    assert!(result.exit_code.is_some());
    assert!(matches!(
        result.stop_reason,
        RunStopReason::MainThreadTerminated | RunStopReason::AllThreadsTerminated
    ));
    assert_eq!(
        engine.scheduler().thread_state(main_tid).unwrap(),
        "terminated"
    );
}

#[test]
fn load_accepts_x64_sample_config_and_prepares_export_entry() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_9b66f94497b13dd05fc6840894374776_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let module = engine.load().unwrap().clone();
    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    let rsp = *thread.registers.get("rsp").unwrap();

    assert_eq!(
        module
            .path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("567dbfa9f7d29702a70feb934ec08e54")
    );
    assert_eq!(
        engine
            .entry_module()
            .unwrap()
            .path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("9b66f94497b13dd05fc6840894374776")
    );
    assert_eq!(thread.registers.get("rip"), engine.entry_address().as_ref());
    assert_eq!(
        thread.registers.get("rcx"),
        Some(&engine.entry_arguments()[0])
    );
    assert_eq!(thread.registers.get("rflags"), Some(&0x202));
    assert!(thread.stack_limit < thread.stack_top);
    assert!(rsp >= thread.stack_limit);
    assert!(rsp < thread.stack_top);

    let frame = engine.modules().memory().read(rsp, 8).unwrap();
    assert_eq!(
        u64::from_le_bytes(frame.try_into().unwrap()),
        engine.main_thread_exit_sentinel()
    );
    assert_eq!(
        read_wide_c_string(&engine, engine.entry_arguments()[0], 8),
        ""
    );
}

#[test]
fn load_initializes_main_thread_x86_context_and_stack_frame() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    let module = engine.load().unwrap().clone();
    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    let esp = *thread.registers.get("esp").unwrap();

    assert_eq!(thread.registers.get("eip"), Some(&module.entrypoint));
    assert_eq!(thread.registers.get("eflags"), Some(&0x202));
    assert_eq!(thread.exit_address, engine.main_thread_exit_sentinel());
    assert!(thread.stack_limit < thread.stack_top);
    assert!(esp >= thread.stack_limit);
    assert!(esp < thread.stack_top);

    let frame = engine.modules().memory().read(esp, 8).unwrap();
    assert_eq!(frame, vec![0u8; 8]);
}

#[test]
fn run_command_prints_expected_summary_fields() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("hvm-hikari-virtual-engine"));
    cmd.args(["run", "--config", config_path.to_str().unwrap()]);
    cmd.assert().success().stdout(
        contains("entrypoint=")
            .and(contains("instructions="))
            .and(contains("stopped="))
            .and(contains("exit_code="))
            .and(contains("stop_reason=")),
    );
}

#[test]
fn load_registers_main_thread_and_main_module() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    assert!(engine
        .modules()
        .get_loaded(&runtime_sample_name())
        .is_some());
    assert_eq!(
        engine
            .scheduler()
            .thread_state(engine.main_thread_tid().unwrap())
            .unwrap(),
        "ready"
    );
}

#[test]
fn load_syncs_peb_loader_modules_in_windows_startup_order() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    let loader_modules = engine.process_env().loader_module_names().unwrap();
    assert_eq!(loader_modules[0], runtime_sample_name());
    assert_eq!(
        &loader_modules[1..6],
        &[
            "ntdll.dll",
            "kernel32.dll",
            "lpk.dll",
            "usp10.dll",
            "kernelbase.dll",
        ]
    );
}

#[test]
fn run_emits_startup_notifications_and_ntcontinue_resume_chain() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    let trace_path = write_temp_trace_path("startup");
    config.trace_api_calls = true;
    config.api_jsonl_path = Some(trace_path.clone());
    config.max_instructions = 512;

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let _ = engine.run().unwrap();

    let jsonl = fs::read_to_string(trace_path).unwrap();
    assert!(jsonl.contains("\"marker\":\"DLL_NOTIFICATION\""));
    assert!(jsonl.contains("\"module\":\"ntdll.dll\""));
    assert!(jsonl.matches("\"target\":\"ntdll.dll!NtContinue\"").count() >= 2);
    assert!(jsonl.contains("\"marker\":\"STARTUP_RESUME\""));
}

#[test]
fn load_defaults_command_line_to_main_module_name_when_config_is_empty() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.command_line.clear();
    let expected = std::path::absolute(&config.main_module)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    assert_eq!(engine.command_line(), expected);
}

#[test]
fn load_resolves_non_whitelisted_imports_to_synthetic_modules_and_iat_stubs() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    let main_module = engine.load().unwrap().clone();
    let kernel32 = engine.modules().get_loaded("kernel32.dll").unwrap();
    assert!(kernel32.synthetic);
    assert!(kernel32.base > 0);

    let bytes = std::fs::read(main_module.path.as_ref().unwrap()).unwrap();
    let pe = goblin::pe::PE::parse(&bytes).unwrap();
    let import = pe
        .imports
        .iter()
        .find(|item| item.dll.eq_ignore_ascii_case("KERNEL32.dll"))
        .unwrap();
    let thunk_address = main_module.base + import.offset as u64;
    let resolved = engine
        .modules()
        .memory()
        .read(thunk_address, import.size)
        .unwrap();

    let resolved_address = u32::from_le_bytes(resolved[0..4].try_into().unwrap()) as u64;

    assert!(resolved.iter().any(|byte| *byte != 0));
    assert!(kernel32.base <= resolved_address);
    assert!(resolved_address < kernel32.base + kernel32.size);
}

#[test]
fn kernel32_synthetic_export_table_contains_expand_environment_strings_a() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    let kernel32 = engine.modules().get_loaded("kernel32.dll").unwrap();
    assert!(kernel32.synthetic);
    assert!(kernel32
        .exports_by_name
        .contains_key("expandenvironmentstringsa"));

    let pe_offset = read_runtime_u32(&engine, kernel32.base + 0x3C) as u64;
    let export_directory_rva = read_runtime_u32(&engine, kernel32.base + pe_offset + 0x78);
    assert_ne!(export_directory_rva, 0);

    let export_directory = kernel32.base + export_directory_rva as u64;
    let name_count = read_runtime_u32(&engine, export_directory + 24);
    let name_pointer_table_rva = read_runtime_u32(&engine, export_directory + 32);
    let mut export_names = Vec::new();
    for index in 0..name_count {
        let name_rva = read_runtime_u32(
            &engine,
            kernel32.base + name_pointer_table_rva as u64 + index as u64 * 4,
        );
        export_names.push(read_c_string(&engine, kernel32.base + name_rva as u64, 512));
    }

    assert!(
        export_names
            .iter()
            .any(|name| name == "ExpandEnvironmentStringsA"),
        "missing export in synthetic image: {export_names:?}"
    );
}

#[test]
fn x86_loader_hash_resolver_finds_expand_environment_strings_a() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    let resolved = resolve_shell_hash_from_process_memory(&engine, 0x7E7C04F2)
        .expect("shell-style hash resolver should find kernel32!ExpandEnvironmentStringsA");
    let kernel32 = engine.modules().get_loaded("kernel32.dll").unwrap();
    let expected = *kernel32
        .exports_by_name
        .get("expandenvironmentstringsa")
        .unwrap();

    assert_eq!(resolved, expected);
}

#[test]
fn new_engine_exposes_parity_managers_and_process_heap_state() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    assert_eq!(
        engine.process_heap_handle() as u64,
        engine.heap_manager().process_heap() as u64
    );
    assert_eq!(engine.device_manager().list_devices("", "", true).len(), 3);
    assert!(engine
        .device_manager()
        .find_by_instance_id("ROOT\\HTREE\\ROOT\\0")
        .is_some());
    assert_eq!(engine.network_manager().last_error(), 0);

    let socket = engine.network_manager_mut().create_socket(2, 1, 6);
    assert!(engine.network_manager().get_socket(socket).is_some());

    let store = engine.crypto_manager_mut().open_store("ROOT", false);
    assert_ne!(engine.crypto_manager().find_certificate(store, 0), 0);
}

#[test]
fn log_zero_unknown_api_policy_preserves_zero_return_for_unimplemented_runtime_stub() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.unknown_api_policy = "log_zero".to_string();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("rpcrt4.dll", "RpcBindingFree");
    let retval = engine.dispatch_bound_stub(stub, &[0]).unwrap();

    assert_eq!(retval, 0);
}

#[test]
fn strict_unknown_api_policy_rejects_unimplemented_runtime_stub() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.unknown_api_policy = "strict".to_string();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("rpcrt4.dll", "RpcBindingFree");
    let error = engine.dispatch_bound_stub(stub, &[0]).unwrap_err();

    assert!(error.to_string().contains("unknown_api_policy=strict"));
    assert!(error.to_string().contains("rpcrt4.dll!RpcBindingFree"));
}

#[test]
fn load_dll_export_entry_uses_host_image_identity_and_prepares_export_args() {
    let Some(dll_sample) = first_runnable_exported_sample().unwrap() else {
        return;
    };
    let (config_path, dll_path, host_path, export_name) = write_temp_dll_export_config(
        &dll_sample,
        r#"[4660,{"type":"string","value":"ansi-arg"},{"type":"wstring","value":"宽参数"},{"type":"bytes","hex":"41 42 43"}]"#,
    );
    let config = load_config(&config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    engine.load().unwrap();

    let process_image = engine.main_module().unwrap().clone();
    let entry_module = engine.entry_module().unwrap().clone();
    let entry_address = engine.entry_address().unwrap();
    let prepared_args = engine.entry_arguments().to_vec();
    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();

    assert_eq!(process_image.path.as_ref(), Some(&host_path));
    assert_eq!(entry_module.path.as_ref(), Some(&dll_path));
    assert_eq!(
        process_image.name,
        host_path.file_name().unwrap().to_string_lossy()
    );
    assert_eq!(
        entry_module.name,
        dll_path.file_name().unwrap().to_string_lossy()
    );
    assert_eq!(
        entry_address,
        *entry_module
            .exports_by_name
            .get(&export_name.to_ascii_lowercase())
            .unwrap()
    );
    assert_eq!(thread.start_address, entry_address);
    if dll_sample.arch.eq_ignore_ascii_case("x64") {
        assert_eq!(thread.registers.get("rip"), Some(&entry_address));
        assert_eq!(thread.registers.get("rcx"), Some(&4660));
        let rsp = *thread.registers.get("rsp").unwrap();
        let frame = engine.modules().memory().read(rsp, 8).unwrap();
        assert_eq!(
            u64::from_le_bytes(frame.try_into().unwrap()),
            engine.main_thread_exit_sentinel()
        );
    } else {
        assert_eq!(thread.registers.get("eip"), Some(&entry_address));
        let esp = *thread.registers.get("esp").unwrap();
        let frame = engine.modules().memory().read(esp, 8).unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64,
            engine.main_thread_exit_sentinel()
        );
        assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 4660);
    }
    assert_eq!(thread.parameter, 4660);
    assert_eq!(engine.command_line(), host_path.to_string_lossy());
    assert_eq!(
        engine
            .process_env()
            .read_pointer(
                engine.process_env().current_peb()
                    + engine.process_env().offsets().peb_image_base as u64
            )
            .unwrap(),
        process_image.base
    );

    let get_module_handle = engine.bind_hook_for_test("kernel32.dll", "GetModuleHandleW");
    assert_eq!(
        engine.dispatch_bound_stub(get_module_handle, &[0]).unwrap(),
        process_image.base
    );

    let get_module_file_name = engine.bind_hook_for_test("kernel32.dll", "GetModuleFileNameW");
    let buffer = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    assert!(
        engine
            .dispatch_bound_stub(get_module_file_name, &[0, buffer, 260])
            .unwrap()
            > 0
    );
    assert!(PathBuf::from(read_wide_c_string(&engine, buffer, 260))
        .ends_with(Path::new("Sample").join(host_path.file_name().unwrap())));

    assert_eq!(prepared_args[0], 4660);
    assert_eq!(read_c_string(&engine, prepared_args[1], 64), "ansi-arg");
    assert_eq!(read_wide_c_string(&engine, prepared_args[2], 64), "宽参数");
    assert_eq!(
        engine.modules().memory().read(prepared_args[3], 3).unwrap(),
        b"ABC"
    );

    fs::remove_file(config_path).unwrap();
}

#[test]
fn load_native_dll_entry_without_explicit_args_defaults_to_dllmain_signature() {
    let dll_sample = native_dll_sample();
    let config_path = write_temp_config(format!(
        "{{\"main_module\":\"{}\"}}",
        dll_sample.path.to_string_lossy().replace('\\', "\\\\"),
    ));
    let config = load_config(&config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    let entry_module = engine.load().unwrap().clone();
    let prepared_args = engine.entry_arguments().to_vec();
    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();

    assert_eq!(entry_module.path.as_ref(), Some(&dll_sample.path));
    assert_eq!(prepared_args, vec![entry_module.base, 1, 0]);
    assert_eq!(thread.parameter, entry_module.base);
    if dll_sample.arch.eq_ignore_ascii_case("x64") {
        assert_eq!(thread.registers.get("rcx"), Some(&entry_module.base));
    }

    fs::remove_file(config_path).unwrap();
}

#[test]
fn run_dll_export_config_executes_resolved_export() {
    let Some(dll_sample) = first_runnable_exported_sample().unwrap() else {
        return;
    };
    let (config_path, _dll_path, _host_path, _export_name) =
        write_temp_dll_export_config(&dll_sample, default_export_entry_args(&dll_sample));
    let config = load_config(&config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();

    let entry_address = {
        engine.load().unwrap();
        engine.entry_address().unwrap()
    };
    let result = engine.run().unwrap();

    assert_eq!(result.entrypoint, entry_address);
    assert!(result.instructions > 1);
    assert!(result.stopped);
    assert!(matches!(
        result.stop_reason,
        RunStopReason::MainThreadTerminated
            | RunStopReason::AllThreadsTerminated
            | RunStopReason::InstructionBudgetExhausted
    ));
    if result.stop_reason == RunStopReason::InstructionBudgetExhausted {
        assert_eq!(result.exit_code, None);
    } else {
        assert_eq!(
            result.exit_code,
            Some(if dll_sample.arch.eq_ignore_ascii_case("x64") {
                1
            } else {
                0
            })
        );
    }

    fs::remove_file(config_path).unwrap();
}

#[test]
fn run_dll_export_logs_dllmain_before_export_invoke() {
    let Some(dll_sample) = first_runnable_exported_sample().unwrap() else {
        return;
    };
    let (config_path, _dll_path, _host_path, export_name) =
        write_temp_dll_export_config(&dll_sample, default_export_entry_args(&dll_sample));
    let mut config = load_config(&config_path).unwrap();
    let trace_path = write_temp_trace_path("dll-export-entry");
    config.trace_api_calls = true;
    config.api_jsonl_path = Some(trace_path.clone());
    config.max_instructions = 2048;

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let _ = engine.run().unwrap();

    let jsonl = fs::read_to_string(trace_path).unwrap();
    let dllmain_index = jsonl
        .find("\"marker\":\"DLL_NOTIFICATION\"")
        .expect("expected DllMain notification in trace");
    let entry_index = jsonl
        .find("\"marker\":\"ENTRY_INVOKE\"")
        .expect("expected entry invoke event in trace");
    assert!(dllmain_index < entry_index);
    assert!(jsonl.contains("\"invocation\":\"export\""));
    assert!(jsonl.contains(&format!("\"export\":\"{export_name}\"")));

    fs::remove_file(config_path).unwrap();
}

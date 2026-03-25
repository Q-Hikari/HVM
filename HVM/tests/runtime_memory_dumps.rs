use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::samples::first_runnable_sample;
use serde_json::Value;

const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE_READ: u64 = 0x20;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const INVALID_HANDLE_VALUE: u64 = u32::MAX as u64;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn runtime_sample() -> hvm::samples::SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
}

fn trace_config(test_name: &str) -> (hvm::config::EngineConfig, PathBuf, PathBuf) {
    let mut config = sample_config();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let trace_path = root.join("trace.api.jsonl");
    config.trace_api_calls = true;
    config.api_log_to_console = false;
    config.console_output_to_console = false;
    config.sandbox_output_dir = root.join("sandbox");
    config.api_log_path = Some(root.join("trace.api.log"));
    config.api_jsonl_path = Some(trace_path.clone());
    config.console_output_path = Some(root.join("trace.console.log"));
    (config, trace_path, root)
}

fn load_records(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn parent_process_trace_config(
    test_name: &str,
) -> (hvm::config::EngineConfig, PathBuf, PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let main_sample = runtime_sample();
    let parent_image = repo_root.join("Sample").join("parent_host.exe");
    let config_path = root.join("config.json");
    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"parent_process_image\":\"{}\",",
                "\"parent_process_pid\":17185,",
                "\"parent_process_command_line\":\"\\\"{}\\\" -Embedding\",",
                "\"sandbox_output_dir\":\"{}\",",
                "\"trace_api_calls\":true,",
                "\"api_log_path\":\"{}\",",
                "\"api_jsonl_path\":\"{}\"",
                "}}"
            ),
            main_sample.path.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
            root.join("sandbox").to_string_lossy().replace('\\', "\\\\"),
            root.join("trace.api.log")
                .to_string_lossy()
                .replace('\\', "\\\\"),
            root.join("trace.api.jsonl")
                .to_string_lossy()
                .replace('\\', "\\\\"),
        ),
    )
    .unwrap();
    let config = load_config(&config_path).unwrap();
    let trace_path = root.join("trace.api.jsonl");
    (config, trace_path, root)
}

#[test]
fn virtual_protect_emits_memory_dump_artifact() {
    let (config, trace_path, _) = trace_config("mem-protect-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let old_protect = engine.allocate_executable_test_page(0x6338_0000).unwrap();

    let region = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_READWRITE])
        .unwrap();
    assert_ne!(region, 0);
    engine
        .write_test_bytes(region, b"\x90\x90\xCC\xC3MEMDUMP")
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[region, 0x1000, PAGE_EXECUTE_READ, old_protect]
            )
            .unwrap(),
        1
    );
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("MEM_PROTECT_DUMP"))
        .unwrap();
    assert_eq!(dump.get("dump_base").and_then(Value::as_u64), Some(region));
    assert_eq!(
        dump.get("region_type_name").and_then(Value::as_str),
        Some("private")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert!(bytes.starts_with(b"\x90\x90\xCC\xC3MEMDUMP"));
}

#[test]
fn create_thread_from_private_region_emits_thread_start_dump() {
    let (config, trace_path, _) = trace_config("thread-start-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let tid_ptr = engine.allocate_executable_test_page(0x6339_0000).unwrap();
    let region = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_EXECUTE_READWRITE])
        .unwrap();
    assert_ne!(region, 0);
    engine
        .write_test_bytes(region, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90])
        .unwrap();

    let thread_handle = engine
        .dispatch_bound_stub(create_thread, &[0, 0, region, 0x4141, 0, tid_ptr])
        .unwrap();
    assert_ne!(thread_handle, 0);
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("THREAD_START_DUMP"))
        .unwrap();
    assert_eq!(
        dump.get("start_address").and_then(Value::as_u64),
        Some(region)
    );
    assert_eq!(dump.get("parameter").and_then(Value::as_u64), Some(0x4141));
    assert_eq!(
        dump.get("region_type_name").and_then(Value::as_str),
        Some("private")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert!(bytes.starts_with(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]));
}

#[test]
fn create_remote_thread_from_private_region_emits_remote_thread_record() {
    let (config, trace_path, _) = parent_process_trace_config("remote-thread-record-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let create_remote_thread = engine.bind_hook_for_test("kernel32.dll", "CreateRemoteThread");

    let tid_ptr = engine.allocate_executable_test_page(0x6339_1000).unwrap();
    let bytes_written_ptr = engine.allocate_executable_test_page(0x6339_2000).unwrap();
    let buffer = engine.allocate_executable_test_page(0x6339_3000).unwrap();
    let payload = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
    engine.write_test_bytes(buffer, &payload).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);
    assert_ne!(process, INVALID_HANDLE_VALUE);

    let remote_code = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_EXECUTE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote_code, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[
                    process,
                    remote_code,
                    buffer,
                    payload.len() as u64,
                    bytes_written_ptr
                ]
            )
            .unwrap(),
        1
    );

    let thread_handle = engine
        .dispatch_bound_stub(
            create_remote_thread,
            &[process, 0, 0, remote_code, remote_code + 0x20, 0, tid_ptr],
        )
        .unwrap();
    assert_ne!(thread_handle, 0);
    let tid = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(tid_ptr, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_ne!(tid, 0);
    assert_eq!(engine.scheduler().thread_state(tid), Some("ready"));

    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("REMOTE_THREAD_RECORD"))
        .unwrap();
    assert_eq!(
        dump.get("source_process_handle").and_then(Value::as_u64),
        Some(process)
    );
    assert_eq!(
        dump.get("source_allocation_base").and_then(Value::as_u64),
        Some(remote_code)
    );
    assert_eq!(
        dump.get("start_address").and_then(Value::as_u64),
        Some(remote_code)
    );
    assert_eq!(
        dump.get("parameter").and_then(Value::as_u64),
        Some(remote_code + 0x20)
    );
    assert_eq!(
        dump.get("region_type_name").and_then(Value::as_str),
        Some("private")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert!(bytes.starts_with(&payload));
}

#[test]
fn create_remote_api_thread_translates_entry_and_stages_remote_parameter() {
    let (config, trace_path, _) = parent_process_trace_config("remote-api-thread-translate");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let create_remote_thread = engine.bind_hook_for_test("kernel32.dll", "CreateRemoteThread");
    let load_library_a = engine.bind_hook_for_test("kernel32.dll", "LoadLibraryA");

    let tid_ptr = engine.allocate_executable_test_page(0x6339_4000).unwrap();
    let bytes_written_ptr = engine.allocate_executable_test_page(0x6339_5000).unwrap();
    let buffer = engine.allocate_executable_test_page(0x6339_6000).unwrap();
    let dll_name = b"user32.dll\0";
    engine.write_test_bytes(buffer, dll_name).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);
    assert_ne!(process, INVALID_HANDLE_VALUE);

    let remote_buffer = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote_buffer, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[
                    process,
                    remote_buffer,
                    buffer,
                    dll_name.len() as u64,
                    bytes_written_ptr
                ]
            )
            .unwrap(),
        1
    );

    let thread_handle = engine
        .dispatch_bound_stub(
            create_remote_thread,
            &[process, 0, 0, load_library_a, remote_buffer, 0, tid_ptr],
        )
        .unwrap();
    assert_ne!(thread_handle, 0);
    let tid = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(tid_ptr, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_ne!(tid, 0);

    engine.prepare_remote_thread_for_test(tid).unwrap();

    let thread = engine.scheduler().thread_snapshot(tid).unwrap();
    assert_eq!(thread.start_address, load_library_a);
    let staged_parameter = thread.parameter;
    assert_ne!(staged_parameter, 0);
    assert_ne!(staged_parameter, remote_buffer);
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(staged_parameter, dll_name.len())
            .unwrap(),
        dll_name
    );
    assert_eq!(
        thread
            .registers
            .get("eip")
            .copied()
            .or_else(|| thread.registers.get("rip").copied()),
        Some(load_library_a)
    );

    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let stage = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("REMOTE_THREAD_STAGE"))
        .unwrap();
    assert_eq!(
        stage.get("entry_mode").and_then(Value::as_str),
        Some("api_translation")
    );
    let translation_source = stage
        .get("translation_source")
        .and_then(Value::as_str)
        .unwrap();
    assert!(
        matches!(
            translation_source,
            "bound_hook_address" | "current_module_address"
        ),
        "unexpected translation_source={translation_source}"
    );
    assert_eq!(
        stage.get("translated_module_name").and_then(Value::as_str),
        Some("kernel32.dll")
    );
    if translation_source == "bound_hook_address" {
        assert_eq!(
            stage
                .get("translated_function_name")
                .and_then(Value::as_str),
            Some("loadlibrarya")
        );
    }
    assert_eq!(
        stage.get("source_parameter").and_then(Value::as_u64),
        Some(remote_buffer)
    );
    assert_eq!(
        stage.get("staged_start_address").and_then(Value::as_u64),
        Some(load_library_a)
    );
    assert_eq!(
        stage.get("staged_parameter").and_then(Value::as_u64),
        Some(staged_parameter)
    );
}

#[test]
fn write_process_memory_emits_memory_dump_artifact() {
    let (config, trace_path, _) = parent_process_trace_config("write-process-memory-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let bytes_written_ptr = engine.allocate_executable_test_page(0x633A_0000).unwrap();
    let buffer = engine.allocate_executable_test_page(0x633B_0000).unwrap();
    let payload = [0x90, 0x90, 0xCC, 0xC3, 0x41, 0x42, 0x43, 0x44];
    engine.write_test_bytes(buffer, &payload).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);
    assert_ne!(process, INVALID_HANDLE_VALUE);
    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_EXECUTE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[
                    process,
                    remote,
                    buffer,
                    payload.len() as u64,
                    bytes_written_ptr
                ]
            )
            .unwrap(),
        1
    );
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("MEM_WRITE_DUMP"))
        .unwrap();
    assert_eq!(dump.get("address").and_then(Value::as_u64), Some(remote));
    assert_eq!(
        dump.get("source").and_then(Value::as_str),
        Some("WriteProcessMemory")
    );
    assert_eq!(
        dump.get("region_type_name").and_then(Value::as_str),
        Some("private")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert_eq!(&bytes[..payload.len()], &payload);
}

#[test]
fn write_process_memory_dump_is_not_limited_to_single_page() {
    let (config, trace_path, _) = trace_config("write-process-memory-large-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let bytes_written_ptr = engine.allocate_executable_test_page(0x6341_0000).unwrap();
    let payload_len = 0x1200usize;
    let payload = (0..payload_len)
        .map(|value| (value & 0xFF) as u8)
        .collect::<Vec<_>>();
    let source_buffer = engine
        .dispatch_bound_stub(
            virtual_alloc,
            &[0, payload_len as u64, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    let target_region = engine
        .dispatch_bound_stub(
            virtual_alloc,
            &[0, payload_len as u64, 0x3000, PAGE_EXECUTE_READWRITE],
        )
        .unwrap();
    assert_ne!(source_buffer, 0);
    assert_ne!(target_region, 0);
    engine.write_test_bytes(source_buffer, &payload).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[
                    u32::MAX as u64,
                    target_region,
                    source_buffer,
                    payload_len as u64,
                    bytes_written_ptr
                ]
            )
            .unwrap(),
        1
    );
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("MEM_WRITE_DUMP"))
        .unwrap();
    assert_eq!(
        dump.get("captured_size").and_then(Value::as_u64),
        Some(payload_len as u64)
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert_eq!(bytes.len(), payload_len);
    assert_eq!(bytes, payload);
}

#[test]
fn dynamic_code_chain_links_write_protect_and_thread_events() {
    let (config, trace_path, _) = trace_config("mem-exec-chain");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");
    let virtual_protect = engine.bind_hook_for_test("kernel32.dll", "VirtualProtect");
    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let bytes_written_ptr = engine.allocate_executable_test_page(0x633D_0000).unwrap();
    let old_protect_ptr = engine.allocate_executable_test_page(0x633E_0000).unwrap();
    let tid_ptr = engine.allocate_executable_test_page(0x633F_0000).unwrap();
    let source_buffer = engine.allocate_executable_test_page(0x6340_0000).unwrap();
    let payload = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];

    let region = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_READWRITE])
        .unwrap();
    assert_ne!(region, 0);
    engine.write_test_bytes(source_buffer, &payload).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[
                    u32::MAX as u64,
                    region,
                    source_buffer,
                    payload.len() as u64,
                    bytes_written_ptr
                ]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(
                virtual_protect,
                &[region, 0x1000, PAGE_EXECUTE_READ, old_protect_ptr]
            )
            .unwrap(),
        1
    );
    let thread_handle = engine
        .dispatch_bound_stub(create_thread, &[0, 0, region, 0x7171, 0, tid_ptr])
        .unwrap();
    assert_ne!(thread_handle, 0);
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let chain_records = records
        .iter()
        .filter(|record| record.get("marker").and_then(Value::as_str) == Some("MEM_EXEC_CHAIN"))
        .collect::<Vec<_>>();
    assert_eq!(chain_records.len(), 3);
    assert_eq!(
        chain_records[0].get("stage").and_then(Value::as_str),
        Some("write")
    );
    assert_eq!(
        chain_records[1].get("stage").and_then(Value::as_str),
        Some("protect")
    );
    assert_eq!(
        chain_records[2].get("stage").and_then(Value::as_str),
        Some("thread")
    );

    let final_record = chain_records[2];
    assert_eq!(
        final_record.get("has_write").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        final_record.get("has_protect").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        final_record.get("has_thread").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        final_record
            .get("write_source_buffer")
            .and_then(Value::as_u64),
        Some(source_buffer)
    );
    assert_eq!(
        final_record
            .get("write_target_address")
            .and_then(Value::as_u64),
        Some(region)
    );
    assert_eq!(
        final_record
            .get("thread_start_address")
            .and_then(Value::as_u64),
        Some(region)
    );
    assert_eq!(
        final_record
            .get("became_executable")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn executable_virtual_alloc_without_protect_change_emits_exit_dump() {
    let (config, trace_path, _) = trace_config("mem-exec-exit-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let region = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_EXECUTE_READWRITE])
        .unwrap();
    assert_ne!(region, 0);
    engine
        .write_test_bytes(region, b"\x90\x90\xCC\xC3EXIT-EXEC-DUMP")
        .unwrap();

    engine
        .log_exit_executable_allocation_dumps_for_test("test_exit")
        .unwrap();
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("MEM_EXEC_EXIT_DUMP"))
        .unwrap();
    assert_eq!(dump.get("address").and_then(Value::as_u64), Some(region));
    assert_eq!(
        dump.get("region_type_name").and_then(Value::as_str),
        Some("private")
    );
    assert_eq!(
        dump.get("reason").and_then(Value::as_str),
        Some("test_exit")
    );
    assert_eq!(
        dump.get("trigger").and_then(Value::as_str),
        Some("RUN_STOP")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert!(bytes.starts_with(b"\x90\x90\xCC\xC3EXIT-EXEC-DUMP"));
}

#[test]
fn modified_image_emits_exit_dump_when_hash_changes() {
    let (config, trace_path, _) = trace_config("image-modified-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();
    engine.capture_image_hash_baselines_for_test().unwrap();

    let main_module = engine.main_module().unwrap().clone();
    let capture_size = fs::metadata(main_module.path.as_ref().unwrap())
        .unwrap()
        .len();
    let patch_address = main_module.base + 0x1000;
    engine
        .write_test_bytes(patch_address, b"\xCC\xCC\xCC\xCC")
        .unwrap();

    engine
        .log_modified_image_dumps_for_test("test_exit")
        .unwrap();
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("IMAGE_MODIFIED_DUMP"))
        .unwrap();
    assert_eq!(
        dump.get("module_base").and_then(Value::as_u64),
        Some(main_module.base)
    );
    assert_eq!(
        dump.get("module_name").and_then(Value::as_str),
        Some(main_module.name.as_str())
    );
    assert_eq!(
        dump.get("captured_size").and_then(Value::as_u64),
        Some(capture_size)
    );
    assert_eq!(
        dump.get("trigger").and_then(Value::as_str),
        Some("RUN_STOP")
    );
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert_eq!(bytes.len() as u64, capture_size);
    assert_eq!(&bytes[0x1000..0x1004], b"\xCC\xCC\xCC\xCC");
}

#[test]
fn resume_thread_from_private_region_emits_thread_resume_dump() {
    let (config, trace_path, _) = trace_config("thread-resume-dump");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let virtual_alloc = engine.bind_hook_for_test("kernel32.dll", "VirtualAlloc");
    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let resume_thread = engine.bind_hook_for_test("kernel32.dll", "ResumeThread");
    let tid_ptr = engine.allocate_executable_test_page(0x633C_0000).unwrap();
    let region = engine
        .dispatch_bound_stub(virtual_alloc, &[0, 0x1000, 0x3000, PAGE_EXECUTE_READWRITE])
        .unwrap();
    assert_ne!(region, 0);
    engine
        .write_test_bytes(region, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90])
        .unwrap();

    let thread_handle = engine
        .dispatch_bound_stub(create_thread, &[0, 0, region, 0x5151, 0x4, tid_ptr])
        .unwrap();
    assert_ne!(thread_handle, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(resume_thread, &[thread_handle])
            .unwrap(),
        1
    );
    engine.flush_api_logs_for_test().unwrap();

    let records = load_records(&trace_path);
    let dump = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("THREAD_RESUME_DUMP"))
        .unwrap();
    assert_eq!(
        dump.get("start_address").and_then(Value::as_u64),
        Some(region)
    );
    assert_eq!(dump.get("parameter").and_then(Value::as_u64), Some(0x5151));
    let dump_path = PathBuf::from(dump.get("dump_path").and_then(Value::as_str).unwrap());
    let bytes = fs::read(dump_path).unwrap();
    assert!(bytes.starts_with(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]));
}

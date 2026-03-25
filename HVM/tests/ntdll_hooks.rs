use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use hvm::runtime::scheduler::{WAIT_IO_COMPLETION, WAIT_TIMEOUT};
use hvm::samples::first_runnable_sample;
use hvm::tests_support::build_loaded_engine;

const INVALID_HANDLE_VALUE: u64 = u32::MAX as u64;
const PAGE_READONLY: u64 = 0x02;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_GUARD: u64 = 0x100;
const PAGE_EXECUTE_READ: u64 = 0x20;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u64 = 0x0000_4000;
const FILE_MAP_READ: u64 = 0x0004;
const FILE_MAP_WRITE: u64 = 0x0002;
const MEM_FREE: u32 = 0x10000;
const MEM_MAPPED: u32 = 0x40000;
const STATUS_OBJECT_NAME_EXISTS: u64 = 0x4000_0000;
const STATUS_INVALID_INFO_CLASS: u64 = 0xC000_0003;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xC000_0004;
const X86_CONTEXT_EFLAGS_OFFSET: u64 = 0xC0;
const X86_CONTEXT_ESP_OFFSET: u64 = 0xC4;
const X86_CONTEXT_EIP_OFFSET: u64 = 0xB8;

fn runtime_sample() -> hvm::samples::SampleDescriptor {
    first_runnable_sample()
        .unwrap()
        .expect("expected at least one runnable x86 sample")
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

fn write_runtime_pointer(engine: &mut VirtualExecutionEngine, address: u64, value: u64) {
    if runtime_pointer_size(engine) == 8 {
        engine
            .write_test_bytes(address, &value.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(address, &(value as u32).to_le_bytes())
            .unwrap();
    }
}

fn write_runtime_unicode_string(
    engine: &mut VirtualExecutionEngine,
    unicode_string: u64,
    buffer: u64,
    text: &str,
) {
    let encoded = text.encode_utf16().collect::<Vec<_>>();
    let mut buffer_bytes = encoded
        .iter()
        .copied()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    buffer_bytes.extend_from_slice(&[0, 0]);
    engine.write_test_bytes(buffer, &buffer_bytes).unwrap();

    engine
        .write_test_bytes(unicode_string, &(encoded.len() as u16 * 2).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(
            unicode_string + 2,
            &((encoded.len() as u16 * 2).saturating_add(2)).to_le_bytes(),
        )
        .unwrap();
    if runtime_pointer_size(engine) == 8 {
        engine
            .write_test_bytes(unicode_string + 4, &[0u8; 4])
            .unwrap();
        engine
            .write_test_bytes(unicode_string + 8, &buffer.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(unicode_string + 4, &(buffer as u32).to_le_bytes())
            .unwrap();
    }
}

fn write_runtime_object_attributes(
    engine: &mut VirtualExecutionEngine,
    object_attributes: u64,
    unicode_string: u64,
) {
    if runtime_pointer_size(engine) == 8 {
        engine
            .write_test_bytes(object_attributes, &48u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 4, &[0u8; 4])
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 8, &0u64.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 16, &unicode_string.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 24, &0u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 28, &[0u8; 4])
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 32, &0u64.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 40, &0u64.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(object_attributes, &24u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 4, &0u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(
                object_attributes + 8,
                &(unicode_string as u32).to_le_bytes(),
            )
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 12, &0u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 16, &0u32.to_le_bytes())
            .unwrap();
        engine
            .write_test_bytes(object_attributes + 20, &0u32.to_le_bytes())
            .unwrap();
    }
}

fn parent_process_config() -> hvm::config::EngineConfig {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let main_sample = runtime_sample();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_path = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-parent-hooks-{timestamp}.json"
    ));
    let main_module = main_sample.path;
    let parent_image = repo_root.join("Sample").join("parent_host.exe");

    fs::write(
        &config_path,
        format!(
            concat!(
                "{{",
                "\"main_module\":\"{}\",",
                "\"parent_process_image\":\"{}\",",
                "\"parent_process_pid\":17185,",
                "\"parent_process_command_line\":\"\\\"{}\\\" -Embedding\"",
                "}}"
            ),
            main_module.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
            parent_image.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    fs::remove_file(config_path).unwrap();
    config
}

fn loaded_runtime_engine() -> VirtualExecutionEngine {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();
    engine
}

fn parse_system_process_entries(
    engine: &VirtualExecutionEngine,
    address: u64,
    total_size: usize,
) -> Vec<(u32, u32, String, Vec<u32>)> {
    let base_size = 0xB8u64;
    let image_name_offset = 0x38u64;
    let pid_offset = 0x44u64;
    let ppid_offset = 0x48u64;
    let thread_size = 0x40u64;
    let thread_client_id_offset = 0x20u64;
    let mut cursor = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let mut entries = Vec::new();

    while cursor < total_size && seen.insert(cursor) {
        let base = address + cursor as u64;
        let next_offset = u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ) as usize;
        let thread_count = u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base + 4, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ) as usize;
        let process_id = u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base + pid_offset, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let parent_id = u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base + ppid_offset, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let name_length = u16::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base + image_name_offset, 2)
                .unwrap()
                .try_into()
                .unwrap(),
        ) as usize;
        let name_buffer = u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(base + image_name_offset + 4, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        ) as u64;
        let image_name = if name_buffer == 0 || name_length == 0 {
            String::new()
        } else {
            let bytes = engine
                .modules()
                .memory()
                .read(name_buffer, name_length)
                .unwrap();
            let words = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&words)
        };
        let mut thread_ids = Vec::new();
        let thread_base = base + base_size;
        for index in 0..thread_count {
            let entry_base = thread_base + index as u64 * thread_size;
            thread_ids.push(u32::from_le_bytes(
                engine
                    .modules()
                    .memory()
                    .read(entry_base + thread_client_id_offset + 4, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ));
        }
        entries.push((process_id, parent_id, image_name, thread_ids));
        if next_offset == 0 {
            break;
        }
        cursor += next_offset;
    }

    entries
}

#[test]
fn nt_queue_apc_thread_wakes_alertable_wait() {
    let mut engine = build_loaded_engine();
    let main_thread_handle = engine.main_thread_handle();
    let event = engine
        .kernel32()
        .create_event_for_test(false, false)
        .unwrap();

    assert_eq!(
        engine
            .kernel32()
            .wait_for_single_object_ex_for_main_thread(event, 100, true),
        WAIT_TIMEOUT
    );
    assert_eq!(
        engine
            .ntdll()
            .queue_apc_thread_for_test(main_thread_handle, 0x401000, 0x6161),
        0
    );

    engine.poll_scheduler(100);

    assert_eq!(
        engine
            .kernel32()
            .wait_for_single_object_ex_for_main_thread(event, 100, true),
        WAIT_IO_COMPLETION
    );
}

#[test]
fn nt_queue_apc_thread_dispatches_through_runtime_stub() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let main_tid = engine.main_thread_tid().unwrap();
    let main_thread_handle = engine.main_thread_handle().unwrap();
    let event = engine
        .scheduler_mut()
        .create_event(false, false)
        .unwrap()
        .handle;
    let _ = engine
        .scheduler_mut()
        .begin_alertable_wait(main_tid, event, 100);

    let stub = engine.bind_hook_for_test("ntdll.dll", "NtQueueApcThread");
    let status = engine
        .call_native_for_test(stub, &[main_thread_handle as u64, 0x401000, 0x6161, 0, 0])
        .unwrap();

    engine.scheduler_mut().poll_blocked_threads(100);

    assert_eq!(status, 0);
    assert_eq!(
        engine.scheduler_mut().resume_wait_result(main_tid),
        Some(WAIT_IO_COMPLETION)
    );
}

#[test]
fn nt_continue_restores_context_and_skips_hook_return_path() {
    let mut engine = loaded_runtime_engine();
    let nt_continue = engine.bind_hook_for_test("ntdll.dll", "NtContinue");
    let code = engine.allocate_executable_test_page(0x6320_0000).unwrap();
    let target = engine.allocate_executable_test_page(0x6321_0000).unwrap();
    let context = engine.allocate_executable_test_page(0x6322_0000).unwrap();
    let main_tid = engine.main_thread_tid().unwrap();
    let outer_esp = engine
        .scheduler()
        .thread_snapshot(main_tid)
        .unwrap()
        .stack_top
        .saturating_sub(4);

    let hook_return = code + 21;
    let mut code_bytes = Vec::new();
    code_bytes.extend_from_slice(&[0x68, 0x00, 0x00, 0x00, 0x00]);
    code_bytes.push(0x68);
    code_bytes.extend_from_slice(&(context as u32).to_le_bytes());
    code_bytes.push(0x68);
    code_bytes.extend_from_slice(&(hook_return as u32).to_le_bytes());
    code_bytes.push(0x68);
    code_bytes.extend_from_slice(&(nt_continue as u32).to_le_bytes());
    code_bytes.push(0xC3);
    code_bytes.push(0xB8);
    code_bytes.extend_from_slice(&0x1111u32.to_le_bytes());
    code_bytes.push(0xC3);
    engine.write_test_bytes(code, &code_bytes).unwrap();

    let mut target_bytes = Vec::new();
    target_bytes.push(0xB8);
    target_bytes.extend_from_slice(&0x4242u32.to_le_bytes());
    target_bytes.push(0xC3);
    engine.write_test_bytes(target, &target_bytes).unwrap();

    engine.write_test_bytes(context, &[0u8; 0x200]).unwrap();
    engine
        .write_test_bytes(
            context + X86_CONTEXT_EIP_OFFSET,
            &(target as u32).to_le_bytes(),
        )
        .unwrap();
    engine
        .write_test_bytes(
            context + X86_CONTEXT_ESP_OFFSET,
            &(outer_esp as u32).to_le_bytes(),
        )
        .unwrap();
    engine
        .write_test_bytes(context + X86_CONTEXT_EFLAGS_OFFSET, &0x202u32.to_le_bytes())
        .unwrap();

    assert_eq!(engine.call_native_for_test(code, &[]).unwrap(), 0x4242);
}

#[test]
fn interpreter_progress_advances_emulated_tick_count() {
    let mut engine = loaded_runtime_engine();
    let tick_count = engine.bind_hook_for_test("kernel32.dll", "GetTickCount");
    let code = engine.allocate_executable_test_page(0x6323_0000).unwrap();
    let before = engine.dispatch_bound_stub(tick_count, &[]).unwrap();

    let mut code_bytes = vec![0x90; 2_048];
    code_bytes.push(0xC3);
    engine.write_test_bytes(code, &code_bytes).unwrap();

    assert_eq!(engine.call_native_for_test(code, &[]).unwrap(), 0);
    let after = engine.dispatch_bound_stub(tick_count, &[]).unwrap();
    assert!(
        after > before,
        "expected emulated tick count to advance, before={before}, after={after}"
    );
}

#[test]
fn nt_map_view_of_section_maps_current_process_and_preserves_section_content() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let nt_map = engine.bind_hook_for_test("ntdll.dll", "NtMapViewOfSection");
    let nt_unmap = engine.bind_hook_for_test("ntdll.dll", "NtUnmapViewOfSection");
    let base_ptr = engine.allocate_executable_test_page(0x6314_0000).unwrap();
    let view_size_ptr = engine.allocate_executable_test_page(0x6315_0000).unwrap();

    let section = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x2000, 0],
        )
        .unwrap();
    assert_ne!(section, 0);

    let pointer_size = runtime_pointer_size(&engine);
    engine
        .write_test_bytes(base_ptr, &vec![0; pointer_size])
        .unwrap();
    if pointer_size == 8 {
        engine
            .write_test_bytes(view_size_ptr, &0x1000u64.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(view_size_ptr, &0x1000u32.to_le_bytes())
            .unwrap();
    }

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_map,
                &[
                    section,
                    u32::MAX as u64,
                    base_ptr,
                    0,
                    0,
                    0,
                    view_size_ptr,
                    0,
                    0,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let first_base = read_runtime_pointer(&engine, base_ptr);
    assert_ne!(first_base, 0);
    assert_eq!(read_runtime_pointer(&engine, view_size_ptr), 0x1000);
    engine.write_test_bytes(first_base, b"SECT").unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_unmap, &[u32::MAX as u64, first_base])
            .unwrap(),
        0
    );

    engine
        .write_test_bytes(base_ptr, &vec![0; pointer_size])
        .unwrap();
    if pointer_size == 8 {
        engine
            .write_test_bytes(view_size_ptr, &0x1000u64.to_le_bytes())
            .unwrap();
    } else {
        engine
            .write_test_bytes(view_size_ptr, &0x1000u32.to_le_bytes())
            .unwrap();
    }

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_map,
                &[
                    section,
                    u32::MAX as u64,
                    base_ptr,
                    0,
                    0,
                    0,
                    view_size_ptr,
                    0,
                    0,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let second_base = read_runtime_pointer(&engine, base_ptr);
    assert_eq!(
        engine.modules().memory().read(second_base, 4).unwrap(),
        b"SECT"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(nt_unmap, &[u32::MAX as u64, second_base])
            .unwrap(),
        0
    );
}

#[test]
fn nt_map_view_of_section_supports_remote_process_address_space() {
    let config = parent_process_config();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let flush_view = engine.bind_hook_for_test("kernel32.dll", "FlushViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let read_process_memory = engine.bind_hook_for_test("kernel32.dll", "ReadProcessMemory");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let nt_map = engine.bind_hook_for_test("ntdll.dll", "NtMapViewOfSection");
    let nt_unmap = engine.bind_hook_for_test("ntdll.dll", "NtUnmapViewOfSection");
    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryVirtualMemory");

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);

    let section = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    assert_ne!(section, 0);

    let current_view = engine
        .dispatch_bound_stub(
            map_view,
            &[section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x1000],
        )
        .unwrap();
    assert_ne!(current_view, 0);
    engine.write_test_bytes(current_view, b"RMAP").unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(flush_view, &[current_view, 4])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(unmap_view, &[current_view])
            .unwrap(),
        1
    );

    let base_ptr = engine.allocate_executable_test_page(0x632E_0000).unwrap();
    let view_size_ptr = engine.allocate_executable_test_page(0x632F_0000).unwrap();
    let read_back = engine.allocate_executable_test_page(0x6330_0000).unwrap();
    let read_count = engine.allocate_executable_test_page(0x6331_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x6332_0000).unwrap();
    write_runtime_pointer(&mut engine, base_ptr, 0);
    write_runtime_pointer(&mut engine, view_size_ptr, 0x1000);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_map,
                &[
                    section,
                    process,
                    base_ptr,
                    0,
                    0,
                    0,
                    view_size_ptr,
                    0,
                    0,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let remote_base = read_runtime_pointer(&engine, base_ptr);
    assert_ne!(remote_base, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                read_process_memory,
                &[process, remote_base, read_back, 4, read_count]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_runtime_pointer(&engine, read_count), 4);
    assert_eq!(
        engine.modules().memory().read(read_back, 4).unwrap(),
        b"RMAP"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_query, &[process, remote_base, 0, info, 28, read_count])
            .unwrap(),
        0
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

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_unmap, &[process, remote_base])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(nt_query, &[process, remote_base, 0, info, 28, read_count])
            .unwrap(),
        0
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
    assert_eq!(engine.dispatch_bound_stub(close, &[section]).unwrap(), 1);
}

#[test]
fn rtl_fill_memory_and_zero_memory_write_requested_pattern() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let buffer = engine.allocate_executable_test_page(0x6332_0000).unwrap();
    engine.write_test_bytes(buffer, &[0u8; 16]).unwrap();

    let rtl_fill = engine.bind_hook_for_test("ntdll.dll", "RtlFillMemory");
    let rtl_zero = engine.bind_hook_for_test("ntdll.dll", "RtlZeroMemory");

    assert_eq!(
        engine
            .dispatch_bound_stub(rtl_fill, &[buffer, 16, 0x41])
            .unwrap(),
        0
    );
    assert_eq!(
        engine.modules().memory().read(buffer, 16).unwrap(),
        vec![0x41; 16]
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(rtl_zero, &[buffer + 4, 8])
            .unwrap(),
        0
    );
    assert_eq!(
        engine.modules().memory().read(buffer, 16).unwrap(),
        [
            0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x41,
            0x41, 0x41
        ]
    );
}

#[test]
fn nt_create_section_parses_object_attributes_and_reuses_named_mapping_namespace() {
    let mut engine = loaded_runtime_engine();

    let nt_create = engine.bind_hook_for_test("ntdll.dll", "NtCreateSection");
    let nt_map = engine.bind_hook_for_test("ntdll.dll", "NtMapViewOfSection");
    let nt_unmap = engine.bind_hook_for_test("ntdll.dll", "NtUnmapViewOfSection");
    let open_mapping = engine.bind_hook_for_test("kernel32.dll", "OpenFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let long_name_buffer = engine.allocate_executable_test_page(0x6316_0000).unwrap();
    let short_name_buffer = engine.allocate_executable_test_page(0x6317_0000).unwrap();
    let unicode_string = engine.allocate_executable_test_page(0x6318_0000).unwrap();
    let object_attributes = engine.allocate_executable_test_page(0x6319_0000).unwrap();
    let maximum_size = engine.allocate_executable_test_page(0x631A_0000).unwrap();
    let section_handle_ptr = engine.allocate_executable_test_page(0x631B_0000).unwrap();
    let alias_handle_ptr = engine.allocate_executable_test_page(0x631C_0000).unwrap();
    let base_ptr = engine.allocate_executable_test_page(0x631D_0000).unwrap();
    let view_size_ptr = engine.allocate_executable_test_page(0x631E_0000).unwrap();

    write_runtime_unicode_string(
        &mut engine,
        unicode_string,
        long_name_buffer,
        "\\BaseNamedObjects\\Local\\VmNtSection",
    );
    write_runtime_object_attributes(&mut engine, object_attributes, unicode_string);
    engine
        .write_test_bytes(
            short_name_buffer,
            &"Local\\VmNtSection\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    engine
        .write_test_bytes(maximum_size, &0x1000u64.to_le_bytes())
        .unwrap();
    write_runtime_pointer(&mut engine, section_handle_ptr, 0);
    write_runtime_pointer(&mut engine, alias_handle_ptr, 0);
    write_runtime_pointer(&mut engine, base_ptr, 0);
    write_runtime_pointer(&mut engine, view_size_ptr, 0x1000);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_create,
                &[
                    section_handle_ptr,
                    0,
                    object_attributes,
                    maximum_size,
                    PAGE_READWRITE,
                    0,
                    INVALID_HANDLE_VALUE
                ]
            )
            .unwrap(),
        0
    );
    let section = read_runtime_pointer(&engine, section_handle_ptr);
    assert_ne!(section, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_create,
                &[
                    alias_handle_ptr,
                    0,
                    object_attributes,
                    maximum_size,
                    PAGE_READWRITE,
                    0,
                    INVALID_HANDLE_VALUE
                ]
            )
            .unwrap(),
        STATUS_OBJECT_NAME_EXISTS
    );
    let alias = read_runtime_pointer(&engine, alias_handle_ptr);
    assert_ne!(alias, 0);
    assert_ne!(alias, section);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_map,
                &[
                    section,
                    u32::MAX as u64,
                    base_ptr,
                    0,
                    0,
                    0,
                    view_size_ptr,
                    0,
                    0,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let view = read_runtime_pointer(&engine, base_ptr);
    engine.write_test_bytes(view, b"NTSH").unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(nt_unmap, &[u32::MAX as u64, view])
            .unwrap(),
        0
    );

    let opened = engine
        .dispatch_bound_stub(open_mapping, &[FILE_MAP_READ, 0, short_name_buffer])
        .unwrap();
    assert_ne!(opened, 0);

    let reopened_view = engine
        .dispatch_bound_stub(map_view, &[opened, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();
    assert_eq!(
        engine.modules().memory().read(reopened_view, 4).unwrap(),
        b"NTSH"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(unmap_view, &[reopened_view])
            .unwrap(),
        1
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[opened]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[alias]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[section]).unwrap(), 1);
}

#[test]
fn nt_query_virtual_memory_reports_mapped_and_free_regions() {
    let mut engine = loaded_runtime_engine();

    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryVirtualMemory");
    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let map_view = engine.bind_hook_for_test("kernel32.dll", "MapViewOfFile");
    let unmap_view = engine.bind_hook_for_test("kernel32.dll", "UnmapViewOfFile");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");

    let info = engine.allocate_executable_test_page(0x631F_0000).unwrap();
    let return_len = engine.allocate_executable_test_page(0x6320_0000).unwrap();
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
    let type_offset = if runtime_pointer_size(&engine) == 8 {
        40u64
    } else {
        24u64
    };

    let mapping = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0],
        )
        .unwrap();
    let view = engine
        .dispatch_bound_stub(map_view, &[mapping, FILE_MAP_READ, 0, 0, 0x1000])
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query,
                &[
                    u32::MAX as u64,
                    view,
                    0,
                    info,
                    struct_size as u64,
                    return_len
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_runtime_pointer(&engine, return_len),
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
        0x1000
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

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query,
                &[
                    u32::MAX as u64,
                    0x1234,
                    0,
                    info,
                    struct_size as u64,
                    return_len
                ]
            )
            .unwrap(),
        0
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
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query,
                &[
                    u32::MAX as u64,
                    view,
                    1,
                    info,
                    struct_size as u64,
                    return_len
                ]
            )
            .unwrap(),
        STATUS_INVALID_INFO_CLASS
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query,
                &[
                    u32::MAX as u64,
                    view,
                    0,
                    info,
                    (struct_size - 1) as u64,
                    return_len
                ]
            )
            .unwrap(),
        STATUS_INFO_LENGTH_MISMATCH
    );

    assert_eq!(engine.dispatch_bound_stub(unmap_view, &[view]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[mapping]).unwrap(), 1);
}

#[test]
fn nt_read_and_write_virtual_memory_follow_remote_access_rules() {
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let nt_read = engine.bind_hook_for_test("ntdll.dll", "NtReadVirtualMemory");
    let nt_write = engine.bind_hook_for_test("ntdll.dll", "NtWriteVirtualMemory");
    let nt_protect = engine.bind_hook_for_test("ntdll.dll", "NtProtectVirtualMemory");

    let input = engine.allocate_executable_test_page(0x6321_0000).unwrap();
    let output = engine.allocate_executable_test_page(0x6322_0000).unwrap();
    let count = engine.allocate_executable_test_page(0x6323_0000).unwrap();
    let protect_base_ptr = engine.allocate_executable_test_page(0x6324_0000).unwrap();
    let protect_size_ptr = engine.allocate_executable_test_page(0x6325_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x6326_0000).unwrap();
    engine.write_test_bytes(input, b"NTVM!").unwrap();
    engine.write_test_bytes(output, &[0u8; 5]).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
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
            .dispatch_bound_stub(nt_write, &[process, remote, input, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 5);

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_read, &[process, remote, output, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 5);
    assert_eq!(engine.modules().memory().read(output, 5).unwrap(), b"NTVM!");

    write_runtime_pointer(&mut engine, protect_base_ptr, remote);
    write_runtime_pointer(&mut engine, protect_size_ptr, 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_protect,
                &[
                    process,
                    protect_base_ptr,
                    protect_size_ptr,
                    PAGE_READONLY,
                    old_protect
                ]
            )
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_write, &[process, remote, input, 5, count])
            .unwrap(),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);

    let reserved = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, MEM_RESERVE as u64, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(reserved, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(nt_read, &[process, reserved, output, 5, count])
            .unwrap(),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(read_runtime_pointer(&engine, count), 0);

    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn nt_read_virtual_memory_consumes_guard_pages_once() {
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let nt_read = engine.bind_hook_for_test("ntdll.dll", "NtReadVirtualMemory");
    let nt_protect = engine.bind_hook_for_test("ntdll.dll", "NtProtectVirtualMemory");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");

    let input = engine.allocate_executable_test_page(0x6327_0000).unwrap();
    let output = engine.allocate_executable_test_page(0x6328_0000).unwrap();
    let count = engine.allocate_executable_test_page(0x6329_0000).unwrap();
    let protect_base_ptr = engine.allocate_executable_test_page(0x632A_0000).unwrap();
    let protect_size_ptr = engine.allocate_executable_test_page(0x632B_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x632C_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x632D_0000).unwrap();
    engine.write_test_bytes(input, b"GUARD").unwrap();
    engine.write_test_bytes(output, &[0u8; 5]).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x1000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(write_process_memory, &[process, remote, input, 5, count])
            .unwrap(),
        1
    );

    write_runtime_pointer(&mut engine, protect_base_ptr, remote);
    write_runtime_pointer(&mut engine, protect_size_ptr, 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_protect,
                &[
                    process,
                    protect_base_ptr,
                    protect_size_ptr,
                    PAGE_READONLY | PAGE_GUARD,
                    old_protect
                ]
            )
            .unwrap(),
        0
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
            .dispatch_bound_stub(nt_read, &[process, remote, output, 5, count])
            .unwrap(),
        STATUS_INVALID_PARAMETER
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
            .dispatch_bound_stub(nt_read, &[process, remote, output, 5, count])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, count), 5);
    assert_eq!(engine.modules().memory().read(output, 5).unwrap(), b"GUARD");
    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn nt_allocate_and_free_virtual_memory_track_reserved_state() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let nt_allocate = engine.bind_hook_for_test("ntdll.dll", "NtAllocateVirtualMemory");
    let nt_free = engine.bind_hook_for_test("ntdll.dll", "NtFreeVirtualMemory");
    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryVirtualMemory");
    let base_ptr = engine.allocate_executable_test_page(0x6333_0000).unwrap();
    let size_ptr = engine.allocate_executable_test_page(0x6334_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x6335_0000).unwrap();
    let return_len = engine.allocate_executable_test_page(0x6336_0000).unwrap();
    let struct_size = if runtime_pointer_size(&engine) == 8 {
        48
    } else {
        28
    };

    write_runtime_pointer(&mut engine, base_ptr, 0);
    write_runtime_pointer(&mut engine, size_ptr, 0x2000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_allocate,
                &[
                    u32::MAX as u64,
                    base_ptr,
                    0,
                    size_ptr,
                    MEM_RESERVE as u64,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let reserved = read_runtime_pointer(&engine, base_ptr);
    assert_ne!(reserved, 0);
    assert_eq!(read_runtime_pointer(&engine, size_ptr), 0x2000);

    assert_eq!(
        engine
            .call_native_for_test(
                nt_query,
                &[
                    u32::MAX as u64,
                    reserved + 0x100,
                    0,
                    info,
                    struct_size as u64,
                    return_len,
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, info), reserved);
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        reserved
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        16
                    } else {
                        8
                    },
                    4,
                )
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
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        32
                    } else {
                        16
                    },
                    4,
                )
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_RESERVE
    );

    write_runtime_pointer(&mut engine, base_ptr, reserved + 0x1000);
    write_runtime_pointer(&mut engine, size_ptr, 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_allocate,
                &[
                    u32::MAX as u64,
                    base_ptr,
                    0,
                    size_ptr,
                    MEM_COMMIT as u64,
                    PAGE_READONLY
                ]
            )
            .unwrap(),
        0
    );
    let committed = read_runtime_pointer(&engine, base_ptr);
    assert_eq!(committed, reserved + 0x1000);

    assert_eq!(
        engine
            .call_native_for_test(
                nt_query,
                &[
                    u32::MAX as u64,
                    committed + 0x100,
                    0,
                    info,
                    struct_size as u64,
                    return_len,
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, info), committed);
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        reserved
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        16
                    } else {
                        8
                    },
                    4,
                )
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
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        36
                    } else {
                        20
                    },
                    4,
                )
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        PAGE_READONLY
    );

    write_runtime_pointer(&mut engine, base_ptr, committed);
    write_runtime_pointer(&mut engine, size_ptr, 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_free,
                &[u32::MAX as u64, base_ptr, size_ptr, MEM_DECOMMIT]
            )
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, base_ptr), committed);
    assert_eq!(read_runtime_pointer(&engine, size_ptr), 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_query,
                &[
                    u32::MAX as u64,
                    committed + 0x100,
                    0,
                    info,
                    struct_size as u64,
                    return_len,
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        32
                    } else {
                        16
                    },
                    4,
                )
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_RESERVE
    );

    write_runtime_pointer(&mut engine, base_ptr, reserved);
    write_runtime_pointer(&mut engine, size_ptr, 0);
    assert_eq!(
        engine
            .call_native_for_test(nt_free, &[u32::MAX as u64, base_ptr, size_ptr, 0x8000])
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, base_ptr), 0);
    assert_eq!(read_runtime_pointer(&engine, size_ptr), 0);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_query,
                &[
                    u32::MAX as u64,
                    reserved + 0x100,
                    0,
                    info,
                    struct_size as u64,
                    return_len,
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(
                    info + if runtime_pointer_size(&engine) == 8 {
                        32
                    } else {
                        16
                    },
                    4,
                )
                .unwrap()
                .try_into()
                .unwrap()
        ),
        MEM_FREE
    );
}

#[test]
fn nt_query_information_process_returns_basic_information_and_image_name() {
    let sample = runtime_sample();
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("ntdll.dll", "NtQueryInformationProcess");
    let basic = engine.allocate_executable_test_page(0x6320_0000).unwrap();
    let basic_len = engine.allocate_executable_test_page(0x6321_0000).unwrap();
    let image = engine.allocate_executable_test_page(0x6322_0000).unwrap();
    let image_len = engine.allocate_executable_test_page(0x6323_0000).unwrap();

    let basic_status = engine
        .call_native_for_test(stub, &[u32::MAX as u64, 0, basic, 24, basic_len])
        .unwrap();
    let image_status = engine
        .call_native_for_test(stub, &[u32::MAX as u64, 27, image, 0x400, image_len])
        .unwrap();

    assert_eq!(basic_status, 0);
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(basic_len, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        24
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(basic + 4, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ) as u64,
        engine.process_env().current_peb()
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(basic + 16, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        0x1337
    );

    assert_eq!(image_status, 0);
    let image_buffer = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(image + 4, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    ) as u64;
    assert_eq!(image_buffer, image + 8);
    assert!(
        PathBuf::from(read_wide_c_string(&engine, image_buffer, 260))
            .ends_with(std::path::Path::new("Sample").join(&sample.name))
    );
}

#[test]
fn nt_query_information_process_exposes_configured_parent_process_identity() {
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryInformationProcess");
    let nt_open = engine.bind_hook_for_test("ntdll.dll", "NtOpenProcess");
    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let query_full_name = engine.bind_hook_for_test("kernel32.dll", "QueryFullProcessImageNameW");
    let basic = engine.allocate_executable_test_page(0x6324_0000).unwrap();
    let basic_len = engine.allocate_executable_test_page(0x6325_0000).unwrap();
    let client_id = engine.allocate_executable_test_page(0x6326_0000).unwrap();
    let handle_ptr = engine.allocate_executable_test_page(0x6327_0000).unwrap();
    let image = engine.allocate_executable_test_page(0x6328_0000).unwrap();
    let image_len = engine.allocate_executable_test_page(0x6329_0000).unwrap();
    let size_ptr = engine.allocate_executable_test_page(0x632A_0000).unwrap();
    let query_buffer = engine.allocate_executable_test_page(0x632B_0000).unwrap();

    assert_eq!(
        engine
            .call_native_for_test(nt_query, &[u32::MAX as u64, 0, basic, 24, basic_len])
            .unwrap(),
        0
    );
    assert_eq!(
        u32::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(basic + 20, 4)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        17185
    );

    engine
        .write_test_bytes(client_id, &17185u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(client_id + 4, &0u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .call_native_for_test(nt_open, &[handle_ptr, 0, 0, client_id])
            .unwrap(),
        0
    );
    let parent_handle = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(handle_ptr, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    ) as u64;
    assert!(parent_handle != 0);

    assert_eq!(
        engine
            .call_native_for_test(nt_query, &[parent_handle, 27, image, 0x400, image_len])
            .unwrap(),
        0
    );
    let image_buffer = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(image + 4, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    ) as u64;
    assert!(
        PathBuf::from(read_wide_c_string(&engine, image_buffer, 260))
            .ends_with(std::path::Path::new("Sample").join("parent_host.exe"))
    );

    let opened_parent_handle = engine
        .dispatch_bound_stub(open_process, &[0, 0, 17185])
        .unwrap();
    assert!(opened_parent_handle != 0);
    assert_ne!(opened_parent_handle, parent_handle);

    engine
        .write_test_bytes(size_ptr, &260u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_full_name,
                &[opened_parent_handle, 0, query_buffer, size_ptr]
            )
            .unwrap(),
        1
    );
    assert!(
        PathBuf::from(read_wide_c_string(&engine, query_buffer, 260))
            .ends_with(std::path::Path::new("Sample").join("parent_host.exe"))
    );
}

#[test]
fn nt_protect_virtual_memory_updates_remote_page_permissions_and_aligned_range() {
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let virtual_alloc_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualAllocEx");
    let virtual_query_ex = engine.bind_hook_for_test("kernel32.dll", "VirtualQueryEx");
    let nt_protect = engine.bind_hook_for_test("ntdll.dll", "NtProtectVirtualMemory");

    let base_ptr = engine.allocate_executable_test_page(0x632E_0000).unwrap();
    let size_ptr = engine.allocate_executable_test_page(0x632F_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x6330_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x6331_0000).unwrap();

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);
    let remote = engine
        .dispatch_bound_stub(
            virtual_alloc_ex,
            &[process, 0, 0x2000, 0x3000, PAGE_READWRITE],
        )
        .unwrap();
    assert_ne!(remote, 0);

    write_runtime_pointer(&mut engine, base_ptr, remote + 0x123);
    write_runtime_pointer(&mut engine, size_ptr, 0x20);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_protect,
                &[process, base_ptr, size_ptr, PAGE_EXECUTE_READ, old_protect]
            )
            .unwrap(),
        0
    );
    assert_eq!(read_runtime_pointer(&engine, base_ptr), remote);
    assert_eq!(read_runtime_pointer(&engine, size_ptr), 0x1000);
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
            .dispatch_bound_stub(virtual_query_ex, &[process, remote + 0x200, info, 28])
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
}

#[test]
fn nt_query_virtual_memory_preserves_remote_mapped_allocation_metadata_after_protect_split() {
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let open_process = engine.bind_hook_for_test("kernel32.dll", "OpenProcess");
    let create_mapping = engine.bind_hook_for_test("kernel32.dll", "CreateFileMappingW");
    let close = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let nt_map = engine.bind_hook_for_test("ntdll.dll", "NtMapViewOfSection");
    let nt_unmap = engine.bind_hook_for_test("ntdll.dll", "NtUnmapViewOfSection");
    let nt_query = engine.bind_hook_for_test("ntdll.dll", "NtQueryVirtualMemory");
    let nt_protect = engine.bind_hook_for_test("ntdll.dll", "NtProtectVirtualMemory");

    let base_ptr = engine.allocate_executable_test_page(0x6332_0000).unwrap();
    let view_size_ptr = engine.allocate_executable_test_page(0x6333_0000).unwrap();
    let protect_base_ptr = engine.allocate_executable_test_page(0x6334_0000).unwrap();
    let protect_size_ptr = engine.allocate_executable_test_page(0x6335_0000).unwrap();
    let old_protect = engine.allocate_executable_test_page(0x6336_0000).unwrap();
    let info = engine.allocate_executable_test_page(0x6337_0000).unwrap();
    let return_len = engine.allocate_executable_test_page(0x6338_0000).unwrap();
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

    let process = engine
        .dispatch_bound_stub(open_process, &[0x1F0FFF, 0, 17185])
        .unwrap();
    assert_ne!(process, 0);
    let section = engine
        .dispatch_bound_stub(
            create_mapping,
            &[INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x2000, 0],
        )
        .unwrap();
    assert_ne!(section, 0);

    write_runtime_pointer(&mut engine, base_ptr, 0);
    write_runtime_pointer(&mut engine, view_size_ptr, 0x2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_map,
                &[
                    section,
                    process,
                    base_ptr,
                    0,
                    0,
                    0,
                    view_size_ptr,
                    0,
                    0,
                    PAGE_READWRITE
                ]
            )
            .unwrap(),
        0
    );
    let remote_base = read_runtime_pointer(&engine, base_ptr);
    assert_ne!(remote_base, 0);

    write_runtime_pointer(&mut engine, protect_base_ptr, remote_base + 0x1000);
    write_runtime_pointer(&mut engine, protect_size_ptr, 0x1000);
    assert_eq!(
        engine
            .call_native_for_test(
                nt_protect,
                &[
                    process,
                    protect_base_ptr,
                    protect_size_ptr,
                    PAGE_READONLY,
                    old_protect
                ]
            )
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query,
                &[
                    process,
                    remote_base + 0x1100,
                    0,
                    info,
                    struct_size as u64,
                    return_len
                ]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_runtime_pointer(&engine, info + runtime_pointer_size(&engine) as u64),
        remote_base
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

    assert_eq!(
        engine
            .dispatch_bound_stub(nt_unmap, &[process, remote_base])
            .unwrap(),
        0
    );
    assert_eq!(engine.dispatch_bound_stub(close, &[section]).unwrap(), 1);
    assert_eq!(engine.dispatch_bound_stub(close, &[process]).unwrap(), 1);
}

#[test]
fn nt_query_system_information_lists_current_and_parent_processes() {
    let sample = runtime_sample();
    let mut engine = VirtualExecutionEngine::new(parent_process_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("ntdll.dll", "NtQuerySystemInformation");
    let buffer = engine.allocate_executable_test_page(0x632C_0000).unwrap();
    let return_len = engine.allocate_executable_test_page(0x632D_0000).unwrap();

    assert_eq!(
        engine
            .call_native_for_test(stub, &[5, buffer, 0x4000, return_len])
            .unwrap(),
        0
    );
    let total = u32::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(return_len, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    ) as usize;
    let entries = parse_system_process_entries(&engine, buffer, total);
    let main_tid = engine.main_thread_tid().unwrap();

    assert!(entries.iter().any(|(pid, ppid, image_name, thread_ids)| {
        *pid == 0x1337
            && *ppid == 17185
            && image_name.eq_ignore_ascii_case(&sample.name)
            && thread_ids.contains(&main_tid)
    }));
    assert!(entries.iter().any(|(pid, ppid, image_name, thread_ids)| {
        *pid == 17185
            && *ppid == 0
            && image_name.eq_ignore_ascii_case("parent_host.exe")
            && thread_ids.is_empty()
    }));
}

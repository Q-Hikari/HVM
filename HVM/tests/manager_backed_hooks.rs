use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use serde_json::Value;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn trace_config(test_name: &str) -> (hvm::config::EngineConfig, PathBuf) {
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
    config.api_log_path = Some(root.join("trace.api.log"));
    config.api_jsonl_path = Some(trace_path.clone());
    config.console_output_path = Some(root.join("trace.console.log"));
    (config, trace_path)
}

fn load_api_calls(path: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record.get("marker").and_then(Value::as_str) == Some("API_CALL"))
        .collect()
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

#[test]
fn wininet_runtime_hooks_allocate_handles_and_stream_request_bytes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let data_page = engine.allocate_executable_test_page(0x7100_0000).unwrap();
    engine
        .write_test_bytes(data_page, b"agent\0example.com\0GET\0/index\0")
        .unwrap();
    let buffer_page = engine.allocate_executable_test_page(0x7101_0000).unwrap();
    engine.write_test_bytes(buffer_page, &[0; 0x100]).unwrap();

    let open = engine.bind_hook_for_test("wininet.dll", "InternetOpenA");
    let connect = engine.bind_hook_for_test("wininet.dll", "InternetConnectA");
    let request_open = engine.bind_hook_for_test("wininet.dll", "HttpOpenRequestA");
    let query_available = engine.bind_hook_for_test("wininet.dll", "InternetQueryDataAvailable");
    let read_file = engine.bind_hook_for_test("wininet.dll", "InternetReadFile");

    let session = engine
        .dispatch_bound_stub(open, &[data_page, 0, 0, 0, 0])
        .unwrap() as u32;
    let server_ptr = data_page + 6;
    let verb_ptr = server_ptr + 12;
    let path_ptr = verb_ptr + 4;
    let connection = engine
        .dispatch_bound_stub(connect, &[session as u64, server_ptr, 443, 0, 0, 3, 0, 0])
        .unwrap() as u32;
    let request = engine
        .dispatch_bound_stub(
            request_open,
            &[connection as u64, verb_ptr, path_ptr, 0, 0, 0, 0, 0],
        )
        .unwrap() as u32;

    engine
        .network_manager_mut()
        .with_request_mut(request, |record| {
            record.response_body = b"abcdef".to_vec();
        })
        .unwrap();

    let available_ptr = buffer_page;
    let read_ptr = buffer_page + 4;
    let body_ptr = buffer_page + 8;
    assert_eq!(
        engine
            .dispatch_bound_stub(query_available, &[request as u64, available_ptr, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        u32::from_le_bytes(
            engine.modules().memory().read(available_ptr, 4).unwrap()[..4]
                .try_into()
                .unwrap()
        ),
        6
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(read_file, &[request as u64, body_ptr, 4, read_ptr])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.modules().memory().read(body_ptr, 4).unwrap(),
        b"abcd"
    );
    assert_eq!(
        u32::from_le_bytes(
            engine.modules().memory().read(read_ptr, 4).unwrap()[..4]
                .try_into()
                .unwrap()
        ),
        4
    );
}

#[test]
fn crypt32_runtime_hooks_open_store_and_find_default_certificate() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let data_page = engine.allocate_executable_test_page(0x7102_0000).unwrap();
    engine
        .write_test_bytes(
            data_page,
            &"ROOT\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let open_store = engine.bind_hook_for_test("crypt32.dll", "CertOpenSystemStoreW");
    let find = engine.bind_hook_for_test("crypt32.dll", "CertFindCertificateInStore");
    let close = engine.bind_hook_for_test("crypt32.dll", "CertCloseStore");
    let open_message = engine.bind_hook_for_test("crypt32.dll", "CryptMsgOpenToDecode");
    let close_message = engine.bind_hook_for_test("crypt32.dll", "CryptMsgClose");

    let store = engine
        .dispatch_bound_stub(open_store, &[0, data_page])
        .unwrap() as u32;
    assert_ne!(store, 0);

    let cert = engine
        .dispatch_bound_stub(find, &[store as u64, 0, 0, 0, 0, 0])
        .unwrap() as u32;
    assert_ne!(cert, 0);

    let message = engine
        .dispatch_bound_stub(open_message, &[0, 0, 0, 0, 0, 0])
        .unwrap() as u32;
    assert_ne!(message, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(close_message, &[message as u64])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close, &[store as u64, 0])
            .unwrap(),
        1
    );
}

#[test]
fn sleep_reentry_preserves_api_frame_and_revisits_same_hook_site() {
    let (config, trace_path) = trace_config("sleep-reentry");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let code = engine.allocate_executable_test_page(0x7103_0000).unwrap();
    let next = code + 7;
    let rel = (sleep as i64 - next as i64) as i32;
    let bytes = [
        0x6A,
        0x05,
        0xE8,
        rel as u8,
        (rel >> 8) as u8,
        (rel >> 16) as u8,
        (rel >> 24) as u8,
        0xB8,
        0x34,
        0x12,
        0x00,
        0x00,
        0xC3,
    ];
    engine.write_test_bytes(code, &bytes).unwrap();

    let retval = engine.call_native_for_test(code, &[]).unwrap();
    engine.flush_api_logs_for_test().unwrap();

    let sleep_calls: Vec<_> = load_api_calls(&trace_path)
        .into_iter()
        .filter(|record| record.get("target_function").and_then(Value::as_str) == Some("Sleep"))
        .collect();

    assert_eq!(retval, 0x1234);
    assert_eq!(sleep_calls.len(), 2);
    assert_eq!(
        sleep_calls[0].get("return_owner").and_then(Value::as_str),
        sleep_calls[1].get("return_owner").and_then(Value::as_str)
    );
}

#[test]
fn read_file_on_std_input_reports_success_with_zero_bytes_and_keeps_last_error() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let read_file = engine.bind_hook_for_test("kernel32.dll", "ReadFile");
    let page = engine.allocate_executable_test_page(0x7104_0000).unwrap();
    engine.write_test_bytes(page, &[0xCC; 0x20]).unwrap();
    engine.set_last_error(0xCAFE_BABE);

    let bytes_read_ptr = page;
    let buffer = page + 4;
    let retval = engine
        .dispatch_bound_stub(read_file, &[0xFFFF_FFF6, buffer, 16, bytes_read_ptr, 0])
        .unwrap();
    let bytes_read = u32::from_le_bytes(
        engine.modules().memory().read(bytes_read_ptr, 4).unwrap()[..4]
            .try_into()
            .unwrap(),
    );

    assert_eq!(retval, 1);
    assert_eq!(bytes_read, 0);
    assert_eq!(engine.last_error(), 0xCAFE_BABE);
}

#[test]
fn api_trace_decodes_string_arguments_and_conversion_outputs() {
    let (mut config, trace_path) = trace_config("decoded-api-args");
    let human_path = trace_path.parent().unwrap().join("trace.api.human.log");
    config.api_human_log_path = Some(human_path.clone());
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let page = engine.allocate_executable_test_page(0x7105_0000).unwrap();
    engine.write_test_bytes(page, &[0u8; 0x400]).unwrap();

    let wide_text = "cmd.exe";
    let mut wide_bytes = wide_text
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    wide_bytes.extend_from_slice(&[0, 0]);

    let proc_name = b"GetCurrentProcessId\0";
    let wide_ptr = page;
    let proc_name_ptr = page + wide_bytes.len() as u64;
    let output_ptr = page + 0x100;
    engine.write_test_bytes(wide_ptr, &wide_bytes).unwrap();
    engine.write_test_bytes(proc_name_ptr, proc_name).unwrap();

    let wide_to_multi = engine.bind_hook_for_test("kernel32.dll", "WideCharToMultiByte");
    let get_proc = engine.bind_hook_for_test("kernel32.dll", "GetProcAddress");
    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let kernel32 = engine.modules().get_loaded("kernel32.dll").unwrap().base;
    let tid_ptr = page + 0x200;

    let written = engine
        .dispatch_bound_stub(
            wide_to_multi,
            &[
                65001,
                0,
                wide_ptr,
                wide_text.len() as u64,
                output_ptr,
                0x40,
                0,
                0,
            ],
        )
        .unwrap();
    let proc = engine
        .dispatch_bound_stub(get_proc, &[kernel32, proc_name_ptr])
        .unwrap();
    let thread_handle = engine
        .dispatch_bound_stub(create_thread, &[0, 0, kernel32, 0, 0x4, tid_ptr])
        .unwrap();
    engine.flush_api_logs_for_test().unwrap();

    assert!(written > 0);
    assert_ne!(proc, 0);
    assert_ne!(thread_handle, 0);

    let calls = load_api_calls(&trace_path);
    let wide_call = calls
        .iter()
        .find(|record| {
            record.get("target_function").and_then(Value::as_str) == Some("WideCharToMultiByte")
        })
        .unwrap();
    let wide_args = wide_call.get("args").and_then(Value::as_array).unwrap();
    assert_eq!(
        wide_args[2].get("name").and_then(Value::as_str),
        Some("lpWideCharStr")
    );
    assert!(wide_args[2]
        .get("text")
        .and_then(Value::as_str)
        .unwrap()
        .contains("cmd.exe"));

    let get_proc_call = calls
        .iter()
        .find(|record| {
            record.get("target_function").and_then(Value::as_str) == Some("GetProcAddress")
        })
        .unwrap();
    let proc_args = get_proc_call.get("args").and_then(Value::as_array).unwrap();
    assert_eq!(
        proc_args[1].get("name").and_then(Value::as_str),
        Some("lpProcName")
    );
    assert!(proc_args[1]
        .get("text")
        .and_then(Value::as_str)
        .unwrap()
        .contains("GetCurrentProcessId"));

    let create_thread_call = calls
        .iter()
        .find(|record| {
            record.get("target_function").and_then(Value::as_str) == Some("CreateThread")
        })
        .unwrap();
    let thread_args = create_thread_call
        .get("args")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(
        thread_args[2].get("name").and_then(Value::as_str),
        Some("lpStartAddress")
    );
    let thread_start = thread_args[2].get("text").and_then(Value::as_str).unwrap();
    assert!(thread_start.contains("kernel32.dll"));
    assert!(!thread_start.contains("\""));

    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("lpWideCharStr="));
    assert!(human_log.contains("\"cmd.exe\""));
    assert!(human_log.contains("decoded={lpMultiByteStr="));
    assert!(human_log.contains("lpProcName="));
    assert!(human_log.contains("GetCurrentProcessId"));
    assert!(human_log.contains("lpStartAddress="));
}

#[test]
fn set_current_directory_w_updates_runtime_state_and_process_parameters() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let target = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-setcwd-{}-{unique}",
        std::process::id()
    ));
    let target_text = target.to_string_lossy().to_string();
    let mut wide = target_text
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    wide.extend_from_slice(&[0, 0]);

    let input_page = engine.allocate_executable_test_page(0x7106_0000).unwrap();
    let output_page = engine.allocate_executable_test_page(0x7107_0000).unwrap();
    engine.write_test_bytes(input_page, &wide).unwrap();

    let set_current_directory = engine.bind_hook_for_test("kernel32.dll", "SetCurrentDirectoryW");
    let get_current_directory = engine.bind_hook_for_test("kernel32.dll", "GetCurrentDirectoryW");

    assert_eq!(
        engine
            .dispatch_bound_stub(set_current_directory, &[input_page])
            .unwrap(),
        1
    );
    assert_eq!(engine.current_directory(), target.as_path());

    let written = engine
        .dispatch_bound_stub(get_current_directory, &[260, output_page])
        .unwrap();
    assert!(written > 0);
    assert_eq!(read_wide_c_string(&engine, output_page, 260), target_text);

    let _ = fs::remove_dir_all(target);
}

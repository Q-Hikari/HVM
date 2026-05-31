use std::path::{Path, PathBuf};

use super::{
    format_writeback_error_detail, writeback_range_chunks, RunStopReason, VirtualExecutionEngine,
};
use crate::config::{load_config, HttpResponseHeader, HttpResponsePayload, HttpResponseRule};
use crate::environment_profile::{
    DisplayProfileOverrides, EnvironmentOverrides, UserAccountProfile, WindowProfile,
};
use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{
    HookFlags, LogicalAbi, ParamDirection, ParamType, ParamTypeDiscriminant,
};
use crate::memory::manager::PAGE_SIZE;
use crate::runtime::scheduler::{WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT};

const TEST_TYPED_ONLY_PARAMS: &[ParamSpec] = &[ParamSpec::new("value", ParamType::U32)];
const TEST_TYPED_PREFIX_PARAMS: &[ParamSpec] = &[ParamSpec::new("first", ParamType::U32)];
const TEST_TYPED_PTR_IN_PARAMS: &[ParamSpec] = &[ParamSpec::new(
    "value",
    ParamType::GuestPtrTo(ParamTypeDiscriminant::U32),
)];
const TEST_TYPED_PTR_OUT_PARAMS: &[ParamSpec] = &[ParamSpec::with_dir(
    "out_value",
    ParamType::GuestPtrTo(ParamTypeDiscriminant::U32),
    ParamDirection::Out,
)];

fn make_logging_test_engine() -> VirtualExecutionEngine {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.trace_api_calls = true;
    VirtualExecutionEngine::new(config).unwrap()
}

fn make_network_test_engine(http_response_rules: Vec<HttpResponseRule>) -> VirtualExecutionEngine {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.trace_api_calls = false;
    config.http_response_rules = http_response_rules;
    VirtualExecutionEngine::new(config).unwrap()
}

fn allocate_test_memory(engine: &mut VirtualExecutionEngine, size: u64, label: &str) -> u64 {
    engine
        .core
        .modules
        .memory_mut()
        .reserve(size, None, label, true)
        .unwrap()
}

fn make_wtpsvc_engine_config() -> crate::config::EngineConfig {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let sample_dir = repo_root.join("Sample").join("WtpSvc");
    let system_root = repo_root.join("system_dll");
    let system32 = system_root.join("System32");
    let mut config =
        crate::config::EngineConfig::for_tests(repo_root.join(".hvm_hikari_virtual_engine/output"));
    config.main_module = sample_dir.join("WtpSvc.exe");
    config.process_image = Some(sample_dir.join("WtpSvc.exe"));
    config.module_search_paths = vec![sample_dir, system32.clone(), system_root];
    config.module_directory_x64 = Some(system32);
    config.whitelist_modules = ["wtpsvc.exe", "wtplib.dll"]
        .into_iter()
        .map(str::to_string)
        .collect();
    config
}

#[test]
fn writeback_range_chunks_split_on_page_boundaries() {
    assert_eq!(
        writeback_range_chunks(PAGE_SIZE - 0x10, 0x40),
        vec![(PAGE_SIZE - 0x10, 0x10), (PAGE_SIZE, 0x30),]
    );
}

#[test]
fn writeback_error_detail_includes_requested_range_failed_chunk_and_pc() {
    let detail = format_writeback_error_detail(
        "uc_mem_read: Invalid memory read (UC_ERR_READ_UNMAPPED)",
        0x1234,
        0x2200,
        0x2000,
        0x1000,
        Some(0x40269D),
    );
    assert!(detail.contains("write_range=0x1234+0x2200"));
    assert!(detail.contains("failed_chunk=0x2000+0x1000"));
    assert!(detail.contains("flush_pc=0x40269D"));
}

#[test]
fn signature_driven_api_log_args_do_not_emit_auto_kind_for_declared_params() {
    let engine = make_logging_test_engine();
    let signature = HookSignature {
        module: "test.dll",
        function: "TypedOnly",
        abi: LogicalAbi::WinApi,
        params: TEST_TYPED_ONLY_PARAMS,
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    };

    let rendered = engine.describe_api_call_args(&signature, &[0x41]);

    assert_eq!(rendered.len(), 1);
    assert_eq!(rendered[0].name, "value");
    assert_eq!(rendered[0].kind, "u32");
    assert_eq!(rendered[0].text, "65");
    assert!(rendered.iter().all(|arg| arg.kind != "auto"));
}

#[test]
fn signature_driven_api_log_args_render_undeclared_tail_as_raw_not_auto() {
    let engine = make_logging_test_engine();
    let signature = HookSignature {
        module: "test.dll",
        function: "TypedPrefix",
        abi: LogicalAbi::WinApi,
        params: TEST_TYPED_PREFIX_PARAMS,
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    };

    let rendered = engine.describe_api_call_args(&signature, &[7, 0x1234_5678_9ABC_DEF0]);

    assert_eq!(rendered.len(), 2);
    assert_eq!(rendered[0].kind, "u32");
    assert_eq!(rendered[1].name, "arg1");
    assert_eq!(rendered[1].kind, "raw");
    assert_eq!(rendered[1].text, "0x123456789ABCDEF0");
    assert!(rendered.iter().all(|arg| arg.kind != "auto"));
}

#[test]
fn engine_load_keeps_whitelisted_wtplib_exports_observed_only() {
    let mut engine = VirtualExecutionEngine::new(make_wtpsvc_engine_config()).unwrap();
    engine.load().unwrap();

    for (name, address) in [
        ("WtpEnableFilter", 0x1800_37C90u64),
        ("WtpOpenDevice", 0x1800_62BE0u64),
        ("sqlite3_win32_is_nt", 0x1800_36180u64),
    ] {
        assert!(
            engine.core.hooks.bound_lookup(address).is_none(),
            "{name} unexpectedly became hook-dispatchable at 0x{address:X} during engine.load()"
        );
        let observed = engine
            .core
            .hooks
            .observed_real_export_for_address(address)
            .unwrap_or_else(|| panic!("{name} should remain observable at 0x{address:X}"));
        assert_eq!(observed.0, "wtplib.dll");
    }
}

#[test]
fn signature_driven_api_log_args_render_in_typed_pointer_pointee() {
    let mut engine = make_logging_test_engine();
    let pointer = engine
        .core
        .modules
        .memory_mut()
        .reserve(PAGE_SIZE, None, "typed-pointer", false)
        .unwrap();
    engine.write_u32(pointer, 0x1234_5678).unwrap();
    let signature = HookSignature {
        module: "test.dll",
        function: "TypedPointerIn",
        abi: LogicalAbi::WinApi,
        params: TEST_TYPED_PTR_IN_PARAMS,
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    };

    let rendered = engine.describe_api_call_args(&signature, &[pointer]);

    assert_eq!(rendered.len(), 1);
    assert_eq!(rendered[0].kind, "ptr_to_u32");
    assert!(rendered[0].text.contains("->0x12345678"));
}

#[test]
fn signature_driven_api_log_args_leave_out_typed_pointer_as_address() {
    let mut engine = make_logging_test_engine();
    let pointer = engine
        .core
        .modules
        .memory_mut()
        .reserve(PAGE_SIZE, None, "typed-pointer-out", false)
        .unwrap();
    engine.write_u32(pointer, 0xDEAD_BEEF).unwrap();
    let signature = HookSignature {
        module: "test.dll",
        function: "TypedPointerOut",
        abi: LogicalAbi::WinApi,
        params: TEST_TYPED_PTR_OUT_PARAMS,
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    };

    let rendered = engine.describe_api_call_args(&signature, &[pointer]);

    assert_eq!(rendered.len(), 1);
    assert_eq!(rendered[0].kind, "ptr_to_u32");
    assert!(!rendered[0].text.contains("->"));
}

#[test]
fn raw_socket_http_rules_match_actual_request_and_stream_response_across_select_and_recv() {
    let mut engine = make_network_test_engine(vec![
        HttpResponseRule {
            host: Some("example.com".to_string()),
            path: Some("/upload".to_string()),
            verb: Some("POST".to_string()),
            responses: vec![HttpResponsePayload {
                status_code: 201,
                headers: vec![HttpResponseHeader {
                    name: "Content-Type".to_string(),
                    value: "text/plain".to_string(),
                }],
                body: b"created".to_vec(),
            }],
        },
        HttpResponseRule {
            host: Some("example.com".to_string()),
            path: Some("/health".to_string()),
            verb: Some("GET".to_string()),
            responses: vec![HttpResponsePayload {
                status_code: 200,
                headers: Vec::new(),
                body: b"wrong".to_vec(),
            }],
        },
    ]);
    let socket_hook = engine.bind_hook_for_test("ws2_32.dll", "socket");
    let connect_hook = engine.bind_hook_for_test("ws2_32.dll", "connect");
    let send_hook = engine.bind_hook_for_test("ws2_32.dll", "send");
    let select_hook = engine.bind_hook_for_test("ws2_32.dll", "select");
    let recv_hook = engine.bind_hook_for_test("ws2_32.dll", "recv");

    let socket = engine.dispatch_bound_stub(socket_hook, &[2, 1, 6]).unwrap();
    let sockaddr = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_sockaddr");
    engine.write_sockaddr(sockaddr, "100.64.0.1", 80).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(connect_hook, &[socket, sockaddr, 16])
            .unwrap(),
        0
    );

    let request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ndata";
    let request_ptr = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_request");
    engine.write_test_bytes(request_ptr, request).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(send_hook, &[socket, request_ptr, request.len() as u64, 0])
            .unwrap(),
        request.len() as u64
    );

    let read_set = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_fd_set");
    engine
        .write_fd_set_handles(read_set, &[socket as u32])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(select_hook, &[1, read_set, 0, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.read_fd_set_handles(read_set).unwrap(),
        vec![socket as u32]
    );

    let recv_ptr = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_recv");
    let first = engine
        .dispatch_bound_stub(recv_hook, &[socket, recv_ptr, 12, 0])
        .unwrap() as usize;
    assert_eq!(first, 12);
    let first_bytes = engine.read_bytes_from_memory(recv_ptr, first).unwrap();
    assert_eq!(&first_bytes, b"HTTP/1.1 201");

    let second = engine
        .dispatch_bound_stub(recv_hook, &[socket, recv_ptr, 256, 0])
        .unwrap() as usize;
    let second_bytes = engine.read_bytes_from_memory(recv_ptr, second).unwrap();
    let remaining_text = String::from_utf8_lossy(&second_bytes);
    assert!(remaining_text.contains("created"));
    assert!(remaining_text.contains("Content-Type: text/plain"));
    assert!(!remaining_text.contains("wrong"));
}

#[test]
fn raw_socket_http_rules_work_for_getaddrinfo_and_wsa_event_select() {
    let mut engine = make_network_test_engine(vec![HttpResponseRule {
        host: Some("api.test.local".to_string()),
        path: Some("/v1/ping".to_string()),
        verb: Some("HEAD".to_string()),
        responses: vec![HttpResponsePayload {
            status_code: 204,
            headers: vec![HttpResponseHeader {
                name: "X-Test".to_string(),
                value: "dns".to_string(),
            }],
            body: Vec::new(),
        }],
    }]);
    let socket_hook = engine.bind_hook_for_test("ws2_32.dll", "socket");
    let getaddrinfo_hook = engine.bind_hook_for_test("ws2_32.dll", "getaddrinfo");
    let connect_hook = engine.bind_hook_for_test("ws2_32.dll", "connect");
    let send_hook = engine.bind_hook_for_test("ws2_32.dll", "send");
    let event_create_hook = engine.bind_hook_for_test("ws2_32.dll", "WSACreateEvent");
    let event_select_hook = engine.bind_hook_for_test("ws2_32.dll", "WSAEventSelect");
    let enum_events_hook = engine.bind_hook_for_test("ws2_32.dll", "WSAEnumNetworkEvents");
    let recv_hook = engine.bind_hook_for_test("ws2_32.dll", "recv");

    let node_name = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_node");
    let service_name = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_service");
    let addrinfo_out = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_addrinfo_out");
    engine
        .write_test_bytes(node_name, b"api.test.local\0")
        .unwrap();
    engine.write_test_bytes(service_name, b"80\0").unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                getaddrinfo_hook,
                &[node_name, service_name, 0, addrinfo_out]
            )
            .unwrap(),
        0
    );
    let addrinfo = engine.read_u32(addrinfo_out).unwrap() as u64;
    let sockaddr = engine.read_u32(addrinfo + 24).unwrap() as u64;
    let (resolved_ip, port, family) = engine.read_sockaddr(sockaddr, 16).unwrap();
    assert_eq!(port, 80);
    assert_eq!(family, 2);
    assert_eq!(
        engine
            .network_state
            .dns
            .reverse(&resolved_ip)
            .map(String::as_str),
        Some("api.test.local")
    );

    let socket = engine.dispatch_bound_stub(socket_hook, &[2, 1, 6]).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(connect_hook, &[socket, sockaddr, 16])
            .unwrap(),
        0
    );

    let event_handle = engine.dispatch_bound_stub(event_create_hook, &[]).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(event_select_hook, &[socket, event_handle, 0x0001])
            .unwrap(),
        0
    );

    let request = b"HEAD /v1/ping HTTP/1.1\r\nHost: api.test.local\r\n\r\n";
    let request_ptr = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_head_request");
    engine.write_test_bytes(request_ptr, request).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(send_hook, &[socket, request_ptr, request.len() as u64, 0])
            .unwrap(),
        request.len() as u64
    );

    let network_events = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_network_events");
    assert_eq!(
        engine
            .dispatch_bound_stub(enum_events_hook, &[socket, event_handle, network_events])
            .unwrap(),
        0
    );
    assert_eq!(engine.read_u32(network_events).unwrap(), 0x0001);

    let recv_ptr = allocate_test_memory(&mut engine, 0x1000, "ws2_32:test_head_recv");
    let received = engine
        .dispatch_bound_stub(recv_hook, &[socket, recv_ptr, 256, 0])
        .unwrap() as usize;
    let response_bytes = engine.read_bytes_from_memory(recv_ptr, received).unwrap();
    let response = String::from_utf8_lossy(&response_bytes);
    assert!(response.contains("HTTP/1.1 204"));
    assert!(response.contains("X-Test: dns"));
}

#[test]
fn unicorn_scheduler_continues_ready_worker_after_main_thread_terminates() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F00_0000).unwrap();
    engine
        .write_test_bytes(worker_code, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
        .unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();
    let worker_stack_base = engine
        .scheduler()
        .thread_snapshot(worker_tid)
        .unwrap()
        .stack_base;
    let main_tid = engine.core.main_thread_tid.unwrap();

    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    assert!(engine.terminate_current_thread(1));
    engine.core.exit_code = Some(1);
    engine.core.stop_reason = None;
    engine.core.process_exit_requested = false;

    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.scheduler().thread_exit_code(worker_tid),
        Some(Some(0x2A))
    );
    assert_eq!(
        engine
            .scheduler()
            .thread_snapshot(worker_tid)
            .unwrap()
            .stack_base,
        0
    );
    assert!(engine
        .core
        .modules
        .memory()
        .find_region(worker_stack_base.saturating_sub(PAGE_SIZE), 1)
        .is_none());
    assert_eq!(
        engine.core.stop_reason,
        Some(RunStopReason::AllThreadsTerminated)
    );
}

#[test]
fn user32_find_window_and_timing_values_follow_environment_profile() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    let configured_hwnd = 0x0010_4000u32;
    config.environment_overrides = Some(EnvironmentOverrides {
        display: Some(DisplayProfileOverrides {
            double_click_time_ms: Some(640),
            caret_blink_time_ms: Some(710),
            windows: Some(vec![WindowProfile {
                handle: configured_hwnd,
                class_name: "SandboxieControlWndClass".to_string(),
                title: "Sandboxie Control".to_string(),
                parent_handle: 0,
                owner_thread_id: 0,
                instance: 0,
            }]),
            ..Default::default()
        }),
        ..Default::default()
    });
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let class_name = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F30_0000),
            "user32:test_findwindow_class",
            true,
        )
        .unwrap();
    let title = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F31_0000),
            "user32:test_findwindow_title",
            true,
        )
        .unwrap();
    engine
        .write_c_string_to_memory(class_name, 128, "sandboxiecontrolwndclass")
        .unwrap();
    engine
        .write_c_string_to_memory(title, 128, "sandboxie control")
        .unwrap();

    let find_window = engine.bind_hook_for_test("user32.dll", "FindWindowA");
    let get_double_click_time = engine.bind_hook_for_test("user32.dll", "GetDoubleClickTime");
    let get_caret_blink_time = engine.bind_hook_for_test("user32.dll", "GetCaretBlinkTime");

    assert_eq!(
        engine
            .dispatch_bound_stub(find_window, &[class_name, title])
            .unwrap(),
        configured_hwnd as u64
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(get_double_click_time, &[])
            .unwrap(),
        640
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(get_caret_blink_time, &[])
            .unwrap(),
        710
    );
}

#[test]
fn kernel32_terminate_thread_marks_worker_terminated() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F32_0000).unwrap();
    engine
        .write_test_bytes(worker_code, &[0x31, 0xC0, 0xC3])
        .unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap();
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle as u32)
        .unwrap();
    let worker_stack_base = engine
        .scheduler()
        .thread_snapshot(worker_tid)
        .unwrap()
        .stack_base;

    let terminate_thread = engine.bind_hook_for_test("kernel32.dll", "TerminateThread");
    assert_eq!(
        engine
            .dispatch_bound_stub(terminate_thread, &[worker_handle, 0x41])
            .unwrap(),
        1
    );
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.scheduler().thread_exit_code(worker_tid),
        Some(Some(0x41))
    );
    assert!(!engine.objects.started_threads.contains(&worker_tid));
    assert_eq!(
        engine
            .scheduler()
            .thread_snapshot(worker_tid)
            .unwrap()
            .stack_base,
        0
    );
    assert!(engine
        .core
        .modules
        .memory()
        .find_region(worker_stack_base.saturating_sub(PAGE_SIZE), 1)
        .is_none());
}

#[test]
fn unicorn_scheduler_resumes_main_thread_after_sleep_and_runs_ready_worker() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();
    assert!(engine.core.arch.is_x86());

    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let main_code = engine.allocate_executable_test_page(0x6F08_0000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F09_0000).unwrap();
    let marker_page = engine
        .core
        .modules
        .memory_mut()
        .reserve(PAGE_SIZE, Some(0x6F0A_0000), "scheduler:test_markers", true)
        .unwrap();
    let main_marker = marker_page;
    let worker_marker = marker_page + 4;
    engine.write_u32(main_marker, 0).unwrap();
    engine.write_u32(worker_marker, 0).unwrap();

    let main_next = main_code + 7;
    let main_rel = (sleep as i64 - main_next as i64) as i32;
    let mut main_bytes = vec![0x6A, 0x05, 0xE8];
    main_bytes.extend_from_slice(&main_rel.to_le_bytes());
    main_bytes.extend_from_slice(&[0xC7, 0x05]);
    main_bytes.extend_from_slice(&(main_marker as u32).to_le_bytes());
    main_bytes.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    main_bytes.push(0xC3);
    engine.write_test_bytes(main_code, &main_bytes).unwrap();

    let mut worker_bytes = vec![0xC7, 0x05];
    worker_bytes.extend_from_slice(&(worker_marker as u32).to_le_bytes());
    worker_bytes.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    worker_bytes.push(0xC3);
    engine.write_test_bytes(worker_code, &worker_bytes).unwrap();

    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    engine.complete_process_startup_sequence().unwrap();
    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(engine.read_u32(main_marker).unwrap(), 0x1122_3344);
    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x5566_7788);
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.core.stop_reason,
        Some(RunStopReason::AllThreadsTerminated)
    );
}

#[test]
fn unicorn_scheduler_runs_worker_created_via_api_after_main_sleep() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let marker_page = engine.allocate_executable_test_page(0x6F12_0000).unwrap();
    let worker_marker = marker_page;
    let main_marker = marker_page + 4;
    engine.write_u32(worker_marker, 0).unwrap();
    engine.write_u32(main_marker, 0).unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F13_0000).unwrap();
    let mut worker_bytes = vec![0xC7, 0x05];
    worker_bytes.extend_from_slice(&(worker_marker as u32).to_le_bytes());
    worker_bytes.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    worker_bytes.push(0xC3);
    engine.write_test_bytes(worker_code, &worker_bytes).unwrap();

    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let main_code = engine.allocate_executable_test_page(0x6F14_0000).unwrap();
    let create_pc = main_code + 15;
    let create_rel = i32::try_from((create_thread as i64) - (create_pc as i64 + 5)).unwrap();
    let sleep_pc = main_code + 25;
    let sleep_rel = i32::try_from((sleep as i64) - (sleep_pc as i64 + 5)).unwrap();
    let mut main_bytes = vec![
        0x6A, 0x00, // lpThreadId
        0x6A, 0x00, // dwCreationFlags
        0x6A, 0x00, // lpParameter
        0x68,
    ];
    main_bytes.extend_from_slice(&(worker_code as u32).to_le_bytes());
    main_bytes.extend_from_slice(&[
        0x6A,
        0x00, // dwStackSize
        0x6A,
        0x00, // lpThreadAttributes
        0xE8,
        create_rel as u8,
        (create_rel >> 8) as u8,
        (create_rel >> 16) as u8,
        (create_rel >> 24) as u8,
        0x68,
        0xB4,
        0x00,
        0x00,
        0x00,
        0xE8,
        sleep_rel as u8,
        (sleep_rel >> 8) as u8,
        (sleep_rel >> 16) as u8,
        (sleep_rel >> 24) as u8,
        0xC7,
        0x05,
    ]);
    main_bytes.extend_from_slice(&(main_marker as u32).to_le_bytes());
    main_bytes.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    main_bytes.push(0xC3);
    engine.write_test_bytes(main_code, &main_bytes).unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    engine.complete_process_startup_sequence().unwrap();
    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x5566_7788);
    assert_eq!(engine.read_u32(main_marker).unwrap(), 0x1122_3344);
    assert_eq!(
        engine.core.stop_reason,
        Some(RunStopReason::AllThreadsTerminated)
    );
}

#[test]
fn unicorn_scheduler_runs_worker_created_via_api_after_main_waits_on_event() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let set_event = engine.bind_hook_for_test("kernel32.dll", "SetEvent");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    let event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();
    let worker_marker = engine.allocate_executable_test_page(0x6F15_0000).unwrap();
    engine.write_u32(worker_marker, 0).unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F16_0000).unwrap();
    let worker_push = worker_code + 5;
    let worker_rel = i32::try_from((set_event as i64) - (worker_push as i64 + 5)).unwrap();
    let mut worker_bytes = vec![0x68];
    worker_bytes.extend_from_slice(&(event as u32).to_le_bytes());
    worker_bytes.extend_from_slice(&[0xE8]);
    worker_bytes.extend_from_slice(&worker_rel.to_le_bytes());
    worker_bytes.extend_from_slice(&[0xC7, 0x05]);
    worker_bytes.extend_from_slice(&(worker_marker as u32).to_le_bytes());
    worker_bytes.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    worker_bytes.push(0xC3);
    engine.write_test_bytes(worker_code, &worker_bytes).unwrap();

    let main_code = engine.allocate_executable_test_page(0x6F17_0000).unwrap();
    let create_pc = main_code + 15;
    let create_rel = i32::try_from((create_thread as i64) - (create_pc as i64 + 5)).unwrap();
    let wait_pc = main_code + 30;
    let wait_rel = i32::try_from((wait as i64) - (wait_pc as i64 + 5)).unwrap();
    let mut main_bytes = vec![
        0x6A, 0x00, // lpThreadId
        0x6A, 0x00, // dwCreationFlags
        0x6A, 0x00, // lpParameter
        0x68,
    ];
    main_bytes.extend_from_slice(&(worker_code as u32).to_le_bytes());
    main_bytes.extend_from_slice(&[
        0x6A, 0x00, // dwStackSize
        0x6A, 0x00, // lpThreadAttributes
        0xE8,
    ]);
    main_bytes.extend_from_slice(&create_rel.to_le_bytes());
    main_bytes.extend_from_slice(&[
        0x68, 0xFF, 0xFF, 0xFF, 0xFF, // INFINITE
        0x68,
    ]);
    main_bytes.extend_from_slice(&(event as u32).to_le_bytes());
    main_bytes.extend_from_slice(&[0xE8]);
    main_bytes.extend_from_slice(&wait_rel.to_le_bytes());
    main_bytes.push(0xC3);
    engine.write_test_bytes(main_code, &main_bytes).unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    engine.complete_process_startup_sequence().unwrap();
    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x5566_7788);
    assert_eq!(
        engine
            .scheduler()
            .thread_state(engine.core.main_thread_tid.unwrap()),
        Some("terminated")
    );
    assert_eq!(
        engine.core.stop_reason,
        Some(RunStopReason::AllThreadsTerminated)
    );
}

#[test]
fn wait_for_single_object_on_thread_handle_resumes_after_worker_exit() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F10_0000).unwrap();
    engine.write_test_bytes(worker_code, &[0xC3]).unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();
    let main_tid = engine.core.main_thread_tid.unwrap();
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[worker_handle as u64, u32::MAX as u64])
            .unwrap(),
        WAIT_TIMEOUT as u64
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("waiting"));

    engine
        .core
        .scheduler
        .switch_to(worker_tid, &mut engine.core.process_env)
        .unwrap();
    assert!(engine.terminate_current_thread(7));

    let main_thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    assert_eq!(main_thread.state, "ready");
    assert_eq!(main_thread.wait_result, Some(WAIT_OBJECT_0));

    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[worker_handle as u64, u32::MAX as u64])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
}

#[test]
fn wait_for_single_object_on_abandoned_mutex_returns_wait_abandoned() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let worker_code = engine.allocate_executable_test_page(0x6F20_0000).unwrap();
    engine.write_test_bytes(worker_code, &[0xC3]).unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();
    let main_tid = engine.core.main_thread_tid.unwrap();
    let create_mutex = engine.bind_hook_for_test("kernel32.dll", "CreateMutexW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");

    engine
        .core
        .scheduler
        .switch_to(worker_tid, &mut engine.core.process_env)
        .unwrap();
    let mutex = engine
        .dispatch_bound_stub(create_mutex, &[0, 1, 0])
        .unwrap() as u32;
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[mutex as u64, u32::MAX as u64])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
    assert!(engine.terminate_current_thread(9));

    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(wait, &[mutex as u64, 0])
            .unwrap(),
        WAIT_ABANDONED_0 as u64
    );
}

#[test]
fn open_mutex_a_missing_sets_file_not_found() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_mutex = engine.bind_hook_for_test("kernel32.dll", "OpenMutexA");
    let get_last_error = engine.bind_hook_for_test("kernel32.dll", "GetLastError");
    let name_ptr = allocate_test_memory(&mut engine, 0x100, "missing_mutex_name");
    engine
        .write_c_string_to_memory(name_ptr, 0x100, "definitely_missing_mutex")
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(open_mutex, &[0x0010_0000, 0, name_ptr])
            .unwrap(),
        0
    );
    assert_eq!(engine.dispatch_bound_stub(get_last_error, &[]).unwrap(), 2);
}

#[test]
fn get_token_information_reports_configured_integrity_level() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.environment_overrides = Some(EnvironmentOverrides {
        users: Some(vec![UserAccountProfile {
            name: "Admin".to_string(),
            integrity_level_rid: Some(0x2000),
            ..UserAccountProfile::default()
        }]),
        ..Default::default()
    });
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_process_token = engine.bind_hook_for_test("advapi32.dll", "OpenProcessToken");
    let get_token_information = engine.bind_hook_for_test("advapi32.dll", "GetTokenInformation");

    let token_ptr = allocate_test_memory(&mut engine, 0x1000, "token_handle_ptr");
    let return_length_ptr = allocate_test_memory(&mut engine, 0x1000, "token_return_length");
    let info_ptr = allocate_test_memory(&mut engine, 0x1000, "token_integrity_info");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                open_process_token,
                &[engine.current_process_id() as u64, 0x0008, token_ptr],
            )
            .unwrap(),
        1
    );

    let token = engine.read_u32(token_ptr).unwrap() as u64;
    assert_eq!(
        engine
            .dispatch_bound_stub(get_token_information, &[token, 25, 0, 0, return_length_ptr])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), 122);

    let required = engine.read_u32(return_length_ptr).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_token_information,
                &[token, 25, info_ptr, required as u64, return_length_ptr],
            )
            .unwrap(),
        1
    );
    assert_eq!(engine.last_error(), 0);

    let sid_ptr = engine.read_pointer_value(info_ptr).unwrap();
    let attributes = engine
        .read_u32(info_ptr + engine.core.arch.pointer_size as u64)
        .unwrap();
    let rid = engine.read_u32(sid_ptr + 8).unwrap();
    assert_eq!(attributes, 0x60);
    assert_eq!(rid, 0x2000);
}

#[test]
fn nt_query_information_token_reports_integrity_level_and_buffer_size() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let mut config = load_config(config_path).unwrap();
    config.environment_overrides = Some(EnvironmentOverrides {
        users: Some(vec![UserAccountProfile {
            name: "Admin".to_string(),
            integrity_level_rid: Some(0x3000),
            ..UserAccountProfile::default()
        }]),
        ..Default::default()
    });
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let nt_open_process_token = engine.bind_hook_for_test("ntdll.dll", "NtOpenProcessToken");
    let nt_query_information_token =
        engine.bind_hook_for_test("ntdll.dll", "NtQueryInformationToken");

    let token_ptr = allocate_test_memory(&mut engine, 0x1000, "nt_token_handle_ptr");
    let return_length_ptr = allocate_test_memory(&mut engine, 0x1000, "nt_token_return_length");
    let info_ptr = allocate_test_memory(&mut engine, 0x1000, "nt_token_integrity_info");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_open_process_token,
                &[engine.current_process_id() as u64, 0x0008, token_ptr],
            )
            .unwrap(),
        0
    );

    let token = engine.read_u32(token_ptr).unwrap() as u64;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query_information_token,
                &[token, 25, 0, 0, return_length_ptr],
            )
            .unwrap(),
        0xC0000023
    );

    let required = engine.read_u32(return_length_ptr).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                nt_query_information_token,
                &[token, 25, info_ptr, required as u64, return_length_ptr],
            )
            .unwrap(),
        0
    );

    let sid_ptr = engine.read_pointer_value(info_ptr).unwrap();
    let attributes = engine
        .read_u32(info_ptr + engine.core.arch.pointer_size as u64)
        .unwrap();
    let rid = engine.read_u32(sid_ptr + 8).unwrap();
    assert_eq!(attributes, 0x60);
    assert_eq!(rid, 0x3000);
}

#[test]
fn x64_entry_frame_wait_on_ready_worker_switches_to_worker() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x64());

    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let main_code = engine.allocate_executable_test_page(0x6F97_0000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F97_1000).unwrap();
    engine
        .write_test_bytes(worker_code, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
        .unwrap();

    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u64;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle as u32)
        .unwrap();

    engine
        .write_test_bytes(
            main_code,
            &[
                0x48,
                0xB9,
                worker_handle as u8,
                (worker_handle >> 8) as u8,
                (worker_handle >> 16) as u8,
                (worker_handle >> 24) as u8,
                (worker_handle >> 32) as u8,
                (worker_handle >> 40) as u8,
                (worker_handle >> 48) as u8,
                (worker_handle >> 56) as u8,
                0xBA,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x48,
                0xB8,
                wait as u8,
                (wait >> 8) as u8,
                (wait >> 16) as u8,
                (wait >> 24) as u8,
                (wait >> 32) as u8,
                (wait >> 40) as u8,
                (wait >> 48) as u8,
                (wait >> 56) as u8,
                0xFF,
                0xD0,
                0xC3,
            ],
        )
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    engine.complete_process_startup_sequence().unwrap();
    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.scheduler().thread_exit_code(worker_tid),
        Some(Some(0x2A))
    );
}

#[test]
fn get_message_waits_for_timer_due_before_returning_wm_timer() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    let msg = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F30_0000), "user32:test_msg", true)
        .unwrap();

    assert_eq!(
        engine.user32_register_timer(0x1234, 0x81, 5, 0).unwrap(),
        0x81
    );
    assert_eq!(engine.ui.user32_state.synthetic_timer_messages, 0);

    assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 0);
    let sleeping_thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    assert_eq!(sleeping_thread.state, "sleeping");
    assert!(sleeping_thread.wake_tick >= engine.dispatch.time.current().tick_ms + 5);
    assert_eq!(engine.ui.user32_state.synthetic_timer_messages, 0);

    engine.handle_requested_thread_yield();
    engine.dispatch.reset_api_flow_control();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 1);
    let hwnd = engine.read_pointer_value(msg).unwrap();
    let message = if engine.core.arch.is_x86() {
        engine.read_u32(msg + 4).unwrap()
    } else {
        engine.read_u32(msg + 8).unwrap()
    };
    let w_param = if engine.core.arch.is_x86() {
        engine.read_u32(msg + 8).unwrap() as u64
    } else {
        engine.read_pointer_value(msg + 16).unwrap()
    };
    let l_param = if engine.core.arch.is_x86() {
        engine.read_u32(msg + 12).unwrap() as u64
    } else {
        engine.read_pointer_value(msg + 24).unwrap()
    };
    assert_eq!(hwnd, 0x1234);
    assert_eq!(message, 0x0113);
    assert_eq!(w_param, 0x81);
    assert_eq!(l_param, 0);
    assert_eq!(engine.ui.user32_state.synthetic_timer_messages, 1);
}

#[test]
fn dispatch_message_invokes_x86_timerproc_callback() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();
    let msg = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F31_0000), "user32:test_msg", true)
        .unwrap();
    let timerproc = engine.allocate_executable_test_page(0x6F40_0000).unwrap();
    engine
        .write_test_bytes(timerproc, &[0xB8, 0x44, 0x33, 0x22, 0x11, 0xC2, 0x10, 0x00])
        .unwrap();

    assert_eq!(
        engine
            .user32_register_timer(0x4321, 0x99, 5, timerproc)
            .unwrap(),
        0x99
    );
    assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 0);

    engine.handle_requested_thread_yield();
    engine.dispatch.reset_api_flow_control();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    assert_eq!(engine.user32_get_message(msg, 0, 0, 0).unwrap(), 1);
    let message = engine.read_u32(msg + 4).unwrap();
    let w_param = engine.read_u32(msg + 8).unwrap() as u64;
    let l_param = engine.read_u32(msg + 12).unwrap() as u64;
    assert_eq!(message, 0x0113);
    assert_eq!(w_param, 0x99);
    assert_eq!(l_param, timerproc);
    assert_eq!(engine.user32_dispatch_message(msg).unwrap(), 0x1122_3344);
}

#[test]
fn send_message_invokes_registered_wndproc_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let class_name = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F50_0000), "user32:test_class_name", true)
        .unwrap();
    let window_title = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F51_0000), "user32:test_window_title", true)
        .unwrap();
    let class_def = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F52_0000), "user32:test_class_def", true)
        .unwrap();
    engine
        .core
        .modules
        .memory_mut()
        .write(class_def, &vec![0u8; 0x100])
        .unwrap();
    engine
        .write_wide_string_to_memory(class_name, 64, "UnitTestWindow")
        .unwrap();
    engine
        .write_wide_string_to_memory(window_title, 64, "UnitTestWindow")
        .unwrap();

    let wnd_proc = engine.allocate_executable_test_page(0x6F60_0000).unwrap();
    engine
        .write_test_bytes(wnd_proc, &[0xB8, 0x78, 0x56, 0x34, 0x12, 0xC2, 0x10, 0x00])
        .unwrap();

    engine.write_u32(class_def, 48).unwrap();
    engine.write_pointer_value(class_def + 8, wnd_proc).unwrap();
    engine
        .write_pointer_value(class_def + 40, class_name)
        .unwrap();

    let register_class = engine.bind_hook_for_test("user32.dll", "RegisterClassExW");
    let create_window = engine.bind_hook_for_test("user32.dll", "CreateWindowExW");
    let send_message = engine.bind_hook_for_test("user32.dll", "SendMessageW");

    let atom = engine
        .dispatch_bound_stub(register_class, &[class_def])
        .unwrap();
    assert_ne!(atom, 0);

    let hwnd = engine
        .dispatch_bound_stub(
            create_window,
            &[0, class_name, window_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    assert_ne!(hwnd, 0);
    assert_eq!(engine.user32_window_proc(hwnd as u32), wnd_proc);

    assert_eq!(
        engine
            .dispatch_bound_stub(send_message, &[hwnd, 0x4242, 1, 2])
            .unwrap(),
        0x1234_5678
    );
}

#[test]
fn find_window_resolves_registered_class_atoms() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let target_class = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F53_0000),
            "user32:test_find_atom_class",
            true,
        )
        .unwrap();
    let shared_title = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F53_1000),
            "user32:test_find_atom_title",
            true,
        )
        .unwrap();
    let other_class = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F53_2000),
            "user32:test_find_atom_other",
            true,
        )
        .unwrap();
    let active_class = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F53_3000),
            "user32:test_find_atom_active",
            true,
        )
        .unwrap();
    let class_def = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F53_4000), "user32:test_find_atom_def", true)
        .unwrap();
    engine
        .core
        .modules
        .memory_mut()
        .write(class_def, &vec![0u8; 0x100])
        .unwrap();
    engine
        .write_wide_string_to_memory(target_class, 64, "AtomWindowClass")
        .unwrap();
    engine
        .write_wide_string_to_memory(shared_title, 64, "SharedTitle")
        .unwrap();
    engine
        .write_wide_string_to_memory(other_class, 64, "OtherWindowClass")
        .unwrap();
    engine
        .write_wide_string_to_memory(active_class, 64, "ActiveWindowClass")
        .unwrap();

    engine.write_u32(class_def, 48).unwrap();
    engine
        .write_pointer_value(class_def + 40, target_class)
        .unwrap();

    let register_class = engine.bind_hook_for_test("user32.dll", "RegisterClassExW");
    let create_window = engine.bind_hook_for_test("user32.dll", "CreateWindowExW");
    let find_window = engine.bind_hook_for_test("user32.dll", "FindWindowW");

    let atom = engine
        .dispatch_bound_stub(register_class, &[class_def])
        .unwrap();
    assert_ne!(atom, 0);

    let other_hwnd = engine
        .dispatch_bound_stub(
            create_window,
            &[0, other_class, shared_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    let target_hwnd = engine
        .dispatch_bound_stub(
            create_window,
            &[0, target_class, shared_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    let active_hwnd = engine
        .dispatch_bound_stub(
            create_window,
            &[0, active_class, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    assert_ne!(other_hwnd, 0);
    assert_ne!(target_hwnd, 0);
    assert_ne!(active_hwnd, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(find_window, &[atom, shared_title])
            .unwrap(),
        target_hwnd
    );
    assert_eq!(
        engine.dispatch_bound_stub(find_window, &[atom, 0]).unwrap(),
        target_hwnd
    );
}

#[test]
fn send_message_invokes_registered_wndproc_x64_from_native_context() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x64());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let class_name = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F70_0000), "user32:test_class_name64", true)
        .unwrap();
    let window_title = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F71_0000),
            "user32:test_window_title64",
            true,
        )
        .unwrap();
    let class_def = engine
        .core
        .modules
        .memory_mut()
        .reserve(0x1000, Some(0x6F72_0000), "user32:test_class_def64", true)
        .unwrap();
    engine
        .core
        .modules
        .memory_mut()
        .write(class_def, &vec![0u8; 0x100])
        .unwrap();
    engine
        .write_wide_string_to_memory(class_name, 64, "UnitTestWindow64")
        .unwrap();
    engine
        .write_wide_string_to_memory(window_title, 64, "UnitTestWindow64")
        .unwrap();

    let wnd_proc = engine.allocate_executable_test_page(0x6F80_0000).unwrap();
    let wnd_proc_result = 0x1122_3344_5566_7788u64;
    let mut wnd_proc_bytes = vec![0x48, 0xB8];
    wnd_proc_bytes.extend_from_slice(&wnd_proc_result.to_le_bytes());
    wnd_proc_bytes.push(0xC3);
    engine.write_test_bytes(wnd_proc, &wnd_proc_bytes).unwrap();

    engine.write_u32(class_def, 80).unwrap();
    engine.write_pointer_value(class_def + 8, wnd_proc).unwrap();
    engine
        .write_pointer_value(class_def + 64, class_name)
        .unwrap();

    let register_class = engine.bind_hook_for_test("user32.dll", "RegisterClassExW");
    let create_window = engine.bind_hook_for_test("user32.dll", "CreateWindowExW");
    let send_message = engine.bind_hook_for_test("user32.dll", "SendMessageW");

    let atom = engine
        .dispatch_bound_stub(register_class, &[class_def])
        .unwrap();
    assert_ne!(atom, 0);

    let hwnd = engine
        .dispatch_bound_stub(
            create_window,
            &[0, class_name, window_title, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    assert_ne!(hwnd, 0);
    assert_eq!(engine.user32_window_proc(hwnd as u32), wnd_proc);

    let caller = engine.allocate_executable_test_page(0x6F81_0000).unwrap();
    let mut caller_bytes = Vec::new();
    caller_bytes.extend_from_slice(&[0x48, 0xB9]);
    caller_bytes.extend_from_slice(&hwnd.to_le_bytes());
    caller_bytes.extend_from_slice(&[0x48, 0xBA]);
    caller_bytes.extend_from_slice(&(0x2B11u64).to_le_bytes());
    caller_bytes.extend_from_slice(&[0x49, 0xB8]);
    caller_bytes.extend_from_slice(&(0xAA55u64).to_le_bytes());
    caller_bytes.extend_from_slice(&[0x49, 0xB9]);
    caller_bytes.extend_from_slice(&(0x55AA_1234u64).to_le_bytes());
    caller_bytes.extend_from_slice(&[0x48, 0xB8]);
    caller_bytes.extend_from_slice(&send_message.to_le_bytes());
    caller_bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0]);
    caller_bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    engine.write_test_bytes(caller, &caller_bytes).unwrap();

    assert_eq!(
        engine.call_native_for_test(caller, &[]).unwrap(),
        wnd_proc_result
    );
    assert!(engine.ui.pending_user32_sendmessage_callbacks.is_empty());
}

#[test]
fn enum_windows_invokes_callback_sync_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let output_ptr = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F90_0000),
            "user32:test_enumwindows_output_x86",
            true,
        )
        .unwrap();
    engine.write_u32(output_ptr, 0).unwrap();

    let callback = engine.allocate_executable_test_page(0x6F91_0000).unwrap();
    engine
        .write_test_bytes(
            callback,
            &[
                0x8B, 0x4C, 0x24, 0x08, // mov ecx, [esp+8]
                0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
                0x89, 0x01, // mov [ecx], eax
                0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
                0xC2, 0x08, 0x00, // ret 8
            ],
        )
        .unwrap();

    let enum_windows = engine.bind_hook_for_test("user32.dll", "EnumWindows");
    assert_eq!(
        engine
            .dispatch_bound_stub(enum_windows, &[callback, output_ptr])
            .unwrap(),
        1
    );
    assert_ne!(engine.read_u32(output_ptr).unwrap(), 0);
}

#[test]
fn enum_windows_native_callback_can_call_nested_winapi_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let state_ptr = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F92_8000),
            "user32:test_enumwindows_nested_winapi_state_x86",
            true,
        )
        .unwrap();
    engine
        .write_u32(state_ptr, engine.current_process_id())
        .unwrap();
    engine.write_u32(state_ptr + 4, 0).unwrap();
    engine.write_u32(state_ptr + 8, 0).unwrap();
    engine.write_u32(state_ptr + 12, 0).unwrap();

    let get_window_thread_process_id =
        engine.bind_hook_for_test("user32.dll", "GetWindowThreadProcessId");
    let show_window = engine.bind_hook_for_test("user32.dll", "ShowWindow");

    let callback = engine.allocate_executable_test_page(0x6F93_8000).unwrap();
    let mut callback_bytes = vec![
        0x8B, 0x5C, 0x24, 0x04, // mov ebx, [esp+4]
        0x8B, 0x74, 0x24, 0x08, // mov esi, [esp+8]
        0x8D, 0x7E, 0x04, // lea edi, [esi+4]
        0x57, // push edi
        0x53, // push ebx
        0xB8, // mov eax, imm32
    ];
    callback_bytes.extend_from_slice(&(get_window_thread_process_id as u32).to_le_bytes());
    callback_bytes.extend_from_slice(&[
        0xFF, 0xD0, // call eax
        0x89, 0x46, 0x08, // mov [esi+8], eax
        0x8B, 0x4E, 0x04, // mov ecx, [esi+4]
        0x3B, 0x0E, // cmp ecx, [esi]
        0x75, 0x16, // jne return_true
        0x6A, 0x00, // push 0
        0x53, // push ebx
        0xB8, // mov eax, imm32
    ]);
    callback_bytes.extend_from_slice(&(show_window as u32).to_le_bytes());
    callback_bytes.extend_from_slice(&[
        0xFF, 0xD0, // call eax
        0xC7, 0x46, 0x0C, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [esi+0xc], 1
        0x31, 0xC0, // xor eax, eax
        0xC2, 0x08, 0x00, // ret 8
        0xB8, 0x01, 0x00, 0x00, 0x00, // return_true: mov eax, 1
        0xC2, 0x08, 0x00, // ret 8
    ]);
    engine.write_test_bytes(callback, &callback_bytes).unwrap();

    let enum_windows = engine.bind_hook_for_test("user32.dll", "EnumWindows");
    let caller = engine.allocate_executable_test_page(0x6F94_8000).unwrap();
    let mut caller_bytes = vec![0x68];
    caller_bytes.extend_from_slice(&(state_ptr as u32).to_le_bytes());
    caller_bytes.push(0x68);
    caller_bytes.extend_from_slice(&(callback as u32).to_le_bytes());
    caller_bytes.push(0xB8);
    caller_bytes.extend_from_slice(&(enum_windows as u32).to_le_bytes());
    caller_bytes.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
    engine.write_test_bytes(caller, &caller_bytes).unwrap();

    assert_eq!(engine.call_native_for_test(caller, &[]).unwrap(), 0);
    assert_eq!(
        engine.read_u32(state_ptr + 4).unwrap(),
        engine.current_process_id()
    );
    assert_eq!(engine.read_u32(state_ptr + 8).unwrap(), main_tid);
    assert_eq!(engine.read_u32(state_ptr + 12).unwrap(), 1);
    assert!(engine.ui.pending_user32_enumwindows_callbacks.is_empty());
}

#[test]
fn ldr_enumerate_loaded_modules_invokes_native_callback_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let output_ptr = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F94_0000),
            "ntdll:test_ldr_enum_output_x86",
            true,
        )
        .unwrap();
    engine.write_u32(output_ptr, 0).unwrap();

    let callback = engine.allocate_executable_test_page(0x6F95_0000).unwrap();
    engine
        .write_test_bytes(
            callback,
            &[
                0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
                0x8B, 0x4C, 0x24, 0x08, // mov ecx, [esp+8]
                0x89, 0x01, // mov [ecx], eax
                0x8B, 0x54, 0x24, 0x0C, // mov edx, [esp+0x0c]
                0xC6, 0x02, 0x01, // mov byte ptr [edx], 1
                0x31, 0xC0, // xor eax, eax
                0xC2, 0x0C, 0x00, // ret 12
            ],
        )
        .unwrap();

    let ldr_enum = engine.bind_hook_for_test("ntdll.dll", "LdrEnumerateLoadedModules");
    let caller = engine.allocate_executable_test_page(0x6F96_0000).unwrap();
    let mut caller_bytes = vec![
        0x68, // push imm32
    ];
    caller_bytes.extend_from_slice(&(output_ptr as u32).to_le_bytes());
    caller_bytes.push(0x68); // push imm32
    caller_bytes.extend_from_slice(&(callback as u32).to_le_bytes());
    caller_bytes.extend_from_slice(&[0x6A, 0x00]); // push 0
    caller_bytes.push(0xB8); // mov eax, imm32
    caller_bytes.extend_from_slice(&(ldr_enum as u32).to_le_bytes());
    caller_bytes.extend_from_slice(&[0xFF, 0xD0]); // call eax
    caller_bytes.push(0xA1); // mov eax, [imm32]
    caller_bytes.extend_from_slice(&(output_ptr as u32).to_le_bytes());
    caller_bytes.push(0xC3); // ret
    engine.write_test_bytes(caller, &caller_bytes).unwrap();

    assert_ne!(engine.call_native_for_test(caller, &[]).unwrap(), 0);
    assert!(engine.dispatch.pending_ldr_enum_callbacks.is_empty());
}

#[test]
fn rtl_exit_user_thread_forces_native_return_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let rtl_exit_user_thread = engine.bind_hook_for_test("ntdll.dll", "RtlExitUserThread");
    let caller = engine.allocate_executable_test_page(0x6F97_0000).unwrap();
    let mut caller_bytes = vec![0xB8];
    caller_bytes.extend_from_slice(&(rtl_exit_user_thread as u32).to_le_bytes());
    caller_bytes.extend_from_slice(&[0xFF, 0xD0]);
    caller_bytes.push(0xB8);
    caller_bytes.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    caller_bytes.push(0xC3);
    engine.write_test_bytes(caller, &caller_bytes).unwrap();

    assert_ne!(
        engine.call_native_for_test(caller, &[]).unwrap(),
        0xDEAD_BEEF
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("ready"));
    assert!(!engine.core.process_exit_requested);
}

#[test]
fn nt_exit_process_forces_native_return_x86() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let nt_exit_process = engine.bind_hook_for_test("ntdll.dll", "NtExitProcess");
    let caller = engine.allocate_executable_test_page(0x6F98_0000).unwrap();
    let mut caller_bytes = vec![0xB8];
    caller_bytes.extend_from_slice(&(nt_exit_process as u32).to_le_bytes());
    caller_bytes.extend_from_slice(&[0xFF, 0xD0]);
    caller_bytes.push(0xB8);
    caller_bytes.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    caller_bytes.push(0xC3);
    engine.write_test_bytes(caller, &caller_bytes).unwrap();

    assert_ne!(
        engine.call_native_for_test(caller, &[]).unwrap(),
        0xDEAD_BEEF
    );
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("ready"));
    assert!(engine.core.process_exit_requested);
}

#[test]
fn sleeping_current_thread_does_not_fast_forward_past_ready_worker() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let main_tid = engine.core.main_thread_tid.unwrap();
    let worker = engine
        .core
        .scheduler
        .create_virtual_thread(0x4029E7, 0x1316, false)
        .unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let tick_before = engine.dispatch.time.current().tick_ms;
    engine
        .core
        .scheduler
        .sleep_current_thread(tick_before, 12, false, false)
        .unwrap();
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("sleeping"));
    assert_eq!(engine.scheduler().thread_state(worker.tid), Some("ready"));

    engine.handle_requested_thread_yield();

    assert_eq!(engine.dispatch.time.current().tick_ms, tick_before);
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("sleeping"));
    assert_eq!(engine.core.scheduler.next_ready_tid(), Some(worker.tid));
}

#[test]
fn sleep_yields_after_returning_api_frame() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    assert_eq!(engine.call_native_for_test(sleep, &[12]).unwrap(), 0);

    assert!(engine.dispatch.thread_yield_requested());
    assert!(!engine.dispatch.api_return_deferred());
    let main_tid = engine.core.main_thread_tid.unwrap();
    let main_thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    assert_eq!(main_thread.state, "sleeping");
    assert_eq!(main_thread.wait_result, None);
}

#[test]
fn x86_entry_frame_continues_after_non_blocking_api() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let code = engine.allocate_executable_test_page(0x6F94_0000).unwrap();
    let hook = engine.bind_hook_for_test("kernel32.dll", "GetCurrentThreadId");
    let rel = (hook as i64) - (code as i64 + 5);
    let rel = i32::try_from(rel).unwrap();
    engine
        .write_test_bytes(
            code,
            &[
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
            ],
        )
        .unwrap();

    engine.prepare_scheduler_main_thread(code, &[]).unwrap();

    let retval = engine
        .call_x86_native_with_entry_frame_unicorn(code, &[])
        .unwrap();
    assert_eq!(retval, 0x1234);
}

#[test]
fn x86_entry_frame_resumes_after_sleep_without_ready_workers() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let code = engine.allocate_executable_test_page(0x6F95_0000).unwrap();
    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let get_tid = engine.bind_hook_for_test("kernel32.dll", "GetCurrentThreadId");
    let sleep_rel = i32::try_from((sleep as i64) - (code as i64 + 10)).unwrap();
    let get_tid_pc = code + 10;
    let get_tid_rel = i32::try_from((get_tid as i64) - (get_tid_pc as i64 + 5)).unwrap();
    engine
        .write_test_bytes(
            code,
            &[
                0x68,
                0xB4,
                0x00,
                0x00,
                0x00,
                0xE8,
                sleep_rel as u8,
                (sleep_rel >> 8) as u8,
                (sleep_rel >> 16) as u8,
                (sleep_rel >> 24) as u8,
                0xE8,
                get_tid_rel as u8,
                (get_tid_rel >> 8) as u8,
                (get_tid_rel >> 16) as u8,
                (get_tid_rel >> 24) as u8,
                0xC3,
            ],
        )
        .unwrap();

    engine.prepare_scheduler_main_thread(code, &[]).unwrap();

    let tick_before = engine.dispatch.time.current().tick_ms;
    let retval = engine
        .call_x86_native_with_entry_frame_unicorn(code, &[])
        .unwrap();
    assert_eq!(retval, engine.core.main_thread_tid.unwrap() as u64);
    assert!(engine.dispatch.time.current().tick_ms >= tick_before + 180);
}

#[test]
fn unicorn_scheduler_sleep_zero_yields_to_ready_worker_after_protected_fetch() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let main_code = engine.allocate_executable_test_page(0x6F95_8000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F95_9000).unwrap();
    let marker_page = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            PAGE_SIZE,
            Some(0x6F95_A000),
            "scheduler:test_sleep_zero_markers",
            true,
        )
        .unwrap();
    let worker_marker = marker_page;
    let main_marker = marker_page + 4;
    engine.write_u32(worker_marker, 0).unwrap();
    engine.write_u32(main_marker, 0).unwrap();

    engine
        .write_test_bytes(
            worker_code,
            &[
                0xC7,
                0x05,
                worker_marker as u8,
                (worker_marker >> 8) as u8,
                (worker_marker >> 16) as u8,
                (worker_marker >> 24) as u8,
                0x88,
                0x77,
                0x66,
                0x55,
                0x31,
                0xC0,
                0xC3,
            ],
        )
        .unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();

    let sleep_rel = i32::try_from((sleep as i64) - (main_code as i64 + 10)).unwrap();
    engine
        .write_test_bytes(
            main_code,
            &[
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0xE8,
                sleep_rel as u8,
                (sleep_rel >> 8) as u8,
                (sleep_rel >> 16) as u8,
                (sleep_rel >> 24) as u8,
                0x83,
                0x3D,
                worker_marker as u8,
                (worker_marker >> 8) as u8,
                (worker_marker >> 16) as u8,
                (worker_marker >> 24) as u8,
                0x00,
                0x74,
                0xED,
                0xC7,
                0x05,
                main_marker as u8,
                (main_marker >> 8) as u8,
                (main_marker >> 16) as u8,
                (main_marker >> 24) as u8,
                0x44,
                0x33,
                0x22,
                0x11,
                0xC3,
            ],
        )
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    engine.complete_process_startup_sequence().unwrap();
    engine.run_unicorn_scheduler_loop().unwrap();

    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x5566_7788);
    assert_eq!(engine.read_u32(main_marker).unwrap(), 0x1122_3344);
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.core.stop_reason,
        Some(RunStopReason::AllThreadsTerminated)
    );
}

#[test]
fn x86_entry_frame_does_not_continue_while_wait_still_blocked() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let get_tid = engine.bind_hook_for_test("kernel32.dll", "GetCurrentThreadId");
    let event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();
    let code = engine.allocate_executable_test_page(0x6F95_0000).unwrap();
    let wait_rel = (wait as i64) - (code as i64 + 15);
    let wait_rel = i32::try_from(wait_rel).unwrap();
    let get_tid_rel = (get_tid as i64) - (code as i64 + 20);
    let get_tid_rel = i32::try_from(get_tid_rel).unwrap();
    engine
        .write_test_bytes(
            code,
            &[
                0x68,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x68,
                event as u8,
                (event >> 8) as u8,
                (event >> 16) as u8,
                (event >> 24) as u8,
                0xE8,
                wait_rel as u8,
                (wait_rel >> 8) as u8,
                (wait_rel >> 16) as u8,
                (wait_rel >> 24) as u8,
                0xE8,
                get_tid_rel as u8,
                (get_tid_rel >> 8) as u8,
                (get_tid_rel >> 16) as u8,
                (get_tid_rel >> 24) as u8,
                0xC3,
            ],
        )
        .unwrap();

    engine.prepare_scheduler_main_thread(code, &[]).unwrap();

    let retval = engine
        .call_x86_native_with_entry_frame_unicorn(code, &[])
        .unwrap();
    assert_eq!(retval, WAIT_TIMEOUT as u64);
    let main_tid = engine.core.main_thread_tid.unwrap();
    assert_eq!(engine.scheduler().thread_state(main_tid), Some("waiting"));
}

#[test]
fn x86_entry_frame_wait_on_ready_worker_switches_to_worker() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let create_thread = engine.bind_hook_for_test("kernel32.dll", "CreateThread");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let main_code = engine.allocate_executable_test_page(0x6F96_0000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F96_1000).unwrap();
    let handle_slot = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F96_2000),
            "scheduler:test_wait_handle",
            true,
        )
        .unwrap();
    engine.write_u32(handle_slot, 0).unwrap();
    engine
        .write_test_bytes(worker_code, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
        .unwrap();

    let create_rel = (create_thread as i64) - (main_code as i64 + 35);
    let create_rel = i32::try_from(create_rel).unwrap();
    let wait_rel = (wait as i64) - (main_code as i64 + 51);
    let wait_rel = i32::try_from(wait_rel).unwrap();
    engine
        .write_test_bytes(
            main_code,
            &[
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0x68,
                worker_code as u8,
                (worker_code >> 8) as u8,
                (worker_code >> 16) as u8,
                (worker_code >> 24) as u8,
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0x68,
                0x00,
                0x00,
                0x00,
                0x00,
                0xE8,
                create_rel as u8,
                (create_rel >> 8) as u8,
                (create_rel >> 16) as u8,
                (create_rel >> 24) as u8,
                0xA3,
                handle_slot as u8,
                (handle_slot >> 8) as u8,
                (handle_slot >> 16) as u8,
                (handle_slot >> 24) as u8,
                0x68,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x50,
                0xE8,
                wait_rel as u8,
                (wait_rel >> 8) as u8,
                (wait_rel >> 16) as u8,
                (wait_rel >> 24) as u8,
                0xC3,
            ],
        )
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();

    assert_eq!(
        engine
            .call_x86_native_with_entry_frame_unicorn(main_code, &[])
            .unwrap(),
        WAIT_OBJECT_0 as u64
    );
    let worker_handle = engine.read_u32(handle_slot).unwrap();
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
    assert_eq!(
        engine.scheduler().thread_exit_code(worker_tid),
        Some(Some(0x2A))
    );
}

#[test]
fn x86_entry_frame_sleep_runs_ready_worker_before_resuming_main() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let sleep = engine.bind_hook_for_test("kernel32.dll", "Sleep");
    let main_code = engine.allocate_executable_test_page(0x6F98_0000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F98_1000).unwrap();
    let worker_marker = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F98_2000),
            "scheduler:test_sleep_worker_marker",
            true,
        )
        .unwrap();
    engine.write_u32(worker_marker, 0).unwrap();
    engine
        .write_test_bytes(
            worker_code,
            &[
                0xC7,
                0x05,
                worker_marker as u8,
                (worker_marker >> 8) as u8,
                (worker_marker >> 16) as u8,
                (worker_marker >> 24) as u8,
                0x44,
                0x33,
                0x22,
                0x11,
                0xB8,
                0x2A,
                0x00,
                0x00,
                0x00,
                0xC3,
            ],
        )
        .unwrap();
    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();

    let sleep_rel = (sleep as i64) - (main_code as i64 + 7);
    let sleep_rel = i32::try_from(sleep_rel).unwrap();
    engine
        .write_test_bytes(
            main_code,
            &[
                0x6A,
                0x05, // 5 ms
                0xE8,
                sleep_rel as u8,
                (sleep_rel >> 8) as u8,
                (sleep_rel >> 16) as u8,
                (sleep_rel >> 24) as u8,
                0xB8,
                0x34,
                0x12,
                0x00,
                0x00,
                0xC3,
            ],
        )
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    let retval = engine
        .call_x86_native_with_entry_frame_unicorn(main_code, &[])
        .unwrap();
    assert_eq!(retval, 0x1234);
    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x1122_3344);
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
}

#[test]
fn x86_entry_frame_wait_on_unrelated_object_runs_ready_worker_then_times_out() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x86());

    let create_event = engine.bind_hook_for_test("kernel32.dll", "CreateEventW");
    let wait = engine.bind_hook_for_test("kernel32.dll", "WaitForSingleObject");
    let main_code = engine.allocate_executable_test_page(0x6F99_0000).unwrap();
    let worker_code = engine.allocate_executable_test_page(0x6F99_1000).unwrap();
    let worker_marker = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F99_2000),
            "scheduler:test_wait_worker_marker",
            true,
        )
        .unwrap();
    engine.write_u32(worker_marker, 0).unwrap();
    engine
        .write_test_bytes(
            worker_code,
            &[
                0xC7,
                0x05,
                worker_marker as u8,
                (worker_marker >> 8) as u8,
                (worker_marker >> 16) as u8,
                (worker_marker >> 24) as u8,
                0x44,
                0x33,
                0x22,
                0x11,
                0xC3,
            ],
        )
        .unwrap();

    let worker_handle = engine.create_runtime_thread(worker_code, 0, 0, 0).unwrap() as u32;
    let worker_tid = engine
        .scheduler()
        .thread_tid_for_handle(worker_handle)
        .unwrap();
    let event = engine
        .dispatch_bound_stub(create_event, &[0, 0, 0, 0])
        .unwrap();

    let wait_rel = (wait as i64) - (main_code as i64 + 15);
    let wait_rel = i32::try_from(wait_rel).unwrap();
    engine
        .write_test_bytes(
            main_code,
            &[
                0x68,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x68,
                event as u8,
                (event >> 8) as u8,
                (event >> 16) as u8,
                (event >> 24) as u8,
                0xE8,
                wait_rel as u8,
                (wait_rel >> 8) as u8,
                (wait_rel >> 16) as u8,
                (wait_rel >> 24) as u8,
                0xC3,
            ],
        )
        .unwrap();

    engine
        .prepare_scheduler_main_thread(main_code, &[])
        .unwrap();
    let retval = engine
        .call_x86_native_with_entry_frame_unicorn(main_code, &[])
        .unwrap();
    assert_eq!(retval, WAIT_TIMEOUT as u64);
    assert_eq!(engine.read_u32(worker_marker).unwrap(), 0x1122_3344);
    assert_eq!(
        engine.scheduler().thread_state(worker_tid),
        Some("terminated")
    );
}

#[test]
fn enum_windows_invokes_callback_sync_x64() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x64());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let output_ptr = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F92_0000),
            "user32:test_enumwindows_output_x64",
            true,
        )
        .unwrap();
    engine.write_pointer_value(output_ptr, 0).unwrap();

    let callback = engine.allocate_executable_test_page(0x6F93_0000).unwrap();
    engine
        .write_test_bytes(
            callback,
            &[
                0x48, 0x89, 0x0A, // mov [rdx], rcx
                0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
                0xC3, // ret
            ],
        )
        .unwrap();

    let enum_windows = engine.bind_hook_for_test("user32.dll", "EnumWindows");
    assert_eq!(
        engine
            .dispatch_bound_stub(enum_windows, &[callback, output_ptr])
            .unwrap(),
        1
    );
    assert_ne!(engine.read_pointer_value(output_ptr).unwrap(), 0);
    assert!(engine.ui.pending_user32_enumwindows_callbacks.is_empty());
}

#[test]
fn get_window_thread_process_id_supports_synthetic_active_window_x64() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    assert!(engine.core.arch.is_x64());

    let main_tid = engine.core.main_thread_tid.unwrap();
    engine
        .core
        .scheduler
        .switch_to(main_tid, &mut engine.core.process_env)
        .unwrap();

    let process_id_ptr = engine
        .core
        .modules
        .memory_mut()
        .reserve(
            0x1000,
            Some(0x6F95_0000),
            "user32:test_window_pid_x64",
            true,
        )
        .unwrap();
    engine.write_u32(process_id_ptr, 0).unwrap();

    let get_active_window = engine.bind_hook_for_test("user32.dll", "GetActiveWindow");
    let get_window_thread_process_id =
        engine.bind_hook_for_test("user32.dll", "GetWindowThreadProcessId");

    let hwnd = engine.dispatch_bound_stub(get_active_window, &[]).unwrap();
    let thread_id = engine
        .dispatch_bound_stub(get_window_thread_process_id, &[hwnd, process_id_ptr])
        .unwrap();

    assert_ne!(hwnd, 0);
    assert_eq!(thread_id, main_tid as u64);
    assert_eq!(
        engine.read_u32(process_id_ptr).unwrap(),
        engine.current_process_id()
    );
}

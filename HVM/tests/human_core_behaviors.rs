use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::{load_config, EngineConfig};
use hvm::runtime::engine::VirtualExecutionEngine;

const HKEY_CURRENT_USER: u64 = 0x8000_0001;
const REG_SZ: u32 = 1;

fn unique_root(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn human_only_config(config_name: &str, root: &Path) -> (EngineConfig, PathBuf) {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs")
        .join(config_name);
    let mut config = load_config(config_path).unwrap();
    let human_path = root.join("trace.api.human.log");
    config.trace_api_calls = false;
    config.api_log_path = None;
    config.api_jsonl_path = None;
    config.api_human_log_path = Some(human_path.clone());
    (config, human_path)
}

fn alloc_page(engine: &mut VirtualExecutionEngine, preferred: u64) -> u64 {
    let address = engine.allocate_executable_test_page(preferred).unwrap();
    engine.write_test_bytes(address, &[0u8; 0x1000]).unwrap();
    address
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn write_sockaddr_v4(engine: &mut VirtualExecutionEngine, address: u64, host: [u8; 4], port: u16) {
    let mut bytes = [0u8; 16];
    bytes[0..2].copy_from_slice(&2u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&host);
    engine.write_test_bytes(address, &bytes).unwrap();
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

fn write_service_profile(root: &Path) -> PathBuf {
    let path = root.join("environment_profile.json");
    fs::write(
        &path,
        r#"{
  "services": [
    {
      "name": "WinDefend",
      "display_name": "Microsoft Defender Antivirus Service",
      "service_type": 32,
      "start_type": 2,
      "current_state": 1,
      "controls_accepted": 1,
      "process_id": 0
    }
  ]
}"#,
    )
    .unwrap();
    path
}

#[test]
fn human_log_records_registry_core_behaviors_without_api_trace() {
    let root = unique_root("human-registry");
    let (config, human_path) =
        human_only_config("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json", &root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let create_key = engine.bind_hook_for_test("advapi32.dll", "RegCreateKeyExW");
    let open_key = engine.bind_hook_for_test("advapi32.dll", "RegOpenKeyExW");
    let set_value = engine.bind_hook_for_test("advapi32.dll", "RegSetValueExW");
    let query_value = engine.bind_hook_for_test("advapi32.dll", "RegQueryValueExW");
    let delete_value = engine.bind_hook_for_test("advapi32.dll", "RegDeleteValueW");
    let delete_key = engine.bind_hook_for_test("advapi32.dll", "RegDeleteKeyW");

    let page = alloc_page(&mut engine, 0x7800_0000);
    let subkey_ptr = page;
    let value_name_ptr = page + 0x200;
    let data_ptr = page + 0x300;
    let out_handle_ptr = page + 0x400;
    let open_handle_ptr = page + 0x404;
    let disposition_ptr = page + 0x408;
    let type_ptr = page + 0x40C;
    let size_ptr = page + 0x410;

    write_wide(&mut engine, subkey_ptr, r"Software\HumanCore");
    write_wide(&mut engine, value_name_ptr, "BeaconPath");
    write_wide(&mut engine, data_ptr, r"C:\Users\Public\beacon.exe");
    engine
        .write_test_bytes(size_ptr, &64u32.to_le_bytes())
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                create_key,
                &[
                    HKEY_CURRENT_USER,
                    subkey_ptr,
                    0,
                    0,
                    0,
                    0,
                    0,
                    out_handle_ptr,
                    disposition_ptr
                ],
            )
            .unwrap(),
        0
    );
    let handle = read_u32(&engine, out_handle_ptr) as u64;
    assert_ne!(handle, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                open_key,
                &[HKEY_CURRENT_USER, subkey_ptr, 0, 0, open_handle_ptr]
            )
            .unwrap(),
        0
    );
    let opened_handle = read_u32(&engine, open_handle_ptr) as u64;
    assert_ne!(opened_handle, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                set_value,
                &[
                    handle,
                    value_name_ptr,
                    0,
                    REG_SZ as u64,
                    data_ptr,
                    ((r"C:\Users\Public\beacon.exe".encode_utf16().count() + 1) * 2) as u64,
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_value,
                &[
                    opened_handle,
                    value_name_ptr,
                    0,
                    type_ptr,
                    data_ptr,
                    size_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(delete_value, &[opened_handle, value_name_ptr])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(delete_key, &[HKEY_CURRENT_USER, subkey_ptr])
            .unwrap(),
        0
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[REG_CREATE_KEY]"));
    assert!(human_log.contains("[REG_OPEN_KEY]"));
    assert!(human_log.contains("[REG_SET_VALUE]"));
    assert!(human_log.contains("[REG_QUERY_VALUE]"));
    assert!(human_log.contains("[REG_DELETE_VALUE]"));
    assert!(human_log.contains("[REG_DELETE_KEY]"));
    assert!(human_log.contains("Software\\\\HumanCore"));
    assert!(human_log.contains("BeaconPath"));
    assert!(human_log.contains(r#"preview_hex="43 00 3A 00 5C 00 55 00 73 00 ...""#));
}

#[test]
fn human_log_records_service_core_behaviors_without_api_trace() {
    let root = unique_root("human-services");
    let profile_path = write_service_profile(&root);
    let (mut config, human_path) =
        human_only_config("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json", &root);
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_scm = engine.bind_hook_for_test("advapi32.dll", "OpenSCManagerW");
    let open_service = engine.bind_hook_for_test("advapi32.dll", "OpenServiceW");
    let start_service = engine.bind_hook_for_test("advapi32.dll", "StartServiceW");
    let control_service = engine.bind_hook_for_test("advapi32.dll", "ControlService");

    let service_name = alloc_page(&mut engine, 0x7810_0000);
    let status_ptr = service_name + 0x200;
    write_wide(&mut engine, service_name, "WinDefend");

    let scm = engine
        .dispatch_bound_stub(open_scm, &[0, 0, 0xF003F])
        .unwrap();
    assert_ne!(scm, 0);

    let service = engine
        .dispatch_bound_stub(open_service, &[scm, service_name, 0xF01FF])
        .unwrap();
    assert_ne!(service, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(start_service, &[service, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(control_service, &[service, 1, status_ptr])
            .unwrap(),
        1
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[SERVICE_OPEN_MANAGER]"));
    assert!(human_log.contains("[SERVICE_OPEN]"));
    assert!(human_log.contains("[SERVICE_START]"));
    assert!(human_log.contains("[SERVICE_CONTROL]"));
    assert!(human_log.contains("WinDefend"));
    assert!(human_log.contains("SERVICE_CONTROL_STOP"));
}

#[test]
fn human_log_records_http_core_behaviors_without_api_trace() {
    let root = unique_root("human-http");
    let (config, human_path) =
        human_only_config("sample_42c4b1eaeba9de5a873970687b4abc34_trace.json", &root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpen");
    let connect = engine.bind_hook_for_test("winhttp.dll", "WinHttpConnect");
    let open_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpenRequest");
    let send_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpSendRequest");
    let write_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpWriteData");

    let agent = alloc_page(&mut engine, 0x7820_0000);
    let server = alloc_page(&mut engine, 0x7820_1000);
    let verb = alloc_page(&mut engine, 0x7820_2000);
    let object = alloc_page(&mut engine, 0x7820_3000);
    let headers = alloc_page(&mut engine, 0x7820_4000);
    let body = alloc_page(&mut engine, 0x7820_5000);
    let extra = alloc_page(&mut engine, 0x7820_6000);
    let written_ptr = alloc_page(&mut engine, 0x7820_7000);
    write_wide(&mut engine, agent, "Rust Agent");
    write_wide(&mut engine, server, "example.com");
    write_wide(&mut engine, verb, "POST");
    write_wide(&mut engine, object, "/submit");
    write_wide(&mut engine, headers, "X-Test: 1");
    engine.write_test_bytes(body, b"payload-123").unwrap();
    engine.write_test_bytes(extra, b"++").unwrap();
    engine.write_test_bytes(written_ptr, &[0u8; 4]).unwrap();

    let session = engine
        .dispatch_bound_stub(open, &[agent, 1, 0, 0, 0])
        .unwrap();
    let connection = engine
        .dispatch_bound_stub(connect, &[session, server, 443, 0])
        .unwrap();
    let request = engine
        .dispatch_bound_stub(open_request, &[connection, verb, object, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                send_request,
                &[request, headers, u32::MAX as u64, body, 11, 13, 0]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(write_data, &[request, extra, 2, written_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, written_ptr), 2);

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[HTTP_CONNECT]"));
    assert!(human_log.contains("[HTTP_REQUEST]"));
    assert!(human_log.contains("example.com"));
    assert!(human_log.contains("/submit"));
    assert!(human_log.contains("POST"));
    assert!(human_log.contains("body_len=13"));
    assert!(human_log.contains(r#"preview_hex="70 61 79 6C 6F 61 64 2D 31 32 ...""#));
}

#[test]
fn human_log_records_file_write_preview_hex() {
    let root = unique_root("human-file-write-preview");
    let (mut config, human_path) =
        human_only_config("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json", &root);
    config.allowed_read_dirs.push(root.clone());
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let create_file = engine.bind_hook_for_test("kernel32.dll", "CreateFileW");
    let write_file = engine.bind_hook_for_test("kernel32.dll", "WriteFile");

    let page = alloc_page(&mut engine, 0x7828_0000);
    let path_ptr = page;
    let data_ptr = page + 0x400;
    let written_ptr = page + 0x500;
    let output_path = root.join("preview.bin");
    let mut path_bytes = output_path
        .to_string_lossy()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    path_bytes.extend_from_slice(&[0, 0]);
    let data = b"ABCDEFGHIJKL";

    engine.write_test_bytes(path_ptr, &path_bytes).unwrap();
    engine.write_test_bytes(data_ptr, data).unwrap();
    engine.write_test_bytes(written_ptr, &[0u8; 4]).unwrap();

    let handle = engine
        .dispatch_bound_stub(create_file, &[path_ptr, 0x4000_0000, 0, 0, 2, 0, 0])
        .unwrap();
    assert_ne!(handle, u32::MAX as u64);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_file,
                &[handle, data_ptr, data.len() as u64, written_ptr, 0]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, written_ptr), data.len() as u32);

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[FILE_WRITE]"));
    assert!(human_log.contains(r#"preview_hex="41 42 43 44 45 46 47 48 49 4A ...""#));
    assert_eq!(fs::read(output_path).unwrap(), data);
}

#[test]
fn human_log_records_mem_write_preview_hex() {
    let root = unique_root("human-mem-write-preview");
    let (config, human_path) =
        human_only_config("sample_567dbfa9f7d29702a70feb934ec08e54_trace.json", &root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_current_process = engine.bind_hook_for_test("kernel32.dll", "GetCurrentProcess");
    let write_process_memory = engine.bind_hook_for_test("kernel32.dll", "WriteProcessMemory");

    let target = alloc_page(&mut engine, 0x7829_0000);
    let source = alloc_page(&mut engine, 0x7829_1000);
    let written_ptr = alloc_page(&mut engine, 0x7829_2000);
    let data = b"ABCDEFGHIJKL";
    engine.write_test_bytes(source, data).unwrap();
    engine.write_test_bytes(written_ptr, &[0u8; 8]).unwrap();

    let process = engine
        .dispatch_bound_stub(get_current_process, &[])
        .unwrap();
    assert_ne!(process, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                write_process_memory,
                &[process, target, source, data.len() as u64, written_ptr]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, written_ptr), data.len() as u32);
    assert_eq!(
        engine.modules().memory().read(target, data.len()).unwrap(),
        data
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[MEM_WRITE]"));
    assert!(human_log.contains(r#"preview_hex="41 42 43 44 45 46 47 48 49 4A ...""#));
}

#[test]
fn human_log_records_socket_core_behaviors_without_api_trace() {
    let root = unique_root("human-socket");
    let (config, human_path) =
        human_only_config("sample_42c4b1eaeba9de5a873970687b4abc34_trace.json", &root);
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let socket_hook = engine.bind_hook_for_test("ws2_32.dll", "socket");
    let connect_hook = engine.bind_hook_for_test("ws2_32.dll", "connect");
    let sendto_hook = engine.bind_hook_for_test("ws2_32.dll", "sendto");
    let recvfrom_hook = engine.bind_hook_for_test("ws2_32.dll", "recvfrom");

    let page = alloc_page(&mut engine, 0x7830_0000);
    let sockaddr_ptr = page;
    let send_buf_ptr = page + 0x100;
    let recv_buf_ptr = page + 0x200;
    let from_sockaddr_ptr = page + 0x300;
    let from_len_ptr = page + 0x400;
    write_sockaddr_v4(&mut engine, sockaddr_ptr, [45, 204, 201, 140], 6666);
    engine.write_test_bytes(send_buf_ptr, b"ping").unwrap();
    engine
        .write_test_bytes(from_len_ptr, &16u32.to_le_bytes())
        .unwrap();

    let socket = engine.dispatch_bound_stub(socket_hook, &[2, 1, 6]).unwrap();
    assert_ne!(socket, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(connect_hook, &[socket, sockaddr_ptr, 16])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(sendto_hook, &[socket, send_buf_ptr, 4, 0, sockaddr_ptr, 16])
            .unwrap(),
        4
    );
    engine
        .network_manager_mut()
        .with_socket_mut(socket as u32, |sock| {
            sock.recv_queue.push(b"pong".to_vec());
        })
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                recvfrom_hook,
                &[socket, recv_buf_ptr, 4, 0, from_sockaddr_ptr, from_len_ptr],
            )
            .unwrap(),
        4
    );

    engine.flush_api_logs_for_test().unwrap();
    let human_log = fs::read_to_string(human_path).unwrap();
    assert!(human_log.contains("[SOCKET_CREATE]"));
    assert!(human_log.contains("[SOCKET_CONNECT]"));
    assert!(human_log.contains("[SOCKET_SEND]"));
    assert!(human_log.contains("[SOCKET_RECV]"));
    assert!(human_log.contains("45.204.201.140"));
    assert!(human_log.contains("6666"));
    assert!(human_log.contains(r#"preview_hex="70 69 6E 67""#));
}

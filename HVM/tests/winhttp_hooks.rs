use std::path::Path;

use hvm::config::{
    load_config, HttpResponseHeader, HttpResponsePayload, HttpResponseRule,
};
use hvm::runtime::engine::VirtualExecutionEngine;

fn read_u32(engine: &VirtualExecutionEngine, address: u64) -> u32 {
    let bytes = engine.modules().memory().read(address, 4).unwrap();
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn alloc_wide(engine: &mut VirtualExecutionEngine, base: u64, text: &str) -> u64 {
    let address = engine.allocate_executable_test_page(base).unwrap();
    let bytes = text
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0, 0])
        .collect::<Vec<_>>();
    engine.write_test_bytes(address, &bytes).unwrap();
    address
}

fn sample_config_x86() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn sample_config_x64() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    load_config(config_path).unwrap()
}

#[test]
fn winhttp_get_ie_proxy_config_zeros_x86_output_structure() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x86()).unwrap();
    engine.load().unwrap();

    let hook = engine.bind_hook_for_test("winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser");
    let buffer = engine.allocate_executable_test_page(0x6310_0000).unwrap();
    engine.write_test_bytes(buffer, &[0xAA; 16]).unwrap();

    assert_eq!(engine.dispatch_bound_stub(hook, &[buffer]).unwrap(), 1);
    assert_eq!(engine.last_error(), 0);
    assert_eq!(
        engine.modules().memory().read(buffer, 16).unwrap(),
        vec![0; 16]
    );
}

#[test]
fn winhttp_get_ie_proxy_config_zeros_x64_output_structure() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let hook = engine.bind_hook_for_test("winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser");
    let buffer = engine.allocate_executable_test_page(0x6311_0000).unwrap();
    engine.write_test_bytes(buffer, &[0xAA; 32]).unwrap();

    assert_eq!(engine.dispatch_bound_stub(hook, &[buffer]).unwrap(), 1);
    assert_eq!(engine.last_error(), 0);
    assert_eq!(
        engine.modules().memory().read(buffer, 32).unwrap(),
        vec![0; 32]
    );
}

#[test]
fn winhttp_basic_session_request_and_proxy_hooks_use_network_manager() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let open = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpen");
    let connect = engine.bind_hook_for_test("winhttp.dll", "WinHttpConnect");
    let open_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpenRequest");
    let add_headers = engine.bind_hook_for_test("winhttp.dll", "WinHttpAddRequestHeaders");
    let send_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpSendRequest");
    let receive_response = engine.bind_hook_for_test("winhttp.dll", "WinHttpReceiveResponse");
    let query_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpQueryDataAvailable");
    let query_headers = engine.bind_hook_for_test("winhttp.dll", "WinHttpQueryHeaders");
    let get_proxy = engine.bind_hook_for_test("winhttp.dll", "WinHttpGetProxyForUrl");
    let close_handle = engine.bind_hook_for_test("winhttp.dll", "WinHttpCloseHandle");

    let agent = alloc_wide(&mut engine, 0x6320_0000, "Rust Agent");
    let server = alloc_wide(&mut engine, 0x6320_1000, "example.com");
    let verb = alloc_wide(&mut engine, 0x6320_2000, "GET");
    let object = alloc_wide(&mut engine, 0x6320_3000, "/");
    let version = alloc_wide(&mut engine, 0x6320_4000, "HTTP/1.1");
    let headers = alloc_wide(&mut engine, 0x6320_5000, "X-Test: 1");
    let query_buffer = engine.allocate_executable_test_page(0x6320_6000).unwrap();
    let query_len = engine.allocate_executable_test_page(0x6320_7000).unwrap();
    let remaining_ptr = engine.allocate_executable_test_page(0x6320_8000).unwrap();
    let proxy_info = engine.allocate_executable_test_page(0x6320_9000).unwrap();
    engine.write_test_bytes(query_buffer, &[0xAA; 128]).unwrap();
    engine.write_test_bytes(query_len, &[0; 8]).unwrap();
    engine.write_test_bytes(remaining_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(proxy_info, &[0xAA; 24]).unwrap();

    let session = engine
        .dispatch_bound_stub(open, &[agent, 1, 0, 0, 0])
        .unwrap();
    let connection = engine
        .dispatch_bound_stub(connect, &[session, server, 443, 0])
        .unwrap();
    let request = engine
        .dispatch_bound_stub(
            open_request,
            &[connection, verb, object, version, 0, 0, 0, 0],
        )
        .unwrap();

    assert_ne!(session, 0);
    assert_ne!(connection, 0);
    assert_ne!(request, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(add_headers, &[request, headers, u32::MAX as u64, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(send_request, &[request, 0, 0, 0, 0, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(receive_response, &[request, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(query_data, &[request, remaining_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, remaining_ptr), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_headers,
                &[request, 0x2000_0000 | 19, 0, query_buffer, query_len, 0],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, query_len), 4);
    assert_eq!(read_u32(&engine, query_buffer), 200);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_proxy, &[session, object, 0, proxy_info])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, proxy_info), 1);
    assert_eq!(
        engine
            .dispatch_bound_stub(close_handle, &[request])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_handle, &[connection])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_handle, &[session])
            .unwrap(),
        1
    );
}

#[test]
fn winhttp_configured_response_rule_exposes_non_empty_body() {
    let mut config = sample_config_x64();
    config.http_response_rules = vec![HttpResponseRule {
        host: Some("example.com".to_string()),
        path: Some("/".to_string()),
        verb: Some("GET".to_string()),
        responses: vec![HttpResponsePayload {
            status_code: 200,
            headers: vec![HttpResponseHeader {
                name: "Content-Type".to_string(),
                value: "text/plain".to_string(),
            }],
            body: b"hello".to_vec(),
        }],
    }];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpen");
    let connect = engine.bind_hook_for_test("winhttp.dll", "WinHttpConnect");
    let open_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpenRequest");
    let receive_response = engine.bind_hook_for_test("winhttp.dll", "WinHttpReceiveResponse");
    let query_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpQueryDataAvailable");
    let read_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpReadData");

    let agent = alloc_wide(&mut engine, 0x6330_0000, "Rust Agent");
    let server = alloc_wide(&mut engine, 0x6330_1000, "example.com");
    let verb = alloc_wide(&mut engine, 0x6330_2000, "GET");
    let object = alloc_wide(&mut engine, 0x6330_3000, "/");
    let available_ptr = engine.allocate_executable_test_page(0x6330_4000).unwrap();
    let read_ptr = engine.allocate_executable_test_page(0x6330_5000).unwrap();
    let body_ptr = engine.allocate_executable_test_page(0x6330_6000).unwrap();
    engine.write_test_bytes(available_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(read_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(body_ptr, &[0; 16]).unwrap();

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
            .dispatch_bound_stub(receive_response, &[request, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(query_data, &[request, available_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, available_ptr), 5);
    assert_eq!(
        engine
            .dispatch_bound_stub(read_data, &[request, body_ptr, 5, read_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, read_ptr), 5);
    assert_eq!(
        engine.modules().memory().read(body_ptr, 5).unwrap(),
        b"hello"
    );
}

#[test]
fn winhttp_response_rule_sequence_advances_across_requests() {
    let mut config = sample_config_x64();
    config.http_response_rules = vec![HttpResponseRule {
        host: Some("example.com".to_string()),
        path: Some("/poll".to_string()),
        verb: Some("GET".to_string()),
        responses: vec![
            HttpResponsePayload {
                status_code: 204,
                headers: Vec::new(),
                body: Vec::new(),
            },
            HttpResponsePayload {
                status_code: 200,
                headers: vec![HttpResponseHeader {
                    name: "Content-Type".to_string(),
                    value: "text/plain".to_string(),
                }],
                body: b"task".to_vec(),
            },
        ],
    }];

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpen");
    let connect = engine.bind_hook_for_test("winhttp.dll", "WinHttpConnect");
    let open_request = engine.bind_hook_for_test("winhttp.dll", "WinHttpOpenRequest");
    let receive_response = engine.bind_hook_for_test("winhttp.dll", "WinHttpReceiveResponse");
    let query_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpQueryDataAvailable");
    let query_headers = engine.bind_hook_for_test("winhttp.dll", "WinHttpQueryHeaders");
    let read_data = engine.bind_hook_for_test("winhttp.dll", "WinHttpReadData");

    let agent = alloc_wide(&mut engine, 0x6340_0000, "Rust Agent");
    let server = alloc_wide(&mut engine, 0x6340_1000, "example.com");
    let verb = alloc_wide(&mut engine, 0x6340_2000, "GET");
    let object = alloc_wide(&mut engine, 0x6340_3000, "/poll");
    let available_ptr = engine.allocate_executable_test_page(0x6340_4000).unwrap();
    let read_ptr = engine.allocate_executable_test_page(0x6340_5000).unwrap();
    let body_ptr = engine.allocate_executable_test_page(0x6340_6000).unwrap();
    let status_len_ptr = engine.allocate_executable_test_page(0x6340_7000).unwrap();
    let status_buf = engine.allocate_executable_test_page(0x6340_8000).unwrap();
    engine.write_test_bytes(available_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(read_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(body_ptr, &[0; 16]).unwrap();
    engine.write_test_bytes(status_len_ptr, &[0; 8]).unwrap();
    engine.write_test_bytes(status_buf, &[0; 8]).unwrap();

    let session = engine
        .dispatch_bound_stub(open, &[agent, 1, 0, 0, 0])
        .unwrap();
    let connection = engine
        .dispatch_bound_stub(connect, &[session, server, 443, 0])
        .unwrap();

    let first_request = engine
        .dispatch_bound_stub(open_request, &[connection, verb, object, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(receive_response, &[first_request, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(query_data, &[first_request, available_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, available_ptr), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_headers,
                &[
                    first_request,
                    0x2000_0000 | 19,
                    0,
                    status_buf,
                    status_len_ptr,
                    0
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status_buf), 204);

    let second_request = engine
        .dispatch_bound_stub(open_request, &[connection, verb, object, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(receive_response, &[second_request, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(query_data, &[second_request, available_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, available_ptr), 4);
    assert_eq!(
        engine
            .dispatch_bound_stub(read_data, &[second_request, body_ptr, 4, read_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, read_ptr), 4);
    assert_eq!(
        engine.modules().memory().read(body_ptr, 4).unwrap(),
        b"task"
    );
}

use std::path::Path;

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config_x64() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    load_config(config_path).unwrap()
}

fn alloc_c_string(engine: &mut VirtualExecutionEngine, base: u64, text: &str) -> u64 {
    let address = engine.allocate_executable_test_page(base).unwrap();
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    engine.write_test_bytes(address, &bytes).unwrap();
    address
}

fn pointer_size(engine: &VirtualExecutionEngine) -> usize {
    if engine
        .main_module()
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        8
    } else {
        4
    }
}

fn read_ptr(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    let size = pointer_size(engine);
    let bytes = engine.modules().memory().read(address, size).unwrap();
    if size == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn read_u16(engine: &VirtualExecutionEngine, address: u64) -> u16 {
    let bytes = engine.modules().memory().read(address, 2).unwrap();
    u16::from_le_bytes(bytes.try_into().unwrap())
}

fn read_hostent_ipv4(engine: &VirtualExecutionEngine, hostent: u64) -> String {
    let addr_list_offset = if pointer_size(engine) == 8 { 24 } else { 12 };
    let addr_list = read_ptr(engine, hostent + addr_list_offset);
    let addr = read_ptr(engine, addr_list);
    let bytes = engine.modules().memory().read(addr, 4).unwrap();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn read_sockaddr_ipv4(engine: &VirtualExecutionEngine, sockaddr: u64) -> (String, u16) {
    let bytes = engine.modules().memory().read(sockaddr, 16).unwrap();
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    (
        format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]),
        port,
    )
}

#[test]
fn gethostbyname_preserves_numeric_ipv4_literal() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let hook = engine.bind_hook_for_test("ws2_32.dll", "gethostbyname");
    let name = alloc_c_string(&mut engine, 0x6350_0000, "45.204.201.140");

    let hostent = engine.dispatch_bound_stub(hook, &[name]).unwrap();

    assert_ne!(hostent, 0);
    assert_eq!(read_hostent_ipv4(&engine, hostent), "45.204.201.140");
}

#[test]
fn getaddrinfo_preserves_numeric_ipv4_literal() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let hook = engine.bind_hook_for_test("ws2_32.dll", "getaddrinfo");
    let node = alloc_c_string(&mut engine, 0x6351_0000, "45.204.201.140");
    let service = alloc_c_string(&mut engine, 0x6351_1000, "6666");
    let out_ptr = engine.allocate_executable_test_page(0x6351_2000).unwrap();
    engine.write_test_bytes(out_ptr, &[0; 8]).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(hook, &[node, service, 0, out_ptr])
            .unwrap(),
        0
    );

    let addrinfo = read_ptr(&engine, out_ptr);
    assert_ne!(addrinfo, 0);
    let sockaddr_offset = if pointer_size(&engine) == 8 { 32 } else { 24 };
    let sockaddr = read_ptr(&engine, addrinfo + sockaddr_offset);
    assert_ne!(sockaddr, 0);
    assert_eq!(read_u16(&engine, sockaddr), 2);
    assert_eq!(
        read_sockaddr_ipv4(&engine, sockaddr),
        ("45.204.201.140".to_string(), 6666)
    );
}

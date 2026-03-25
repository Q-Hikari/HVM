use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

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

fn write_profile(root: &PathBuf) -> PathBuf {
    let path = root.join("environment_profile.json");
    fs::write(
        &path,
        r#"{
  "machine": {
    "computer_name": "WINLAB-42",
    "user_name": "analyst",
    "user_domain": "CORP"
  },
  "display": {
    "remote_session": false
  }
}"#,
    )
    .unwrap();
    path
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

fn read_u16(engine: &VirtualExecutionEngine, address: u64) -> u16 {
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

fn read_ptr(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    let size = pointer_size(engine);
    let bytes = engine.modules().memory().read(address, size).unwrap();
    if size == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn read_wide_string(engine: &VirtualExecutionEngine, address: u64, words: usize) -> String {
    let bytes = engine.modules().memory().read(address, words * 2).unwrap();
    let mut data = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        data.push(word);
    }
    String::from_utf16_lossy(&data)
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

#[derive(Clone, Copy)]
struct SessionLayout {
    station_name_offset: u64,
    state_offset: u64,
}

fn session_layout(engine: &VirtualExecutionEngine) -> SessionLayout {
    if pointer_size(engine) == 8 {
        SessionLayout {
            station_name_offset: 8,
            state_offset: 16,
        }
    } else {
        SessionLayout {
            station_name_offset: 4,
            state_offset: 8,
        }
    }
}

#[test]
fn wtsapi32_hooks_expose_console_session_profile() {
    let root = unique_root("wtsapi32-hooks");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_server = engine.bind_hook_for_test("wtsapi32.dll", "WTSOpenServerW");
    let close_server = engine.bind_hook_for_test("wtsapi32.dll", "WTSCloseServer");
    let enumerate_sessions = engine.bind_hook_for_test("wtsapi32.dll", "WTSEnumerateSessionsW");
    let query_info = engine.bind_hook_for_test("wtsapi32.dll", "WTSQuerySessionInformationW");
    let free_memory = engine.bind_hook_for_test("wtsapi32.dll", "WTSFreeMemory");
    let query_user_token = engine.bind_hook_for_test("wtsapi32.dll", "WTSQueryUserToken");

    let server_name = alloc_page(&mut engine, 0x7800_0000);
    write_wide(&mut engine, server_name, "WINLAB-42");
    let server = engine
        .dispatch_bound_stub(open_server, &[server_name])
        .unwrap();
    assert_ne!(server, 0);

    let sessions_ptr = alloc_page(&mut engine, 0x7800_1000);
    let count_ptr = alloc_page(&mut engine, 0x7800_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(enumerate_sessions, &[server, 0, 1, sessions_ptr, count_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, count_ptr), 1);
    let session_buffer = read_ptr(&engine, sessions_ptr);
    assert_ne!(session_buffer, 0);

    let layout = session_layout(&engine);
    assert_eq!(read_u32(&engine, session_buffer), 1);
    let station_name_ptr = read_ptr(&engine, session_buffer + layout.station_name_offset);
    assert_eq!(read_wide_string(&engine, station_name_ptr, 64), "Console");
    assert_eq!(read_u32(&engine, session_buffer + layout.state_offset), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(free_memory, &[session_buffer])
            .unwrap(),
        0
    );

    let query_buffer_ptr = alloc_page(&mut engine, 0x7800_3000);
    let query_len_ptr = alloc_page(&mut engine, 0x7800_4000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_info, &[server, 1, 5, query_buffer_ptr, query_len_ptr])
            .unwrap(),
        1
    );
    let user_buffer = read_ptr(&engine, query_buffer_ptr);
    assert_eq!(read_wide_string(&engine, user_buffer, 64), "analyst");
    assert_eq!(read_u32(&engine, query_len_ptr), 16);
    assert_eq!(
        engine
            .dispatch_bound_stub(free_memory, &[user_buffer])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(query_info, &[server, 1, 7, query_buffer_ptr, query_len_ptr])
            .unwrap(),
        1
    );
    let domain_buffer = read_ptr(&engine, query_buffer_ptr);
    assert_eq!(read_wide_string(&engine, domain_buffer, 64), "CORP");
    assert_eq!(
        engine
            .dispatch_bound_stub(free_memory, &[domain_buffer])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_info,
                &[server, 1, 16, query_buffer_ptr, query_len_ptr]
            )
            .unwrap(),
        1
    );
    let protocol_buffer = read_ptr(&engine, query_buffer_ptr);
    assert_eq!(read_u16(&engine, protocol_buffer), 0);
    assert_eq!(read_u32(&engine, query_len_ptr), 2);
    assert_eq!(
        engine
            .dispatch_bound_stub(free_memory, &[protocol_buffer])
            .unwrap(),
        0
    );

    let token_ptr = alloc_page(&mut engine, 0x7800_5000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_user_token, &[1, token_ptr])
            .unwrap(),
        1
    );
    assert_ne!(read_ptr(&engine, token_ptr), 0);

    assert_eq!(
        engine.dispatch_bound_stub(close_server, &[server]).unwrap(),
        0
    );
}

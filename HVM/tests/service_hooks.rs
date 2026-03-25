use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

const ERROR_MORE_DATA: u32 = 234;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

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
  "services": [
    {
      "name": "WinDefend",
      "display_name": "Microsoft Defender Antivirus Service",
      "service_type": 32,
      "current_state": 4,
      "controls_accepted": 1,
      "process_id": 3540
    },
    {
      "name": "wuauserv",
      "display_name": "Windows Update",
      "service_type": 32,
      "current_state": 4,
      "controls_accepted": 1,
      "process_id": 2800
    }
  ]
}"#,
    )
    .unwrap();
    path
}

fn write_service_control_profile(root: &PathBuf) -> PathBuf {
    let path = root.join("environment_profile_services.json");
    fs::write(
        &path,
        r#"{
  "services": [
    {
      "name": "WinDefend",
      "display_name": "Microsoft Defender Antivirus Service",
      "service_type": 32,
      "start_type": 2,
      "error_control": 1,
      "current_state": 1,
      "controls_accepted": 7,
      "process_id": 0,
      "binary_path": "%ProgramFiles%\\Windows Defender\\MsMpEng.exe",
      "dependencies": ["RpcSs", "WdFilter"],
      "start_name": "LocalSystem",
      "description": "Helps protect users from malware and other potentially unwanted software.",
      "delayed_auto_start": true,
      "failure_actions_on_non_crash_failures": true,
      "service_sid_type": 1,
      "required_privileges": ["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"],
      "pre_shutdown_timeout_ms": 180000,
      "failure_reset_period_secs": 86400,
      "failure_command": "%SystemRoot%\\System32\\cmd.exe /c exit 0"
    }
  ]
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

fn read_wide_multi_string(
    engine: &VirtualExecutionEngine,
    address: u64,
    words: usize,
) -> Vec<String> {
    let bytes = engine.modules().memory().read(address, words * 2).unwrap();
    let mut current = Vec::new();
    let mut values = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            if current.is_empty() {
                break;
            }
            values.push(String::from_utf16_lossy(&current));
            current.clear();
        } else {
            current.push(word);
        }
    }
    values
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
struct EnumLayout {
    size: u64,
    service_name_offset: u64,
    display_name_offset: u64,
    status_offset: u64,
}

fn enum_layout(engine: &VirtualExecutionEngine) -> EnumLayout {
    if pointer_size(engine) == 8 {
        EnumLayout {
            size: 56,
            service_name_offset: 0,
            display_name_offset: 8,
            status_offset: 16,
        }
    } else {
        EnumLayout {
            size: 44,
            service_name_offset: 0,
            display_name_offset: 4,
            status_offset: 8,
        }
    }
}

#[derive(Clone, Copy)]
struct QueryConfigLayout {
    binary_path_offset: u64,
    load_order_group_offset: u64,
    tag_id_offset: u64,
    dependencies_offset: u64,
    service_start_name_offset: u64,
    display_name_offset: u64,
}

fn query_config_layout(engine: &VirtualExecutionEngine) -> QueryConfigLayout {
    if pointer_size(engine) == 8 {
        QueryConfigLayout {
            binary_path_offset: 16,
            load_order_group_offset: 24,
            tag_id_offset: 32,
            dependencies_offset: 40,
            service_start_name_offset: 48,
            display_name_offset: 56,
        }
    } else {
        QueryConfigLayout {
            binary_path_offset: 12,
            load_order_group_offset: 16,
            tag_id_offset: 20,
            dependencies_offset: 24,
            service_start_name_offset: 28,
            display_name_offset: 32,
        }
    }
}

#[derive(Clone, Copy)]
struct FailureActionsLayout {
    reboot_msg_offset: u64,
    command_offset: u64,
    actions_count_offset: u64,
    actions_offset: u64,
}

fn failure_actions_layout(engine: &VirtualExecutionEngine) -> FailureActionsLayout {
    if pointer_size(engine) == 8 {
        FailureActionsLayout {
            reboot_msg_offset: 8,
            command_offset: 16,
            actions_count_offset: 24,
            actions_offset: 32,
        }
    } else {
        FailureActionsLayout {
            reboot_msg_offset: 4,
            command_offset: 8,
            actions_count_offset: 12,
            actions_offset: 16,
        }
    }
}

#[test]
fn service_hooks_expose_scm_inventory_and_status() {
    let root = unique_root("service-hooks");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_scm = engine.bind_hook_for_test("advapi32.dll", "OpenSCManagerW");
    let open_service = engine.bind_hook_for_test("advapi32.dll", "OpenServiceW");
    let query_status = engine.bind_hook_for_test("advapi32.dll", "QueryServiceStatus");
    let query_status_ex = engine.bind_hook_for_test("advapi32.dll", "QueryServiceStatusEx");
    let enum_services = engine.bind_hook_for_test("advapi32.dll", "EnumServicesStatusExW");
    let close_service_handle = engine.bind_hook_for_test("advapi32.dll", "CloseServiceHandle");

    let scm = engine
        .dispatch_bound_stub(open_scm, &[0, 0, 0xF003F])
        .unwrap();
    assert_ne!(scm, 0);

    let missing_name = alloc_page(&mut engine, 0x7700_0000);
    write_wide(&mut engine, missing_name, "MissingSvc");
    assert_eq!(
        engine
            .dispatch_bound_stub(open_service, &[scm, missing_name, 0xF01FF])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_SERVICE_DOES_NOT_EXIST);

    let service_name = alloc_page(&mut engine, 0x7700_1000);
    write_wide(&mut engine, service_name, "WinDefend");
    let service = engine
        .dispatch_bound_stub(open_service, &[scm, service_name, 0xF01FF])
        .unwrap();
    assert_ne!(service, 0);

    let status = alloc_page(&mut engine, 0x7700_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_status, &[service, status])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status), 32);
    assert_eq!(read_u32(&engine, status + 4), 4);
    assert_eq!(read_u32(&engine, status + 8), 1);

    let needed_ptr = alloc_page(&mut engine, 0x7700_3000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_status_ex, &[service, 0, 0, 0, needed_ptr])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_INSUFFICIENT_BUFFER);
    assert_eq!(read_u32(&engine, needed_ptr), 36);

    let status_ex = alloc_page(&mut engine, 0x7700_4000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_status_ex, &[service, 0, status_ex, 36, needed_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status_ex), 32);
    assert_eq!(read_u32(&engine, status_ex + 4), 4);
    assert_eq!(read_u32(&engine, status_ex + 28), 3540);

    let enum_needed = alloc_page(&mut engine, 0x7700_5000);
    let returned_ptr = enum_needed + 4;
    let resume_ptr = enum_needed + 8;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                enum_services,
                &[
                    scm,
                    0,
                    0x30,
                    3,
                    0,
                    0,
                    enum_needed,
                    returned_ptr,
                    resume_ptr,
                    0
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_MORE_DATA);
    let enum_size = read_u32(&engine, enum_needed);
    assert!(enum_size >= 88);

    let enum_buffer = alloc_page(&mut engine, 0x7700_6000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                enum_services,
                &[
                    scm,
                    0,
                    0x30,
                    3,
                    enum_buffer,
                    enum_size as u64,
                    enum_needed,
                    returned_ptr,
                    resume_ptr,
                    0
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, returned_ptr), 2);
    assert_eq!(read_u32(&engine, resume_ptr), 0);

    let layout = enum_layout(&engine);
    let mut observed = Vec::new();
    for index in 0..read_u32(&engine, returned_ptr) {
        let entry = enum_buffer + index as u64 * layout.size;
        let name_ptr = read_ptr(&engine, entry + layout.service_name_offset);
        let display_ptr = read_ptr(&engine, entry + layout.display_name_offset);
        let name = read_wide_string(&engine, name_ptr, 128);
        let display = read_wide_string(&engine, display_ptr, 128);
        let state = read_u32(&engine, entry + layout.status_offset + 4);
        let pid = read_u32(&engine, entry + layout.status_offset + 28);
        observed.push((name, display, state, pid));
    }
    assert!(
        observed.iter().any(|(name, display, state, pid)| {
            name == "WinDefend"
                && display == "Microsoft Defender Antivirus Service"
                && *state == 4
                && *pid == 3540
        }),
        "{observed:#?}"
    );
    assert!(
        observed.iter().any(|(name, display, state, pid)| {
            name == "wuauserv" && display == "Windows Update" && *state == 4 && *pid == 2800
        }),
        "{observed:#?}"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(close_service_handle, &[service])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_service_handle, &[scm])
            .unwrap(),
        1
    );
}

#[test]
fn service_hooks_expose_configuration_and_control_state() {
    let root = unique_root("service-config-control");
    let profile_path = write_service_control_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_scm = engine.bind_hook_for_test("advapi32.dll", "OpenSCManagerW");
    let open_service = engine.bind_hook_for_test("advapi32.dll", "OpenServiceW");
    let query_config = engine.bind_hook_for_test("advapi32.dll", "QueryServiceConfigW");
    let query_config2 = engine.bind_hook_for_test("advapi32.dll", "QueryServiceConfig2W");
    let query_status_ex = engine.bind_hook_for_test("advapi32.dll", "QueryServiceStatusEx");
    let start_service = engine.bind_hook_for_test("advapi32.dll", "StartServiceW");
    let control_service = engine.bind_hook_for_test("advapi32.dll", "ControlService");

    let scm = engine
        .dispatch_bound_stub(open_scm, &[0, 0, 0xF003F])
        .unwrap();
    assert_ne!(scm, 0);

    let service_name = alloc_page(&mut engine, 0x7710_0000);
    write_wide(&mut engine, service_name, "WinDefend");
    let service = engine
        .dispatch_bound_stub(open_service, &[scm, service_name, 0xF01FF])
        .unwrap();
    assert_ne!(service, 0);

    let needed_ptr = alloc_page(&mut engine, 0x7710_1000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_config, &[service, 0, 0, needed_ptr])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_INSUFFICIENT_BUFFER);
    let config_size = read_u32(&engine, needed_ptr);
    assert!(config_size >= 120);

    let config_buffer = alloc_page(&mut engine, 0x7710_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config,
                &[service, config_buffer, config_size as u64, needed_ptr]
            )
            .unwrap(),
        1
    );

    let layout = query_config_layout(&engine);
    assert_eq!(read_u32(&engine, config_buffer), 32);
    assert_eq!(read_u32(&engine, config_buffer + 4), 2);
    assert_eq!(read_u32(&engine, config_buffer + 8), 1);
    assert_eq!(read_u32(&engine, config_buffer + layout.tag_id_offset), 0);

    let binary_path_ptr = read_ptr(&engine, config_buffer + layout.binary_path_offset);
    let load_group_ptr = read_ptr(&engine, config_buffer + layout.load_order_group_offset);
    let dependencies_ptr = read_ptr(&engine, config_buffer + layout.dependencies_offset);
    let start_name_ptr = read_ptr(&engine, config_buffer + layout.service_start_name_offset);
    let display_name_ptr = read_ptr(&engine, config_buffer + layout.display_name_offset);

    assert_eq!(
        read_wide_string(&engine, binary_path_ptr, 128),
        "%ProgramFiles%\\Windows Defender\\MsMpEng.exe"
    );
    assert_eq!(load_group_ptr, 0);
    assert_eq!(
        read_wide_multi_string(&engine, dependencies_ptr, 64),
        vec!["RpcSs".to_string(), "WdFilter".to_string()]
    );
    assert_eq!(read_wide_string(&engine, start_name_ptr, 64), "LocalSystem");
    assert_eq!(
        read_wide_string(&engine, display_name_ptr, 128),
        "Microsoft Defender Antivirus Service"
    );

    let description_needed = alloc_page(&mut engine, 0x7710_3000);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_config2, &[service, 1, 0, 0, description_needed])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_INSUFFICIENT_BUFFER);
    let description_size = read_u32(&engine, description_needed);
    let description_buffer = alloc_page(&mut engine, 0x7710_4000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config2,
                &[
                    service,
                    1,
                    description_buffer,
                    description_size as u64,
                    description_needed
                ],
            )
            .unwrap(),
        1
    );
    let description_ptr = read_ptr(&engine, description_buffer);
    assert_eq!(
        read_wide_string(&engine, description_ptr, 160),
        "Helps protect users from malware and other potentially unwanted software."
    );

    let failure_needed = alloc_page(&mut engine, 0x7710_5000);
    let failure_buffer = alloc_page(&mut engine, 0x7710_6000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config2,
                &[service, 2, failure_buffer, 128, failure_needed]
            )
            .unwrap(),
        1
    );
    let failure_layout = failure_actions_layout(&engine);
    assert_eq!(read_u32(&engine, failure_buffer), 86_400);
    assert_eq!(
        read_u32(
            &engine,
            failure_buffer + failure_layout.actions_count_offset
        ),
        0
    );
    assert_eq!(
        read_ptr(&engine, failure_buffer + failure_layout.actions_offset),
        0
    );
    let failure_command_ptr = read_ptr(&engine, failure_buffer + failure_layout.command_offset);
    let failure_reboot_ptr = read_ptr(&engine, failure_buffer + failure_layout.reboot_msg_offset);
    assert_eq!(failure_reboot_ptr, 0);
    assert_eq!(
        read_wide_string(&engine, failure_command_ptr, 128),
        "%SystemRoot%\\System32\\cmd.exe /c exit 0"
    );

    let delayed_buffer = alloc_page(&mut engine, 0x7710_7000);
    let delayed_needed = alloc_page(&mut engine, 0x7710_7100);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config2,
                &[service, 3, delayed_buffer, 4, delayed_needed]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, delayed_buffer), 1);

    let sid_buffer = alloc_page(&mut engine, 0x7710_7200);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_config2, &[service, 5, sid_buffer, 4, delayed_needed])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, sid_buffer), 1);

    let privileges_buffer = alloc_page(&mut engine, 0x7710_7300);
    let privileges_needed = alloc_page(&mut engine, 0x7710_7400);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config2,
                &[service, 6, privileges_buffer, 128, privileges_needed]
            )
            .unwrap(),
        1
    );
    let privileges_ptr = read_ptr(&engine, privileges_buffer);
    assert_eq!(
        read_wide_multi_string(&engine, privileges_ptr, 128),
        vec![
            "SeChangeNotifyPrivilege".to_string(),
            "SeImpersonatePrivilege".to_string()
        ]
    );

    let preshutdown_buffer = alloc_page(&mut engine, 0x7710_7500);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_config2,
                &[service, 7, preshutdown_buffer, 4, delayed_needed]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, preshutdown_buffer), 180_000);

    let status_ex = alloc_page(&mut engine, 0x7710_7600);
    assert_eq!(
        engine
            .dispatch_bound_stub(query_status_ex, &[service, 0, status_ex, 36, needed_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status_ex + 4), 1);
    assert_eq!(read_u32(&engine, status_ex + 8), 0);
    assert_eq!(read_u32(&engine, status_ex + 28), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(start_service, &[service, 0, 0])
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(start_service, &[service, 0, 0])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_SERVICE_ALREADY_RUNNING);

    assert_eq!(
        engine
            .dispatch_bound_stub(query_status_ex, &[service, 0, status_ex, 36, needed_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status_ex + 4), 4);
    assert_eq!(read_u32(&engine, status_ex + 8), 7);
    assert_ne!(read_u32(&engine, status_ex + 28), 0);

    let status = alloc_page(&mut engine, 0x7710_7700);
    assert_eq!(
        engine
            .dispatch_bound_stub(control_service, &[service, 2, status])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status + 4), 7);

    assert_eq!(
        engine
            .dispatch_bound_stub(control_service, &[service, 3, status])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status + 4), 4);

    assert_eq!(
        engine
            .dispatch_bound_stub(control_service, &[service, 1, status])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status + 4), 1);
    assert_eq!(read_u32(&engine, status + 8), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(query_status_ex, &[service, 0, status_ex, 36, needed_ptr])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, status_ex + 4), 1);
    assert_eq!(read_u32(&engine, status_ex + 8), 0);
    assert_eq!(read_u32(&engine, status_ex + 28), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(control_service, &[service, 1, status])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_SERVICE_NOT_ACTIVE);
}

use hvm::config::load_config;
use hvm::config::EnvironmentOverrides;
use hvm::environment_profile::{
    LocalGroupProfile, MachineIdentityOverrides, RegistryKeyProfile, RegistrySnapshot,
    RegistryValueProfile, UserAccountProfile,
};
use hvm::runtime::engine::VirtualExecutionEngine;

const HKEY_LOCAL_MACHINE: u64 = 0x8000_0002;
const REG_SZ: u32 = 1;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn alloc_page(engine: &mut VirtualExecutionEngine, preferred: u64) -> u64 {
    let address = engine.allocate_executable_test_page(preferred).unwrap();
    engine.write_test_bytes(address, &[0u8; 0x1000]).unwrap();
    address
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
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

fn read_u8(engine: &VirtualExecutionEngine, address: u64) -> u8 {
    engine.modules().memory().read(address, 1).unwrap()[0]
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

fn read_u64(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    u64::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(address, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn write_ascii(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    engine.write_test_bytes(address, &bytes).unwrap();
}

#[test]
fn open_process_token_and_get_token_information_follow_python_success_path() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let open_process_token = engine.bind_hook_for_test("advapi32.dll", "OpenProcessToken");
    let get_token_information = engine.bind_hook_for_test("advapi32.dll", "GetTokenInformation");
    let close_handle = engine.bind_hook_for_test("kernel32.dll", "CloseHandle");
    let page = engine.allocate_executable_test_page(0x6400_0000).unwrap();
    let token_ptr = page;
    let info_ptr = page + 4;
    let return_len_ptr = page + 8;

    assert_eq!(
        engine
            .dispatch_bound_stub(open_process_token, &[0xFFFF_FFFF, 8, token_ptr])
            .unwrap(),
        1
    );
    let token = u32::from_le_bytes(
        engine.modules().memory().read(token_ptr, 4).unwrap()[..4]
            .try_into()
            .unwrap(),
    ) as u64;

    assert_ne!(token, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_token_information,
                &[token, 20, info_ptr, 4, return_len_ptr]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        engine.modules().memory().read(info_ptr, 4).unwrap(),
        [0, 0, 0, 0]
    );
    assert_eq!(
        u32::from_le_bytes(
            engine.modules().memory().read(return_len_ptr, 4).unwrap()[..4]
                .try_into()
                .unwrap()
        ),
        4
    );
    assert_eq!(
        engine.dispatch_bound_stub(close_handle, &[token]).unwrap(),
        1
    );
}

#[test]
fn convert_string_sid_to_sid_a_allocates_and_returns_sid() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let convert = engine.bind_hook_for_test("advapi32.dll", "ConvertStringSidToSidA");
    let free_sid = engine.bind_hook_for_test("advapi32.dll", "FreeSid");
    let page = engine.allocate_executable_test_page(0x6400_2000).unwrap();
    let sid_text = page;
    let sid_out = page + 0x40;

    write_ascii(&mut engine, sid_text, "S-1-5-32-544");
    assert_eq!(
        engine
            .dispatch_bound_stub(convert, &[sid_text, sid_out])
            .unwrap(),
        1
    );

    let sid = read_u64(&engine, sid_out);
    assert_ne!(sid, 0);
    assert_eq!(engine.modules().memory().read(sid, 16).unwrap()[0], 1);
    assert_eq!(engine.modules().memory().read(sid, 16).unwrap()[1], 2);
    assert_eq!(
        u32::from_le_bytes(
            engine.modules().memory().read(sid + 12, 4).unwrap()[..4]
                .try_into()
                .unwrap()
        ),
        544
    );
    assert_eq!(engine.dispatch_bound_stub(free_sid, &[sid]).unwrap(), 0);
}

#[test]
fn convert_sid_to_string_sid_a_round_trips_sid_text() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let convert_to_sid = engine.bind_hook_for_test("advapi32.dll", "ConvertStringSidToSidA");
    let convert_to_string = engine.bind_hook_for_test("advapi32.dll", "ConvertSidToStringSidA");
    let free_sid = engine.bind_hook_for_test("advapi32.dll", "FreeSid");
    let local_free = engine.bind_hook_for_test("kernel32.dll", "LocalFree");
    let page = engine.allocate_executable_test_page(0x6400_3000).unwrap();
    let sid_text = page;
    let sid_out = page + 0x40;
    let string_out = page + 0x48;

    write_ascii(&mut engine, sid_text, "S-1-5-32-544");
    assert_eq!(
        engine
            .dispatch_bound_stub(convert_to_sid, &[sid_text, sid_out])
            .unwrap(),
        1
    );

    let sid = read_u64(&engine, sid_out);
    assert_eq!(
        engine
            .dispatch_bound_stub(convert_to_string, &[sid, string_out])
            .unwrap(),
        1
    );

    let string_sid = read_u64(&engine, string_out);
    let bytes = engine.modules().memory().read(string_sid, 32).unwrap();
    let length = bytes.iter().position(|byte| *byte == 0).unwrap();
    assert_eq!(String::from_utf8_lossy(&bytes[..length]), "S-1-5-32-544");
    assert_eq!(engine.dispatch_bound_stub(free_sid, &[sid]).unwrap(), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(local_free, &[string_sid])
            .unwrap(),
        0
    );
}

#[test]
fn reg_open_key_a_and_w_reuse_registry_open_logic() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let create_key = engine.bind_hook_for_test("advapi32.dll", "RegCreateKeyA");
    let open_key_a = engine.bind_hook_for_test("advapi32.dll", "RegOpenKeyA");
    let open_key_w = engine.bind_hook_for_test("advapi32.dll", "RegOpenKeyW");
    let page = alloc_page(&mut engine, 0x6400_5000);
    let subkey_a = page;
    let subkey_w = page + 0x80;
    let created_ptr = page + 0x180;
    let opened_a_ptr = page + 0x188;
    let opened_w_ptr = page + 0x190;

    write_ascii(&mut engine, subkey_a, r"Software\OpenKeyCompat");
    write_wide(&mut engine, subkey_w, r"Software\OpenKeyCompat");

    assert_eq!(
        engine
            .dispatch_bound_stub(create_key, &[HKEY_LOCAL_MACHINE, subkey_a, created_ptr])
            .unwrap(),
        0
    );
    assert_ne!(read_u32(&engine, created_ptr), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(open_key_a, &[HKEY_LOCAL_MACHINE, subkey_a, opened_a_ptr])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(open_key_w, &[HKEY_LOCAL_MACHINE, subkey_w, opened_w_ptr])
            .unwrap(),
        0
    );
    assert_ne!(read_u32(&engine, opened_a_ptr), 0);
    assert_ne!(read_u32(&engine, opened_w_ptr), 0);
}

#[test]
fn get_service_display_name_a_and_event_registration_succeed() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let open_scm = engine.bind_hook_for_test("advapi32.dll", "OpenSCManagerA");
    let get_display = engine.bind_hook_for_test("advapi32.dll", "GetServiceDisplayNameA");
    let event_register = engine.bind_hook_for_test("advapi32.dll", "EventRegister");
    let register_trace = engine.bind_hook_for_test("advapi32.dll", "RegisterTraceGuidsW");
    let page = alloc_page(&mut engine, 0x6400_7000);
    let service_name = page;
    let display_name = page + 0x80;
    let display_len_ptr = page + 0x180;
    let event_handle_ptr = page + 0x188;
    let trace_handle_ptr = page + 0x190;

    write_ascii(&mut engine, service_name, "EventLog");
    engine
        .write_test_bytes(display_len_ptr, &64u32.to_le_bytes())
        .unwrap();

    let scm = engine.dispatch_bound_stub(open_scm, &[0, 0, 0]).unwrap();
    assert_ne!(scm, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_display,
                &[scm, service_name, display_name, display_len_ptr]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        String::from_utf8_lossy(&engine.modules().memory().read(display_name, 64).unwrap()[..18])
            .trim_end_matches('\0'),
        "Windows Event Log"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(event_register, &[0, 0, 0, event_handle_ptr])
            .unwrap(),
        0
    );
    assert_ne!(read_u64(&engine, event_handle_ptr), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(register_trace, &[0, 0, 0, 0, 0, 0, 0, trace_handle_ptr])
            .unwrap(),
        0
    );
    assert_ne!(read_u64(&engine, trace_handle_ptr), 0);
}

#[test]
fn get_token_information_without_output_buffer_sets_insufficient_buffer() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let open_process_token = engine.bind_hook_for_test("advapi32.dll", "OpenProcessToken");
    let get_token_information = engine.bind_hook_for_test("advapi32.dll", "GetTokenInformation");
    let page = engine.allocate_executable_test_page(0x6401_0000).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(open_process_token, &[0xFFFF_FFFF, 8, page])
            .unwrap(),
        1
    );
    let token = u32::from_le_bytes(
        engine.modules().memory().read(page, 4).unwrap()[..4]
            .try_into()
            .unwrap(),
    ) as u64;

    assert_eq!(
        engine
            .dispatch_bound_stub(get_token_information, &[token, 20, 0, 0, page + 4])
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), 122);
}

#[test]
fn reg_open_key_and_get_value_hide_configured_registry_key() {
    let mut config = sample_config();
    config.hidden_registry_keys = vec![String::from(r"SOFTWARE\VMware, Inc.\VMware Tools")];
    config.environment_overrides = Some(EnvironmentOverrides {
        registry: Some(RegistrySnapshot {
            keys: vec![RegistryKeyProfile {
                path: String::from(r"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools"),
                values: vec![RegistryValueProfile {
                    name: String::from("InstallPath"),
                    value_type: REG_SZ,
                    string: Some(String::from(r"C:\Program Files\VMware\VMware Tools")),
                    dword: None,
                    qword: None,
                    multi_string: Vec::new(),
                    binary_hex: None,
                }],
            }],
        }),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let open_key = engine.bind_hook_for_test("advapi32.dll", "RegOpenKeyExW");
    let get_value = engine.bind_hook_for_test("advapi32.dll", "RegGetValueW");
    let page = alloc_page(&mut engine, 0x6401_8000);
    let subkey_ptr = page;
    let out_handle_ptr = page + 0x200;
    let value_name_ptr = page + 0x240;
    let type_ptr = page + 0x280;
    let size_ptr = page + 0x284;
    let data_ptr = page + 0x300;

    write_wide(
        &mut engine,
        subkey_ptr,
        r"SOFTWARE\VMware, Inc.\VMware Tools",
    );
    write_wide(&mut engine, value_name_ptr, "InstallPath");
    engine
        .write_test_bytes(size_ptr, &260u32.to_le_bytes())
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                open_key,
                &[HKEY_LOCAL_MACHINE, subkey_ptr, 0, 0, out_handle_ptr]
            )
            .unwrap(),
        2
    );
    assert_eq!(read_u32(&engine, out_handle_ptr), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_value,
                &[
                    HKEY_LOCAL_MACHINE,
                    subkey_ptr,
                    value_name_ptr,
                    0,
                    type_ptr,
                    data_ptr,
                    size_ptr,
                ],
            )
            .unwrap(),
        2
    );
}

#[test]
fn lookup_account_name_and_sid_follow_profiled_accounts() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            computer_name: Some("LABWIN10".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        users: Some(vec![UserAccountProfile {
            name: "Analyst".to_string(),
            rid: 1101,
            ..UserAccountProfile::default()
        }]),
        local_groups: Some(vec![LocalGroupProfile {
            name: "Administrators".to_string(),
            comment: "Administrative operators".to_string(),
            domain: "BUILTIN".to_string(),
            rid: 544,
            members: vec!["Analyst".to_string()],
        }]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let lookup_account_name = engine.bind_hook_for_test("advapi32.dll", "LookupAccountNameW");
    let lookup_account_sid = engine.bind_hook_for_test("advapi32.dll", "LookupAccountSidW");
    let page = alloc_page(&mut engine, 0x6402_0000);

    let analyst_name = page;
    write_wide(&mut engine, analyst_name, "Analyst");
    let sid_ptr = page + 0x100;
    let sid_len_ptr = page + 0x140;
    let domain_ptr = page + 0x180;
    let domain_len_ptr = page + 0x1c0;
    let sid_use_ptr = page + 0x1c4;
    engine
        .write_test_bytes(sid_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(domain_len_ptr, &64u32.to_le_bytes())
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                lookup_account_name,
                &[
                    0,
                    analyst_name,
                    sid_ptr,
                    sid_len_ptr,
                    domain_ptr,
                    domain_len_ptr,
                    sid_use_ptr
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, sid_use_ptr), 1);
    assert_eq!(read_u32(&engine, sid_len_ptr), 28);
    assert_eq!(read_wide_string(&engine, domain_ptr, 64), "LABWIN10");

    let name_out = page + 0x220;
    let name_len_ptr = page + 0x260;
    let domain_out = page + 0x280;
    let domain_out_len_ptr = page + 0x2c0;
    let sid_use_out = page + 0x2c4;
    engine
        .write_test_bytes(name_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(domain_out_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                lookup_account_sid,
                &[
                    0,
                    sid_ptr,
                    name_out,
                    name_len_ptr,
                    domain_out,
                    domain_out_len_ptr,
                    sid_use_out
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_wide_string(&engine, name_out, 64), "Analyst");
    assert_eq!(read_wide_string(&engine, domain_out, 64), "LABWIN10");
    assert_eq!(read_u32(&engine, sid_use_out), 1);

    let group_name = page + 0x300;
    write_wide(&mut engine, group_name, "BUILTIN\\Administrators");
    engine
        .write_test_bytes(sid_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(domain_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                lookup_account_name,
                &[
                    0,
                    group_name,
                    sid_ptr,
                    sid_len_ptr,
                    domain_ptr,
                    domain_len_ptr,
                    sid_use_ptr
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, sid_use_ptr), 4);
    assert_eq!(read_u32(&engine, sid_len_ptr), 16);
    assert_eq!(read_wide_string(&engine, domain_ptr, 64), "BUILTIN");

    engine
        .write_test_bytes(name_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(domain_out_len_ptr, &64u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                lookup_account_sid,
                &[
                    0,
                    sid_ptr,
                    name_out,
                    name_len_ptr,
                    domain_out,
                    domain_out_len_ptr,
                    sid_use_out
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_wide_string(&engine, name_out, 64), "Administrators");
    assert_eq!(read_wide_string(&engine, domain_out, 64), "BUILTIN");
    assert_eq!(read_u32(&engine, sid_use_out), 4);
}

#[test]
fn initialize_security_descriptor_and_set_dacl_populate_absolute_descriptor() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let initialize = engine.bind_hook_for_test("advapi32.dll", "InitializeSecurityDescriptor");
    let set_dacl = engine.bind_hook_for_test("advapi32.dll", "SetSecurityDescriptorDacl");
    let page = alloc_page(&mut engine, 0x6402_8000);
    let descriptor = page;
    let acl = page + 0x100;

    assert_eq!(
        engine
            .dispatch_bound_stub(initialize, &[descriptor, 1])
            .unwrap(),
        1
    );
    assert_eq!(read_u8(&engine, descriptor), 1);
    assert_eq!(read_u16(&engine, descriptor + 2), 0);
    assert_eq!(read_u32(&engine, descriptor + 16), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(set_dacl, &[descriptor, 1, acl, 1])
            .unwrap(),
        1
    );
    assert_eq!(read_u16(&engine, descriptor + 2), 0x000C);
    assert_eq!(read_u32(&engine, descriptor + 16), acl as u32);
}

#[test]
fn initialize_security_descriptor_rejects_null_or_wrong_revision() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let initialize = engine.bind_hook_for_test("advapi32.dll", "InitializeSecurityDescriptor");
    let page = alloc_page(&mut engine, 0x6402_9000);

    assert_eq!(engine.dispatch_bound_stub(initialize, &[0, 1]).unwrap(), 0);
    assert_eq!(engine.last_error(), 87);
    assert_eq!(
        engine.dispatch_bound_stub(initialize, &[page, 2]).unwrap(),
        0
    );
    assert_eq!(engine.last_error(), 87);
}

#[test]
fn create_service_w_persists_profile_for_followup_queries() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let open_sc_manager = engine.bind_hook_for_test("advapi32.dll", "OpenSCManagerW");
    let create_service = engine.bind_hook_for_test("advapi32.dll", "CreateServiceW");
    let open_service = engine.bind_hook_for_test("advapi32.dll", "OpenServiceW");
    let query_service_config = engine.bind_hook_for_test("advapi32.dll", "QueryServiceConfigW");
    let page = alloc_page(&mut engine, 0x6402_A000);
    let machine_name_ptr = page;
    let service_name_ptr = page + 0x80;
    let display_name_ptr = page + 0x100;
    let binary_path_ptr = page + 0x180;
    let start_name_ptr = page + 0x280;
    let tag_id_ptr = page + 0x384;
    let config_buffer_ptr = page + 0x400;
    let bytes_needed_ptr = page + 0x700;

    write_wide(&mut engine, machine_name_ptr, "");
    write_wide(&mut engine, service_name_ptr, "hvm_test_service");
    write_wide(&mut engine, display_name_ptr, "HVM Test Service");
    write_wide(
        &mut engine,
        binary_path_ptr,
        r"C:\Windows\System32\svchost.exe -k netsvcs -p",
    );
    write_wide(&mut engine, start_name_ptr, "LocalSystem");

    let manager_handle = engine
        .dispatch_bound_stub(open_sc_manager, &[machine_name_ptr, 0, 0xF003F])
        .unwrap();
    assert_ne!(manager_handle, 0);

    let service_handle = engine
        .dispatch_bound_stub(
            create_service,
            &[
                manager_handle,
                service_name_ptr,
                display_name_ptr,
                0xF01FF,
                0x20,
                0x3,
                0x1,
                binary_path_ptr,
                0,
                tag_id_ptr,
                0,
                start_name_ptr,
                0,
            ],
        )
        .unwrap();
    assert_ne!(service_handle, 0);
    assert_eq!(read_u32(&engine, tag_id_ptr), 0);

    let reopened_handle = engine
        .dispatch_bound_stub(open_service, &[manager_handle, service_name_ptr, 0x1])
        .unwrap();
    assert_ne!(reopened_handle, 0);

    engine
        .write_test_bytes(bytes_needed_ptr, &0u32.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                query_service_config,
                &[reopened_handle, config_buffer_ptr, 0x200, bytes_needed_ptr],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, config_buffer_ptr), 0x20);
    assert_eq!(read_u32(&engine, config_buffer_ptr + 4), 0x3);
    assert_eq!(read_u32(&engine, config_buffer_ptr + 8), 0x1);

    let binary_path_out_ptr = read_u32(&engine, config_buffer_ptr + 12) as u64;
    let start_name_out_ptr = read_u32(&engine, config_buffer_ptr + 28) as u64;
    let display_name_out_ptr = read_u32(&engine, config_buffer_ptr + 32) as u64;
    assert_eq!(
        read_wide_string(&engine, binary_path_out_ptr, 128),
        r"C:\Windows\System32\svchost.exe -k netsvcs -p"
    );
    assert_eq!(
        read_wide_string(&engine, start_name_out_ptr, 64),
        "LocalSystem"
    );
    assert_eq!(
        read_wide_string(&engine, display_name_out_ptr, 64),
        "HVM Test Service"
    );
}

#[test]
fn service_dispatcher_invokes_service_main_and_service_control_apis_succeed() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let start_dispatcher = engine.bind_hook_for_test("advapi32.dll", "StartServiceCtrlDispatcherW");
    let register_handler = engine.bind_hook_for_test("advapi32.dll", "RegisterServiceCtrlHandlerW");
    let set_service_status = engine.bind_hook_for_test("advapi32.dll", "SetServiceStatus");
    let page = alloc_page(&mut engine, 0x6402_C000);
    let service_table = page;
    let service_name = page + 0x100;
    let callback = page + 0x180;
    let argc_out = page + 0x200;
    let argv_out = page + 0x204;
    let first_arg_out = page + 0x208;
    let status_ptr = page + 0x240;

    write_wide(&mut engine, service_name, "hvm_test_service");
    let mut callback_bytes = vec![
        0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
        0xA3,
    ];
    callback_bytes.extend_from_slice(&(argc_out as u32).to_le_bytes());
    callback_bytes.extend_from_slice(&[
        0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
        0xA3,
    ]);
    callback_bytes.extend_from_slice(&(argv_out as u32).to_le_bytes());
    callback_bytes.extend_from_slice(&[
        0x8B, 0x00, // mov eax, [eax]
        0xA3,
    ]);
    callback_bytes.extend_from_slice(&(first_arg_out as u32).to_le_bytes());
    callback_bytes.extend_from_slice(&[
        0x31, 0xC0, // xor eax, eax
        0xC2, 0x08, 0x00, // ret 8
    ]);
    engine.write_test_bytes(callback, &callback_bytes).unwrap();
    engine
        .write_test_bytes(
            service_table,
            &[
                (service_name as u32).to_le_bytes().as_slice(),
                (callback as u32).to_le_bytes().as_slice(),
                &0u32.to_le_bytes(),
                &0u32.to_le_bytes(),
            ]
            .concat(),
        )
        .unwrap();
    engine.write_test_bytes(status_ptr, &[0u8; 28]).unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(start_dispatcher, &[service_table])
            .unwrap(),
        1
    );
    assert_eq!(engine.last_error(), 0);
    assert_eq!(read_u32(&engine, argc_out), 1);
    assert_ne!(read_u32(&engine, argv_out), 0);
    assert_eq!(read_u32(&engine, first_arg_out) as u64, service_name);

    let handler = engine
        .dispatch_bound_stub(register_handler, &[service_name, 0x401000])
        .unwrap();
    assert_ne!(handler, 0);
    assert_eq!(engine.last_error(), 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(set_service_status, &[handler, status_ptr])
            .unwrap(),
        1
    );
    assert_eq!(engine.last_error(), 0);
}

#[test]
fn eventing_controller_api_set_start_and_stop_trace_handles() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let start_trace =
        engine.bind_hook_for_test("api-ms-win-eventing-controller-l1-1-0.dll", "StartTraceW");
    let query_all = engine.bind_hook_for_test(
        "api-ms-win-eventing-controller-l1-1-0.dll",
        "QueryAllTracesW",
    );
    let stop_trace =
        engine.bind_hook_for_test("api-ms-win-eventing-controller-l1-1-0.dll", "StopTraceW");
    let page = alloc_page(&mut engine, 0x6403_0000);
    let trace_handle_ptr = page;
    let session_name_ptr = page + 0x100;
    let logger_count_ptr = page + 0x200;

    write_wide(&mut engine, session_name_ptr, "HvmEventingSession");

    assert_eq!(
        engine
            .dispatch_bound_stub(start_trace, &[trace_handle_ptr, session_name_ptr, 0])
            .unwrap(),
        0
    );
    let trace_handle = read_u32(&engine, trace_handle_ptr) as u64;
    assert_ne!(trace_handle, 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(query_all, &[0, 0, logger_count_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, logger_count_ptr), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(stop_trace, &[trace_handle, session_name_ptr, 0])
            .unwrap(),
        0
    );
}

#[test]
fn eventing_consumer_api_set_processes_and_closes_trace_handles() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let open_trace =
        engine.bind_hook_for_test("api-ms-win-eventing-consumer-l1-1-0.dll", "OpenTraceW");
    let process_trace =
        engine.bind_hook_for_test("api-ms-win-eventing-consumer-l1-1-0.dll", "ProcessTrace");
    let close_trace =
        engine.bind_hook_for_test("api-ms-win-eventing-consumer-l1-1-0.dll", "CloseTrace");
    let page = alloc_page(&mut engine, 0x6404_0000);
    let handle_array_ptr = page + 0x100;

    let trace_handle = engine.dispatch_bound_stub(open_trace, &[page]).unwrap();

    assert_ne!(trace_handle, u64::MAX);
    engine
        .write_test_bytes(handle_array_ptr, &trace_handle.to_le_bytes())
        .unwrap();
    assert_eq!(read_u64(&engine, handle_array_ptr), trace_handle);

    assert_eq!(
        engine
            .dispatch_bound_stub(process_trace, &[handle_array_ptr, 1, 0, 0])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_trace, &[trace_handle])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_trace, &[trace_handle])
            .unwrap(),
        6
    );
}

#[test]
fn advapi32_eventing_exports_forward_into_api_set_semantics() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let start_trace = engine.bind_hook_for_test("advapi32.dll", "StartTraceW");
    let stop_trace = engine.bind_hook_for_test("advapi32.dll", "StopTraceW");
    let open_trace = engine.bind_hook_for_test("advapi32.dll", "OpenTraceW");
    let process_trace = engine.bind_hook_for_test("advapi32.dll", "ProcessTrace");
    let close_trace = engine.bind_hook_for_test("advapi32.dll", "CloseTrace");
    let page = alloc_page(&mut engine, 0x6405_0000);
    let controller_handle_ptr = page;
    let session_name_ptr = page + 0x100;
    let consumer_handle_array_ptr = page + 0x200;

    write_wide(&mut engine, session_name_ptr, "StrictForwardedEventing");

    assert_eq!(
        engine
            .dispatch_bound_stub(start_trace, &[controller_handle_ptr, session_name_ptr, 0])
            .unwrap(),
        0
    );
    let controller_handle = read_u32(&engine, controller_handle_ptr) as u64;
    assert_ne!(controller_handle, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(stop_trace, &[controller_handle, session_name_ptr, 0])
            .unwrap(),
        0
    );

    let consumer_handle = engine.dispatch_bound_stub(open_trace, &[page]).unwrap();
    assert_ne!(consumer_handle, u64::MAX);
    engine
        .write_test_bytes(consumer_handle_array_ptr, &consumer_handle.to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(process_trace, &[consumer_handle_array_ptr, 1, 0, 0])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(close_trace, &[consumer_handle])
            .unwrap(),
        0
    );
}

#[test]
fn event_set_information_returns_success() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let stub = engine.bind_hook_for_test("advapi32.dll", "EventSetInformation");
    assert_eq!(engine.dispatch_bound_stub(stub, &[1, 2, 3, 4]).unwrap(), 0);
}

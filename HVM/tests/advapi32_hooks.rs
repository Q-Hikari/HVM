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

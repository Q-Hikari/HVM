use hvm::config::load_config;
use hvm::config::EnvironmentOverrides;
use hvm::environment_profile::{
    LocalGroupProfile, MachineIdentityOverrides, NetworkAdapterProfile, NetworkAddressProfile,
    NetworkProfileOverrides, NetworkSessionProfile, NetworkUseProfile, OpenFileProfile,
    ShareProfile, UserAccountProfile, WorkstationUserProfile,
};
use hvm::runtime::engine::VirtualExecutionEngine;

const ERROR_NO_SUCH_DOMAIN: u64 = 1355;
const DOMAIN_TRUST_FLAGS_PRIMARY: u32 = 0x0000_0008;

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

fn read_bytes(engine: &VirtualExecutionEngine, address: u64, len: usize) -> Vec<u8> {
    engine.modules().memory().read(address, len).unwrap()
}

fn write_ptr(engine: &mut VirtualExecutionEngine, address: u64, value: u64) {
    let bytes = if pointer_size(engine) == 8 {
        value.to_le_bytes().to_vec()
    } else {
        (value as u32).to_le_bytes().to_vec()
    };
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn write_wide_input(engine: &mut VirtualExecutionEngine, address: u64, value: &str) -> u64 {
    let bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine.write_test_bytes(address, &bytes).unwrap();
    address
}

#[test]
fn netbios_returns_error_for_null_ncb_pointer() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let netbios = engine.bind_hook_for_test("netapi32.dll", "Netbios");

    assert_eq!(engine.dispatch_bound_stub(netbios, &[0]).unwrap(), 0x01);
}

#[test]
fn netbios_writes_lana_enum_and_clears_status_bytes() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let netbios = engine.bind_hook_for_test("netapi32.dll", "Netbios");
    let page = engine.allocate_executable_test_page(0x6500_0000).unwrap();
    let ncb = page;
    let buffer = page + 0x100;
    let length = 32u16;
    engine.write_test_bytes(buffer, &[0xCC; 32]).unwrap();

    let mut payload = vec![0u8; 64];
    payload[0] = 0x37;
    payload[1] = 0xAA;
    payload[4..8].copy_from_slice(&(buffer as u32).to_le_bytes());
    payload[8..10].copy_from_slice(&length.to_le_bytes());
    payload[49] = 0xBB;
    engine.write_test_bytes(ncb, &payload).unwrap();

    assert_eq!(engine.dispatch_bound_stub(netbios, &[ncb]).unwrap(), 0);
    let data = engine
        .modules()
        .memory()
        .read(buffer, length as usize)
        .unwrap();
    assert!(data.iter().all(|byte| *byte == 0));
    assert_eq!(engine.modules().memory().read(ncb + 1, 1).unwrap(), vec![0]);
    assert_eq!(
        engine.modules().memory().read(ncb + 49, 1).unwrap(),
        vec![0]
    );
}

#[test]
fn netbios_astat_queries_leave_python_style_buffer_contents_unchanged() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let netbios = engine.bind_hook_for_test("netapi32.dll", "Netbios");
    let page = engine.allocate_executable_test_page(0x6501_0000).unwrap();
    let ncb = page;
    let buffer = page + 0x100;
    let length = 600u16;
    engine.write_test_bytes(buffer, &[0xCC; 600]).unwrap();

    let mut payload = vec![0u8; 64];
    payload[0] = 0x33;
    payload[1] = 0xAA;
    payload[4..8].copy_from_slice(&(buffer as u32).to_le_bytes());
    payload[8..10].copy_from_slice(&length.to_le_bytes());
    payload[49] = 0xBB;
    engine.write_test_bytes(ncb, &payload).unwrap();

    assert_eq!(engine.dispatch_bound_stub(netbios, &[ncb]).unwrap(), 0);
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(buffer, length as usize)
            .unwrap(),
        vec![0xCC; length as usize]
    );
    assert_eq!(engine.modules().memory().read(ncb + 1, 1).unwrap(), vec![0]);
    assert_eq!(
        engine.modules().memory().read(ncb + 49, 1).unwrap(),
        vec![0]
    );
}

#[derive(Clone, Copy)]
struct WkstaInfo102Layout {
    computer_name_offset: u64,
    langroup_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    lanroot_offset: u64,
    logged_on_users_offset: u64,
}

fn wksta_info_102_layout(engine: &VirtualExecutionEngine) -> WkstaInfo102Layout {
    if pointer_size(engine) == 8 {
        WkstaInfo102Layout {
            computer_name_offset: 8,
            langroup_offset: 16,
            ver_major_offset: 24,
            ver_minor_offset: 28,
            lanroot_offset: 32,
            logged_on_users_offset: 40,
        }
    } else {
        WkstaInfo102Layout {
            computer_name_offset: 4,
            langroup_offset: 8,
            ver_major_offset: 12,
            ver_minor_offset: 16,
            lanroot_offset: 20,
            logged_on_users_offset: 24,
        }
    }
}

#[derive(Clone, Copy)]
struct ServerInfo101Layout {
    name_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    server_type_offset: u64,
    comment_offset: u64,
    size: u64,
}

fn server_info_101_layout(engine: &VirtualExecutionEngine) -> ServerInfo101Layout {
    if pointer_size(engine) == 8 {
        ServerInfo101Layout {
            name_offset: 8,
            ver_major_offset: 16,
            ver_minor_offset: 20,
            server_type_offset: 24,
            comment_offset: 32,
            size: 40,
        }
    } else {
        ServerInfo101Layout {
            name_offset: 4,
            ver_major_offset: 8,
            ver_minor_offset: 12,
            server_type_offset: 16,
            comment_offset: 20,
            size: 24,
        }
    }
}

#[derive(Clone, Copy)]
struct DsRolePrimaryDomainInfoBasicLayout {
    flags_offset: u64,
    flat_name_offset: u64,
    dns_name_offset: u64,
    forest_name_offset: u64,
    domain_guid_offset: u64,
}

fn ds_role_primary_domain_info_basic_layout(
    engine: &VirtualExecutionEngine,
) -> DsRolePrimaryDomainInfoBasicLayout {
    if pointer_size(engine) == 8 {
        DsRolePrimaryDomainInfoBasicLayout {
            flags_offset: 4,
            flat_name_offset: 8,
            dns_name_offset: 16,
            forest_name_offset: 24,
            domain_guid_offset: 32,
        }
    } else {
        DsRolePrimaryDomainInfoBasicLayout {
            flags_offset: 4,
            flat_name_offset: 8,
            dns_name_offset: 12,
            forest_name_offset: 16,
            domain_guid_offset: 20,
        }
    }
}

#[derive(Clone, Copy)]
struct DomainControllerInfoLayout {
    name_offset: u64,
    address_offset: u64,
    address_type_offset: u64,
    domain_guid_offset: u64,
    domain_name_offset: u64,
    forest_name_offset: u64,
    flags_offset: u64,
    dc_site_name_offset: u64,
    client_site_name_offset: u64,
}

fn domain_controller_info_layout(engine: &VirtualExecutionEngine) -> DomainControllerInfoLayout {
    if pointer_size(engine) == 8 {
        DomainControllerInfoLayout {
            name_offset: 0,
            address_offset: 8,
            address_type_offset: 16,
            domain_guid_offset: 20,
            domain_name_offset: 40,
            forest_name_offset: 48,
            flags_offset: 56,
            dc_site_name_offset: 64,
            client_site_name_offset: 72,
        }
    } else {
        DomainControllerInfoLayout {
            name_offset: 0,
            address_offset: 4,
            address_type_offset: 8,
            domain_guid_offset: 12,
            domain_name_offset: 28,
            forest_name_offset: 32,
            flags_offset: 36,
            dc_site_name_offset: 40,
            client_site_name_offset: 44,
        }
    }
}

#[derive(Clone, Copy)]
struct DomainTrustInfoLayout {
    netbios_name_offset: u64,
    dns_name_offset: u64,
    flags_offset: u64,
    parent_index_offset: u64,
    trust_type_offset: u64,
    trust_attributes_offset: u64,
    sid_offset: u64,
    guid_offset: u64,
}

fn domain_trust_info_layout(engine: &VirtualExecutionEngine) -> DomainTrustInfoLayout {
    if pointer_size(engine) == 8 {
        DomainTrustInfoLayout {
            netbios_name_offset: 0,
            dns_name_offset: 8,
            flags_offset: 16,
            parent_index_offset: 20,
            trust_type_offset: 24,
            trust_attributes_offset: 28,
            sid_offset: 32,
            guid_offset: 40,
        }
    } else {
        DomainTrustInfoLayout {
            netbios_name_offset: 0,
            dns_name_offset: 4,
            flags_offset: 8,
            parent_index_offset: 12,
            trust_type_offset: 16,
            trust_attributes_offset: 20,
            sid_offset: 24,
            guid_offset: 28,
        }
    }
}

fn parse_guid_string_le(guid: &str) -> [u8; 16] {
    let trimmed = guid.trim().trim_matches(|ch| ch == '{' || ch == '}');
    let parts = trimmed.split('-').collect::<Vec<_>>();
    let mut bytes = [0u8; 16];
    let time_low = u32::from_str_radix(parts[0], 16).unwrap();
    let time_mid = u16::from_str_radix(parts[1], 16).unwrap();
    let time_hi = u16::from_str_radix(parts[2], 16).unwrap();
    bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
    bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
    bytes[6..8].copy_from_slice(&time_hi.to_le_bytes());
    bytes[8] = u8::from_str_radix(&parts[3][0..2], 16).unwrap();
    bytes[9] = u8::from_str_radix(&parts[3][2..4], 16).unwrap();
    for index in 0..6 {
        let start = index * 2;
        bytes[10 + index] = u8::from_str_radix(&parts[4][start..start + 2], 16).unwrap();
    }
    bytes
}

#[derive(Clone, Copy)]
struct UserInfo1Layout {
    name_offset: u64,
    privilege_offset: u64,
    home_dir_offset: u64,
    comment_offset: u64,
    flags_offset: u64,
    script_path_offset: u64,
    size: u64,
}

fn user_info_1_layout(engine: &VirtualExecutionEngine) -> UserInfo1Layout {
    if pointer_size(engine) == 8 {
        UserInfo1Layout {
            name_offset: 0,
            privilege_offset: 12,
            home_dir_offset: 16,
            comment_offset: 24,
            flags_offset: 32,
            script_path_offset: 40,
            size: 48,
        }
    } else {
        UserInfo1Layout {
            name_offset: 0,
            privilege_offset: 8,
            home_dir_offset: 12,
            comment_offset: 16,
            flags_offset: 20,
            script_path_offset: 24,
            size: 28,
        }
    }
}

#[derive(Clone, Copy)]
struct UserInfo23Layout {
    name_offset: u64,
    full_name_offset: u64,
    comment_offset: u64,
    flags_offset: u64,
    sid_offset: u64,
}

fn user_info_23_layout(engine: &VirtualExecutionEngine) -> UserInfo23Layout {
    if pointer_size(engine) == 8 {
        UserInfo23Layout {
            name_offset: 0,
            full_name_offset: 8,
            comment_offset: 16,
            flags_offset: 24,
            sid_offset: 32,
        }
    } else {
        UserInfo23Layout {
            name_offset: 0,
            full_name_offset: 4,
            comment_offset: 8,
            flags_offset: 12,
            sid_offset: 16,
        }
    }
}

#[derive(Clone, Copy)]
struct LocalGroupInfo1Layout {
    name_offset: u64,
    comment_offset: u64,
    size: u64,
}

fn local_group_info_1_layout(engine: &VirtualExecutionEngine) -> LocalGroupInfo1Layout {
    if pointer_size(engine) == 8 {
        LocalGroupInfo1Layout {
            name_offset: 0,
            comment_offset: 8,
            size: 16,
        }
    } else {
        LocalGroupInfo1Layout {
            name_offset: 0,
            comment_offset: 4,
            size: 8,
        }
    }
}

#[derive(Clone, Copy)]
struct LocalGroupMembersInfo12Layout {
    sid_offset: u64,
    sid_use_offset: u64,
    name_offset: u64,
}

fn local_group_members_info_12_layout(
    engine: &VirtualExecutionEngine,
) -> LocalGroupMembersInfo12Layout {
    if pointer_size(engine) == 8 {
        LocalGroupMembersInfo12Layout {
            sid_offset: 0,
            sid_use_offset: 8,
            name_offset: 16,
        }
    } else {
        LocalGroupMembersInfo12Layout {
            sid_offset: 0,
            sid_use_offset: 4,
            name_offset: 8,
        }
    }
}

#[derive(Clone, Copy)]
struct ShareInfo2Layout {
    name_offset: u64,
    share_type_offset: u64,
    remark_offset: u64,
    permissions_offset: u64,
    max_uses_offset: u64,
    current_uses_offset: u64,
    path_offset: u64,
    password_offset: u64,
    size: u64,
}

fn share_info_2_layout(engine: &VirtualExecutionEngine) -> ShareInfo2Layout {
    if pointer_size(engine) == 8 {
        ShareInfo2Layout {
            name_offset: 0,
            share_type_offset: 8,
            remark_offset: 16,
            permissions_offset: 24,
            max_uses_offset: 28,
            current_uses_offset: 32,
            path_offset: 40,
            password_offset: 48,
            size: 56,
        }
    } else {
        ShareInfo2Layout {
            name_offset: 0,
            share_type_offset: 4,
            remark_offset: 8,
            permissions_offset: 12,
            max_uses_offset: 16,
            current_uses_offset: 20,
            path_offset: 24,
            password_offset: 28,
            size: 32,
        }
    }
}

#[derive(Clone, Copy)]
struct UseInfo2Layout {
    size: u64,
    local_name_offset: u64,
    remote_name_offset: u64,
    password_offset: u64,
    status_offset: u64,
    assignment_type_offset: u64,
    ref_count_offset: u64,
    use_count_offset: u64,
    user_name_offset: u64,
    domain_name_offset: u64,
}

fn use_info_2_layout(engine: &VirtualExecutionEngine) -> UseInfo2Layout {
    if pointer_size(engine) == 8 {
        UseInfo2Layout {
            size: 56,
            local_name_offset: 0,
            remote_name_offset: 8,
            password_offset: 16,
            status_offset: 24,
            assignment_type_offset: 28,
            ref_count_offset: 32,
            use_count_offset: 36,
            user_name_offset: 40,
            domain_name_offset: 48,
        }
    } else {
        UseInfo2Layout {
            size: 36,
            local_name_offset: 0,
            remote_name_offset: 4,
            password_offset: 8,
            status_offset: 12,
            assignment_type_offset: 16,
            ref_count_offset: 20,
            use_count_offset: 24,
            user_name_offset: 28,
            domain_name_offset: 32,
        }
    }
}

fn write_use_info_2(
    engine: &mut VirtualExecutionEngine,
    base: u64,
    local_name: Option<&str>,
    remote_name: &str,
    password: Option<&str>,
    user_name: Option<&str>,
    domain_name: Option<&str>,
) -> u64 {
    let layout = use_info_2_layout(engine);
    engine
        .write_test_bytes(base, &vec![0u8; layout.size as usize])
        .unwrap();

    let mut cursor = base + layout.size;
    if let Some(value) = local_name {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.local_name_offset, pointer);
        cursor += ((value.encode_utf16().count() + 1) * 2) as u64;
    }

    let remote_pointer = write_wide_input(engine, cursor, remote_name);
    write_ptr(engine, base + layout.remote_name_offset, remote_pointer);
    cursor += ((remote_name.encode_utf16().count() + 1) * 2) as u64;

    if let Some(value) = password {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.password_offset, pointer);
        cursor += ((value.encode_utf16().count() + 1) * 2) as u64;
    }

    if let Some(value) = user_name {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.user_name_offset, pointer);
        cursor += ((value.encode_utf16().count() + 1) * 2) as u64;
    }

    if let Some(value) = domain_name {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.domain_name_offset, pointer);
    }

    base
}

#[derive(Clone, Copy)]
struct SessionInfo10Layout {
    client_name_offset: u64,
    user_name_offset: u64,
    active_time_offset: u64,
    idle_time_offset: u64,
}

fn session_info_10_layout(engine: &VirtualExecutionEngine) -> SessionInfo10Layout {
    if pointer_size(engine) == 8 {
        SessionInfo10Layout {
            client_name_offset: 0,
            user_name_offset: 8,
            active_time_offset: 16,
            idle_time_offset: 20,
        }
    } else {
        SessionInfo10Layout {
            client_name_offset: 0,
            user_name_offset: 4,
            active_time_offset: 8,
            idle_time_offset: 12,
        }
    }
}

#[derive(Clone, Copy)]
struct FileInfo3Layout {
    id_offset: u64,
    permissions_offset: u64,
    num_locks_offset: u64,
    path_name_offset: u64,
    user_name_offset: u64,
}

fn file_info_3_layout(engine: &VirtualExecutionEngine) -> FileInfo3Layout {
    if pointer_size(engine) == 8 {
        FileInfo3Layout {
            id_offset: 0,
            permissions_offset: 4,
            num_locks_offset: 8,
            path_name_offset: 16,
            user_name_offset: 24,
        }
    } else {
        FileInfo3Layout {
            id_offset: 0,
            permissions_offset: 4,
            num_locks_offset: 8,
            path_name_offset: 12,
            user_name_offset: 16,
        }
    }
}

#[derive(Clone, Copy)]
struct ConnectionInfo1Layout {
    id_offset: u64,
    type_offset: u64,
    num_opens_offset: u64,
    num_users_offset: u64,
    time_offset: u64,
    user_name_offset: u64,
    net_name_offset: u64,
}

fn connection_info_1_layout(engine: &VirtualExecutionEngine) -> ConnectionInfo1Layout {
    if pointer_size(engine) == 8 {
        ConnectionInfo1Layout {
            id_offset: 0,
            type_offset: 4,
            num_opens_offset: 8,
            num_users_offset: 12,
            time_offset: 16,
            user_name_offset: 24,
            net_name_offset: 32,
        }
    } else {
        ConnectionInfo1Layout {
            id_offset: 0,
            type_offset: 4,
            num_opens_offset: 8,
            num_users_offset: 12,
            time_offset: 16,
            user_name_offset: 20,
            net_name_offset: 24,
        }
    }
}

#[derive(Clone, Copy)]
struct TimeOfDayInfoLayout {
    elapsed_time_offset: u64,
    msecs_offset: u64,
    hours_offset: u64,
    mins_offset: u64,
    secs_offset: u64,
    hunds_offset: u64,
    timezone_offset: u64,
    interval_offset: u64,
    day_offset: u64,
    month_offset: u64,
    year_offset: u64,
    weekday_offset: u64,
}

fn time_of_day_info_layout() -> TimeOfDayInfoLayout {
    TimeOfDayInfoLayout {
        elapsed_time_offset: 0,
        msecs_offset: 4,
        hours_offset: 8,
        mins_offset: 12,
        secs_offset: 16,
        hunds_offset: 20,
        timezone_offset: 24,
        interval_offset: 28,
        day_offset: 32,
        month_offset: 36,
        year_offset: 40,
        weekday_offset: 44,
    }
}

#[derive(Clone, Copy)]
struct WkstaUserInfo1Layout {
    user_name_offset: u64,
    logon_domain_offset: u64,
    other_domains_offset: u64,
    logon_server_offset: u64,
}

fn wksta_user_info_1_layout(engine: &VirtualExecutionEngine) -> WkstaUserInfo1Layout {
    if pointer_size(engine) == 8 {
        WkstaUserInfo1Layout {
            user_name_offset: 0,
            logon_domain_offset: 8,
            other_domains_offset: 16,
            logon_server_offset: 24,
        }
    } else {
        WkstaUserInfo1Layout {
            user_name_offset: 0,
            logon_domain_offset: 4,
            other_domains_offset: 8,
            logon_server_offset: 12,
        }
    }
}

#[test]
fn netapi32_exposes_join_and_workstation_profiles() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            computer_name: Some("LABWIN10".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            dns_domain_name: Some("contoso.local".to_string()),
            forest_name: Some("contoso.local".to_string()),
            domain_controller: Some("\\\\DC01.contoso.local".to_string()),
            domain_guid: Some("{12345678-9ABC-4DEF-8123-456789ABCDEF}".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        network: Some(NetworkProfileOverrides {
            dns_servers: Some(vec!["10.10.20.10".to_string()]),
            ..NetworkProfileOverrides::default()
        }),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_get_join_information =
        engine.bind_hook_for_test("netapi32.dll", "NetGetJoinInformation");
    let net_get_dc_name = engine.bind_hook_for_test("netapi32.dll", "NetGetDCName");
    let net_get_any_dc_name = engine.bind_hook_for_test("netapi32.dll", "NetGetAnyDCName");
    let net_wksta_get_info = engine.bind_hook_for_test("netapi32.dll", "NetWkstaGetInfo");
    let net_local_group_get_info =
        engine.bind_hook_for_test("netapi32.dll", "NetLocalGroupGetInfo");
    let net_server_get_info = engine.bind_hook_for_test("netapi32.dll", "NetServerGetInfo");
    let net_server_enum = engine.bind_hook_for_test("netapi32.dll", "NetServerEnum");
    let ds_get_dc_name_w = engine.bind_hook_for_test("netapi32.dll", "DsGetDcNameW");
    let ds_enumerate_domain_trusts_w =
        engine.bind_hook_for_test("netapi32.dll", "DsEnumerateDomainTrustsW");
    let ds_role_get_primary_domain_information =
        engine.bind_hook_for_test("netapi32.dll", "DsRoleGetPrimaryDomainInformation");
    let ds_role_free_memory = engine.bind_hook_for_test("netapi32.dll", "DsRoleFreeMemory");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6502_0000);
    let join_name_ptr = page;
    let join_status_ptr = page + 8;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_get_join_information,
                &[0, join_name_ptr, join_status_ptr],
            )
            .unwrap(),
        0
    );
    let join_name = read_ptr(&engine, join_name_ptr);
    assert_ne!(join_name, 0);
    assert_eq!(read_u32(&engine, join_status_ptr), 3);
    assert_eq!(read_wide_string(&engine, join_name, 64), "CONTOSO");
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[join_name])
            .unwrap(),
        0
    );

    let wksta_info_ptr = page + 0x20;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_wksta_get_info, &[0, 102, wksta_info_ptr])
            .unwrap(),
        0
    );
    let dc_name_ptr = page + 0x10;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_get_dc_name, &[0, 0, dc_name_ptr])
            .unwrap(),
        0
    );
    let dc_name = read_ptr(&engine, dc_name_ptr);
    assert_eq!(
        read_wide_string(&engine, dc_name, 128),
        "\\\\DC01.contoso.local"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_get_any_dc_name, &[0, 0, dc_name_ptr])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, dc_name_ptr), 128),
        "\\\\DC01.contoso.local"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[dc_name])
            .unwrap(),
        0
    );
    let wksta = read_ptr(&engine, wksta_info_ptr);
    let wksta_layout = wksta_info_102_layout(&engine);
    assert_eq!(read_u32(&engine, wksta), 500);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta + wksta_layout.computer_name_offset),
            64
        ),
        "LABWIN10"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta + wksta_layout.langroup_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(read_u32(&engine, wksta + wksta_layout.ver_major_offset), 10);
    assert_eq!(read_u32(&engine, wksta + wksta_layout.ver_minor_offset), 0);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta + wksta_layout.lanroot_offset),
            64
        ),
        "C:\\Windows"
    );
    assert_eq!(
        read_u32(&engine, wksta + wksta_layout.logged_on_users_offset),
        1
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[wksta])
            .unwrap(),
        0
    );

    let server_info_ptr = page + 0x40;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_server_get_info, &[0, 101, server_info_ptr])
            .unwrap(),
        0
    );
    let server = read_ptr(&engine, server_info_ptr);
    let server_layout = server_info_101_layout(&engine);
    assert_eq!(read_u32(&engine, server), 500);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, server + server_layout.name_offset),
            64
        ),
        "LABWIN10"
    );
    assert_eq!(
        read_u32(&engine, server + server_layout.ver_major_offset),
        10
    );
    assert_eq!(
        read_u32(&engine, server + server_layout.ver_minor_offset),
        0
    );
    assert_ne!(
        read_u32(&engine, server + server_layout.server_type_offset),
        0
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, server + server_layout.comment_offset),
            64
        ),
        "Windows 10 Pro"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[server])
            .unwrap(),
        0
    );

    let server_enum_buf_ptr = page + 0x44;
    let server_enum_entries_ptr = page + 0x48;
    let server_enum_total_ptr = page + 0x4C;
    let server_enum_resume_ptr = page + 0x50;
    let server_enum_domain_ptr = page + 0x200;
    let server_enum_domain_bytes = "CONTOSO"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(server_enum_domain_ptr, &server_enum_domain_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_server_enum,
                &[
                    0,
                    101,
                    server_enum_buf_ptr,
                    u32::MAX as u64,
                    server_enum_entries_ptr,
                    server_enum_total_ptr,
                    0,
                    server_enum_domain_ptr,
                    server_enum_resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, server_enum_entries_ptr), 2);
    assert_eq!(read_u32(&engine, server_enum_total_ptr), 2);
    assert_eq!(read_u32(&engine, server_enum_resume_ptr), 0);
    let servers = read_ptr(&engine, server_enum_buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, servers + server_layout.name_offset),
            64
        ),
        "LABWIN10"
    );
    let dc_server = servers + server_layout.size;
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, dc_server + server_layout.name_offset),
            64
        ),
        "DC01.contoso.local"
    );
    assert_ne!(
        read_u32(&engine, dc_server + server_layout.server_type_offset) & 0x0000_0008,
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[servers])
            .unwrap(),
        0
    );

    let server_filter_page = alloc_page(&mut engine, 0x6502_1000);
    let filter_buf_ptr = server_filter_page;
    let filter_entries_ptr = server_filter_page + 0x08;
    let filter_total_ptr = server_filter_page + 0x0C;
    let filter_resume_ptr = server_filter_page + 0x10;
    let filter_domain_ptr = server_filter_page + 0x40;
    let filter_local_scope_ptr = server_filter_page + 0x80;
    let filter_domain_bytes = "CONTOSO"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    let filter_local_scope_bytes = "LABWIN10.contoso.local"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(filter_domain_ptr, &filter_domain_bytes)
        .unwrap();
    engine
        .write_test_bytes(filter_local_scope_ptr, &filter_local_scope_bytes)
        .unwrap();

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_server_enum,
                &[
                    0,
                    101,
                    filter_buf_ptr,
                    u32::MAX as u64,
                    filter_entries_ptr,
                    filter_total_ptr,
                    0x0000_0008,
                    filter_domain_ptr,
                    filter_resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, filter_entries_ptr), 1);
    let dc_only = read_ptr(&engine, filter_buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, dc_only + server_layout.name_offset),
            64
        ),
        "DC01.contoso.local"
    );
    assert_ne!(
        read_u32(&engine, dc_only + server_layout.server_type_offset) & 0x0000_0008,
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[dc_only])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_server_enum,
                &[
                    0,
                    101,
                    filter_buf_ptr,
                    u32::MAX as u64,
                    filter_entries_ptr,
                    filter_total_ptr,
                    0x0000_0001,
                    filter_domain_ptr,
                    filter_resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, filter_entries_ptr), 1);
    let workstation_only = read_ptr(&engine, filter_buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, workstation_only + server_layout.name_offset),
            64
        ),
        "LABWIN10"
    );
    assert_ne!(
        read_u32(&engine, workstation_only + server_layout.server_type_offset) & 0x0000_0001,
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[workstation_only])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_server_enum,
                &[
                    0,
                    101,
                    filter_buf_ptr,
                    u32::MAX as u64,
                    filter_entries_ptr,
                    filter_total_ptr,
                    0x8000_0000,
                    filter_domain_ptr,
                    filter_resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, filter_entries_ptr), 1);
    let domain_enum = read_ptr(&engine, filter_buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, domain_enum + server_layout.name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        read_u32(&engine, domain_enum + server_layout.server_type_offset),
        0x8000_0000
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[domain_enum])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_server_enum,
                &[
                    0,
                    101,
                    filter_buf_ptr,
                    u32::MAX as u64,
                    filter_entries_ptr,
                    filter_total_ptr,
                    0,
                    filter_local_scope_ptr,
                    filter_resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, filter_entries_ptr), 1);
    let local_scope = read_ptr(&engine, filter_buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, local_scope + server_layout.name_offset),
            64
        ),
        "LABWIN10"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[local_scope])
            .unwrap(),
        0
    );

    let ds_role_ptr = page + 0x60;
    assert_eq!(
        engine
            .dispatch_bound_stub(ds_role_get_primary_domain_information, &[0, 1, ds_role_ptr],)
            .unwrap(),
        0
    );
    let ds_role = read_ptr(&engine, ds_role_ptr);
    let ds_layout = ds_role_primary_domain_info_basic_layout(&engine);
    assert_eq!(read_u32(&engine, ds_role), 1);
    assert_eq!(read_u32(&engine, ds_role + ds_layout.flags_offset), 0);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_role + ds_layout.flat_name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_role + ds_layout.dns_name_offset),
            64
        ),
        "contoso.local"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_role + ds_layout.forest_name_offset),
            64
        ),
        "contoso.local"
    );
    assert_eq!(
        read_bytes(&engine, ds_role + ds_layout.domain_guid_offset, 16),
        parse_guid_string_le("{12345678-9ABC-4DEF-8123-456789ABCDEF}").to_vec()
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(ds_role_free_memory, &[ds_role])
            .unwrap(),
        0
    );

    let domain_guid_ptr = page + 0x80;
    engine
        .write_test_bytes(
            domain_guid_ptr,
            &parse_guid_string_le("{12345678-9ABC-4DEF-8123-456789ABCDEF}"),
        )
        .unwrap();
    let ds_dc_info_ptr = page + 0xA0;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                ds_get_dc_name_w,
                &[0, 0, domain_guid_ptr, 0, 0, ds_dc_info_ptr]
            )
            .unwrap(),
        0
    );
    let ds_dc_info = read_ptr(&engine, ds_dc_info_ptr);
    let ds_dc_layout = domain_controller_info_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.name_offset),
            128
        ),
        "\\\\DC01.contoso.local"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.address_offset),
            64
        ),
        "\\\\10.10.20.10"
    );
    assert_eq!(
        read_u32(&engine, ds_dc_info + ds_dc_layout.address_type_offset),
        1
    );
    assert_eq!(
        read_bytes(&engine, ds_dc_info + ds_dc_layout.domain_guid_offset, 16),
        parse_guid_string_le("{12345678-9ABC-4DEF-8123-456789ABCDEF}").to_vec()
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.domain_name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.forest_name_offset),
            64
        ),
        "contoso.local"
    );
    assert_ne!(read_u32(&engine, ds_dc_info + ds_dc_layout.flags_offset), 0);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.dc_site_name_offset),
            64
        ),
        "Default-First-Site-Name"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, ds_dc_info + ds_dc_layout.client_site_name_offset),
            64
        ),
        "Default-First-Site-Name"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[ds_dc_info])
            .unwrap(),
        0
    );

    let trusts_ptr = page + 0xC0;
    let trust_count_ptr = page + 0xC8;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                ds_enumerate_domain_trusts_w,
                &[
                    0,
                    DOMAIN_TRUST_FLAGS_PRIMARY as u64,
                    trusts_ptr,
                    trust_count_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, trust_count_ptr), 1);
    let trust_info = read_ptr(&engine, trusts_ptr);
    let trust_layout = domain_trust_info_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, trust_info + trust_layout.netbios_name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, trust_info + trust_layout.dns_name_offset),
            64
        ),
        "contoso.local"
    );
    assert_ne!(read_u32(&engine, trust_info + trust_layout.flags_offset), 0);
    assert_eq!(
        read_u32(&engine, trust_info + trust_layout.parent_index_offset),
        u32::MAX
    );
    assert_eq!(
        read_u32(&engine, trust_info + trust_layout.trust_type_offset),
        2
    );
    assert_eq!(
        read_u32(&engine, trust_info + trust_layout.trust_attributes_offset),
        0
    );
    let trust_sid = read_ptr(&engine, trust_info + trust_layout.sid_offset);
    let trust_sid_bytes = read_bytes(&engine, trust_sid, 24);
    assert_eq!(trust_sid_bytes[0], 1);
    assert_eq!(trust_sid_bytes[1], 4);
    assert_eq!(
        read_bytes(&engine, trust_info + trust_layout.guid_offset, 16),
        parse_guid_string_le("{12345678-9ABC-4DEF-8123-456789ABCDEF}").to_vec()
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[trust_info])
            .unwrap(),
        0
    );

    let local_group_info_ptr = page + 0xE0;
    let group_name_ptr = page + 0xF0;
    let group_name_bytes = "Administrators"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(group_name_ptr, &group_name_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_local_group_get_info,
                &[0, group_name_ptr, 1, local_group_info_ptr]
            )
            .unwrap(),
        0
    );
    let local_group_info = read_ptr(&engine, local_group_info_ptr);
    let local_group_layout = local_group_info_1_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, local_group_info + local_group_layout.name_offset),
            64
        ),
        "Administrators"
    );
    assert!(read_wide_string(
        &engine,
        read_ptr(
            &engine,
            local_group_info + local_group_layout.comment_offset
        ),
        128
    )
    .contains("complete and unrestricted access"));
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[local_group_info])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_dc_queries_fail_on_workgroup_profiles() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let net_get_dc_name = engine.bind_hook_for_test("netapi32.dll", "NetGetDCName");
    let ds_get_dc_name_w = engine.bind_hook_for_test("netapi32.dll", "DsGetDcNameW");
    let ds_enumerate_domain_trusts_w =
        engine.bind_hook_for_test("netapi32.dll", "DsEnumerateDomainTrustsW");
    let page = alloc_page(&mut engine, 0x6503_0000);
    let buffer_ptr = page;
    let count_ptr = page + 8;

    assert_eq!(
        engine
            .dispatch_bound_stub(net_get_dc_name, &[0, 0, buffer_ptr])
            .unwrap(),
        ERROR_NO_SUCH_DOMAIN
    );
    assert_eq!(engine.last_error() as u64, ERROR_NO_SUCH_DOMAIN);
    assert_eq!(
        engine
            .dispatch_bound_stub(ds_get_dc_name_w, &[0, 0, 0, 0, 0, buffer_ptr])
            .unwrap(),
        ERROR_NO_SUCH_DOMAIN
    );
    assert_eq!(engine.last_error() as u64, ERROR_NO_SUCH_DOMAIN);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                ds_enumerate_domain_trusts_w,
                &[0, DOMAIN_TRUST_FLAGS_PRIMARY as u64, buffer_ptr, count_ptr],
            )
            .unwrap(),
        ERROR_NO_SUCH_DOMAIN
    );
    assert_eq!(engine.last_error() as u64, ERROR_NO_SUCH_DOMAIN);
    assert_eq!(read_ptr(&engine, buffer_ptr), 0);
    assert_eq!(read_u32(&engine, count_ptr), 0);
}

#[test]
fn netapi32_enumerates_and_queries_user_profiles() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            machine_guid: Some("8f2c1e53-9d5a-4c16-9a6e-1e4c2a9f7b31".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        users: Some(vec![
            UserAccountProfile {
                name: "Analyst".to_string(),
                full_name: "Malware Analyst".to_string(),
                comment: "Primary reverse engineering user".to_string(),
                privilege_level: 2,
                home_dir: r"C:\Users\Analyst".to_string(),
                script_path: "login.cmd".to_string(),
                rid: 1101,
                ..UserAccountProfile::default()
            },
            UserAccountProfile {
                name: "Guest".to_string(),
                comment: "Built-in guest account".to_string(),
                flags: 0x0001 | 0x0002 | 0x0200,
                privilege_level: 0,
                rid: 501,
                ..UserAccountProfile::default()
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_user_enum = engine.bind_hook_for_test("netapi32.dll", "NetUserEnum");
    let net_user_get_info = engine.bind_hook_for_test("netapi32.dll", "NetUserGetInfo");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6504_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_user_enum,
                &[
                    0,
                    1,
                    0,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr,
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    assert_eq!(read_u32(&engine, total_ptr), 2);
    assert_eq!(read_u32(&engine, resume_ptr), 0);

    let users = read_ptr(&engine, buf_ptr);
    let layout = user_info_1_layout(&engine);
    let first = users;
    let second = users + layout.size;
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, first + layout.name_offset), 64),
        "Analyst"
    );
    assert_eq!(read_u32(&engine, first + layout.privilege_offset), 2);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, first + layout.home_dir_offset),
            64
        ),
        r"C:\Users\Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, first + layout.comment_offset),
            64
        ),
        "Primary reverse engineering user"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, first + layout.script_path_offset),
            64
        ),
        "login.cmd"
    );
    assert_eq!(
        read_u32(&engine, first + layout.flags_offset),
        0x0001 | 0x0200 | 0x10000
    );
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, second + layout.name_offset), 64),
        "Guest"
    );
    assert_eq!(read_u32(&engine, second + layout.privilege_offset), 0);
    assert_eq!(
        read_u32(&engine, second + layout.flags_offset),
        0x0001 | 0x0002 | 0x0200
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[users])
            .unwrap(),
        0
    );

    let name = page + 0x100;
    let name_bytes = "Analyst"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine.write_test_bytes(name, &name_bytes).unwrap();
    let info_ptr = page + 0x20;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_user_get_info, &[0, name, 23, info_ptr])
            .unwrap(),
        0
    );
    let info = read_ptr(&engine, info_ptr);
    let info_layout = user_info_23_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, info + info_layout.name_offset),
            64
        ),
        "Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, info + info_layout.full_name_offset),
            64
        ),
        "Malware Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, info + info_layout.comment_offset),
            64
        ),
        "Primary reverse engineering user"
    );
    assert_eq!(
        read_u32(&engine, info + info_layout.flags_offset),
        0x0001 | 0x0200 | 0x10000
    );
    let sid = read_ptr(&engine, info + info_layout.sid_offset);
    let sid_bytes = read_bytes(&engine, sid, 28);
    assert_eq!(sid_bytes[0], 1);
    assert_eq!(sid_bytes[1], 5);
    assert_eq!(
        u32::from_le_bytes(sid_bytes[24..28].try_into().unwrap()),
        1101
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[info])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_enumerates_local_groups_and_user_memberships() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        users: Some(vec![
            UserAccountProfile {
                name: "Analyst".to_string(),
                rid: 1101,
                ..UserAccountProfile::default()
            },
            UserAccountProfile {
                name: "Operator".to_string(),
                rid: 1102,
                ..UserAccountProfile::default()
            },
        ]),
        local_groups: Some(vec![
            LocalGroupProfile {
                name: "Administrators".to_string(),
                comment: "Administrative operators".to_string(),
                domain: "BUILTIN".to_string(),
                rid: 544,
                members: vec!["Analyst".to_string()],
            },
            LocalGroupProfile {
                name: "Users".to_string(),
                comment: "Standard local users".to_string(),
                domain: "BUILTIN".to_string(),
                rid: 545,
                members: vec!["Analyst".to_string(), "Operator".to_string()],
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_local_group_enum = engine.bind_hook_for_test("netapi32.dll", "NetLocalGroupEnum");
    let net_user_get_local_groups =
        engine.bind_hook_for_test("netapi32.dll", "NetUserGetLocalGroups");
    let net_local_group_get_members =
        engine.bind_hook_for_test("netapi32.dll", "NetLocalGroupGetMembers");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6505_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_local_group_enum,
                &[
                    0,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    assert_eq!(read_u32(&engine, total_ptr), 2);
    assert_eq!(read_u32(&engine, resume_ptr), 0);
    let groups = read_ptr(&engine, buf_ptr);
    let layout = local_group_info_1_layout(&engine);
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, groups + layout.name_offset), 64),
        "Administrators"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, groups + layout.comment_offset),
            64
        ),
        "Administrative operators"
    );
    let second = groups + layout.size;
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, second + layout.name_offset), 64),
        "Users"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, second + layout.comment_offset),
            64
        ),
        "Standard local users"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[groups])
            .unwrap(),
        0
    );

    let username = page + 0x100;
    let username_bytes = "Analyst"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine.write_test_bytes(username, &username_bytes).unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_user_get_local_groups,
                &[
                    0,
                    username,
                    0,
                    0,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    assert_eq!(read_u32(&engine, total_ptr), 2);
    let analyst_groups = read_ptr(&engine, buf_ptr);
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, analyst_groups), 64),
        "Administrators"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, analyst_groups + pointer_size(&engine) as u64),
            64
        ),
        "Users"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[analyst_groups])
            .unwrap(),
        0
    );

    let group_name = page + 0x180;
    let group_name_bytes = "Administrators"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(group_name, &group_name_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_local_group_get_members,
                &[
                    0,
                    group_name,
                    2,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let members = read_ptr(&engine, buf_ptr);
    let members_layout = local_group_members_info_12_layout(&engine);
    assert_eq!(
        read_u32(&engine, members + members_layout.sid_use_offset),
        1
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, members + members_layout.name_offset),
            64
        ),
        r"DESKTOP-9F4A8D2\Analyst"
    );
    let sid = read_ptr(&engine, members + members_layout.sid_offset);
    let sid_bytes = read_bytes(&engine, sid, 28);
    assert_eq!(sid_bytes[0], 1);
    assert_eq!(sid_bytes[1], 5);
    assert_eq!(
        u32::from_le_bytes(sid_bytes[24..28].try_into().unwrap()),
        1101
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[members])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_enumerates_domain_groups_and_memberships() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            user_domain: Some("CONTOSO".to_string()),
            dns_domain_name: Some("contoso.local".to_string()),
            domain_guid: Some("{87654321-4321-4ABC-9123-ABCDEF012345}".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        users: Some(vec![
            UserAccountProfile {
                name: "Analyst".to_string(),
                full_name: "Malware Analyst".to_string(),
                comment: "Primary reverse engineering user".to_string(),
                privilege_level: 2,
                rid: 1101,
                ..UserAccountProfile::default()
            },
            UserAccountProfile {
                name: "Guest".to_string(),
                comment: "Built-in guest account".to_string(),
                flags: 0x0001 | 0x0002 | 0x0200,
                privilege_level: 0,
                rid: 501,
                ..UserAccountProfile::default()
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_group_enum = engine.bind_hook_for_test("netapi32.dll", "NetGroupEnum");
    let net_group_get_info = engine.bind_hook_for_test("netapi32.dll", "NetGroupGetInfo");
    let net_user_get_groups = engine.bind_hook_for_test("netapi32.dll", "NetUserGetGroups");
    let net_group_get_users = engine.bind_hook_for_test("netapi32.dll", "NetGroupGetUsers");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6506_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_group_enum,
                &[
                    0,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 4);
    assert_eq!(read_u32(&engine, total_ptr), 4);
    assert_eq!(read_u32(&engine, resume_ptr), 0);
    let groups = read_ptr(&engine, buf_ptr);
    let group_layout = local_group_info_1_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, groups + group_layout.name_offset),
            64
        ),
        "Domain Admins"
    );
    assert!(read_wide_string(
        &engine,
        read_ptr(&engine, groups + group_layout.comment_offset),
        96
    )
    .contains("administrators of the domain"));
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(
                &engine,
                groups + group_layout.size + group_layout.name_offset
            ),
            64
        ),
        "Domain Users"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[groups])
            .unwrap(),
        0
    );

    let group_name_ptr = page + 0x40;
    let group_name_bytes = "Domain Users"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(group_name_ptr, &group_name_bytes)
        .unwrap();
    let group_info_ptr = page + 0x60;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_group_get_info, &[0, group_name_ptr, 1, group_info_ptr])
            .unwrap(),
        0
    );
    let group_info = read_ptr(&engine, group_info_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, group_info + group_layout.name_offset),
            64
        ),
        "Domain Users"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, group_info + group_layout.comment_offset),
            64
        ),
        "All domain user accounts"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[group_info])
            .unwrap(),
        0
    );

    let user_name_ptr = page + 0x80;
    let user_name_bytes = "Analyst"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(user_name_ptr, &user_name_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_user_get_groups,
                &[
                    0,
                    user_name_ptr,
                    0,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    assert_eq!(read_u32(&engine, total_ptr), 2);
    let user_groups = read_ptr(&engine, buf_ptr);
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, user_groups), 64),
        "Domain Admins"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, user_groups + pointer_size(&engine) as u64),
            64
        ),
        "Domain Users"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[user_groups])
            .unwrap(),
        0
    );

    let admin_group_name_ptr = page + 0xA0;
    let admin_group_name_bytes = "Domain Admins"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(admin_group_name_ptr, &admin_group_name_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_group_get_users,
                &[
                    0,
                    admin_group_name_ptr,
                    0,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let group_users = read_ptr(&engine, buf_ptr);
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, group_users), 64),
        "Analyst"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[group_users])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_enumerates_shares_sessions_and_workstation_users() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            computer_name: Some("LABWS01".to_string()),
            user_name: Some("Analyst".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            dns_domain_name: Some("contoso.local".to_string()),
            domain_controller: Some("\\\\DC01.contoso.local".to_string()),
            system_root: Some(r"C:\Windows".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        shares: Some(vec![
            ShareProfile {
                name: "ADMIN$".to_string(),
                share_type: 0x8000_0000,
                remark: "Remote Admin".to_string(),
                path: r"C:\Windows".to_string(),
                permissions: 0,
                max_uses: u32::MAX,
                current_uses: 1,
                password: String::new(),
            },
            ShareProfile {
                name: "Samples".to_string(),
                share_type: 0,
                remark: "Malware sample staging".to_string(),
                path: r"C:\Samples".to_string(),
                permissions: 0,
                max_uses: 32,
                current_uses: 2,
                password: String::new(),
            },
        ]),
        network_uses: Some(vec![NetworkUseProfile {
            local_name: "Z:".to_string(),
            remote_name: "\\\\DC01.contoso.local\\SYSVOL".to_string(),
            password: String::new(),
            status: 0,
            assignment_type: 0,
            ref_count: 1,
            use_count: 1,
            user_name: "Analyst".to_string(),
            domain_name: "CONTOSO".to_string(),
            provider: "Microsoft Windows Network".to_string(),
            comment: "Default domain policy share".to_string(),
        }]),
        workstation_users: Some(vec![WorkstationUserProfile {
            user_name: "Analyst".to_string(),
            logon_domain: "CONTOSO".to_string(),
            other_domains: "BUILTIN".to_string(),
            logon_server: "\\\\DC01".to_string(),
        }]),
        network_sessions: Some(vec![
            NetworkSessionProfile {
                client_name: "\\\\10.10.20.15".to_string(),
                user_name: "CONTOSO\\Analyst".to_string(),
                active_time_secs: 5400,
                idle_time_secs: 120,
            },
            NetworkSessionProfile {
                client_name: "\\\\10.10.20.25".to_string(),
                user_name: "CONTOSO\\BackupSvc".to_string(),
                active_time_secs: 1800,
                idle_time_secs: 30,
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_share_enum = engine.bind_hook_for_test("netapi32.dll", "NetShareEnum");
    let net_share_get_info = engine.bind_hook_for_test("netapi32.dll", "NetShareGetInfo");
    let net_use_enum = engine.bind_hook_for_test("netapi32.dll", "NetUseEnum");
    let net_use_get_info = engine.bind_hook_for_test("netapi32.dll", "NetUseGetInfo");
    let net_session_enum = engine.bind_hook_for_test("netapi32.dll", "NetSessionEnum");
    let net_wksta_user_enum = engine.bind_hook_for_test("netapi32.dll", "NetWkstaUserEnum");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6507_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_share_enum,
                &[
                    0,
                    2,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    assert_eq!(read_u32(&engine, total_ptr), 2);
    assert_eq!(read_u32(&engine, resume_ptr), 0);
    let shares = read_ptr(&engine, buf_ptr);
    let share_layout = share_info_2_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, shares + share_layout.name_offset),
            64
        ),
        "ADMIN$"
    );
    assert_eq!(
        read_u32(&engine, shares + share_layout.share_type_offset),
        0x8000_0000
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, shares + share_layout.path_offset),
            64
        ),
        r"C:\Windows"
    );
    let second_share = shares + share_layout.size;
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, second_share + share_layout.name_offset),
            64
        ),
        "Samples"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, second_share + share_layout.remark_offset),
            64
        ),
        "Malware sample staging"
    );
    assert_eq!(
        read_u32(&engine, second_share + share_layout.max_uses_offset),
        32
    );
    assert_eq!(
        read_u32(&engine, second_share + share_layout.current_uses_offset),
        2
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[shares])
            .unwrap(),
        0
    );

    let share_name_ptr = page + 0x40;
    let share_name_bytes = "Samples"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(share_name_ptr, &share_name_bytes)
        .unwrap();
    let share_info_ptr = page + 0x60;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_share_get_info, &[0, share_name_ptr, 2, share_info_ptr])
            .unwrap(),
        0
    );
    let share_info = read_ptr(&engine, share_info_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, share_info + share_layout.name_offset),
            64
        ),
        "Samples"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, share_info + share_layout.path_offset),
            64
        ),
        r"C:\Samples"
    );
    assert_eq!(
        read_u32(&engine, share_info + share_layout.permissions_offset),
        0
    );
    assert_eq!(
        read_ptr(&engine, share_info + share_layout.password_offset),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[share_info])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_use_enum,
                &[
                    0,
                    2,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let network_uses = read_ptr(&engine, buf_ptr);
    let use_layout = use_info_2_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, network_uses + use_layout.local_name_offset),
            32
        ),
        "Z:"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, network_uses + use_layout.remote_name_offset),
            128
        ),
        "\\\\DC01.contoso.local\\SYSVOL"
    );
    assert_eq!(
        read_u32(&engine, network_uses + use_layout.status_offset),
        0
    );
    assert_eq!(
        read_u32(&engine, network_uses + use_layout.assignment_type_offset),
        0
    );
    assert_eq!(
        read_u32(&engine, network_uses + use_layout.ref_count_offset),
        1
    );
    assert_eq!(
        read_u32(&engine, network_uses + use_layout.use_count_offset),
        1
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, network_uses + use_layout.user_name_offset),
            64
        ),
        "Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, network_uses + use_layout.domain_name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[network_uses])
            .unwrap(),
        0
    );

    let use_name_ptr = page + 0x70;
    let use_name_bytes = "Z:"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(use_name_ptr, &use_name_bytes)
        .unwrap();
    let use_info_ptr = page + 0x74;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_use_get_info, &[0, use_name_ptr, 2, use_info_ptr])
            .unwrap(),
        0
    );
    let use_info = read_ptr(&engine, use_info_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, use_info + use_layout.remote_name_offset),
            128
        ),
        "\\\\DC01.contoso.local\\SYSVOL"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[use_info])
            .unwrap(),
        0
    );

    let client_name_ptr = page + 0x80;
    let client_name_bytes = "\\\\10.10.20.15"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(client_name_ptr, &client_name_bytes)
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_session_enum,
                &[
                    0,
                    client_name_ptr,
                    0,
                    10,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let sessions = read_ptr(&engine, buf_ptr);
    let session_layout = session_info_10_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, sessions + session_layout.client_name_offset),
            64
        ),
        "\\\\10.10.20.15"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, sessions + session_layout.user_name_offset),
            64
        ),
        "CONTOSO\\Analyst"
    );
    assert_eq!(
        read_u32(&engine, sessions + session_layout.active_time_offset),
        5400
    );
    assert_eq!(
        read_u32(&engine, sessions + session_layout.idle_time_offset),
        120
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[sessions])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_wksta_user_enum,
                &[
                    0,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let wksta_users = read_ptr(&engine, buf_ptr);
    let wksta_layout = wksta_user_info_1_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta_users + wksta_layout.user_name_offset),
            64
        ),
        "Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta_users + wksta_layout.logon_domain_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta_users + wksta_layout.other_domains_offset),
            64
        ),
        "BUILTIN"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, wksta_users + wksta_layout.logon_server_offset),
            64
        ),
        "\\\\DC01"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[wksta_users])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_supports_dynamic_use_add_and_delete() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            user_name: Some("Analyst".to_string()),
            user_domain: Some("WORKGROUP".to_string()),
            dns_domain_name: Some(String::new()),
            ..MachineIdentityOverrides::default()
        }),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_use_add = engine.bind_hook_for_test("netapi32.dll", "NetUseAdd");
    let net_use_del = engine.bind_hook_for_test("netapi32.dll", "NetUseDel");
    let net_use_enum = engine.bind_hook_for_test("netapi32.dll", "NetUseEnum");
    let net_use_get_info = engine.bind_hook_for_test("netapi32.dll", "NetUseGetInfo");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");
    let get_connection = engine.bind_hook_for_test("mpr.dll", "WNetGetConnectionW");

    let page = alloc_page(&mut engine, 0x6508_0000);
    let use_info = write_use_info_2(
        &mut engine,
        page,
        Some("X:"),
        r"\\FS01.contoso.local\IPC$",
        Some("Secr3t!"),
        Some("Operator"),
        Some("CONTOSO"),
    );
    let parm_error_ptr = page + 0x200;
    engine
        .write_test_bytes(parm_error_ptr, &(0u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(net_use_add, &[0, 2, use_info, parm_error_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, parm_error_ptr), 0);

    let buf_ptr = page + 0x208;
    let entries_ptr = page + 0x210;
    let total_ptr = page + 0x214;
    let resume_ptr = page + 0x218;
    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_use_enum,
                &[
                    0,
                    2,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    let enum_uses = read_ptr(&engine, buf_ptr);
    let use_layout = use_info_2_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, enum_uses + use_layout.local_name_offset),
            32
        ),
        "X:"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, enum_uses + use_layout.remote_name_offset),
            128
        ),
        "\\\\FS01.contoso.local\\IPC$"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[enum_uses])
            .unwrap(),
        0
    );

    let use_name_ptr = page + 0x240;
    write_wide_input(&mut engine, use_name_ptr, "X:");
    let use_info_ptr = page + 0x260;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_use_get_info, &[0, use_name_ptr, 2, use_info_ptr])
            .unwrap(),
        0
    );
    let use_info_out = read_ptr(&engine, use_info_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, use_info_out + use_layout.remote_name_offset),
            128
        ),
        "\\\\FS01.contoso.local\\IPC$"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, use_info_out + use_layout.user_name_offset),
            64
        ),
        "Operator"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, use_info_out + use_layout.domain_name_offset),
            64
        ),
        "CONTOSO"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[use_info_out])
            .unwrap(),
        0
    );

    let remote_buffer = page + 0x300;
    let remote_len = page + 0x2F0;
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[use_name_ptr, remote_buffer, remote_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        "\\\\FS01.contoso.local\\IPC$"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(net_use_del, &[0, use_name_ptr, 0])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_use_get_info, &[0, use_name_ptr, 2, use_info_ptr])
            .unwrap(),
        2250
    );
}

#[test]
fn netapi32_enumerates_remote_open_files_and_supports_close() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        open_files: Some(vec![
            OpenFileProfile {
                id: 0x401,
                permissions: 0x0000_0003,
                num_locks: 1,
                path_name: r"C:\Windows\Temp\desktop.ini".to_string(),
                user_name: r"CONTOSO\Analyst".to_string(),
                client_name: r"\\10.10.20.15".to_string(),
            },
            OpenFileProfile {
                id: 0x402,
                permissions: 0x0000_0001,
                num_locks: 0,
                path_name: r"C:\Samples\loader.bin".to_string(),
                user_name: r"CONTOSO\BackupSvc".to_string(),
                client_name: r"\\10.10.20.25".to_string(),
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_file_enum = engine.bind_hook_for_test("netapi32.dll", "NetFileEnum");
    let net_file_get_info = engine.bind_hook_for_test("netapi32.dll", "NetFileGetInfo");
    let net_file_close = engine.bind_hook_for_test("netapi32.dll", "NetFileClose");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x6509_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;
    let base_path_ptr = page + 0x40;
    let user_name_ptr = page + 0x80;
    write_wide_input(&mut engine, base_path_ptr, r"C:\Windows");
    write_wide_input(&mut engine, user_name_ptr, "Analyst");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_file_enum,
                &[
                    0,
                    base_path_ptr,
                    user_name_ptr,
                    3,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    assert_eq!(read_u32(&engine, resume_ptr), 0);
    let files = read_ptr(&engine, buf_ptr);
    let file_layout = file_info_3_layout(&engine);
    assert_eq!(read_u32(&engine, files + file_layout.id_offset), 0x401);
    assert_eq!(
        read_u32(&engine, files + file_layout.permissions_offset),
        0x3
    );
    assert_eq!(read_u32(&engine, files + file_layout.num_locks_offset), 1);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, files + file_layout.path_name_offset),
            128
        ),
        r"C:\Windows\Temp\desktop.ini"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, files + file_layout.user_name_offset),
            64
        ),
        r"CONTOSO\Analyst"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[files])
            .unwrap(),
        0
    );

    let file_info_ptr = page + 0xC0;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_file_get_info, &[0, 0x402, 3, file_info_ptr])
            .unwrap(),
        0
    );
    let file_info = read_ptr(&engine, file_info_ptr);
    assert_eq!(read_u32(&engine, file_info + file_layout.id_offset), 0x402);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, file_info + file_layout.path_name_offset),
            128
        ),
        r"C:\Samples\loader.bin"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[file_info])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_file_enum,
                &[
                    0,
                    0,
                    0,
                    2,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 2);
    let file_ids = read_ptr(&engine, buf_ptr);
    assert_eq!(read_u32(&engine, file_ids), 0x401);
    assert_eq!(read_u32(&engine, file_ids + 4), 0x402);
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[file_ids])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(net_file_close, &[0, 0x402])
            .unwrap(),
        0
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_file_get_info, &[0, 0x402, 3, file_info_ptr])
            .unwrap(),
        2314
    );
}

#[test]
fn netapi32_enumerates_share_connections_from_share_and_client_views() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        shares: Some(vec![
            ShareProfile {
                name: "Samples".to_string(),
                share_type: 0,
                remark: "Sample staging".to_string(),
                path: r"C:\Samples".to_string(),
                permissions: 0,
                max_uses: 32,
                current_uses: 2,
                password: String::new(),
            },
            ShareProfile {
                name: "IPC$".to_string(),
                share_type: 3 | 0x8000_0000,
                remark: "Remote IPC".to_string(),
                path: String::new(),
                permissions: 0,
                max_uses: u32::MAX,
                current_uses: 1,
                password: String::new(),
            },
        ]),
        network_sessions: Some(vec![NetworkSessionProfile {
            client_name: r"\\10.10.20.15".to_string(),
            user_name: r"CONTOSO\Analyst".to_string(),
            active_time_secs: 5400,
            idle_time_secs: 120,
        }]),
        open_files: Some(vec![
            OpenFileProfile {
                id: 0x501,
                permissions: 0x3,
                num_locks: 0,
                path_name: r"C:\Samples\a.bin".to_string(),
                user_name: r"CONTOSO\Analyst".to_string(),
                client_name: r"\\10.10.20.15".to_string(),
            },
            OpenFileProfile {
                id: 0x502,
                permissions: 0x1,
                num_locks: 0,
                path_name: r"C:\Samples\b.bin".to_string(),
                user_name: r"CONTOSO\Analyst".to_string(),
                client_name: r"\\10.10.20.15".to_string(),
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_connection_enum = engine.bind_hook_for_test("netapi32.dll", "NetConnectionEnum");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x650A_0000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;
    let share_name_ptr = page + 0x40;
    let client_name_ptr = page + 0x80;
    write_wide_input(&mut engine, share_name_ptr, "Samples");
    write_wide_input(&mut engine, client_name_ptr, r"\\10.10.20.15");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_connection_enum,
                &[
                    0,
                    share_name_ptr,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    assert_eq!(read_u32(&engine, total_ptr), 1);
    let connections = read_ptr(&engine, buf_ptr);
    let layout = connection_info_1_layout(&engine);
    assert_eq!(read_u32(&engine, connections + layout.id_offset), 0x501);
    assert_eq!(read_u32(&engine, connections + layout.type_offset), 0);
    assert_eq!(read_u32(&engine, connections + layout.num_opens_offset), 2);
    assert_eq!(read_u32(&engine, connections + layout.num_users_offset), 1);
    assert_eq!(read_u32(&engine, connections + layout.time_offset), 5400);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, connections + layout.user_name_offset),
            64
        ),
        r"CONTOSO\Analyst"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, connections + layout.net_name_offset),
            64
        ),
        r"\\10.10.20.15"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[connections])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_connection_enum,
                &[
                    0,
                    client_name_ptr,
                    0,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    let connection_ids = read_ptr(&engine, buf_ptr);
    assert_eq!(read_u32(&engine, connection_ids), 0x501);
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[connection_ids])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_connection_enum,
                &[
                    0,
                    client_name_ptr,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    let client_connections = read_ptr(&engine, buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, client_connections + layout.net_name_offset),
            64
        ),
        "Samples"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[client_connections])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_synthesizes_default_ipc_session_and_pipe_activity() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            user_name: Some("Analyst".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            dns_domain_name: Some("contoso.local".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        network: Some(NetworkProfileOverrides {
            adapters: Some(vec![NetworkAdapterProfile {
                ipv4_addresses: vec![NetworkAddressProfile {
                    address: "10.10.20.21".to_string(),
                    netmask: "255.255.255.0".to_string(),
                }],
                gateways: vec!["10.10.20.1".to_string()],
                dns_servers: vec!["10.10.20.10".to_string()],
                ..NetworkAdapterProfile::default()
            }]),
            ..NetworkProfileOverrides::default()
        }),
        shares: Some(vec![ShareProfile {
            name: "IPC$".to_string(),
            share_type: 3 | 0x8000_0000,
            remark: "Remote IPC".to_string(),
            path: String::new(),
            permissions: 0,
            max_uses: u32::MAX,
            current_uses: 1,
            password: String::new(),
        }]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_session_enum = engine.bind_hook_for_test("netapi32.dll", "NetSessionEnum");
    let net_file_enum = engine.bind_hook_for_test("netapi32.dll", "NetFileEnum");
    let net_connection_enum = engine.bind_hook_for_test("netapi32.dll", "NetConnectionEnum");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");

    let page = alloc_page(&mut engine, 0x650A_8000);
    let buf_ptr = page;
    let entries_ptr = page + 8;
    let total_ptr = page + 12;
    let resume_ptr = page + 16;
    let client_name_ptr = page + 0x40;
    let share_name_ptr = page + 0x80;
    write_wide_input(&mut engine, client_name_ptr, r"\\10.10.20.26");
    write_wide_input(&mut engine, share_name_ptr, "IPC$");

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_session_enum,
                &[
                    0,
                    0,
                    0,
                    10,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    let sessions = read_ptr(&engine, buf_ptr);
    let session_layout = session_info_10_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, sessions + session_layout.client_name_offset),
            64
        ),
        r"\\10.10.20.26"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, sessions + session_layout.user_name_offset),
            64
        ),
        r"CONTOSO\Analyst"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[sessions])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_file_enum,
                &[
                    0,
                    0,
                    0,
                    3,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    let files = read_ptr(&engine, buf_ptr);
    let file_layout = file_info_3_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, files + file_layout.path_name_offset),
            64
        ),
        r"\PIPE\srvsvc"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, files + file_layout.user_name_offset),
            64
        ),
        r"CONTOSO\Analyst"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[files])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_connection_enum,
                &[
                    0,
                    share_name_ptr,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, entries_ptr), 1);
    let share_connections = read_ptr(&engine, buf_ptr);
    let connection_layout = connection_info_1_layout(&engine);
    assert_eq!(
        read_u32(&engine, share_connections + connection_layout.type_offset),
        3
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(
                &engine,
                share_connections + connection_layout.net_name_offset
            ),
            64
        ),
        r"\\10.10.20.26"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[share_connections])
            .unwrap(),
        0
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(
                net_connection_enum,
                &[
                    0,
                    client_name_ptr,
                    1,
                    buf_ptr,
                    u32::MAX as u64,
                    entries_ptr,
                    total_ptr,
                    resume_ptr
                ],
            )
            .unwrap(),
        0
    );
    let client_connections = read_ptr(&engine, buf_ptr);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(
                &engine,
                client_connections + connection_layout.net_name_offset
            ),
            32
        ),
        "IPC$"
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[client_connections])
            .unwrap(),
        0
    );
}

#[test]
fn netapi32_reports_share_visibility_and_remote_time_of_day() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            system_root: Some(r"C:\Windows".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        shares: Some(vec![
            ShareProfile {
                name: "ADMIN$".to_string(),
                share_type: 0x8000_0000,
                remark: "Remote Admin".to_string(),
                path: r"C:\Windows".to_string(),
                permissions: 0,
                max_uses: u32::MAX,
                current_uses: 1,
                password: String::new(),
            },
            ShareProfile {
                name: "Samples".to_string(),
                share_type: 0,
                remark: "Sample staging".to_string(),
                path: r"C:\Samples".to_string(),
                permissions: 0,
                max_uses: 16,
                current_uses: 1,
                password: String::new(),
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let net_share_check = engine.bind_hook_for_test("netapi32.dll", "NetShareCheck");
    let net_remote_tod = engine.bind_hook_for_test("netapi32.dll", "NetRemoteTOD");
    let net_api_buffer_free = engine.bind_hook_for_test("netapi32.dll", "NetApiBufferFree");
    let get_local_time = engine.bind_hook_for_test("kernel32.dll", "GetLocalTime");

    let page = alloc_page(&mut engine, 0x650B_0000);
    let share_type_ptr = page;
    let admin_device_ptr = page + 0x40;
    let sample_device_ptr = page + 0x80;
    let missing_device_ptr = page + 0xC0;
    write_wide_input(&mut engine, admin_device_ptr, "C:");
    write_wide_input(&mut engine, sample_device_ptr, r"C:\Samples");
    write_wide_input(&mut engine, missing_device_ptr, r"D:\Secret");

    assert_eq!(
        engine
            .dispatch_bound_stub(net_share_check, &[0, admin_device_ptr, share_type_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, share_type_ptr), 0x8000_0000);

    assert_eq!(
        engine
            .dispatch_bound_stub(net_share_check, &[0, sample_device_ptr, share_type_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, share_type_ptr), 0);

    assert_eq!(
        engine
            .dispatch_bound_stub(net_share_check, &[0, missing_device_ptr, share_type_ptr])
            .unwrap(),
        2311
    );

    let tod_ptr = page + 0x100;
    assert_eq!(
        engine
            .dispatch_bound_stub(net_remote_tod, &[0, tod_ptr])
            .unwrap(),
        0
    );
    let tod = read_ptr(&engine, tod_ptr);
    let tod_layout = time_of_day_info_layout();
    assert!(read_u32(&engine, tod + tod_layout.elapsed_time_offset) > 1_600_000_000);
    assert_eq!(read_u32(&engine, tod + tod_layout.timezone_offset), 0);
    assert_eq!(read_u32(&engine, tod + tod_layout.interval_offset), 310);
    assert!(read_u32(&engine, tod + tod_layout.hunds_offset) < 100);
    assert!(read_u32(&engine, tod + tod_layout.msecs_offset) > 0);

    let local_time_ptr = page + 0x180;
    assert_eq!(
        engine
            .dispatch_bound_stub(get_local_time, &[local_time_ptr])
            .unwrap(),
        0
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.year_offset),
        read_u16(&engine, local_time_ptr) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.month_offset),
        read_u16(&engine, local_time_ptr + 2) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.weekday_offset),
        read_u16(&engine, local_time_ptr + 4) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.day_offset),
        read_u16(&engine, local_time_ptr + 6) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.hours_offset),
        read_u16(&engine, local_time_ptr + 8) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.mins_offset),
        read_u16(&engine, local_time_ptr + 10) as u32
    );
    assert_eq!(
        read_u32(&engine, tod + tod_layout.secs_offset),
        read_u16(&engine, local_time_ptr + 12) as u32
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(net_api_buffer_free, &[tod])
            .unwrap(),
        0
    );
}

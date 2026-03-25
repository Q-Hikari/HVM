use hvm::config::load_config;
use hvm::config::EnvironmentOverrides;
use hvm::environment_profile::{MachineIdentityOverrides, NetworkUseProfile};
use hvm::runtime::engine::VirtualExecutionEngine;

const CONNECT_REDIRECT: u32 = 0x0000_0080;
const CONNECT_LOCALDRIVE: u32 = 0x0000_0100;

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

#[derive(Clone, Copy)]
struct NetResourceLayout {
    size: u64,
    scope_offset: u64,
    type_offset: u64,
    display_type_offset: u64,
    usage_offset: u64,
    local_name_offset: u64,
    remote_name_offset: u64,
    comment_offset: u64,
    provider_offset: u64,
}

fn net_resource_layout(engine: &VirtualExecutionEngine) -> NetResourceLayout {
    if pointer_size(engine) == 8 {
        NetResourceLayout {
            size: 48,
            scope_offset: 0,
            type_offset: 4,
            display_type_offset: 8,
            usage_offset: 12,
            local_name_offset: 16,
            remote_name_offset: 24,
            comment_offset: 32,
            provider_offset: 40,
        }
    } else {
        NetResourceLayout {
            size: 32,
            scope_offset: 0,
            type_offset: 4,
            display_type_offset: 8,
            usage_offset: 12,
            local_name_offset: 16,
            remote_name_offset: 20,
            comment_offset: 24,
            provider_offset: 28,
        }
    }
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

fn write_net_resource_w(
    engine: &mut VirtualExecutionEngine,
    base: u64,
    local_name: Option<&str>,
    remote_name: &str,
    comment: Option<&str>,
    provider: Option<&str>,
) -> u64 {
    let layout = net_resource_layout(engine);
    engine
        .write_test_bytes(base, &vec![0u8; layout.size as usize])
        .unwrap();
    engine
        .write_test_bytes(base + layout.type_offset, &(1u32).to_le_bytes())
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

    if let Some(value) = comment {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.comment_offset, pointer);
        cursor += ((value.encode_utf16().count() + 1) * 2) as u64;
    }

    if let Some(value) = provider {
        let pointer = write_wide_input(engine, cursor, value);
        write_ptr(engine, base + layout.provider_offset, pointer);
    }

    base
}

#[derive(Clone, Copy)]
struct NetInfoStructLayout {
    size: u64,
    provider_version_offset: u64,
    status_offset: u64,
    characteristics_offset: u64,
    net_type_offset: u64,
    printers_offset: u64,
    drives_offset: u64,
}

fn net_info_struct_layout(engine: &VirtualExecutionEngine) -> NetInfoStructLayout {
    if pointer_size(engine) == 8 {
        NetInfoStructLayout {
            size: 40,
            provider_version_offset: 4,
            status_offset: 8,
            characteristics_offset: 12,
            net_type_offset: 24,
            printers_offset: 28,
            drives_offset: 32,
        }
    } else {
        NetInfoStructLayout {
            size: 32,
            provider_version_offset: 4,
            status_offset: 8,
            characteristics_offset: 12,
            net_type_offset: 20,
            printers_offset: 24,
            drives_offset: 28,
        }
    }
}

#[derive(Clone, Copy)]
struct NetConnectInfoLayout {
    size: u64,
    flags_offset: u64,
    speed_offset: u64,
    delay_offset: u64,
    opt_data_size_offset: u64,
}

fn net_connect_info_layout() -> NetConnectInfoLayout {
    NetConnectInfoLayout {
        size: 20,
        flags_offset: 4,
        speed_offset: 8,
        delay_offset: 12,
        opt_data_size_offset: 16,
    }
}

#[test]
fn mpr_hooks_expose_network_use_queries_and_resource_enumeration() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            user_name: Some("Analyst".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            ..MachineIdentityOverrides::default()
        }),
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
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_connection = engine.bind_hook_for_test("mpr.dll", "WNetGetConnectionW");
    let get_user = engine.bind_hook_for_test("mpr.dll", "WNetGetUserW");
    let get_universal_name = engine.bind_hook_for_test("mpr.dll", "WNetGetUniversalNameW");
    let open_enum = engine.bind_hook_for_test("mpr.dll", "WNetOpenEnumW");
    let enum_resource = engine.bind_hook_for_test("mpr.dll", "WNetEnumResourceW");
    let close_enum = engine.bind_hook_for_test("mpr.dll", "WNetCloseEnum");

    let page = alloc_page(&mut engine, 0x7900_0000);
    let local_name = page;
    let local_name_bytes = "Z:"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect::<Vec<_>>();
    engine
        .write_test_bytes(local_name, &local_name_bytes)
        .unwrap();

    let remote_buffer = page + 0x40;
    let remote_len = page + 0x20;
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[local_name, remote_buffer, remote_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        "\\\\DC01.contoso.local\\SYSVOL"
    );

    let user_buffer = page + 0x180;
    let user_len = page + 0x24;
    engine.write_test_bytes(user_buffer, &[0u8; 0x100]).unwrap();
    engine
        .write_test_bytes(user_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_user, &[local_name, user_buffer, user_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, user_buffer, 128),
        "CONTOSO\\Analyst"
    );

    let path_input = page + 0x260;
    write_wide_input(&mut engine, path_input, r"Z:\Policies\PolicyDefinitions");
    let universal_len = page + 0x34;
    let universal_buffer = page + 0x380;
    engine
        .write_test_bytes(universal_len, &(0x100u32).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(universal_buffer, &[0u8; 0x100])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_universal_name,
                &[path_input, 1, universal_buffer, universal_len],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, universal_buffer), 128),
        "\\\\DC01.contoso.local\\SYSVOL\\Policies\\PolicyDefinitions"
    );

    let remote_name_len = page + 0x38;
    let remote_name_buffer = page + 0x500;
    engine
        .write_test_bytes(remote_name_len, &(0x140u32).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(remote_name_buffer, &[0u8; 0x140])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_universal_name,
                &[path_input, 2, remote_name_buffer, remote_name_len],
            )
            .unwrap(),
        0
    );
    let ptr_size = pointer_size(&engine) as u64;
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, remote_name_buffer), 128),
        "\\\\DC01.contoso.local\\SYSVOL\\Policies\\PolicyDefinitions"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, remote_name_buffer + ptr_size),
            128
        ),
        "\\\\DC01.contoso.local\\SYSVOL"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, remote_name_buffer + ptr_size * 2),
            128
        ),
        "\\Policies\\PolicyDefinitions"
    );

    let enum_handle_ptr = page + 0x28;
    assert_eq!(
        engine
            .dispatch_bound_stub(open_enum, &[1, 0, 0, 0, enum_handle_ptr])
            .unwrap(),
        0
    );
    let enum_handle = read_u32(&engine, enum_handle_ptr);
    assert_ne!(enum_handle, 0);

    let count_ptr = page + 0x2C;
    let buffer_size_ptr = page + 0x30;
    let resource_buffer = page + 0x280;
    engine
        .write_test_bytes(count_ptr, &u32::MAX.to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(buffer_size_ptr, &(0x400u32).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(resource_buffer, &[0u8; 0x400])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                enum_resource,
                &[
                    enum_handle as u64,
                    count_ptr,
                    resource_buffer,
                    buffer_size_ptr
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, count_ptr), 1);
    let layout = net_resource_layout(&engine);
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_buffer + layout.local_name_offset),
            32
        ),
        "Z:"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_buffer + layout.remote_name_offset),
            128
        ),
        "\\\\DC01.contoso.local\\SYSVOL"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_buffer + layout.comment_offset),
            64
        ),
        "Default domain policy share"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_buffer + layout.provider_offset),
            64
        ),
        "Microsoft Windows Network"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(close_enum, &[enum_handle as u64])
            .unwrap(),
        0
    );
}

#[test]
fn mpr_hooks_support_dynamic_connection_lifecycle() {
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

    let add_connection = engine.bind_hook_for_test("mpr.dll", "WNetAddConnection2W");
    let use_connection = engine.bind_hook_for_test("mpr.dll", "WNetUseConnectionW");
    let cancel_connection = engine.bind_hook_for_test("mpr.dll", "WNetCancelConnection2W");
    let get_connection = engine.bind_hook_for_test("mpr.dll", "WNetGetConnectionW");
    let get_universal_name = engine.bind_hook_for_test("mpr.dll", "WNetGetUniversalNameW");

    let page = alloc_page(&mut engine, 0x7901_0000);

    let explicit_resource = write_net_resource_w(
        &mut engine,
        page,
        Some("Y:"),
        r"\\FS01.contoso.local\Public",
        Some("Drop zone"),
        Some("Microsoft Windows Network"),
    );
    let user_name = page + 0x200;
    write_wide_input(&mut engine, user_name, r"CONTOSO\Operator");
    assert_eq!(
        engine
            .dispatch_bound_stub(add_connection, &[explicit_resource, 0, user_name, 0])
            .unwrap(),
        0
    );

    let mapped_drive = page + 0x300;
    write_wide_input(&mut engine, mapped_drive, "Y:");
    let remote_buffer = page + 0x320;
    let remote_len = page + 0x2F0;
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[mapped_drive, remote_buffer, remote_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        "\\\\FS01.contoso.local\\Public"
    );

    let universal_input = page + 0x430;
    write_wide_input(&mut engine, universal_input, r"Y:\tools\loader");
    let universal_buffer = page + 0x480;
    let universal_len = page + 0x470;
    engine
        .write_test_bytes(universal_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(universal_len, &(0x100u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_universal_name,
                &[universal_input, 1, universal_buffer, universal_len],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, universal_buffer), 128),
        "\\\\FS01.contoso.local\\Public\\tools\\loader"
    );

    let redirected_resource = write_net_resource_w(
        &mut engine,
        page + 0x600,
        None,
        r"\\OPS-SRV\Drop",
        None,
        None,
    );
    let access_name_buffer = page + 0x700;
    let access_name_len = page + 0x6E0;
    let result_ptr = page + 0x6E4;
    engine
        .write_test_bytes(access_name_buffer, &[0u8; 0x40])
        .unwrap();
    engine
        .write_test_bytes(access_name_len, &(32u32).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(result_ptr, &(0u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                use_connection,
                &[
                    0,
                    redirected_resource,
                    0,
                    0,
                    CONNECT_REDIRECT as u64,
                    access_name_buffer,
                    access_name_len,
                    result_ptr,
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_wide_string(&engine, access_name_buffer, 32), "Z:");
    assert_eq!(read_u32(&engine, result_ptr), CONNECT_LOCALDRIVE);

    let redirected_drive = page + 0x760;
    write_wide_input(&mut engine, redirected_drive, "Z:");
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_connection,
                &[redirected_drive, remote_buffer, remote_len]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        "\\\\OPS-SRV\\Drop"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(cancel_connection, &[redirected_drive, 0, 1])
            .unwrap(),
        0
    );
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_connection,
                &[redirected_drive, remote_buffer, remote_len]
            )
            .unwrap(),
        2250
    );
}

#[test]
fn mpr_hooks_support_legacy_connection_entrypoints_and_error_queries() {
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

    let add_connection = engine.bind_hook_for_test("mpr.dll", "WNetAddConnectionW");
    let add_connection3 = engine.bind_hook_for_test("mpr.dll", "WNetAddConnection3W");
    let cancel_connection = engine.bind_hook_for_test("mpr.dll", "WNetCancelConnectionW");
    let get_connection = engine.bind_hook_for_test("mpr.dll", "WNetGetConnectionW");
    let get_last_error = engine.bind_hook_for_test("mpr.dll", "WNetGetLastErrorW");

    let page = alloc_page(&mut engine, 0x7902_0000);
    let remote_name = page;
    let local_name = page + 0x80;
    write_wide_input(&mut engine, remote_name, r"\\FS02.contoso.local\Drop");
    write_wide_input(&mut engine, local_name, "Q:");
    assert_eq!(
        engine
            .dispatch_bound_stub(add_connection, &[remote_name, 0, local_name])
            .unwrap(),
        0
    );

    let remote_buffer = page + 0x100;
    let remote_len = page + 0x0F0;
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[local_name, remote_buffer, remote_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        r"\\FS02.contoso.local\Drop"
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(cancel_connection, &[local_name, 1])
            .unwrap(),
        0
    );
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[local_name, remote_buffer, remote_len])
            .unwrap(),
        2250
    );

    let resource = write_net_resource_w(
        &mut engine,
        page + 0x200,
        Some("R:"),
        r"\\FS03.contoso.local\Tools",
        None,
        None,
    );
    let drive_r = page + 0x360;
    write_wide_input(&mut engine, drive_r, "R:");
    assert_eq!(
        engine
            .dispatch_bound_stub(add_connection3, &[0, resource, 0, 0, 0])
            .unwrap(),
        0
    );
    engine
        .write_test_bytes(remote_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(remote_len, &(128u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection, &[drive_r, remote_buffer, remote_len])
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, remote_buffer, 128),
        r"\\FS03.contoso.local\Tools"
    );

    let invalid_remote = page + 0x400;
    write_wide_input(&mut engine, invalid_remote, r"FS03\Broken");
    assert_eq!(
        engine
            .dispatch_bound_stub(add_connection, &[invalid_remote, 0, 0])
            .unwrap(),
        67
    );

    let error_code_ptr = page + 0x480;
    let error_buf = page + 0x500;
    let provider_buf = page + 0x680;
    engine.write_test_bytes(error_buf, &[0u8; 0x100]).unwrap();
    engine
        .write_test_bytes(provider_buf, &[0u8; 0x100])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_last_error,
                &[error_code_ptr, error_buf, 64, provider_buf, 64],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, error_code_ptr), 67);
    assert_eq!(
        read_wide_string(&engine, error_buf, 64),
        "The network name cannot be found."
    );
    assert_eq!(
        read_wide_string(&engine, provider_buf, 64),
        "Microsoft Windows Network"
    );
}

#[test]
fn mpr_hooks_expose_provider_and_resource_metadata_queries() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            computer_name: Some("LABWIN10".to_string()),
            user_name: Some("Analyst".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            dns_domain_name: Some("contoso.local".to_string()),
            domain_controller: Some("\\\\DC01.contoso.local".to_string()),
            ..MachineIdentityOverrides::default()
        }),
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
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_provider_name = engine.bind_hook_for_test("mpr.dll", "WNetGetProviderNameW");
    let get_network_information =
        engine.bind_hook_for_test("mpr.dll", "WNetGetNetworkInformationW");
    let get_resource_information =
        engine.bind_hook_for_test("mpr.dll", "WNetGetResourceInformationW");
    let get_resource_parent = engine.bind_hook_for_test("mpr.dll", "WNetGetResourceParentW");

    let page = alloc_page(&mut engine, 0x7904_0000);
    let provider_buffer = page + 0x100;
    let provider_len = page + 0x80;
    engine
        .write_test_bytes(provider_buffer, &[0u8; 0x100])
        .unwrap();
    engine
        .write_test_bytes(provider_len, &(64u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_provider_name,
                &[0x0002_0000, provider_buffer, provider_len],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_wide_string(&engine, provider_buffer, 64),
        "Microsoft Windows Network"
    );

    let network_info_layout = net_info_struct_layout(&engine);
    let network_info_ptr = page + 0x200;
    engine
        .write_test_bytes(
            network_info_ptr,
            &vec![0u8; network_info_layout.size as usize],
        )
        .unwrap();
    engine
        .write_test_bytes(
            network_info_ptr,
            &(network_info_layout.size as u32).to_le_bytes(),
        )
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_network_information,
                &[provider_buffer, network_info_ptr]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_u32(&engine, network_info_ptr),
        network_info_layout.size as u32
    );
    assert_eq!(
        read_u32(
            &engine,
            network_info_ptr + network_info_layout.provider_version_offset
        ),
        0x0005_0001
    );
    assert_eq!(
        read_u32(
            &engine,
            network_info_ptr + network_info_layout.status_offset
        ),
        0
    );
    assert_eq!(
        read_u32(
            &engine,
            network_info_ptr + network_info_layout.characteristics_offset
        ),
        4
    );
    assert_eq!(
        read_u16(
            &engine,
            network_info_ptr + network_info_layout.net_type_offset
        ),
        2
    );
    assert_eq!(
        read_u32(
            &engine,
            network_info_ptr + network_info_layout.printers_offset
        ),
        0
    );
    assert_eq!(
        read_u32(
            &engine,
            network_info_ptr + network_info_layout.drives_offset
        ),
        1
    );

    let resource_input = write_net_resource_w(
        &mut engine,
        page + 0x400,
        Some("Z:"),
        r"\\DC01.contoso.local\SYSVOL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}",
        None,
        None,
    );
    let resource_output = page + 0x700;
    let resource_output_size = page + 0x6F0;
    let system_ptr_slot = page + 0x6E0;
    engine
        .write_test_bytes(resource_output, &[0u8; 0x280])
        .unwrap();
    engine
        .write_test_bytes(resource_output_size, &(0x280u32).to_le_bytes())
        .unwrap();
    engine
        .write_test_bytes(system_ptr_slot, &vec![0u8; pointer_size(&engine)])
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_resource_information,
                &[
                    resource_input,
                    resource_output,
                    resource_output_size,
                    system_ptr_slot
                ],
            )
            .unwrap(),
        0
    );
    let resource_layout = net_resource_layout(&engine);
    assert_eq!(
        read_u32(&engine, resource_output + resource_layout.scope_offset),
        2
    );
    assert_eq!(
        read_u32(&engine, resource_output + resource_layout.type_offset),
        1
    );
    assert_eq!(
        read_u32(
            &engine,
            resource_output + resource_layout.display_type_offset
        ),
        3
    );
    assert_eq!(
        read_u32(&engine, resource_output + resource_layout.usage_offset),
        1
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_output + resource_layout.local_name_offset),
            16
        ),
        "Z:"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(
                &engine,
                resource_output + resource_layout.remote_name_offset
            ),
            128
        ),
        r"\\DC01.contoso.local\SYSVOL"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_output + resource_layout.comment_offset),
            128
        ),
        "Default domain policy share"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, resource_output + resource_layout.provider_offset),
            64
        ),
        "Microsoft Windows Network"
    );
    assert_eq!(
        read_wide_string(&engine, read_ptr(&engine, system_ptr_slot), 128),
        r"\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
    );

    let parent_output = page + 0xA00;
    let parent_output_size = page + 0x9F0;
    engine
        .write_test_bytes(parent_output, &[0u8; 0x200])
        .unwrap();
    engine
        .write_test_bytes(parent_output_size, &(0x200u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(
                get_resource_parent,
                &[resource_input, parent_output, parent_output_size],
            )
            .unwrap(),
        0
    );
    assert_eq!(
        read_u32(&engine, parent_output + resource_layout.scope_offset),
        2
    );
    assert_eq!(
        read_u32(&engine, parent_output + resource_layout.type_offset),
        0
    );
    assert_eq!(
        read_u32(&engine, parent_output + resource_layout.display_type_offset),
        2
    );
    assert_eq!(
        read_u32(&engine, parent_output + resource_layout.usage_offset),
        2
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, parent_output + resource_layout.remote_name_offset),
            128
        ),
        r"\\DC01.contoso.local"
    );
    assert_eq!(
        read_wide_string(
            &engine,
            read_ptr(&engine, parent_output + resource_layout.comment_offset),
            64
        ),
        "CONTOSO Domain Controller"
    );
}

#[test]
fn mpr_hooks_expose_connection_performance_profiles() {
    let mut config = sample_config();
    config.environment_overrides = Some(EnvironmentOverrides {
        machine: Some(MachineIdentityOverrides {
            user_name: Some("Analyst".to_string()),
            user_domain: Some("CONTOSO".to_string()),
            ..MachineIdentityOverrides::default()
        }),
        network_uses: Some(vec![
            NetworkUseProfile {
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
            },
            NetworkUseProfile {
                local_name: String::new(),
                remote_name: "\\\\LABWIN10\\IPC$".to_string(),
                password: String::new(),
                status: 0,
                assignment_type: 0,
                ref_count: 1,
                use_count: 1,
                user_name: "Analyst".to_string(),
                domain_name: "CONTOSO".to_string(),
                provider: "Microsoft Windows Network".to_string(),
                comment: "Remote IPC".to_string(),
            },
        ]),
        ..EnvironmentOverrides::default()
    });

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_connection_performance =
        engine.bind_hook_for_test("mpr.dll", "MultinetGetConnectionPerformanceW");
    let page = alloc_page(&mut engine, 0x7906_0000);
    let connect_layout = net_connect_info_layout();

    let disk_resource = write_net_resource_w(
        &mut engine,
        page + 0x100,
        Some("Z:"),
        r"\\DC01.contoso.local\SYSVOL\Policies",
        None,
        None,
    );
    let disk_info = page + 0x400;
    engine
        .write_test_bytes(disk_info, &vec![0u8; connect_layout.size as usize])
        .unwrap();
    engine
        .write_test_bytes(disk_info, &(connect_layout.size as u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection_performance, &[disk_resource, disk_info])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, disk_info), connect_layout.size as u32);
    assert_eq!(
        read_u32(&engine, disk_info + connect_layout.flags_offset),
        8
    );
    assert_eq!(
        read_u32(&engine, disk_info + connect_layout.speed_offset),
        10_000_000
    );
    assert_eq!(
        read_u32(&engine, disk_info + connect_layout.delay_offset),
        1
    );
    assert_eq!(
        read_u32(&engine, disk_info + connect_layout.opt_data_size_offset),
        65_536
    );

    let ipc_resource = write_net_resource_w(
        &mut engine,
        page + 0x500,
        None,
        r"\\LABWIN10\IPC$\srvsvc",
        None,
        None,
    );
    let ipc_info = page + 0x700;
    engine
        .write_test_bytes(ipc_info, &vec![0u8; connect_layout.size as usize])
        .unwrap();
    engine
        .write_test_bytes(ipc_info, &(connect_layout.size as u32).to_le_bytes())
        .unwrap();
    assert_eq!(
        engine
            .dispatch_bound_stub(get_connection_performance, &[ipc_resource, ipc_info])
            .unwrap(),
        0
    );
    assert_eq!(
        read_u32(&engine, ipc_info + connect_layout.speed_offset),
        1_000_000
    );
    assert_eq!(read_u32(&engine, ipc_info + connect_layout.delay_offset), 2);
    assert_eq!(
        read_u32(&engine, ipc_info + connect_layout.opt_data_size_offset),
        4_096
    );
}

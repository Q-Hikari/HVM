use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

const DIGCF_PRESENT: u64 = 0x0000_0002;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const SPDRP_DEVICEDESC: u64 = 0;
const CM_DRP_SERVICE: u64 = 5;
const CR_SUCCESS: u64 = 0;
const CR_BUFFER_SMALL: u64 = 0x1A;

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

fn write_guid_le(engine: &mut VirtualExecutionEngine, address: u64, guid: &str) {
    let bytes = parse_guid_string_le(guid);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn write_wide(engine: &mut VirtualExecutionEngine, address: u64, value: &str) {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    engine.write_test_bytes(address, &bytes).unwrap();
}

fn write_u32(engine: &mut VirtualExecutionEngine, address: u64, value: u32) {
    engine
        .write_test_bytes(address, &value.to_le_bytes())
        .unwrap();
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

fn read_wide_multi_sz(engine: &VirtualExecutionEngine, address: u64, words: usize) -> Vec<String> {
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

#[test]
fn setupapi_and_cfgmgr32_hooks_expose_seeded_devices() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let setup_get_class_devs = engine.bind_hook_for_test("setupapi.dll", "SetupDiGetClassDevsW");
    let setup_enum_info = engine.bind_hook_for_test("setupapi.dll", "SetupDiEnumDeviceInfo");
    let setup_get_property =
        engine.bind_hook_for_test("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW");
    let setup_get_instance =
        engine.bind_hook_for_test("setupapi.dll", "SetupDiGetDeviceInstanceIdW");
    let setup_open_reg_key = engine.bind_hook_for_test("setupapi.dll", "SetupDiOpenDevRegKey");
    let setup_enum_interfaces =
        engine.bind_hook_for_test("setupapi.dll", "SetupDiEnumDeviceInterfaces");
    let setup_get_interface_detail =
        engine.bind_hook_for_test("setupapi.dll", "SetupDiGetDeviceInterfaceDetailW");
    let setup_class_guids = engine.bind_hook_for_test("setupapi.dll", "SetupDiClassGuidsFromNameW");
    let setup_get_inf_class = engine.bind_hook_for_test("setupapi.dll", "SetupDiGetINFClassW");
    let setup_destroy = engine.bind_hook_for_test("setupapi.dll", "SetupDiDestroyDeviceInfoList");

    let cm_locate = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Locate_DevNodeW");
    let cm_get_id = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Device_IDW");
    let cm_get_id_size = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Device_ID_Size");
    let cm_get_parent = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Parent");
    let cm_get_child = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Child");
    let cm_get_sibling = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Sibling");
    let cm_get_status = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_DevNode_Status");
    let cm_get_property =
        engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_DevNode_Registry_PropertyW");
    let cm_map_err = engine.bind_hook_for_test("cfgmgr32.dll", "CM_MapCrToWin32Err");
    let cm_list_size = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Device_ID_List_SizeW");
    let cm_list = engine.bind_hook_for_test("cfgmgr32.dll", "CM_Get_Device_ID_ListW");
    let reg_query = engine.bind_hook_for_test("advapi32.dll", "RegQueryValueExW");
    let reg_close = engine.bind_hook_for_test("advapi32.dll", "RegCloseKey");

    let net_guid = alloc_page(&mut engine, 0x7900_0000);
    write_guid_le(
        &mut engine,
        net_guid,
        "{4D36E972-E325-11CE-BFC1-08002BE10318}",
    );
    let enumerator = alloc_page(&mut engine, 0x7900_1000);
    write_wide(&mut engine, enumerator, "PCI");
    let devinfo = engine
        .dispatch_bound_stub(
            setup_get_class_devs,
            &[net_guid, enumerator, 0, DIGCF_PRESENT],
        )
        .unwrap();
    assert_ne!(devinfo, u32::MAX as u64);

    let devinfo_data = alloc_page(&mut engine, 0x7900_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(setup_enum_info, &[devinfo, 0, devinfo_data])
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, devinfo_data + 20), 0x10001);
    assert_eq!(
        engine
            .dispatch_bound_stub(setup_enum_info, &[devinfo, 1, devinfo_data])
            .unwrap(),
        0
    );

    let property_type = alloc_page(&mut engine, 0x7900_3000);
    let property_buffer = alloc_page(&mut engine, 0x7900_4000);
    let property_required = alloc_page(&mut engine, 0x7900_5000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_get_property,
                &[
                    devinfo,
                    devinfo_data,
                    SPDRP_DEVICEDESC,
                    property_type,
                    property_buffer,
                    256,
                    property_required
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, property_type), 1);
    assert_eq!(
        read_wide_string(&engine, property_buffer, 128),
        "Sandbox Intel(R) PRO/1000 MT Desktop Adapter"
    );

    let instance_required = alloc_page(&mut engine, 0x7900_6000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_get_instance,
                &[
                    devinfo,
                    devinfo_data,
                    property_buffer,
                    260,
                    instance_required
                ],
            )
            .unwrap(),
        1
    );
    let instance_id = read_wide_string(&engine, property_buffer, 260);
    assert_eq!(
        instance_id,
        r"PCI\VEN_8086&DEV_100E&SUBSYS_00008086&REV_02\3&11583659&0&18"
    );

    let reg_handle = engine
        .dispatch_bound_stub(setup_open_reg_key, &[devinfo, devinfo_data, 0, 0, 0, 0])
        .unwrap();
    assert_ne!(reg_handle, u32::MAX as u64);
    let value_name = alloc_page(&mut engine, 0x7900_7000);
    write_wide(&mut engine, value_name, "Service");
    write_u32(&mut engine, property_required, 128);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                reg_query,
                &[
                    reg_handle,
                    value_name,
                    0,
                    property_type,
                    property_buffer,
                    property_required
                ],
            )
            .unwrap(),
        0
    );
    assert_eq!(read_wide_string(&engine, property_buffer, 64), "e1iexpress");
    assert_eq!(
        engine
            .dispatch_bound_stub(reg_close, &[reg_handle])
            .unwrap(),
        0
    );

    let interface_data = alloc_page(&mut engine, 0x7900_8000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_enum_interfaces,
                &[devinfo, 0, net_guid, 0, interface_data],
            )
            .unwrap(),
        1
    );
    let detail_required = alloc_page(&mut engine, 0x7900_9000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_get_interface_detail,
                &[devinfo, interface_data, 0, 0, detail_required, 0],
            )
            .unwrap(),
        0
    );
    assert_eq!(engine.last_error(), ERROR_INSUFFICIENT_BUFFER);
    let detail_size = read_u32(&engine, detail_required);
    assert!(detail_size > 8);
    let detail_buffer = alloc_page(&mut engine, 0x7900_A000);
    let returned_devinfo = alloc_page(&mut engine, 0x7900_B000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_get_interface_detail,
                &[
                    devinfo,
                    interface_data,
                    detail_buffer,
                    detail_size as u64,
                    detail_required,
                    returned_devinfo
                ],
            )
            .unwrap(),
        1
    );
    assert!(read_wide_string(&engine, detail_buffer + 4, 260)
        .starts_with(r"\\?\PCI#VEN_8086&DEV_100E&SUBSYS_00008086&REV_02#"));
    assert_eq!(read_u32(&engine, returned_devinfo + 20), 0x10001);

    let class_name = alloc_page(&mut engine, 0x7900_C000);
    write_wide(&mut engine, class_name, "Net");
    let guid_list = alloc_page(&mut engine, 0x7900_D000);
    let guid_required = alloc_page(&mut engine, 0x7900_E000);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_class_guids,
                &[class_name, guid_list, 4, guid_required]
            )
            .unwrap(),
        1
    );
    assert_eq!(read_u32(&engine, guid_required), 1);
    assert_eq!(
        engine.modules().memory().read(guid_list, 16).unwrap(),
        parse_guid_string_le("{4D36E972-E325-11CE-BFC1-08002BE10318}")
    );

    let inf_path = alloc_page(&mut engine, 0x7900_F000);
    write_wide(&mut engine, inf_path, r"C:\Windows\INF\nete1i.inf");
    write_u32(&mut engine, guid_required, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                setup_get_inf_class,
                &[inf_path, property_buffer, 64, guid_required, guid_list],
            )
            .unwrap(),
        1
    );
    assert_eq!(read_wide_string(&engine, property_buffer, 64), "Net");
    assert_eq!(
        engine.modules().memory().read(guid_list, 16).unwrap(),
        parse_guid_string_le("{4D36E972-E325-11CE-BFC1-08002BE10318}")
    );

    let located_devinst = alloc_page(&mut engine, 0x7901_0000);
    let instance_name = alloc_page(&mut engine, 0x7901_1000);
    write_wide(&mut engine, instance_name, &instance_id);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_locate, &[located_devinst, instance_name, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, located_devinst), 0x10001);

    let id_size = alloc_page(&mut engine, 0x7901_2000);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_id_size, &[id_size, 0x10001, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(
        read_u32(&engine, id_size) as usize,
        instance_id.encode_utf16().count()
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_id, &[0x10001, property_buffer, 260, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_wide_string(&engine, property_buffer, 260), instance_id);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_id, &[0x10001, property_buffer, 8, 0])
            .unwrap(),
        CR_BUFFER_SMALL
    );
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_map_err, &[CR_BUFFER_SMALL, 5])
            .unwrap(),
        122
    );

    let parent_ptr = alloc_page(&mut engine, 0x7901_3000);
    let child_ptr = alloc_page(&mut engine, 0x7901_4000);
    let sibling_ptr = alloc_page(&mut engine, 0x7901_5000);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_parent, &[parent_ptr, 0x10001, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, parent_ptr), 0x10000);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_child, &[child_ptr, 0x10000, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, child_ptr), 0x10001);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_sibling, &[sibling_ptr, 0x10001, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, sibling_ptr), 0x10002);

    let status_ptr = alloc_page(&mut engine, 0x7901_6000);
    let problem_ptr = alloc_page(&mut engine, 0x7901_7000);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_get_status, &[status_ptr, problem_ptr, 0x10001, 0])
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, status_ptr), 0x0180_200);
    assert_eq!(read_u32(&engine, problem_ptr), 0);

    write_u32(&mut engine, property_required, 128);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                cm_get_property,
                &[
                    0x10001,
                    CM_DRP_SERVICE,
                    property_type,
                    property_buffer,
                    property_required,
                    0
                ],
            )
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(read_u32(&engine, property_type), 1);
    assert_eq!(read_wide_string(&engine, property_buffer, 64), "e1iexpress");

    let filter_name = alloc_page(&mut engine, 0x7901_8000);
    write_wide(&mut engine, filter_name, "PCI");
    let list_size_ptr = alloc_page(&mut engine, 0x7901_9000);
    assert_eq!(
        engine
            .dispatch_bound_stub(cm_list_size, &[list_size_ptr, filter_name, 0])
            .unwrap(),
        CR_SUCCESS
    );
    let list_chars = read_u32(&engine, list_size_ptr);
    assert!(list_chars >= 4);
    assert_eq!(
        engine
            .dispatch_bound_stub(
                cm_list,
                &[filter_name, property_buffer, list_chars as u64, 0]
            )
            .unwrap(),
        CR_SUCCESS
    );
    assert_eq!(
        read_wide_multi_sz(&engine, property_buffer, list_chars as usize),
        vec![instance_id]
    );

    assert_eq!(
        engine
            .dispatch_bound_stub(setup_destroy, &[devinfo])
            .unwrap(),
        1
    );
}

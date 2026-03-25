use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

const ERROR_BUFFER_OVERFLOW: u64 = 111;

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
    "computer_name": "WINLAB-42"
  },
  "network": {
    "host_name": "WINLAB-42",
    "domain_name": "corp.local",
    "dns_suffix": "corp.local",
    "dns_servers": [
      "10.0.0.2",
      "1.1.1.1"
    ],
    "adapters": [
      {
        "name": "{8E8047D0-8C4F-4A14-9F1A-3D12E4A4F201}",
        "description": "Intel(R) Ethernet Connection (7) I219-LM",
        "friendly_name": "CorpLAN",
        "dns_suffix": "corp.local",
        "if_index": 17,
        "adapter_type": 6,
        "mac_address": "00:50:56:C0:00:08",
        "mtu": 1500,
        "oper_status": 1,
        "ipv4_addresses": [
          {
            "address": "10.0.2.15",
            "netmask": "255.255.255.0"
          }
        ],
        "gateways": [
          "10.0.2.2"
        ],
        "dns_servers": [
          "10.0.0.2",
          "1.1.1.1"
        ],
        "dhcp_enabled": true,
        "dhcp_server": "10.0.2.2"
      }
    ]
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

fn read_ptr(engine: &VirtualExecutionEngine, address: u64) -> u64 {
    let size = pointer_size(engine);
    let bytes = engine.modules().memory().read(address, size).unwrap();
    if size == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn read_c_string(engine: &VirtualExecutionEngine, address: u64, capacity: usize) -> String {
    let bytes = engine.modules().memory().read(address, capacity).unwrap();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
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

fn read_ipv4_from_sockaddr(engine: &VirtualExecutionEngine, address: u64) -> String {
    let bytes = engine.modules().memory().read(address + 4, 4).unwrap();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
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
struct FixedInfoLayout {
    dns_list_offset: u64,
}

fn fixed_info_layout(engine: &VirtualExecutionEngine) -> FixedInfoLayout {
    if pointer_size(engine) == 8 {
        FixedInfoLayout {
            dns_list_offset: 272,
        }
    } else {
        FixedInfoLayout {
            dns_list_offset: 268,
        }
    }
}

#[derive(Clone, Copy)]
struct AdapterInfoLayout {
    adapter_name_offset: u64,
    description_offset: u64,
    address_offset: u64,
    address_length_offset: u64,
    index_offset: u64,
    type_offset: u64,
    dhcp_enabled_offset: u64,
    ip_list_offset: u64,
    gateway_list_offset: u64,
}

fn adapter_info_layout(engine: &VirtualExecutionEngine) -> AdapterInfoLayout {
    if pointer_size(engine) == 8 {
        AdapterInfoLayout {
            adapter_name_offset: 12,
            description_offset: 272,
            address_offset: 408,
            address_length_offset: 404,
            index_offset: 416,
            type_offset: 420,
            dhcp_enabled_offset: 424,
            ip_list_offset: 440,
            gateway_list_offset: 488,
        }
    } else {
        AdapterInfoLayout {
            adapter_name_offset: 8,
            description_offset: 268,
            address_offset: 404,
            address_length_offset: 400,
            index_offset: 412,
            type_offset: 416,
            dhcp_enabled_offset: 420,
            ip_list_offset: 428,
            gateway_list_offset: 468,
        }
    }
}

#[derive(Clone, Copy)]
struct AdapterAddressesLayout {
    adapter_name_offset: u64,
    first_unicast_offset: u64,
    dns_suffix_offset: u64,
    description_offset: u64,
    friendly_name_offset: u64,
    physical_address_offset: u64,
    physical_address_length_offset: u64,
    mtu_offset: u64,
    if_type_offset: u64,
    oper_status_offset: u64,
}

fn adapter_addresses_layout(engine: &VirtualExecutionEngine) -> AdapterAddressesLayout {
    if pointer_size(engine) == 8 {
        AdapterAddressesLayout {
            adapter_name_offset: 16,
            first_unicast_offset: 24,
            dns_suffix_offset: 56,
            description_offset: 64,
            friendly_name_offset: 72,
            physical_address_offset: 80,
            physical_address_length_offset: 88,
            mtu_offset: 96,
            if_type_offset: 100,
            oper_status_offset: 104,
        }
    } else {
        AdapterAddressesLayout {
            adapter_name_offset: 12,
            first_unicast_offset: 16,
            dns_suffix_offset: 32,
            description_offset: 36,
            friendly_name_offset: 40,
            physical_address_offset: 44,
            physical_address_length_offset: 52,
            mtu_offset: 60,
            if_type_offset: 64,
            oper_status_offset: 68,
        }
    }
}

#[derive(Clone, Copy)]
struct UnicastLayout {
    socket_address_offset: u64,
    socket_length_offset: u64,
    on_link_prefix_length_offset: u64,
}

fn unicast_layout(engine: &VirtualExecutionEngine) -> UnicastLayout {
    if pointer_size(engine) == 8 {
        UnicastLayout {
            socket_address_offset: 16,
            socket_length_offset: 24,
            on_link_prefix_length_offset: 56,
        }
    } else {
        UnicastLayout {
            socket_address_offset: 12,
            socket_length_offset: 16,
            on_link_prefix_length_offset: 44,
        }
    }
}

#[test]
fn iphlpapi_hooks_expose_profiled_network_inventory() {
    let root = unique_root("iphlpapi-hooks");
    let profile_path = write_profile(&root);
    let mut config = sample_config();
    config.environment_profile = Some(profile_path);

    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let get_number = engine.bind_hook_for_test("iphlpapi.dll", "GetNumberOfInterfaces");
    let get_best = engine.bind_hook_for_test("iphlpapi.dll", "GetBestInterface");
    let get_friendly = engine.bind_hook_for_test("iphlpapi.dll", "GetFriendlyIfIndex");
    let get_network = engine.bind_hook_for_test("iphlpapi.dll", "GetNetworkParams");
    let get_info = engine.bind_hook_for_test("iphlpapi.dll", "GetAdaptersInfo");
    let get_addresses = engine.bind_hook_for_test("iphlpapi.dll", "GetAdaptersAddresses");

    let count_ptr = alloc_page(&mut engine, 0x7600_0000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_number, &[count_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, count_ptr), 1);

    let best_ptr = alloc_page(&mut engine, 0x7600_1000);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_best, &[0x0F02000A, best_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_u32(&engine, best_ptr), 17);
    assert_eq!(engine.dispatch_bound_stub(get_friendly, &[17]).unwrap(), 17);

    let fixed_len_ptr = alloc_page(&mut engine, 0x7600_2000);
    write_u32(&mut engine, fixed_len_ptr, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_network, &[0, fixed_len_ptr])
            .unwrap(),
        ERROR_BUFFER_OVERFLOW
    );
    let fixed_size = read_u32(&engine, fixed_len_ptr) as u64;
    assert!(fixed_size >= 584);
    let fixed_info = alloc_page(&mut engine, 0x7600_3000);
    write_u32(&mut engine, fixed_len_ptr, fixed_size as u32);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_network, &[fixed_info, fixed_len_ptr])
            .unwrap(),
        0
    );
    assert_eq!(read_c_string(&engine, fixed_info, 132), "WINLAB-42");
    assert_eq!(read_c_string(&engine, fixed_info + 132, 132), "corp.local");
    let fixed_layout = fixed_info_layout(&engine);
    assert_eq!(
        read_c_string(&engine, fixed_info + fixed_layout.dns_list_offset + 4, 16),
        "10.0.0.2"
    );

    let info_len_ptr = alloc_page(&mut engine, 0x7600_4000);
    write_u32(&mut engine, info_len_ptr, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_info, &[0, info_len_ptr])
            .unwrap(),
        ERROR_BUFFER_OVERFLOW
    );
    let info_size = read_u32(&engine, info_len_ptr) as u64;
    assert!(info_size >= 640);
    let info = alloc_page(&mut engine, 0x7600_5000);
    write_u32(&mut engine, info_len_ptr, info_size as u32);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_info, &[info, info_len_ptr])
            .unwrap(),
        0
    );
    let info_layout = adapter_info_layout(&engine);
    assert_eq!(
        read_c_string(&engine, info + info_layout.adapter_name_offset, 260),
        "{8E8047D0-8C4F-4A14-9F1A-3D12E4A4F201}"
    );
    assert_eq!(
        read_c_string(&engine, info + info_layout.description_offset, 132),
        "Intel(R) Ethernet Connection (7) I219-LM"
    );
    assert_eq!(
        read_u32(&engine, info + info_layout.address_length_offset),
        6
    );
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(info + info_layout.address_offset, 6)
            .unwrap(),
        vec![0x00, 0x50, 0x56, 0xC0, 0x00, 0x08]
    );
    assert_eq!(read_u32(&engine, info + info_layout.index_offset), 17);
    assert_eq!(read_u32(&engine, info + info_layout.type_offset), 6);
    assert_eq!(read_u32(&engine, info + info_layout.dhcp_enabled_offset), 1);
    assert_eq!(
        read_c_string(&engine, info + info_layout.ip_list_offset + 4, 16),
        "10.0.2.15"
    );
    assert_eq!(
        read_c_string(&engine, info + info_layout.gateway_list_offset + 4, 16),
        "10.0.2.2"
    );

    let addr_len_ptr = alloc_page(&mut engine, 0x7600_6000);
    write_u32(&mut engine, addr_len_ptr, 0);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_addresses, &[2, 0, 0, 0, addr_len_ptr])
            .unwrap(),
        ERROR_BUFFER_OVERFLOW
    );
    let addr_size = read_u32(&engine, addr_len_ptr) as u64;
    assert!(addr_size >= 144);
    let addresses = alloc_page(&mut engine, 0x7600_7000);
    write_u32(&mut engine, addr_len_ptr, addr_size as u32);
    assert_eq!(
        engine
            .dispatch_bound_stub(get_addresses, &[2, 0, 0, addresses, addr_len_ptr])
            .unwrap(),
        0
    );
    let addresses_layout = adapter_addresses_layout(&engine);
    assert_eq!(
        read_u32(&engine, addresses),
        if pointer_size(&engine) == 8 { 184 } else { 144 }
    );
    assert_eq!(read_u32(&engine, addresses + 4), 17);

    let adapter_name_ptr = read_ptr(&engine, addresses + addresses_layout.adapter_name_offset);
    let dns_suffix_ptr = read_ptr(&engine, addresses + addresses_layout.dns_suffix_offset);
    let description_ptr = read_ptr(&engine, addresses + addresses_layout.description_offset);
    let friendly_name_ptr = read_ptr(&engine, addresses + addresses_layout.friendly_name_offset);
    assert_eq!(
        read_c_string(&engine, adapter_name_ptr, 128),
        "{8E8047D0-8C4F-4A14-9F1A-3D12E4A4F201}"
    );
    assert_eq!(read_wide_string(&engine, dns_suffix_ptr, 64), "corp.local");
    assert_eq!(
        read_wide_string(&engine, description_ptr, 128),
        "Intel(R) Ethernet Connection (7) I219-LM"
    );
    assert_eq!(read_wide_string(&engine, friendly_name_ptr, 64), "CorpLAN");
    assert_eq!(
        read_u32(
            &engine,
            addresses + addresses_layout.physical_address_length_offset
        ),
        6
    );
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(addresses + addresses_layout.physical_address_offset, 6)
            .unwrap(),
        vec![0x00, 0x50, 0x56, 0xC0, 0x00, 0x08]
    );
    assert_eq!(
        read_u32(&engine, addresses + addresses_layout.mtu_offset),
        1500
    );
    assert_eq!(
        read_u32(&engine, addresses + addresses_layout.if_type_offset),
        6
    );
    assert_eq!(
        read_u32(&engine, addresses + addresses_layout.oper_status_offset),
        1
    );

    let unicast_ptr = read_ptr(&engine, addresses + addresses_layout.first_unicast_offset);
    assert_ne!(unicast_ptr, 0);
    let unicast = unicast_layout(&engine);
    let sockaddr_ptr = read_ptr(&engine, unicast_ptr + unicast.socket_address_offset);
    assert_eq!(
        read_u32(&engine, unicast_ptr + unicast.socket_length_offset),
        16
    );
    assert_eq!(read_ipv4_from_sockaddr(&engine, sockaddr_ptr), "10.0.2.15");
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(unicast_ptr + unicast.on_link_prefix_length_offset, 1)
            .unwrap(),
        vec![24]
    );
}

use super::*;

use crate::environment_profile::NetworkUseProfile;

const ERROR_ALREADY_ASSIGNED: u64 = 85;
const ERROR_BAD_NET_NAME: u64 = 67;
const ERROR_BAD_DEVICE: u64 = 1200;
const ERROR_BAD_PROVIDER: u64 = 1204;
const ERROR_EXTENDED_ERROR: u64 = 1208;
const ERROR_NOT_CONNECTED: u64 = 2250;
const CONNECT_REDIRECT: u32 = 0x0000_0080;
const CONNECT_LOCALDRIVE: u32 = 0x0000_0100;
const DEFAULT_DISK_CONNECTION_DELAY: u32 = 1;
const DEFAULT_DISK_CONNECTION_OPT_DATA_SIZE: u32 = 65_536;
const DEFAULT_DISK_CONNECTION_SPEED: u32 = 10_000_000;
const DEFAULT_IPC_CONNECTION_DELAY: u32 = 2;
const DEFAULT_IPC_CONNECTION_OPT_DATA_SIZE: u32 = 4_096;
const DEFAULT_IPC_CONNECTION_SPEED: u32 = 1_000_000;
const NETINFO_DISKRED: u32 = 0x0000_0004;
const RESOURCE_GLOBALNET: u32 = 0x0000_0002;
const RESOURCETYPE_ANY: u32 = 0x0000_0000;
const RESOURCE_CONNECTED: u32 = 0x0000_0001;
const RESOURCETYPE_DISK: u32 = 0x0000_0001;
const RESOURCEDISPLAYTYPE_SERVER: u32 = 0x0000_0002;
const RESOURCEDISPLAYTYPE_SHARE: u32 = 0x0000_0003;
const RESOURCEUSAGE_CONNECTABLE: u32 = 0x0000_0001;
const RESOURCEUSAGE_CONTAINER: u32 = 0x0000_0002;
const UNIVERSAL_NAME_INFO_LEVEL: u32 = 0x0000_0001;
const REMOTE_NAME_INFO_LEVEL: u32 = 0x0000_0002;
const USE_DISKDEV: u32 = 0x0000_0000;
const WNNC_NET_LANMAN: u32 = 0x0002_0000;
const WNNC_NET_LANMAN_WORD: u16 = 0x0002;
const WNNC_SPEC_VERSION51: u32 = 0x0005_0001;
const WNCON_DYNAMIC: u32 = 0x0000_0008;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_mpr_hook(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        if !matches!(
            function,
            "MultinetGetConnectionPerformanceA"
                | "MultinetGetConnectionPerformanceW"
                | "WNetGetConnectionA"
                | "WNetGetConnectionW"
                | "WNetAddConnectionA"
                | "WNetAddConnectionW"
                | "WNetAddConnection2A"
                | "WNetAddConnection2W"
                | "WNetAddConnection3A"
                | "WNetAddConnection3W"
                | "WNetUseConnectionA"
                | "WNetUseConnectionW"
                | "WNetCancelConnection2A"
                | "WNetCancelConnection2W"
                | "WNetCancelConnectionA"
                | "WNetCancelConnectionW"
                | "WNetGetLastErrorA"
                | "WNetGetLastErrorW"
                | "WNetGetNetworkInformationA"
                | "WNetGetNetworkInformationW"
                | "WNetGetProviderNameA"
                | "WNetGetProviderNameW"
                | "WNetGetResourceInformationA"
                | "WNetGetResourceInformationW"
                | "WNetGetResourceParentA"
                | "WNetGetResourceParentW"
                | "WNetGetUserA"
                | "WNetGetUserW"
                | "WNetGetUniversalNameA"
                | "WNetGetUniversalNameW"
                | "WNetOpenEnumA"
                | "WNetOpenEnumW"
                | "WNetEnumResourceA"
                | "WNetEnumResourceW"
                | "WNetCloseEnum"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "MultinetGetConnectionPerformanceA" => {
                    self.multinet_get_connection_performance(false, ctx.raw(0), ctx.raw(1))
                }
                "MultinetGetConnectionPerformanceW" => {
                    self.multinet_get_connection_performance(true, ctx.raw(0), ctx.raw(1))
                }
                "WNetGetConnectionA" => self.wnet_get_connection(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetGetConnectionW" => self.wnet_get_connection(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetAddConnectionA" => self.wnet_add_connection_legacy(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetAddConnectionW" => self.wnet_add_connection_legacy(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetAddConnection2A" => self.wnet_add_connection(
                    false,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                ),
                "WNetAddConnection2W" => self.wnet_add_connection(
                    true,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                ),
                "WNetAddConnection3A" => self.wnet_add_connection(
                    false,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "WNetAddConnection3W" => self.wnet_add_connection(
                    true,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "WNetUseConnectionA" => self.wnet_use_connection(
                    false,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "WNetUseConnectionW" => self.wnet_use_connection(
                    true,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "WNetCancelConnection2A" => self.wnet_cancel_connection(
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2) != 0,
                ),
                "WNetCancelConnection2W" => self.wnet_cancel_connection(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2) != 0,
                ),
                "WNetCancelConnectionA" => self.wnet_cancel_connection(
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    0,
                    ctx.raw(1) != 0,
                ),
                "WNetCancelConnectionW" => self.wnet_cancel_connection(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    0,
                    ctx.raw(1) != 0,
                ),
                "WNetGetLastErrorA" => self.wnet_get_last_error(
                    false,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "WNetGetLastErrorW" => self.wnet_get_last_error(
                    true,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "WNetGetNetworkInformationA" => self.wnet_get_network_information(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                ),
                "WNetGetNetworkInformationW" => self.wnet_get_network_information(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                ),
                "WNetGetProviderNameA" => {
                    self.wnet_get_provider_name(false, ctx.raw(0) as u32, ctx.raw(1), ctx.raw(2))
                }
                "WNetGetProviderNameW" => {
                    self.wnet_get_provider_name(true, ctx.raw(0) as u32, ctx.raw(1), ctx.raw(2))
                }
                "WNetGetResourceInformationA" => self.wnet_get_resource_information(
                    false,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetGetResourceInformationW" => self.wnet_get_resource_information(
                    true,
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetGetResourceParentA" => {
                    self.wnet_get_resource_parent(false, ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                "WNetGetResourceParentW" => {
                    self.wnet_get_resource_parent(true, ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                "WNetGetUserA" => self.wnet_get_user(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetGetUserW" => self.wnet_get_user(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "WNetGetUniversalNameA" => self.wnet_get_universal_name(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetGetUniversalNameW" => self.wnet_get_universal_name(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetOpenEnumA" | "WNetOpenEnumW" => self.wnet_open_enum(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4),
                ),
                "WNetEnumResourceA" => self.wnet_enum_resource(
                    false,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetEnumResourceW" => self.wnet_enum_resource(
                    true,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "WNetCloseEnum" => Ok(self.wnet_close_enum(ctx.raw(0) as u32)),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

#[derive(Debug, Clone)]
struct MprInputNetResource {
    resource_type: u32,
    local_name: String,
    remote_name: String,
    comment: String,
    provider: String,
}

#[derive(Debug, Clone)]
struct MprConnectionRequest {
    local_name: String,
    remote_name: String,
    password: String,
    user_name: String,
    domain_name: String,
    provider: String,
    comment: String,
    assignment_type: u32,
}

#[derive(Debug, Clone)]
struct UniversalNameMapping {
    universal_name: String,
    connection_name: String,
    remaining_path: String,
}

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone)]
struct MprEnumContext {
    entries: Vec<NetworkUseProfile>,
    cursor: usize,
}

#[derive(Debug, Clone)]
struct MprOutputNetResource {
    scope: u32,
    resource_type: u32,
    display_type: u32,
    usage: u32,
    local_name: String,
    remote_name: String,
    comment: String,
    provider: String,
}

#[derive(Debug, Clone)]
struct MprResolvedResourceInfo {
    resource: MprOutputNetResource,
    system: String,
}

#[derive(Debug, Clone, Copy)]
struct NetInfoStructLayout {
    size: u64,
    provider_version_offset: u64,
    status_offset: u64,
    characteristics_offset: u64,
    handle_offset: u64,
    net_type_offset: u64,
    printers_offset: u64,
    drives_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct NetConnectInfoLayout {
    size: u64,
    flags_offset: u64,
    speed_offset: u64,
    delay_offset: u64,
    opt_data_size_offset: u64,
}

mod mpr_connection;
mod mpr_resource;

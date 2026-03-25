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
        args: &[u64],
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
                    self.multinet_get_connection_performance(false, arg(args, 0), arg(args, 1))
                }
                "MultinetGetConnectionPerformanceW" => {
                    self.multinet_get_connection_performance(true, arg(args, 0), arg(args, 1))
                }
                "WNetGetConnectionA" => self.wnet_get_connection(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetGetConnectionW" => self.wnet_get_connection(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetAddConnectionA" => self.wnet_add_connection_legacy(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetAddConnectionW" => self.wnet_add_connection_legacy(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetAddConnection2A" => self.wnet_add_connection(
                    false,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                ),
                "WNetAddConnection2W" => self.wnet_add_connection(
                    true,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                ),
                "WNetAddConnection3A" => self.wnet_add_connection(
                    false,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4) as u32,
                ),
                "WNetAddConnection3W" => self.wnet_add_connection(
                    true,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4) as u32,
                ),
                "WNetUseConnectionA" => self.wnet_use_connection(
                    false,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                    arg(args, 7),
                ),
                "WNetUseConnectionW" => self.wnet_use_connection(
                    true,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                    arg(args, 7),
                ),
                "WNetCancelConnection2A" => self.wnet_cancel_connection(
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2) != 0,
                ),
                "WNetCancelConnection2W" => self.wnet_cancel_connection(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2) != 0,
                ),
                "WNetCancelConnectionA" => self.wnet_cancel_connection(
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    0,
                    arg(args, 1) != 0,
                ),
                "WNetCancelConnectionW" => self.wnet_cancel_connection(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    0,
                    arg(args, 1) != 0,
                ),
                "WNetGetLastErrorA" => self.wnet_get_last_error(
                    false,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                ),
                "WNetGetLastErrorW" => self.wnet_get_last_error(
                    true,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                ),
                "WNetGetNetworkInformationA" => self.wnet_get_network_information(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                ),
                "WNetGetNetworkInformationW" => self.wnet_get_network_information(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                ),
                "WNetGetProviderNameA" => self.wnet_get_provider_name(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetGetProviderNameW" => self.wnet_get_provider_name(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetGetResourceInformationA" => self.wnet_get_resource_information(
                    false,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetGetResourceInformationW" => self.wnet_get_resource_information(
                    true,
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetGetResourceParentA" => {
                    self.wnet_get_resource_parent(false, arg(args, 0), arg(args, 1), arg(args, 2))
                }
                "WNetGetResourceParentW" => {
                    self.wnet_get_resource_parent(true, arg(args, 0), arg(args, 1), arg(args, 2))
                }
                "WNetGetUserA" => self.wnet_get_user(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetGetUserW" => self.wnet_get_user(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "WNetGetUniversalNameA" => self.wnet_get_universal_name(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetGetUniversalNameW" => self.wnet_get_universal_name(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetOpenEnumA" | "WNetOpenEnumW" => self.wnet_open_enum(
                    arg(args, 0) as u32,
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4),
                ),
                "WNetEnumResourceA" => self.wnet_enum_resource(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetEnumResourceW" => self.wnet_enum_resource(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                ),
                "WNetCloseEnum" => Ok(self.wnet_close_enum(arg(args, 0) as u32)),
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

impl VirtualExecutionEngine {
    fn mpr_net_resource_layout(&self) -> NetResourceLayout {
        if self.arch.is_x86() {
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
        } else {
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
        }
    }

    fn mpr_net_info_layout(&self) -> NetInfoStructLayout {
        if self.arch.is_x86() {
            NetInfoStructLayout {
                size: 32,
                provider_version_offset: 4,
                status_offset: 8,
                characteristics_offset: 12,
                handle_offset: 16,
                net_type_offset: 20,
                printers_offset: 24,
                drives_offset: 28,
            }
        } else {
            NetInfoStructLayout {
                size: 40,
                provider_version_offset: 4,
                status_offset: 8,
                characteristics_offset: 12,
                handle_offset: 16,
                net_type_offset: 24,
                printers_offset: 28,
                drives_offset: 32,
            }
        }
    }

    fn mpr_net_connect_info_layout(&self) -> NetConnectInfoLayout {
        NetConnectInfoLayout {
            size: 20,
            flags_offset: 4,
            speed_offset: 8,
            delay_offset: 12,
            opt_data_size_offset: 16,
        }
    }

    pub(super) fn wnet_get_connection(
        &mut self,
        wide: bool,
        local_name: &str,
        remote_name_ptr: u64,
        length_ptr: u64,
    ) -> Result<u64, VmError> {
        if length_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(network_use) = self
            .netapi_network_uses()
            .into_iter()
            .find(|entry| entry.local_name.eq_ignore_ascii_case(local_name.trim()))
        else {
            self.set_last_error(ERROR_NOT_CONNECTED as u32);
            return Ok(ERROR_NOT_CONNECTED);
        };
        self.write_text_result(
            wide,
            &network_use.remote_name,
            remote_name_ptr,
            length_ptr,
            ERROR_MORE_DATA,
        )
    }

    pub(super) fn wnet_get_user(
        &mut self,
        wide: bool,
        name: &str,
        user_ptr: u64,
        length_ptr: u64,
    ) -> Result<u64, VmError> {
        if length_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let requested = name.trim();
        let text = if requested.is_empty() {
            self.qualified_network_user_name(
                &self.environment_profile.machine.user_name,
                &self.mpr_default_user_domain(),
            )
        } else if let Some(network_use) = self.netapi_network_uses().into_iter().find(|entry| {
            entry.local_name.eq_ignore_ascii_case(requested)
                || entry.remote_name.eq_ignore_ascii_case(requested)
        }) {
            self.qualified_network_user_name(&network_use.user_name, &network_use.domain_name)
        } else {
            self.qualified_network_user_name(
                &self.environment_profile.machine.user_name,
                &self.mpr_default_user_domain(),
            )
        };

        self.write_text_result(wide, &text, user_ptr, length_ptr, ERROR_MORE_DATA)
    }

    pub(super) fn wnet_get_universal_name(
        &mut self,
        wide: bool,
        local_path: &str,
        info_level: u32,
        buffer_ptr: u64,
        buffer_size_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_size_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            info_level,
            UNIVERSAL_NAME_INFO_LEVEL | REMOTE_NAME_INFO_LEVEL
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let Some(mapping) = self.map_local_path_to_universal_name(local_path) else {
            self.set_last_error(ERROR_NOT_CONNECTED as u32);
            return Ok(ERROR_NOT_CONNECTED);
        };
        let pointer_size = self.arch.pointer_size as u64;
        let required = match info_level {
            UNIVERSAL_NAME_INFO_LEVEL => {
                align_up_local(pointer_size, if wide { 2 } else { 1 })
                    + inline_text_storage_size_local(wide, &mapping.universal_name)
            }
            REMOTE_NAME_INFO_LEVEL => {
                let struct_size = pointer_size * 3;
                align_up_local(struct_size, if wide { 2 } else { 1 })
                    + inline_text_storage_size_local(wide, &mapping.universal_name)
                    + inline_text_storage_size_local(wide, &mapping.connection_name)
                    + inline_text_storage_size_required_local(wide, &mapping.remaining_path)
            }
            _ => 0,
        };
        let provided = self.read_u32(buffer_size_ptr)? as u64;
        self.write_u32(buffer_size_ptr, required as u32)?;
        if buffer_ptr == 0 || provided < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        self.fill_memory_pattern(buffer_ptr, provided, 0)?;
        let mut cursor = align_up_local(
            buffer_ptr
                + if info_level == REMOTE_NAME_INFO_LEVEL {
                    pointer_size * 3
                } else {
                    pointer_size
                },
            if wide { 2 } else { 1 },
        );
        let universal_name_ptr =
            write_inline_text_string_local(self, wide, &mut cursor, &mapping.universal_name)?;
        self.write_pointer_value(buffer_ptr, universal_name_ptr)?;
        if info_level == REMOTE_NAME_INFO_LEVEL {
            let connection_name_ptr =
                write_inline_text_string_local(self, wide, &mut cursor, &mapping.connection_name)?;
            let remaining_path_ptr =
                write_inline_text_string_local(self, wide, &mut cursor, &mapping.remaining_path)?;
            self.write_pointer_value(buffer_ptr + pointer_size, connection_name_ptr)?;
            self.write_pointer_value(buffer_ptr + pointer_size * 2, remaining_path_ptr)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_add_connection(
        &mut self,
        wide: bool,
        net_resource_ptr: u64,
        password_ptr: u64,
        user_id_ptr: u64,
        _flags: u32,
    ) -> Result<u64, VmError> {
        let request = match self.prepare_mpr_connection_request(
            wide,
            net_resource_ptr,
            password_ptr,
            user_id_ptr,
            false,
        ) {
            Ok(request) => request,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let status = self.mpr_connection_conflict_status(&request);
        if status != ERROR_SUCCESS {
            self.set_last_error(status as u32);
            return Ok(status);
        }
        let status = self.commit_mpr_connection(request);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn wnet_add_connection_legacy(
        &mut self,
        wide: bool,
        remote_name: &str,
        password_ptr: u64,
        local_name_ptr: u64,
    ) -> Result<u64, VmError> {
        let password = match self.read_mpr_input_text(wide, password_ptr) {
            Ok(password) => password,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let local_name = match self.read_mpr_input_text(wide, local_name_ptr) {
            Ok(local_name) => local_name,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let request =
            match self.prepare_legacy_mpr_connection_request(remote_name, &password, &local_name) {
                Ok(request) => request,
                Err(status) => {
                    self.set_last_error(status as u32);
                    return Ok(status);
                }
            };
        let status = self.mpr_connection_conflict_status(&request);
        if status != ERROR_SUCCESS {
            self.set_last_error(status as u32);
            return Ok(status);
        }
        let status = self.commit_mpr_connection(request);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn wnet_get_provider_name(
        &mut self,
        wide: bool,
        net_type: u32,
        provider_ptr: u64,
        length_ptr: u64,
    ) -> Result<u64, VmError> {
        if length_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !self.mpr_matches_network_type(net_type) {
            self.set_last_error(ERROR_BAD_NET_NAME as u32);
            return Ok(ERROR_BAD_NET_NAME);
        }

        self.write_text_result(
            wide,
            &self.mpr_default_provider_name(),
            provider_ptr,
            length_ptr,
            ERROR_MORE_DATA,
        )
    }

    pub(super) fn wnet_get_network_information(
        &mut self,
        _wide: bool,
        provider_name: &str,
        info_ptr: u64,
    ) -> Result<u64, VmError> {
        if info_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !self.mpr_is_supported_provider(provider_name) {
            self.set_last_error(ERROR_BAD_PROVIDER as u32);
            return Ok(ERROR_BAD_PROVIDER);
        }

        let layout = self.mpr_net_info_layout();
        let declared_size = self.read_u32(info_ptr)? as u64;
        if declared_size < layout.size {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        self.write_u32(info_ptr, layout.size as u32)?;
        self.write_u32(
            info_ptr + layout.provider_version_offset,
            WNNC_SPEC_VERSION51,
        )?;
        self.write_u32(info_ptr + layout.status_offset, ERROR_SUCCESS as u32)?;
        self.write_u32(info_ptr + layout.characteristics_offset, NETINFO_DISKRED)?;
        self.write_pointer_value(info_ptr + layout.handle_offset, 0)?;
        self.write_u16(info_ptr + layout.net_type_offset, WNNC_NET_LANMAN_WORD)?;
        self.write_u32(info_ptr + layout.printers_offset, 0)?;
        self.write_u32(
            info_ptr + layout.drives_offset,
            self.mpr_mapped_drive_count() as u32,
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn multinet_get_connection_performance(
        &mut self,
        wide: bool,
        net_resource_ptr: u64,
        info_ptr: u64,
    ) -> Result<u64, VmError> {
        if net_resource_ptr == 0 || info_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let input = match self.read_mpr_net_resource(wide, net_resource_ptr) {
            Ok(input) => input,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let (remote_name, _) = match self.resolve_mpr_requested_remote_name(&input) {
            Ok(value) => value,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let (_, share_name, _) = match self.parse_unc_resource_path(&remote_name) {
            Some(parts) => parts,
            None => {
                self.set_last_error(ERROR_BAD_NET_NAME as u32);
                return Ok(ERROR_BAD_NET_NAME);
            }
        };

        let layout = self.mpr_net_connect_info_layout();
        let declared_size = self.read_u32(info_ptr)? as u64;
        if declared_size < layout.size {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let (speed, delay, opt_data_size) = if share_name.eq_ignore_ascii_case("IPC$") {
            (
                DEFAULT_IPC_CONNECTION_SPEED,
                DEFAULT_IPC_CONNECTION_DELAY,
                DEFAULT_IPC_CONNECTION_OPT_DATA_SIZE,
            )
        } else {
            (
                DEFAULT_DISK_CONNECTION_SPEED,
                DEFAULT_DISK_CONNECTION_DELAY,
                DEFAULT_DISK_CONNECTION_OPT_DATA_SIZE,
            )
        };
        self.write_u32(info_ptr, layout.size as u32)?;
        self.write_u32(info_ptr + layout.flags_offset, WNCON_DYNAMIC)?;
        self.write_u32(info_ptr + layout.speed_offset, speed)?;
        self.write_u32(info_ptr + layout.delay_offset, delay)?;
        self.write_u32(info_ptr + layout.opt_data_size_offset, opt_data_size)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_use_connection(
        &mut self,
        wide: bool,
        _owner: u64,
        net_resource_ptr: u64,
        password_ptr: u64,
        user_id_ptr: u64,
        flags: u32,
        access_name_ptr: u64,
        buffer_size_ptr: u64,
        result_ptr: u64,
    ) -> Result<u64, VmError> {
        let request = match self.prepare_mpr_connection_request(
            wide,
            net_resource_ptr,
            password_ptr,
            user_id_ptr,
            (flags & CONNECT_REDIRECT) != 0,
        ) {
            Ok(request) => request,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let status = self.mpr_connection_conflict_status(&request);
        if status != ERROR_SUCCESS {
            self.set_last_error(status as u32);
            return Ok(status);
        }

        let access_name = if request.local_name.is_empty() {
            request.remote_name.clone()
        } else {
            request.local_name.clone()
        };
        if access_name_ptr != 0 {
            if buffer_size_ptr == 0 {
                self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                return Ok(ERROR_INVALID_PARAMETER);
            }
            let status = self.write_text_result(
                wide,
                &access_name,
                access_name_ptr,
                buffer_size_ptr,
                ERROR_MORE_DATA,
            )?;
            if status != ERROR_SUCCESS {
                return Ok(status);
            }
        } else if buffer_size_ptr != 0 {
            let required = if wide {
                access_name.encode_utf16().count() + 1
            } else {
                access_name.len() + 1
            };
            self.write_u32(buffer_size_ptr, required as u32)?;
        }

        let status = self.commit_mpr_connection(request);
        if status != ERROR_SUCCESS {
            self.set_last_error(status as u32);
            return Ok(status);
        }
        if result_ptr != 0 {
            self.write_u32(
                result_ptr,
                if (flags & CONNECT_REDIRECT) != 0 && !access_name.starts_with(r"\\") {
                    CONNECT_LOCALDRIVE
                } else {
                    0
                },
            )?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_get_resource_information(
        &mut self,
        wide: bool,
        net_resource_ptr: u64,
        buffer_ptr: u64,
        buffer_size_ptr: u64,
        system_ptr_ptr: u64,
    ) -> Result<u64, VmError> {
        if net_resource_ptr == 0 || buffer_size_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let input = match self.read_mpr_net_resource(wide, net_resource_ptr) {
            Ok(input) => input,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let resolved = match self.resolve_mpr_resource_information(&input) {
            Ok(resolved) => resolved,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        self.write_mpr_resource_query_result(
            wide,
            buffer_ptr,
            buffer_size_ptr,
            system_ptr_ptr,
            &resolved,
        )
    }

    pub(super) fn wnet_get_resource_parent(
        &mut self,
        wide: bool,
        net_resource_ptr: u64,
        buffer_ptr: u64,
        buffer_size_ptr: u64,
    ) -> Result<u64, VmError> {
        if net_resource_ptr == 0 || buffer_size_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let input = match self.read_mpr_net_resource(wide, net_resource_ptr) {
            Ok(input) => input,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let resolved = match self.resolve_mpr_resource_parent(&input) {
            Ok(resolved) => resolved,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        self.write_mpr_resource_query_result(wide, buffer_ptr, buffer_size_ptr, 0, &resolved)
    }

    pub(super) fn wnet_get_last_error(
        &mut self,
        wide: bool,
        error_ptr: u64,
        error_buf_ptr: u64,
        error_buf_size: u32,
        provider_buf_ptr: u64,
        provider_buf_size: u32,
    ) -> Result<u64, VmError> {
        if error_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let code = self.last_error() as u64;
        self.write_u32(error_ptr, code as u32)?;
        let message = self.mpr_error_message(code);
        let provider = if code == ERROR_SUCCESS {
            String::new()
        } else {
            NetworkUseProfile::default().provider
        };

        let error_status =
            self.write_text_buffer_fixed(wide, &message, error_buf_ptr, error_buf_size)?;
        let provider_status =
            self.write_text_buffer_fixed(wide, &provider, provider_buf_ptr, provider_buf_size)?;
        let status = if error_status != ERROR_SUCCESS || provider_status != ERROR_SUCCESS {
            ERROR_MORE_DATA
        } else {
            ERROR_SUCCESS
        };
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn wnet_cancel_connection(
        &mut self,
        name: &str,
        _flags: u32,
        _force: bool,
    ) -> Result<u64, VmError> {
        let requested = name.trim();
        if requested.is_empty() {
            self.set_last_error(ERROR_BAD_DEVICE as u32);
            return Ok(ERROR_BAD_DEVICE);
        }

        self.ensure_materialized_network_uses();
        let uses = &mut self.environment_profile.network_uses;
        let original_len = uses.len();
        if requested.starts_with(r"\\") {
            uses.retain(|network_use| {
                !(network_use.local_name.trim().is_empty()
                    && network_use.remote_name.eq_ignore_ascii_case(requested))
            });
        } else {
            uses.retain(|network_use| !network_use.local_name.eq_ignore_ascii_case(requested));
        }

        let status = if uses.len() == original_len {
            ERROR_NOT_CONNECTED
        } else {
            ERROR_SUCCESS
        };
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn wnet_open_enum(
        &mut self,
        _scope: u32,
        _resource_type: u32,
        _usage: u32,
        _net_resource_ptr: u64,
        enum_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if enum_handle_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let handle = self.network.allocate_custom(
            "mpr_enum",
            MprEnumContext {
                entries: self.netapi_network_uses(),
                cursor: 0,
            },
        );
        self.write_u32(enum_handle_ptr, handle)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_enum_resource(
        &mut self,
        wide: bool,
        enum_handle: u32,
        count_ptr: u64,
        buffer_ptr: u64,
        buffer_size_ptr: u64,
    ) -> Result<u64, VmError> {
        if enum_handle == 0 || count_ptr == 0 || buffer_ptr == 0 || buffer_size_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(kind) = self.network.kind(enum_handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(ERROR_INVALID_HANDLE);
        };
        if kind != "mpr_enum" {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(ERROR_INVALID_HANDLE);
        }

        let requested = self.read_u32(count_ptr)?;
        let buffer_size = self.read_u32(buffer_size_ptr)? as u64;
        let Some((available, cursor)) = self
            .network
            .with_payload::<MprEnumContext, _, _>(enum_handle, |context| {
                (context.entries[context.cursor..].to_vec(), context.cursor)
            })
        else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(ERROR_INVALID_HANDLE);
        };

        if available.is_empty() {
            self.write_u32(count_ptr, 0)?;
            self.set_last_error(ERROR_NO_MORE_ITEMS as u32);
            return Ok(ERROR_NO_MORE_ITEMS);
        }

        let wanted = if requested == u32::MAX || requested == 0 {
            available.len()
        } else {
            requested as usize
        };
        let mut selected = Vec::new();
        let mut required = 0u64;
        for entry in available.iter().take(wanted) {
            let next = self.net_resource_required_size(wide, std::slice::from_ref(entry));
            if selected.is_empty() && next > buffer_size {
                self.write_u32(buffer_size_ptr, next as u32)?;
                self.write_u32(count_ptr, 0)?;
                self.set_last_error(ERROR_MORE_DATA as u32);
                return Ok(ERROR_MORE_DATA);
            }
            if !selected.is_empty() && required + next > buffer_size {
                break;
            }
            selected.push(entry.clone());
            required += next;
        }
        if selected.is_empty() {
            self.write_u32(buffer_size_ptr, 0)?;
            self.write_u32(count_ptr, 0)?;
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        self.fill_memory_pattern(buffer_ptr, buffer_size, 0)?;
        self.write_net_resource_entries(wide, buffer_ptr, &selected)?;
        self.write_u32(count_ptr, selected.len() as u32)?;
        self.write_u32(buffer_size_ptr, required as u32)?;
        let new_cursor = cursor + selected.len();
        let _ = self
            .network
            .with_payload_mut::<MprEnumContext, _, _>(enum_handle, |context| {
                context.cursor = new_cursor;
            });
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_close_enum(&mut self, enum_handle: u32) -> u64 {
        if self.network.kind(enum_handle) != Some("mpr_enum") {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return ERROR_INVALID_HANDLE;
        }
        self.network.close_handle(enum_handle);
        self.set_last_error(ERROR_SUCCESS as u32);
        ERROR_SUCCESS
    }

    fn qualified_network_user_name(&self, user_name: &str, domain_name: &str) -> String {
        if user_name.trim().is_empty() {
            String::new()
        } else if domain_name.trim().is_empty() {
            user_name.to_string()
        } else {
            format!(r"{}\{}", domain_name.trim(), user_name.trim())
        }
    }

    fn mpr_default_user_domain(&self) -> String {
        let domain = self.environment_profile.machine.user_domain.trim();
        if domain.is_empty() || domain.eq_ignore_ascii_case("WORKGROUP") {
            self.active_computer_name().to_string()
        } else {
            domain.to_string()
        }
    }

    fn mpr_default_provider_name(&self) -> String {
        NetworkUseProfile::default().provider
    }

    fn mpr_is_supported_provider(&self, provider_name: &str) -> bool {
        let provider_name = provider_name.trim();
        !provider_name.is_empty()
            && provider_name.eq_ignore_ascii_case(&self.mpr_default_provider_name())
    }

    fn mpr_matches_network_type(&self, net_type: u32) -> bool {
        net_type == WNNC_NET_LANMAN || net_type == u32::from(WNNC_NET_LANMAN_WORD)
    }

    fn mpr_mapped_drive_count(&self) -> usize {
        self.netapi_network_uses()
            .into_iter()
            .filter(|network_use| self.is_valid_drive_name(&network_use.local_name))
            .count()
    }

    fn prepare_mpr_connection_request(
        &mut self,
        wide: bool,
        net_resource_ptr: u64,
        password_ptr: u64,
        user_id_ptr: u64,
        allow_auto_local_name: bool,
    ) -> Result<MprConnectionRequest, u64> {
        if net_resource_ptr == 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let resource = self.read_mpr_net_resource(wide, net_resource_ptr)?;
        if !matches!(resource.resource_type, RESOURCETYPE_ANY | RESOURCETYPE_DISK) {
            return Err(ERROR_INVALID_PARAMETER);
        }

        let remote_name = resource.remote_name.trim().to_string();
        if !self.is_plausible_unc_path(&remote_name) {
            return Err(ERROR_BAD_NET_NAME);
        }

        let mut local_name = resource.local_name.trim().to_string();
        if local_name.is_empty() && allow_auto_local_name {
            if let Some(auto_name) = self.next_available_network_drive_name() {
                local_name = auto_name;
            }
        }
        if !local_name.is_empty() && !self.is_valid_drive_name(&local_name) {
            return Err(ERROR_BAD_DEVICE);
        }

        let provider = if resource.provider.trim().is_empty() {
            NetworkUseProfile::default().provider
        } else {
            resource.provider.trim().to_string()
        };
        if !provider.eq_ignore_ascii_case("Microsoft Windows Network") {
            return Err(ERROR_BAD_PROVIDER);
        }

        let password = self.read_mpr_input_text(wide, password_ptr)?;
        let user_id = self.read_mpr_input_text(wide, user_id_ptr)?;
        let (user_name, domain_name) = self.parse_network_user_identity(&user_id);

        Ok(MprConnectionRequest {
            local_name,
            remote_name,
            password,
            user_name,
            domain_name,
            provider,
            comment: resource.comment.trim().to_string(),
            assignment_type: USE_DISKDEV,
        })
    }

    fn prepare_legacy_mpr_connection_request(
        &self,
        remote_name: &str,
        password: &str,
        local_name: &str,
    ) -> Result<MprConnectionRequest, u64> {
        let remote_name = remote_name.trim().to_string();
        if !self.is_plausible_unc_path(&remote_name) {
            return Err(ERROR_BAD_NET_NAME);
        }
        let local_name = local_name.trim().to_string();
        if !local_name.is_empty() && !self.is_valid_drive_name(&local_name) {
            return Err(ERROR_BAD_DEVICE);
        }

        Ok(MprConnectionRequest {
            local_name,
            remote_name,
            password: password.to_string(),
            user_name: self.environment_profile.machine.user_name.clone(),
            domain_name: self.mpr_default_user_domain(),
            provider: NetworkUseProfile::default().provider,
            comment: String::new(),
            assignment_type: USE_DISKDEV,
        })
    }

    fn commit_mpr_connection(&mut self, request: MprConnectionRequest) -> u64 {
        self.ensure_materialized_network_uses();
        let uses = &mut self.environment_profile.network_uses;

        if !request.local_name.is_empty() {
            if let Some(existing) = uses.iter_mut().find(|network_use| {
                network_use
                    .local_name
                    .eq_ignore_ascii_case(&request.local_name)
            }) {
                if !existing
                    .remote_name
                    .eq_ignore_ascii_case(&request.remote_name)
                {
                    return ERROR_ALREADY_ASSIGNED;
                }
                existing.ref_count = existing.ref_count.saturating_add(1);
                existing.use_count = existing.use_count.saturating_add(1);
                if !request.password.is_empty() {
                    existing.password = request.password;
                }
                if !request.user_name.is_empty() {
                    existing.user_name = request.user_name;
                }
                if !request.domain_name.is_empty() {
                    existing.domain_name = request.domain_name;
                }
                if !request.comment.is_empty() {
                    existing.comment = request.comment;
                }
                if !request.provider.is_empty() {
                    existing.provider = request.provider;
                }
                existing.assignment_type = request.assignment_type;
                return ERROR_SUCCESS;
            }
        } else if let Some(existing) = uses.iter_mut().find(|network_use| {
            network_use.local_name.trim().is_empty()
                && network_use
                    .remote_name
                    .eq_ignore_ascii_case(&request.remote_name)
        }) {
            existing.ref_count = existing.ref_count.saturating_add(1);
            existing.use_count = existing.use_count.saturating_add(1);
            if !request.password.is_empty() {
                existing.password = request.password;
            }
            if !request.user_name.is_empty() {
                existing.user_name = request.user_name;
            }
            if !request.domain_name.is_empty() {
                existing.domain_name = request.domain_name;
            }
            if !request.comment.is_empty() {
                existing.comment = request.comment;
            }
            if !request.provider.is_empty() {
                existing.provider = request.provider;
            }
            existing.assignment_type = request.assignment_type;
            return ERROR_SUCCESS;
        }

        uses.push(NetworkUseProfile {
            local_name: request.local_name,
            remote_name: request.remote_name,
            password: request.password,
            status: 0,
            assignment_type: request.assignment_type,
            ref_count: 1,
            use_count: 1,
            user_name: request.user_name,
            domain_name: request.domain_name,
            provider: request.provider,
            comment: request.comment,
        });
        ERROR_SUCCESS
    }

    fn mpr_connection_conflict_status(&self, request: &MprConnectionRequest) -> u64 {
        let uses = self.netapi_network_uses();
        if request.local_name.is_empty() {
            return ERROR_SUCCESS;
        }
        if let Some(existing) = uses.into_iter().find(|network_use| {
            network_use
                .local_name
                .eq_ignore_ascii_case(&request.local_name)
        }) {
            if !existing
                .remote_name
                .eq_ignore_ascii_case(&request.remote_name)
            {
                return ERROR_ALREADY_ASSIGNED;
            }
        }
        ERROR_SUCCESS
    }

    fn ensure_materialized_network_uses(&mut self) {
        if !self.environment_profile.network_uses.is_empty() {
            return;
        }
        let defaults = self.netapi_network_uses();
        if !defaults.is_empty() {
            self.environment_profile.network_uses = defaults;
        }
    }

    fn read_mpr_net_resource(
        &self,
        wide: bool,
        net_resource_ptr: u64,
    ) -> Result<MprInputNetResource, u64> {
        let layout = self.mpr_net_resource_layout();
        let local_name_ptr = self
            .read_pointer_value(net_resource_ptr + layout.local_name_offset)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let remote_name_ptr = self
            .read_pointer_value(net_resource_ptr + layout.remote_name_offset)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let comment_ptr = self
            .read_pointer_value(net_resource_ptr + layout.comment_offset)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let provider_ptr = self
            .read_pointer_value(net_resource_ptr + layout.provider_offset)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;

        let read_text = |engine: &VirtualExecutionEngine, ptr: u64| -> Result<String, u64> {
            if wide {
                engine
                    .read_wide_string_from_memory(ptr)
                    .map_err(|_| ERROR_INVALID_PARAMETER)
            } else {
                engine
                    .read_c_string_from_memory(ptr)
                    .map_err(|_| ERROR_INVALID_PARAMETER)
            }
        };

        Ok(MprInputNetResource {
            resource_type: self
                .read_u32(net_resource_ptr + layout.type_offset)
                .map_err(|_| ERROR_INVALID_PARAMETER)?,
            local_name: read_text(self, local_name_ptr)?,
            remote_name: read_text(self, remote_name_ptr)?,
            comment: read_text(self, comment_ptr)?,
            provider: read_text(self, provider_ptr)?,
        })
    }

    fn read_mpr_input_text(&self, wide: bool, address: u64) -> Result<String, u64> {
        if address == 0 {
            return Ok(String::new());
        }
        if wide {
            self.read_wide_string_from_memory(address)
                .map_err(|_| ERROR_INVALID_PARAMETER)
        } else {
            self.read_c_string_from_memory(address)
                .map_err(|_| ERROR_INVALID_PARAMETER)
        }
    }

    fn parse_network_user_identity(&self, user_id: &str) -> (String, String) {
        let requested = user_id.trim();
        if requested.is_empty() {
            return (
                self.environment_profile.machine.user_name.clone(),
                self.mpr_default_user_domain(),
            );
        }
        if let Some((domain, user_name)) = requested.split_once('\\') {
            return (user_name.trim().to_string(), domain.trim().to_string());
        }
        if let Some((user_name, domain)) = requested.split_once('@') {
            return (user_name.trim().to_string(), domain.trim().to_string());
        }
        (requested.to_string(), self.mpr_default_user_domain())
    }

    fn next_available_network_drive_name(&self) -> Option<String> {
        let used = self
            .netapi_network_uses()
            .into_iter()
            .filter_map(|network_use| {
                let name = network_use.local_name.trim();
                if self.is_valid_drive_name(name) {
                    Some(name.to_ascii_uppercase())
                } else {
                    None
                }
            })
            .collect::<std::collections::BTreeSet<_>>();
        ('D'..='Z')
            .rev()
            .map(|letter| format!("{letter}:"))
            .find(|candidate| !used.contains(&candidate.to_ascii_uppercase()))
    }

    fn is_plausible_unc_path(&self, remote_name: &str) -> bool {
        let normalized = remote_name.trim();
        if !normalized.starts_with(r"\\") {
            return false;
        }
        let mut segments = normalized[2..]
            .split(['\\', '/'])
            .filter(|segment| !segment.trim().is_empty());
        segments.next().is_some() && segments.next().is_some()
    }

    fn is_valid_drive_name(&self, local_name: &str) -> bool {
        let bytes = local_name.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    }

    fn resolve_mpr_resource_information(
        &self,
        resource: &MprInputNetResource,
    ) -> Result<MprResolvedResourceInfo, u64> {
        let provider = self.mpr_resolve_provider_name(&resource.provider)?;
        let (remote_name, matching_use) = self.resolve_mpr_requested_remote_name(resource)?;
        let (server_name, share_name, system) = self
            .parse_unc_resource_path(&remote_name)
            .ok_or(ERROR_BAD_NET_NAME)?;
        if share_name.is_empty() {
            return Ok(MprResolvedResourceInfo {
                resource: MprOutputNetResource {
                    scope: RESOURCE_GLOBALNET,
                    resource_type: RESOURCETYPE_ANY,
                    display_type: RESOURCEDISPLAYTYPE_SERVER,
                    usage: RESOURCEUSAGE_CONTAINER,
                    local_name: String::new(),
                    remote_name: format!(r"\\{server_name}"),
                    comment: self.mpr_server_comment(&server_name),
                    provider,
                },
                system: String::new(),
            });
        }

        let canonical_remote_name = format!(r"\\{server_name}\{share_name}");
        let share_use = matching_use
            .or_else(|| self.find_matching_network_use_for_remote(&canonical_remote_name));
        let resource_type = if share_name.eq_ignore_ascii_case("IPC$") {
            RESOURCETYPE_ANY
        } else {
            RESOURCETYPE_DISK
        };

        Ok(MprResolvedResourceInfo {
            resource: MprOutputNetResource {
                scope: RESOURCE_GLOBALNET,
                resource_type,
                display_type: RESOURCEDISPLAYTYPE_SHARE,
                usage: RESOURCEUSAGE_CONNECTABLE,
                local_name: share_use
                    .as_ref()
                    .map(|network_use| network_use.local_name.clone())
                    .unwrap_or_default(),
                remote_name: canonical_remote_name,
                comment: self.mpr_share_comment(&share_name, share_use.as_ref()),
                provider,
            },
            system,
        })
    }

    fn resolve_mpr_resource_parent(
        &self,
        resource: &MprInputNetResource,
    ) -> Result<MprResolvedResourceInfo, u64> {
        let provider = self.mpr_resolve_provider_name(&resource.provider)?;
        let (remote_name, _) = self.resolve_mpr_requested_remote_name(resource)?;
        let (server_name, share_name, _) = self
            .parse_unc_resource_path(&remote_name)
            .ok_or(ERROR_BAD_NET_NAME)?;
        if share_name.is_empty() {
            return Err(ERROR_NO_MORE_ITEMS);
        }

        Ok(MprResolvedResourceInfo {
            resource: MprOutputNetResource {
                scope: RESOURCE_GLOBALNET,
                resource_type: RESOURCETYPE_ANY,
                display_type: RESOURCEDISPLAYTYPE_SERVER,
                usage: RESOURCEUSAGE_CONTAINER,
                local_name: String::new(),
                remote_name: format!(r"\\{server_name}"),
                comment: self.mpr_server_comment(&server_name),
                provider,
            },
            system: String::new(),
        })
    }

    fn write_mpr_resource_query_result(
        &mut self,
        wide: bool,
        buffer_ptr: u64,
        buffer_size_ptr: u64,
        system_ptr_ptr: u64,
        resolved: &MprResolvedResourceInfo,
    ) -> Result<u64, VmError> {
        let required = self.mpr_output_net_resource_required_size(wide, resolved);
        let provided = self.read_u32(buffer_size_ptr)? as u64;
        self.write_u32(buffer_size_ptr, required as u32)?;
        if buffer_ptr == 0 || provided < required {
            if system_ptr_ptr != 0 {
                self.write_pointer_value(system_ptr_ptr, 0)?;
            }
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        self.fill_memory_pattern(buffer_ptr, provided, 0)?;
        let system_ptr = self.write_output_net_resource(wide, buffer_ptr, resolved)?;
        if system_ptr_ptr != 0 {
            self.write_pointer_value(system_ptr_ptr, system_ptr)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    fn write_output_net_resource(
        &mut self,
        wide: bool,
        base: u64,
        resolved: &MprResolvedResourceInfo,
    ) -> Result<u64, VmError> {
        let layout = self.mpr_net_resource_layout();
        let mut cursor = align_up_local(base + layout.size, if wide { 2 } else { 1 });
        let local_name_ptr = write_optional_inline_text_string(
            self,
            wide,
            &mut cursor,
            &resolved.resource.local_name,
        )?;
        let remote_name_ptr = write_optional_inline_text_string(
            self,
            wide,
            &mut cursor,
            &resolved.resource.remote_name,
        )?;
        let comment_ptr =
            write_optional_inline_text_string(self, wide, &mut cursor, &resolved.resource.comment)?;
        let provider_ptr = write_optional_inline_text_string(
            self,
            wide,
            &mut cursor,
            &resolved.resource.provider,
        )?;
        let system_ptr =
            write_optional_inline_text_string(self, wide, &mut cursor, &resolved.system)?;

        self.write_u32(base + layout.scope_offset, resolved.resource.scope)?;
        self.write_u32(base + layout.type_offset, resolved.resource.resource_type)?;
        self.write_u32(
            base + layout.display_type_offset,
            resolved.resource.display_type,
        )?;
        self.write_u32(base + layout.usage_offset, resolved.resource.usage)?;
        self.write_pointer_value(base + layout.local_name_offset, local_name_ptr)?;
        self.write_pointer_value(base + layout.remote_name_offset, remote_name_ptr)?;
        self.write_pointer_value(base + layout.comment_offset, comment_ptr)?;
        self.write_pointer_value(base + layout.provider_offset, provider_ptr)?;
        Ok(system_ptr)
    }

    fn mpr_output_net_resource_required_size(
        &self,
        wide: bool,
        resolved: &MprResolvedResourceInfo,
    ) -> u64 {
        let layout = self.mpr_net_resource_layout();
        align_up_local(layout.size, self.arch.pointer_size as u64)
            + inline_text_storage_size_local(wide, &resolved.resource.local_name)
            + inline_text_storage_size_local(wide, &resolved.resource.remote_name)
            + inline_text_storage_size_local(wide, &resolved.resource.comment)
            + inline_text_storage_size_local(wide, &resolved.resource.provider)
            + inline_text_storage_size_local(wide, &resolved.system)
    }

    fn resolve_mpr_requested_remote_name(
        &self,
        resource: &MprInputNetResource,
    ) -> Result<(String, Option<NetworkUseProfile>), u64> {
        let remote_name = resource.remote_name.trim();
        if !remote_name.is_empty() {
            if !remote_name.starts_with(r"\\") {
                return Err(ERROR_BAD_NET_NAME);
            }
            return Ok((
                remote_name.replace('/', r"\"),
                self.find_matching_network_use_for_remote(remote_name),
            ));
        }

        let local_name = resource.local_name.trim();
        if local_name.is_empty() {
            return Err(ERROR_BAD_NET_NAME);
        }

        let Some(network_use) = self.netapi_network_uses().into_iter().find(|network_use| {
            network_use.local_name.eq_ignore_ascii_case(local_name)
                || network_use.remote_name.eq_ignore_ascii_case(local_name)
        }) else {
            return Err(ERROR_NOT_CONNECTED);
        };
        Ok((network_use.remote_name.clone(), Some(network_use)))
    }

    fn parse_unc_resource_path(&self, remote_name: &str) -> Option<(String, String, String)> {
        let normalized = remote_name
            .trim()
            .trim_end_matches(['\\', '/'])
            .replace('/', r"\");
        if !normalized.starts_with(r"\\") {
            return None;
        }

        let segments = normalized[2..]
            .split('\\')
            .filter(|segment| !segment.trim().is_empty())
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return None;
        }

        let system = if segments.len() > 2 {
            format!(r"\{}", segments[2..].join(r"\"))
        } else {
            String::new()
        };
        Some((
            segments[0].to_string(),
            segments
                .get(1)
                .map(|value| value.to_string())
                .unwrap_or_default(),
            system,
        ))
    }

    fn find_matching_network_use_for_remote(&self, remote_name: &str) -> Option<NetworkUseProfile> {
        self.netapi_network_uses()
            .into_iter()
            .filter(|network_use| {
                self.mpr_remote_path_matches_prefix(remote_name, &network_use.remote_name)
            })
            .max_by_key(|network_use| network_use.remote_name.len())
    }

    fn mpr_remote_path_matches_prefix(&self, requested: &str, prefix: &str) -> bool {
        let requested = requested.trim().trim_end_matches(['\\', '/']);
        let prefix = prefix.trim().trim_end_matches(['\\', '/']);
        if requested.eq_ignore_ascii_case(prefix) {
            return true;
        }
        if requested.len() <= prefix.len() {
            return false;
        }

        let requested_lower = requested.to_ascii_lowercase();
        let prefix_lower = prefix.to_ascii_lowercase();
        requested_lower.starts_with(&prefix_lower)
            && matches!(
                requested.as_bytes().get(prefix.len()),
                Some(b'\\') | Some(b'/')
            )
    }

    fn mpr_resolve_provider_name(&self, provider_name: &str) -> Result<String, u64> {
        if provider_name.trim().is_empty() {
            return Ok(self.mpr_default_provider_name());
        }
        if self.mpr_is_supported_provider(provider_name) {
            return Ok(self.mpr_default_provider_name());
        }
        Err(ERROR_BAD_PROVIDER)
    }

    fn mpr_share_comment(
        &self,
        share_name: &str,
        network_use: Option<&NetworkUseProfile>,
    ) -> String {
        if let Some(network_use) = network_use {
            if !network_use.comment.trim().is_empty() {
                return network_use.comment.clone();
            }
        }
        if share_name.eq_ignore_ascii_case("ADMIN$") {
            "Remote Admin".to_string()
        } else if share_name.eq_ignore_ascii_case("IPC$") {
            "Remote IPC".to_string()
        } else if share_name.eq_ignore_ascii_case("SYSVOL")
            || share_name.eq_ignore_ascii_case("NETLOGON")
        {
            "Logon server share".to_string()
        } else if share_name.len() == 2
            && share_name.as_bytes()[0].is_ascii_alphabetic()
            && share_name.as_bytes()[1] == b'$'
        {
            "Default share".to_string()
        } else {
            String::new()
        }
    }

    fn mpr_server_comment(&self, server_name: &str) -> String {
        if self.mpr_server_matches_active_host(server_name) {
            return self.environment_profile.os_version.product_name.clone();
        }

        let domain_controller = self
            .environment_profile
            .machine
            .domain_controller
            .trim()
            .trim_start_matches('\\');
        if !domain_controller.is_empty()
            && (server_name.eq_ignore_ascii_case(domain_controller)
                || domain_controller
                    .split('.')
                    .next()
                    .map(|short_name| server_name.eq_ignore_ascii_case(short_name))
                    .unwrap_or(false))
        {
            let domain_name = self.environment_profile.machine.user_domain.trim();
            if !domain_name.is_empty() && !domain_name.eq_ignore_ascii_case("WORKGROUP") {
                return format!("{domain_name} Domain Controller");
            }
            return "Domain Controller".to_string();
        }

        String::new()
    }

    fn mpr_server_matches_active_host(&self, server_name: &str) -> bool {
        if server_name.eq_ignore_ascii_case(self.active_computer_name()) {
            return true;
        }
        let dns_domain = self.environment_profile.machine.dns_domain_name.trim();
        !dns_domain.is_empty()
            && server_name.eq_ignore_ascii_case(&format!(
                "{}.{}",
                self.active_computer_name(),
                dns_domain
            ))
    }

    fn map_local_path_to_universal_name(&self, local_path: &str) -> Option<UniversalNameMapping> {
        let path = local_path.trim();
        self.netapi_network_uses()
            .into_iter()
            .find_map(|network_use| {
                let local_name = network_use.local_name.trim();
                if local_name.is_empty() {
                    return None;
                }
                let path_lower = path.to_ascii_lowercase();
                let local_lower = local_name.to_ascii_lowercase();
                if !path_lower.starts_with(&local_lower) {
                    return None;
                }
                if path.len() > local_name.len()
                    && !matches!(path.chars().nth(local_name.len()), Some('\\') | Some('/'))
                {
                    return None;
                }
                let suffix = path[local_name.len()..]
                    .trim_start_matches('\\')
                    .trim_start_matches('/');
                let remaining_path = if suffix.is_empty() {
                    String::new()
                } else {
                    format!(r"\{}", suffix.replace('/', r"\"))
                };
                Some(UniversalNameMapping {
                    universal_name: if remaining_path.is_empty() {
                        network_use.remote_name.clone()
                    } else {
                        format!(
                            r"{}{}",
                            network_use.remote_name.trim_end_matches('\\'),
                            remaining_path
                        )
                    },
                    connection_name: network_use.remote_name,
                    remaining_path,
                })
            })
    }

    fn write_text_result(
        &mut self,
        wide: bool,
        value: &str,
        buffer_ptr: u64,
        length_ptr: u64,
        insufficient_status: u64,
    ) -> Result<u64, VmError> {
        let required = if wide {
            value.encode_utf16().count() + 1
        } else {
            value.len() + 1
        };
        let capacity = self.read_u32(length_ptr)? as usize;
        self.write_u32(length_ptr, required as u32)?;
        if buffer_ptr == 0 || capacity < required {
            self.set_last_error(insufficient_status as u32);
            return Ok(insufficient_status);
        }
        if wide {
            self.write_wide_string_to_memory(buffer_ptr, capacity, value)?;
        } else {
            self.write_c_string_to_memory(buffer_ptr, capacity, value)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    fn write_text_buffer_fixed(
        &mut self,
        wide: bool,
        value: &str,
        buffer_ptr: u64,
        capacity: u32,
    ) -> Result<u64, VmError> {
        let required = if wide {
            value.encode_utf16().count() + 1
        } else {
            value.len() + 1
        };
        if capacity == 0 || buffer_ptr == 0 {
            return Ok(if required == 0 {
                ERROR_SUCCESS
            } else {
                ERROR_MORE_DATA
            });
        }
        if (capacity as usize) < required {
            return Ok(ERROR_MORE_DATA);
        }
        if wide {
            self.write_wide_string_to_memory(buffer_ptr, capacity as usize, value)?;
        } else {
            self.write_c_string_to_memory(buffer_ptr, capacity as usize, value)?;
        }
        Ok(ERROR_SUCCESS)
    }

    fn mpr_error_message(&self, code: u64) -> String {
        match code {
            ERROR_SUCCESS => String::new(),
            ERROR_BAD_NET_NAME => "The network name cannot be found.".to_string(),
            ERROR_ALREADY_ASSIGNED => "The local device name is already in use.".to_string(),
            ERROR_BAD_DEVICE => "The specified device name is invalid.".to_string(),
            ERROR_BAD_PROVIDER => "The specified provider name is invalid.".to_string(),
            ERROR_NOT_CONNECTED => "This network connection does not exist.".to_string(),
            ERROR_EXTENDED_ERROR => "The network provider reported an extended error.".to_string(),
            ERROR_INVALID_PARAMETER => "The parameter is incorrect.".to_string(),
            _ => format!("Network provider error {code}."),
        }
    }

    fn net_resource_required_size(&self, wide: bool, entries: &[NetworkUseProfile]) -> u64 {
        let layout = self.mpr_net_resource_layout();
        let mut required = align_up_local(
            entries.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for entry in entries {
            required += inline_text_storage_size_local(wide, &entry.local_name);
            required += inline_text_storage_size_local(wide, &entry.remote_name);
            required += inline_text_storage_size_local(wide, &entry.comment);
            required += inline_text_storage_size_local(wide, &entry.provider);
        }
        required
    }

    fn write_net_resource_entries(
        &mut self,
        wide: bool,
        base: u64,
        entries: &[NetworkUseProfile],
    ) -> Result<(), VmError> {
        let layout = self.mpr_net_resource_layout();
        let mut cursor = align_up_local(
            base + entries.len() as u64 * layout.size,
            if wide { 2 } else { 1 },
        );
        for (index, entry) in entries.iter().enumerate() {
            let address = base + index as u64 * layout.size;
            let local_name_ptr =
                write_optional_inline_text_string(self, wide, &mut cursor, &entry.local_name)?;
            let remote_name_ptr =
                write_optional_inline_text_string(self, wide, &mut cursor, &entry.remote_name)?;
            let comment_ptr =
                write_optional_inline_text_string(self, wide, &mut cursor, &entry.comment)?;
            let provider_ptr =
                write_optional_inline_text_string(self, wide, &mut cursor, &entry.provider)?;
            self.write_u32(address + layout.scope_offset, RESOURCE_CONNECTED)?;
            self.write_u32(address + layout.type_offset, RESOURCETYPE_DISK)?;
            self.write_u32(
                address + layout.display_type_offset,
                RESOURCEDISPLAYTYPE_SHARE,
            )?;
            self.write_u32(address + layout.usage_offset, RESOURCEUSAGE_CONNECTABLE)?;
            self.write_pointer_value(address + layout.local_name_offset, local_name_ptr)?;
            self.write_pointer_value(address + layout.remote_name_offset, remote_name_ptr)?;
            self.write_pointer_value(address + layout.comment_offset, comment_ptr)?;
            self.write_pointer_value(address + layout.provider_offset, provider_ptr)?;
        }
        Ok(())
    }
}

fn write_optional_inline_text_string(
    engine: &mut VirtualExecutionEngine,
    wide: bool,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    if value.is_empty() {
        return Ok(0);
    }
    if wide {
        *cursor = align_up_local(*cursor, 2);
        let address = *cursor;
        let capacity = value.encode_utf16().count() + 1;
        engine.write_wide_string_to_memory(address, capacity, value)?;
        *cursor += (capacity * 2) as u64;
        Ok(address)
    } else {
        let address = *cursor;
        let capacity = value.len() + 1;
        engine.write_c_string_to_memory(address, capacity, value)?;
        *cursor += capacity as u64;
        Ok(address)
    }
}

fn write_inline_text_string_local(
    engine: &mut VirtualExecutionEngine,
    wide: bool,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    if wide {
        *cursor = align_up_local(*cursor, 2);
        let address = *cursor;
        let capacity = value.encode_utf16().count() + 1;
        engine.write_wide_string_to_memory(address, capacity, value)?;
        *cursor += (capacity * 2) as u64;
        Ok(address)
    } else {
        let address = *cursor;
        let capacity = value.len() + 1;
        engine.write_c_string_to_memory(address, capacity, value)?;
        *cursor += capacity as u64;
        Ok(address)
    }
}

fn align_up_local(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

fn inline_text_storage_size_local(wide: bool, value: &str) -> u64 {
    if value.is_empty() {
        0
    } else if wide {
        ((value.encode_utf16().count() + 1) * 2) as u64
    } else {
        (value.len() + 1) as u64
    }
}

fn inline_text_storage_size_required_local(wide: bool, value: &str) -> u64 {
    if wide {
        ((value.encode_utf16().count() + 1) * 2) as u64
    } else {
        (value.len() + 1) as u64
    }
}

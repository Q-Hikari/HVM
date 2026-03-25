use super::*;

use crate::environment_profile::{
    LocalGroupProfile, NetworkSessionProfile, NetworkUseProfile, OpenFileProfile, ShareProfile,
    UserAccountProfile, WorkstationUserProfile,
};

const NETSETUP_WORKGROUP_NAME: u32 = 2;
const NETSETUP_DOMAIN_NAME: u32 = 3;
const PLATFORM_ID_NT: u32 = 500;
const SV_TYPE_WORKSTATION: u32 = 0x0000_0001;
const SV_TYPE_SERVER: u32 = 0x0000_0002;
const SV_TYPE_DOMAIN_CTRL: u32 = 0x0000_0008;
const SV_TYPE_DOMAIN_MEMBER: u32 = 0x0000_0100;
const SV_TYPE_SERVER_NT: u32 = 0x0000_8000;
const SV_TYPE_DOMAIN_ENUM: u32 = 0x8000_0000;
const SV_TYPE_ALL: u32 = 0xFFFF_FFFF;
const DSROLE_PRIMARY_DOMAIN_INFO_BASIC: u32 = 1;
const DSROLE_ROLE_STANDALONE_WORKSTATION: u32 = 0;
const DSROLE_ROLE_MEMBER_WORKSTATION: u32 = 1;
const DSROLE_ROLE_STANDALONE_SERVER: u32 = 2;
const DSROLE_ROLE_MEMBER_SERVER: u32 = 3;
const USER_INFO_LEVEL_0: u32 = 0;
const USER_INFO_LEVEL_1: u32 = 1;
const USER_INFO_LEVEL_23: u32 = 23;
const GROUP_INFO_LEVEL_0: u32 = 0;
const GROUP_INFO_LEVEL_1: u32 = 1;
const GROUP_USERS_INFO_LEVEL_0: u32 = 0;
const USE_INFO_LEVEL_0: u32 = 0;
const USE_INFO_LEVEL_1: u32 = 1;
const USE_INFO_LEVEL_2: u32 = 2;
const CONNECTION_INFO_LEVEL_0: u32 = 0;
const CONNECTION_INFO_LEVEL_1: u32 = 1;
const FILE_INFO_LEVEL_2: u32 = 2;
const FILE_INFO_LEVEL_3: u32 = 3;
const SHARE_INFO_LEVEL_0: u32 = 0;
const SHARE_INFO_LEVEL_1: u32 = 1;
const SHARE_INFO_LEVEL_2: u32 = 2;
const SESSION_INFO_LEVEL_10: u32 = 10;
const WKSTA_USER_INFO_LEVEL_0: u32 = 0;
const WKSTA_USER_INFO_LEVEL_1: u32 = 1;
const LOCALGROUP_INFO_LEVEL_0: u32 = 0;
const LOCALGROUP_INFO_LEVEL_1: u32 = 1;
const LOCALGROUP_USERS_INFO_LEVEL_0: u32 = 0;
const LOCALGROUP_MEMBERS_INFO_LEVEL_0: u32 = 0;
const LOCALGROUP_MEMBERS_INFO_LEVEL_1: u32 = 1;
const LOCALGROUP_MEMBERS_INFO_LEVEL_2: u32 = 2;
const LOCALGROUP_MEMBERS_INFO_LEVEL_3: u32 = 3;
const DOMAIN_CONTROLLER_ADDRESS_TYPE_INET: u32 = 1;
const DOMAIN_TRUST_FLAGS_IN_FOREST: u32 = 0x0000_0001;
const DOMAIN_TRUST_FLAGS_DIRECT_OUTBOUND: u32 = 0x0000_0002;
const DOMAIN_TRUST_FLAGS_TREE_ROOT: u32 = 0x0000_0004;
const DOMAIN_TRUST_FLAGS_PRIMARY: u32 = 0x0000_0008;
const DOMAIN_TRUST_FLAGS_NATIVE_MODE: u32 = 0x0000_0010;
const DOMAIN_TRUST_FLAGS_DIRECT_INBOUND: u32 = 0x0000_0020;
const DOMAIN_TRUST_TYPE_UPLEVEL: u32 = 2;
const DOMAIN_CONTROLLER_FLAGS: u32 = 0x0000_0001
    | 0x0000_0004
    | 0x0000_0008
    | 0x0000_0010
    | 0x0000_0020
    | 0x0000_0040
    | 0x0000_0080
    | 0x0000_0100
    | 0x0000_0200;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
const STYPE_DISKTREE: u32 = 0;
const STYPE_IPC: u32 = 3;
const STYPE_SPECIAL: u32 = 0x8000_0000;
const USE_DISKDEV: u32 = 0;
const PERM_FILE_READ: u32 = 0x0000_0001;
const PERM_FILE_WRITE: u32 = 0x0000_0002;
const ERROR_ALREADY_ASSIGNED: u64 = 85;
const ERROR_NOT_CONNECTED: u64 = 2250;
const NERR_DEVICE_NOT_SHARED: u64 = 2311;
const NERR_GROUP_NOT_FOUND: u64 = 2220;
const NERR_FILE_ID_NOT_FOUND: u64 = 2314;
const NERR_NET_NAME_NOT_FOUND: u64 = 2310;
const NERR_USER_NOT_FOUND: u64 = 2221;
const TIME_OF_DAY_TICK_INTERVAL: u32 = 310;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_netapi32_hook(
        &mut self,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        if !matches!(
            function,
            "Netbios"
                | "NetApiBufferFree"
                | "NetGetJoinInformation"
                | "NetGetDCName"
                | "NetGetAnyDCName"
                | "NetWkstaGetInfo"
                | "NetUserEnum"
                | "NetUserGetInfo"
                | "NetGroupEnum"
                | "NetGroupGetInfo"
                | "NetUserGetGroups"
                | "NetGroupGetUsers"
                | "NetUseEnum"
                | "NetUseAdd"
                | "NetUseDel"
                | "NetUseGetInfo"
                | "NetFileEnum"
                | "NetFileGetInfo"
                | "NetFileClose"
                | "NetConnectionEnum"
                | "NetShareCheck"
                | "NetRemoteTOD"
                | "NetShareEnum"
                | "NetShareGetInfo"
                | "NetSessionEnum"
                | "NetWkstaUserEnum"
                | "NetLocalGroupEnum"
                | "NetUserGetLocalGroups"
                | "NetLocalGroupGetMembers"
                | "NetLocalGroupGetInfo"
                | "NetServerGetInfo"
                | "NetServerEnum"
                | "DsRoleGetPrimaryDomainInformation"
                | "DsGetDcNameA"
                | "DsGetDcNameW"
                | "DsEnumerateDomainTrustsA"
                | "DsEnumerateDomainTrustsW"
                | "DsRoleFreeMemory"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "Netbios" => {
                    let ncb = arg(args, 0);
                    if ncb == 0 {
                        Ok(0x01)
                    } else {
                        let command = self.read_bytes_from_memory(ncb, 1)?[0];
                        let buffer = self.read_u32(ncb + 4)? as u64;
                        let length = self.read_u16(ncb + 8)? as usize;
                        if command == 0x37 {
                            self.write_netbios_lana_enum(buffer, length)?;
                        }
                        self.modules.memory_mut().write(ncb + 1, &[0])?;
                        self.modules.memory_mut().write(ncb + 49, &[0])?;
                        Ok(0)
                    }
                }
                "NetApiBufferFree" => Ok(self.net_api_buffer_free(arg(args, 0))),
                "NetGetJoinInformation" => self.net_get_join_information(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                ),
                "NetGetDCName" | "NetGetAnyDCName" => self.net_get_dc_name(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                ),
                "NetWkstaGetInfo" => self.net_wksta_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                ),
                "NetUserEnum" => self.net_user_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                    arg(args, 7),
                ),
                "NetUserGetInfo" => self.net_user_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetGroupEnum" => self.net_group_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetGroupGetInfo" => self.net_group_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetUserGetGroups" => self.net_user_get_groups(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetGroupGetUsers" => self.net_group_get_users(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetUseEnum" => self.net_use_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetUseAdd" => self.net_use_add(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "NetUseDel" => self.net_use_del(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                ),
                "NetUseGetInfo" => self.net_use_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetFileEnum" => self.net_file_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    &self.read_wide_string_from_memory(arg(args, 2))?,
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5) as u32,
                    arg(args, 6),
                    arg(args, 7),
                    arg(args, 8),
                ),
                "NetFileGetInfo" => self.net_file_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetFileClose" => self.net_file_close(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                ),
                "NetConnectionEnum" => self.net_connection_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                    arg(args, 7),
                ),
                "NetShareCheck" => self.net_share_check(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                ),
                "NetRemoteTOD" => self.net_remote_tod(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                ),
                "NetShareEnum" => self.net_share_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetShareGetInfo" => self.net_share_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetSessionEnum" => self.net_session_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    &self.read_wide_string_from_memory(arg(args, 2))?,
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5) as u32,
                    arg(args, 6),
                    arg(args, 7),
                    arg(args, 8),
                ),
                "NetWkstaUserEnum" => self.net_wksta_user_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetLocalGroupEnum" => self.net_local_group_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "NetUserGetLocalGroups" => self.net_user_get_local_groups(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5) as u32,
                    arg(args, 6),
                    arg(args, 7),
                ),
                "NetLocalGroupGetMembers" => self.net_local_group_get_members(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5),
                    arg(args, 6),
                    arg(args, 7),
                ),
                "NetLocalGroupGetInfo" => self.net_local_group_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "NetServerGetInfo" => self.net_server_get_info(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                ),
                "NetServerEnum" => self.net_server_enum(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6) as u32,
                    &self.read_wide_string_from_memory(arg(args, 7))?,
                    arg(args, 8),
                ),
                "DsRoleGetPrimaryDomainInformation" => self.ds_role_get_primary_domain_information(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                ),
                "DsGetDcNameA" => self.ds_get_dc_name(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    &self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                    &self.read_c_string_from_memory(arg(args, 3))?,
                    arg(args, 4) as u32,
                    arg(args, 5),
                ),
                "DsGetDcNameW" => self.ds_get_dc_name(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                    &self.read_wide_string_from_memory(arg(args, 3))?,
                    arg(args, 4) as u32,
                    arg(args, 5),
                ),
                "DsEnumerateDomainTrustsA" => self.ds_enumerate_domain_trusts(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "DsEnumerateDomainTrustsW" => self.ds_enumerate_domain_trusts(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                ),
                "DsRoleFreeMemory" => Ok(self.net_api_buffer_free(arg(args, 0))),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

#[derive(Debug, Clone, Copy)]
struct WkstaInfoLayout {
    size: u64,
    computer_name_offset: u64,
    langroup_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    lanroot_offset: Option<u64>,
    logged_on_users_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct ServerInfo101Layout {
    size: u64,
    name_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    server_type_offset: u64,
    comment_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct DsRolePrimaryDomainInfoBasicLayout {
    size: u64,
    flags_offset: u64,
    flat_name_offset: u64,
    dns_name_offset: u64,
    forest_name_offset: u64,
    domain_guid_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct UserInfo1Layout {
    size: u64,
    name_offset: u64,
    password_age_offset: u64,
    privilege_offset: u64,
    home_dir_offset: u64,
    comment_offset: u64,
    flags_offset: u64,
    script_path_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct UserInfo23Layout {
    size: u64,
    name_offset: u64,
    full_name_offset: u64,
    comment_offset: u64,
    flags_offset: u64,
    sid_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct LocalGroupInfo1Layout {
    size: u64,
    name_offset: u64,
    comment_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct LocalGroupMembersInfo12Layout {
    size: u64,
    sid_offset: u64,
    sid_use_offset: u64,
    name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct ShareInfo1Layout {
    size: u64,
    name_offset: u64,
    share_type_offset: u64,
    remark_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct UseInfo1Layout {
    size: u64,
    local_name_offset: u64,
    remote_name_offset: u64,
    password_offset: u64,
    status_offset: u64,
    assignment_type_offset: u64,
    ref_count_offset: u64,
    use_count_offset: u64,
}

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy)]
struct ShareInfo2Layout {
    size: u64,
    name_offset: u64,
    share_type_offset: u64,
    remark_offset: u64,
    permissions_offset: u64,
    max_uses_offset: u64,
    current_uses_offset: u64,
    path_offset: u64,
    password_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct SessionInfo10Layout {
    size: u64,
    client_name_offset: u64,
    user_name_offset: u64,
    active_time_offset: u64,
    idle_time_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct FileInfo3Layout {
    size: u64,
    id_offset: u64,
    permissions_offset: u64,
    num_locks_offset: u64,
    path_name_offset: u64,
    user_name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionInfo1Layout {
    size: u64,
    id_offset: u64,
    type_offset: u64,
    num_opens_offset: u64,
    num_users_offset: u64,
    time_offset: u64,
    user_name_offset: u64,
    net_name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
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
    size: u64,
}

#[derive(Debug, Clone, Copy)]
struct WkstaUserInfo1Layout {
    size: u64,
    user_name_offset: u64,
    logon_domain_offset: u64,
    other_domains_offset: u64,
    logon_server_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct DomainControllerInfoLayout {
    size: u64,
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

#[derive(Debug, Clone, Copy)]
struct DomainTrustInfoLayout {
    size: u64,
    netbios_name_offset: u64,
    dns_name_offset: u64,
    flags_offset: u64,
    parent_index_offset: u64,
    trust_type_offset: u64,
    trust_attributes_offset: u64,
    sid_offset: u64,
    guid_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AccountLookupRecord {
    User {
        profile: UserAccountProfile,
        domain: String,
        sid: Vec<u8>,
    },
    Group {
        profile: LocalGroupProfile,
        domain: String,
        sid: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct DomainTrustRecord {
    netbios_name: String,
    dns_name: String,
    flags: u32,
    parent_index: u32,
    trust_type: u32,
    trust_attributes: u32,
    sid: Vec<u8>,
    guid: [u8; 16],
}

#[derive(Debug, Clone)]
struct ServerInventoryRecord {
    name: String,
    comment: String,
    server_type: u32,
}

#[derive(Debug, Clone)]
struct ConnectionInventoryRecord {
    id: u32,
    connection_type: u32,
    num_opens: u32,
    num_users: u32,
    active_time_secs: u32,
    user_name: String,
    net_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerEnumScope {
    Browser,
    LocalComputer,
}

impl VirtualExecutionEngine {
    fn wksta_info_layout(&self, level: u32) -> Option<WkstaInfoLayout> {
        if self.arch.is_x86() {
            match level {
                100 => Some(WkstaInfoLayout {
                    size: 20,
                    computer_name_offset: 4,
                    langroup_offset: 8,
                    ver_major_offset: 12,
                    ver_minor_offset: 16,
                    lanroot_offset: None,
                    logged_on_users_offset: None,
                }),
                101 => Some(WkstaInfoLayout {
                    size: 24,
                    computer_name_offset: 4,
                    langroup_offset: 8,
                    ver_major_offset: 12,
                    ver_minor_offset: 16,
                    lanroot_offset: Some(20),
                    logged_on_users_offset: None,
                }),
                102 => Some(WkstaInfoLayout {
                    size: 28,
                    computer_name_offset: 4,
                    langroup_offset: 8,
                    ver_major_offset: 12,
                    ver_minor_offset: 16,
                    lanroot_offset: Some(20),
                    logged_on_users_offset: Some(24),
                }),
                _ => None,
            }
        } else {
            match level {
                100 => Some(WkstaInfoLayout {
                    size: 32,
                    computer_name_offset: 8,
                    langroup_offset: 16,
                    ver_major_offset: 24,
                    ver_minor_offset: 28,
                    lanroot_offset: None,
                    logged_on_users_offset: None,
                }),
                101 => Some(WkstaInfoLayout {
                    size: 40,
                    computer_name_offset: 8,
                    langroup_offset: 16,
                    ver_major_offset: 24,
                    ver_minor_offset: 28,
                    lanroot_offset: Some(32),
                    logged_on_users_offset: None,
                }),
                102 => Some(WkstaInfoLayout {
                    size: 48,
                    computer_name_offset: 8,
                    langroup_offset: 16,
                    ver_major_offset: 24,
                    ver_minor_offset: 28,
                    lanroot_offset: Some(32),
                    logged_on_users_offset: Some(40),
                }),
                _ => None,
            }
        }
    }

    fn server_info_101_layout(&self) -> ServerInfo101Layout {
        if self.arch.is_x86() {
            ServerInfo101Layout {
                size: 24,
                name_offset: 4,
                ver_major_offset: 8,
                ver_minor_offset: 12,
                server_type_offset: 16,
                comment_offset: 20,
            }
        } else {
            ServerInfo101Layout {
                size: 40,
                name_offset: 8,
                ver_major_offset: 16,
                ver_minor_offset: 20,
                server_type_offset: 24,
                comment_offset: 32,
            }
        }
    }

    fn ds_role_primary_domain_info_basic_layout(&self) -> DsRolePrimaryDomainInfoBasicLayout {
        if self.arch.is_x86() {
            DsRolePrimaryDomainInfoBasicLayout {
                size: 36,
                flags_offset: 4,
                flat_name_offset: 8,
                dns_name_offset: 12,
                forest_name_offset: 16,
                domain_guid_offset: 20,
            }
        } else {
            DsRolePrimaryDomainInfoBasicLayout {
                size: 48,
                flags_offset: 4,
                flat_name_offset: 8,
                dns_name_offset: 16,
                forest_name_offset: 24,
                domain_guid_offset: 32,
            }
        }
    }

    fn user_info_1_layout(&self) -> UserInfo1Layout {
        if self.arch.is_x86() {
            UserInfo1Layout {
                size: 28,
                name_offset: 0,
                password_age_offset: 4,
                privilege_offset: 8,
                home_dir_offset: 12,
                comment_offset: 16,
                flags_offset: 20,
                script_path_offset: 24,
            }
        } else {
            UserInfo1Layout {
                size: 48,
                name_offset: 0,
                password_age_offset: 8,
                privilege_offset: 12,
                home_dir_offset: 16,
                comment_offset: 24,
                flags_offset: 32,
                script_path_offset: 40,
            }
        }
    }

    fn user_info_23_layout(&self) -> UserInfo23Layout {
        if self.arch.is_x86() {
            UserInfo23Layout {
                size: 20,
                name_offset: 0,
                full_name_offset: 4,
                comment_offset: 8,
                flags_offset: 12,
                sid_offset: 16,
            }
        } else {
            UserInfo23Layout {
                size: 40,
                name_offset: 0,
                full_name_offset: 8,
                comment_offset: 16,
                flags_offset: 24,
                sid_offset: 32,
            }
        }
    }

    fn local_group_info_1_layout(&self) -> LocalGroupInfo1Layout {
        if self.arch.is_x86() {
            LocalGroupInfo1Layout {
                size: 8,
                name_offset: 0,
                comment_offset: 4,
            }
        } else {
            LocalGroupInfo1Layout {
                size: 16,
                name_offset: 0,
                comment_offset: 8,
            }
        }
    }

    fn local_group_members_info_12_layout(&self) -> LocalGroupMembersInfo12Layout {
        if self.arch.is_x86() {
            LocalGroupMembersInfo12Layout {
                size: 12,
                sid_offset: 0,
                sid_use_offset: 4,
                name_offset: 8,
            }
        } else {
            LocalGroupMembersInfo12Layout {
                size: 24,
                sid_offset: 0,
                sid_use_offset: 8,
                name_offset: 16,
            }
        }
    }

    fn share_info_1_layout(&self) -> ShareInfo1Layout {
        if self.arch.is_x86() {
            ShareInfo1Layout {
                size: 12,
                name_offset: 0,
                share_type_offset: 4,
                remark_offset: 8,
            }
        } else {
            ShareInfo1Layout {
                size: 24,
                name_offset: 0,
                share_type_offset: 8,
                remark_offset: 16,
            }
        }
    }

    fn use_info_1_layout(&self) -> UseInfo1Layout {
        if self.arch.is_x86() {
            UseInfo1Layout {
                size: 28,
                local_name_offset: 0,
                remote_name_offset: 4,
                password_offset: 8,
                status_offset: 12,
                assignment_type_offset: 16,
                ref_count_offset: 20,
                use_count_offset: 24,
            }
        } else {
            UseInfo1Layout {
                size: 40,
                local_name_offset: 0,
                remote_name_offset: 8,
                password_offset: 16,
                status_offset: 24,
                assignment_type_offset: 28,
                ref_count_offset: 32,
                use_count_offset: 36,
            }
        }
    }

    fn use_info_2_layout(&self) -> UseInfo2Layout {
        if self.arch.is_x86() {
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
        } else {
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
        }
    }

    fn share_info_2_layout(&self) -> ShareInfo2Layout {
        if self.arch.is_x86() {
            ShareInfo2Layout {
                size: 32,
                name_offset: 0,
                share_type_offset: 4,
                remark_offset: 8,
                permissions_offset: 12,
                max_uses_offset: 16,
                current_uses_offset: 20,
                path_offset: 24,
                password_offset: 28,
            }
        } else {
            ShareInfo2Layout {
                size: 56,
                name_offset: 0,
                share_type_offset: 8,
                remark_offset: 16,
                permissions_offset: 24,
                max_uses_offset: 28,
                current_uses_offset: 32,
                path_offset: 40,
                password_offset: 48,
            }
        }
    }

    fn session_info_10_layout(&self) -> SessionInfo10Layout {
        if self.arch.is_x86() {
            SessionInfo10Layout {
                size: 16,
                client_name_offset: 0,
                user_name_offset: 4,
                active_time_offset: 8,
                idle_time_offset: 12,
            }
        } else {
            SessionInfo10Layout {
                size: 24,
                client_name_offset: 0,
                user_name_offset: 8,
                active_time_offset: 16,
                idle_time_offset: 20,
            }
        }
    }

    fn file_info_3_layout(&self) -> FileInfo3Layout {
        if self.arch.is_x86() {
            FileInfo3Layout {
                size: 20,
                id_offset: 0,
                permissions_offset: 4,
                num_locks_offset: 8,
                path_name_offset: 12,
                user_name_offset: 16,
            }
        } else {
            FileInfo3Layout {
                size: 32,
                id_offset: 0,
                permissions_offset: 4,
                num_locks_offset: 8,
                path_name_offset: 16,
                user_name_offset: 24,
            }
        }
    }

    fn connection_info_1_layout(&self) -> ConnectionInfo1Layout {
        if self.arch.is_x86() {
            ConnectionInfo1Layout {
                size: 28,
                id_offset: 0,
                type_offset: 4,
                num_opens_offset: 8,
                num_users_offset: 12,
                time_offset: 16,
                user_name_offset: 20,
                net_name_offset: 24,
            }
        } else {
            ConnectionInfo1Layout {
                size: 40,
                id_offset: 0,
                type_offset: 4,
                num_opens_offset: 8,
                num_users_offset: 12,
                time_offset: 16,
                user_name_offset: 24,
                net_name_offset: 32,
            }
        }
    }

    fn time_of_day_info_layout(&self) -> TimeOfDayInfoLayout {
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
            size: 48,
        }
    }

    fn wksta_user_info_1_layout(&self) -> WkstaUserInfo1Layout {
        if self.arch.is_x86() {
            WkstaUserInfo1Layout {
                size: 16,
                user_name_offset: 0,
                logon_domain_offset: 4,
                other_domains_offset: 8,
                logon_server_offset: 12,
            }
        } else {
            WkstaUserInfo1Layout {
                size: 32,
                user_name_offset: 0,
                logon_domain_offset: 8,
                other_domains_offset: 16,
                logon_server_offset: 24,
            }
        }
    }

    fn domain_controller_info_layout(&self) -> DomainControllerInfoLayout {
        if self.arch.is_x86() {
            DomainControllerInfoLayout {
                size: 48,
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
        } else {
            DomainControllerInfoLayout {
                size: 80,
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
        }
    }

    fn domain_trust_info_layout(&self) -> DomainTrustInfoLayout {
        if self.arch.is_x86() {
            DomainTrustInfoLayout {
                size: 44,
                netbios_name_offset: 0,
                dns_name_offset: 4,
                flags_offset: 8,
                parent_index_offset: 12,
                trust_type_offset: 16,
                trust_attributes_offset: 20,
                sid_offset: 24,
                guid_offset: 28,
            }
        } else {
            DomainTrustInfoLayout {
                size: 56,
                netbios_name_offset: 0,
                dns_name_offset: 8,
                flags_offset: 16,
                parent_index_offset: 20,
                trust_type_offset: 24,
                trust_attributes_offset: 28,
                sid_offset: 32,
                guid_offset: 40,
            }
        }
    }

    fn netapi_domain_joined(&self) -> bool {
        !self.netapi_join_name().eq_ignore_ascii_case("WORKGROUP")
    }

    fn netapi_join_name(&self) -> String {
        let domain = self.environment_profile.machine.user_domain.trim();
        if domain.is_empty() {
            "WORKGROUP".to_string()
        } else {
            domain.to_string()
        }
    }

    fn netapi_join_status(&self) -> u32 {
        if self.netapi_domain_joined() {
            NETSETUP_DOMAIN_NAME
        } else {
            NETSETUP_WORKGROUP_NAME
        }
    }

    fn netapi_dns_domain_name(&self) -> String {
        if !self
            .environment_profile
            .machine
            .dns_domain_name
            .trim()
            .is_empty()
        {
            return self.environment_profile.machine.dns_domain_name.clone();
        }
        if !self.netapi_domain_joined() {
            return String::new();
        }
        let network_domain = self.environment_profile.network.domain_name.trim();
        if !network_domain.is_empty() && !network_domain.eq_ignore_ascii_case("lan") {
            return network_domain.to_string();
        }
        let dns_suffix = self.environment_profile.network.dns_suffix.trim();
        if !dns_suffix.is_empty() && !dns_suffix.eq_ignore_ascii_case("lan") {
            return dns_suffix.to_string();
        }
        format!("{}.local", self.netapi_join_name().to_ascii_lowercase())
    }

    fn netapi_forest_name(&self) -> String {
        if !self
            .environment_profile
            .machine
            .forest_name
            .trim()
            .is_empty()
        {
            return self.environment_profile.machine.forest_name.clone();
        }
        self.netapi_dns_domain_name()
    }

    fn netapi_domain_controller_name(&self) -> String {
        if !self.netapi_domain_joined() {
            return String::new();
        }
        let configured = self.environment_profile.machine.domain_controller.trim();
        if configured.is_empty() {
            format!(r"\\{}-DC01", self.netapi_join_name().to_ascii_uppercase())
        } else if configured.starts_with(r"\\") {
            configured.to_string()
        } else {
            format!(r"\\{configured}")
        }
    }

    fn netapi_domain_controller_host_name(&self) -> String {
        self.netapi_domain_controller_name()
            .trim_start_matches('\\')
            .to_string()
    }

    fn netapi_domain_controller_dns_name(&self) -> String {
        let host = self.netapi_domain_controller_host_name();
        if host.is_empty() {
            return host;
        }
        if host.contains('.') || !self.netapi_domain_joined() {
            return host;
        }
        let dns_domain = self.netapi_dns_domain_name();
        if dns_domain.is_empty() {
            host
        } else {
            format!("{host}.{dns_domain}")
        }
    }

    fn netapi_active_computer_dns_name(&self) -> String {
        let dns_domain = self.netapi_dns_domain_name();
        if dns_domain.is_empty() {
            self.active_computer_name().to_string()
        } else {
            format!("{}.{}", self.active_computer_name(), dns_domain)
        }
    }

    fn netapi_domain_controller_address(&self) -> String {
        let address = self
            .environment_profile
            .network
            .dns_servers
            .iter()
            .find(|value| !value.trim().is_empty())
            .cloned()
            .or_else(|| {
                self.environment_profile
                    .network
                    .adapters
                    .iter()
                    .flat_map(|adapter| adapter.dns_servers.iter())
                    .find(|value| !value.trim().is_empty())
                    .cloned()
            })
            .or_else(|| {
                self.environment_profile
                    .network
                    .adapters
                    .iter()
                    .flat_map(|adapter| adapter.gateways.iter())
                    .find(|value| !value.trim().is_empty())
                    .cloned()
            })
            .unwrap_or_else(|| "127.0.0.1".to_string());
        format!(r"\\{address}")
    }

    fn netapi_client_site_name(&self) -> String {
        "Default-First-Site-Name".to_string()
    }

    fn netapi_domain_guid_bytes(&self) -> [u8; 16] {
        if !self
            .environment_profile
            .machine
            .domain_guid
            .trim()
            .is_empty()
        {
            if let Some(bytes) = parse_guid_string_le(&self.environment_profile.machine.domain_guid)
            {
                return bytes;
            }
        }
        if !self.netapi_domain_joined() {
            return [0u8; 16];
        }
        deterministic_guid_le(&format!(
            "{}|{}|{}",
            self.netapi_join_name(),
            self.netapi_dns_domain_name(),
            self.environment_profile.machine.machine_guid
        ))
    }

    fn netapi_domain_sid_bytes(&self) -> Vec<u8> {
        domain_sid_base_bytes(
            &self.netapi_dns_domain_name(),
            &self.environment_profile.machine.domain_guid,
        )
    }

    fn netapi_matches_requested_domain(&self, requested: &str) -> bool {
        let requested = requested.trim().trim_start_matches('\\');
        if requested.is_empty() {
            return true;
        }
        let dc_host = self.netapi_domain_controller_host_name();
        let dc_short = dc_host
            .split('.')
            .next()
            .map(str::to_string)
            .unwrap_or_default();
        requested.eq_ignore_ascii_case(&self.netapi_join_name())
            || requested.eq_ignore_ascii_case(&self.netapi_dns_domain_name())
            || requested.eq_ignore_ascii_case(
                self.netapi_domain_controller_name()
                    .trim_start_matches('\\'),
            )
            || (!dc_host.is_empty() && requested.eq_ignore_ascii_case(&dc_host))
            || (!dc_short.is_empty() && requested.eq_ignore_ascii_case(&dc_short))
    }

    fn netapi_matches_local_computer_scope(&self, requested: &str) -> bool {
        let requested = requested.trim().trim_start_matches('\\');
        !requested.is_empty()
            && (requested.eq_ignore_ascii_case(self.active_computer_name())
                || requested.eq_ignore_ascii_case(&self.netapi_active_computer_dns_name()))
    }

    fn netapi_resolve_server_enum_scope(&self, requested: &str) -> Result<ServerEnumScope, u64> {
        let requested = requested.trim();
        if requested.is_empty() {
            return Ok(ServerEnumScope::Browser);
        }
        if self.netapi_matches_local_computer_scope(requested) {
            return Ok(ServerEnumScope::LocalComputer);
        }
        if self.netapi_matches_requested_domain(requested) {
            return Ok(ServerEnumScope::Browser);
        }
        Err(ERROR_NO_SUCH_DOMAIN)
    }

    fn ds_role_machine_role(&self) -> u32 {
        match (
            self.environment_profile.os_version.product_type,
            self.netapi_domain_joined(),
        ) {
            (1, false) => DSROLE_ROLE_STANDALONE_WORKSTATION,
            (1, true) => DSROLE_ROLE_MEMBER_WORKSTATION,
            (_, false) => DSROLE_ROLE_STANDALONE_SERVER,
            (_, true) => DSROLE_ROLE_MEMBER_SERVER,
        }
    }

    fn netapi_users(&self) -> &[UserAccountProfile] {
        &self.environment_profile.users
    }

    fn netapi_find_user(&self, name: &str) -> Option<UserAccountProfile> {
        self.netapi_users()
            .iter()
            .find(|user| user.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    fn netapi_local_groups(&self) -> &[LocalGroupProfile] {
        &self.environment_profile.local_groups
    }

    fn netapi_find_local_group(&self, name: &str) -> Option<LocalGroupProfile> {
        self.netapi_local_groups()
            .iter()
            .find(|group| group.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    fn netapi_domain_groups(&self) -> Vec<LocalGroupProfile> {
        if !self.netapi_domain_joined() {
            return Vec::new();
        }

        let admin_members = self
            .netapi_users()
            .iter()
            .filter(|user| {
                user.privilege_level >= 2
                    || user.name.eq_ignore_ascii_case("Administrator")
                    || user.name.eq_ignore_ascii_case("Admin")
            })
            .map(|user| user.name.clone())
            .collect::<Vec<_>>();
        let user_members = self
            .netapi_users()
            .iter()
            .map(|user| user.name.clone())
            .collect::<Vec<_>>();
        let guest_members = self
            .netapi_users()
            .iter()
            .filter(|user| user.name.eq_ignore_ascii_case("Guest") || (user.flags & 0x0002) != 0)
            .map(|user| user.name.clone())
            .collect::<Vec<_>>();
        let domain = self.netapi_join_name();
        vec![
            LocalGroupProfile {
                name: "Domain Admins".to_string(),
                comment: "Designated administrators of the domain".to_string(),
                domain: domain.clone(),
                rid: 512,
                members: admin_members,
            },
            LocalGroupProfile {
                name: "Domain Users".to_string(),
                comment: "All domain user accounts".to_string(),
                domain: domain.clone(),
                rid: 513,
                members: user_members,
            },
            LocalGroupProfile {
                name: "Domain Guests".to_string(),
                comment: "All domain guest accounts".to_string(),
                domain: domain.clone(),
                rid: 514,
                members: guest_members,
            },
            LocalGroupProfile {
                name: "Domain Computers".to_string(),
                comment: "All domain joined computers".to_string(),
                domain,
                rid: 515,
                members: Vec::new(),
            },
        ]
    }

    fn netapi_find_domain_group(&self, name: &str) -> Option<LocalGroupProfile> {
        self.netapi_domain_groups()
            .into_iter()
            .find(|group| group.name.eq_ignore_ascii_case(name))
    }

    fn netapi_group_domain(&self, group: &LocalGroupProfile) -> String {
        if !group.domain.trim().is_empty() {
            group.domain.clone()
        } else if is_builtin_alias_rid(group.rid) {
            "BUILTIN".to_string()
        } else {
            self.active_computer_name().to_string()
        }
    }

    fn netapi_group_sid(&self, group: &LocalGroupProfile) -> Vec<u8> {
        let group_domain = self.netapi_group_domain(group);
        if group_domain.eq_ignore_ascii_case("BUILTIN") {
            builtin_alias_sid_bytes(group.rid)
        } else if self.netapi_domain_joined()
            && (group_domain.eq_ignore_ascii_case(&self.netapi_join_name())
                || group_domain.eq_ignore_ascii_case(&self.netapi_dns_domain_name()))
        {
            domain_sid_bytes(
                &self.netapi_dns_domain_name(),
                &self.environment_profile.machine.domain_guid,
                group.rid,
            )
        } else {
            local_account_sid_bytes(&self.environment_profile.machine.machine_guid, group.rid)
        }
    }

    fn netapi_shares(&self) -> Vec<ShareProfile> {
        if !self.environment_profile.shares.is_empty() {
            return self.environment_profile.shares.clone();
        }

        let admin_share = ShareProfile {
            name: "ADMIN$".to_string(),
            share_type: STYPE_SPECIAL,
            remark: "Remote Admin".to_string(),
            path: self.environment_profile.machine.system_root.clone(),
            ..ShareProfile::default()
        };
        let drive_name = self
            .environment_profile
            .volume
            .root_path
            .chars()
            .next()
            .map(|drive| format!("{}$", drive.to_ascii_uppercase()))
            .unwrap_or_else(|| "C$".to_string());
        let root_share = ShareProfile {
            name: drive_name,
            share_type: STYPE_DISKTREE | STYPE_SPECIAL,
            remark: "Default share".to_string(),
            path: self.environment_profile.volume.root_path.clone(),
            ..ShareProfile::default()
        };
        let ipc_share = ShareProfile {
            name: "IPC$".to_string(),
            share_type: STYPE_IPC | STYPE_SPECIAL,
            remark: "Remote IPC".to_string(),
            ..ShareProfile::default()
        };
        vec![admin_share, root_share, ipc_share]
    }

    fn netapi_find_share(&self, name: &str) -> Option<ShareProfile> {
        self.netapi_shares()
            .into_iter()
            .find(|share| share.name.eq_ignore_ascii_case(name))
    }

    pub(super) fn netapi_network_uses(&self) -> Vec<NetworkUseProfile> {
        if !self.environment_profile.network_uses.is_empty() {
            return self.environment_profile.network_uses.clone();
        }
        if !self.netapi_domain_joined() {
            return Vec::new();
        }

        let dc_name = self.netapi_domain_controller_dns_name();
        if dc_name.is_empty() {
            return Vec::new();
        }
        vec![NetworkUseProfile {
            local_name: "Z:".to_string(),
            remote_name: format!(r"\\{dc_name}\SYSVOL"),
            status: 0,
            assignment_type: USE_DISKDEV,
            ref_count: 1,
            use_count: 1,
            user_name: self.environment_profile.machine.user_name.clone(),
            domain_name: self.netapi_join_name(),
            comment: "Default domain policy share".to_string(),
            ..NetworkUseProfile::default()
        }]
    }

    fn netapi_find_network_use(&self, use_name: &str) -> Option<NetworkUseProfile> {
        let requested = use_name.trim();
        self.netapi_network_uses().into_iter().find(|network_use| {
            network_use.local_name.eq_ignore_ascii_case(requested)
                || network_use.remote_name.eq_ignore_ascii_case(requested)
        })
    }

    fn ensure_materialized_netapi_network_uses(&mut self) {
        if !self.environment_profile.network_uses.is_empty() {
            return;
        }
        let defaults = self.netapi_network_uses();
        if !defaults.is_empty() {
            self.environment_profile.network_uses = defaults;
        }
    }

    fn netapi_use_add_conflict_status(&self, network_use: &NetworkUseProfile) -> u64 {
        if network_use.local_name.trim().is_empty() {
            return ERROR_SUCCESS;
        }
        if let Some(existing) = self.netapi_network_uses().into_iter().find(|current| {
            current
                .local_name
                .eq_ignore_ascii_case(&network_use.local_name)
        }) {
            if !existing
                .remote_name
                .eq_ignore_ascii_case(&network_use.remote_name)
            {
                return ERROR_ALREADY_ASSIGNED;
            }
        }
        ERROR_SUCCESS
    }

    fn netapi_parse_use_add_input(
        &self,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<NetworkUseProfile, u64> {
        if buffer_ptr == 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }

        let (
            local_name_ptr,
            remote_name_ptr,
            password_ptr,
            assignment_type,
            user_name_ptr,
            domain_name_ptr,
        ) = match level {
            USE_INFO_LEVEL_1 => {
                let layout = self.use_info_1_layout();
                (
                    self.read_pointer_value(buffer_ptr + layout.local_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.remote_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.password_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_u32(buffer_ptr + layout.assignment_type_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    0,
                    0,
                )
            }
            USE_INFO_LEVEL_2 => {
                let layout = self.use_info_2_layout();
                (
                    self.read_pointer_value(buffer_ptr + layout.local_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.remote_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.password_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_u32(buffer_ptr + layout.assignment_type_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.user_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    self.read_pointer_value(buffer_ptr + layout.domain_name_offset)
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                )
            }
            _ => return Err(ERROR_INVALID_LEVEL),
        };

        let local_name = self
            .read_wide_string_from_memory(local_name_ptr)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let remote_name = self
            .read_wide_string_from_memory(remote_name_ptr)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let password = self
            .read_wide_string_from_memory(password_ptr)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let user_name = self
            .read_wide_string_from_memory(user_name_ptr)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;
        let domain_name = self
            .read_wide_string_from_memory(domain_name_ptr)
            .map_err(|_| ERROR_INVALID_PARAMETER)?;

        Ok(NetworkUseProfile {
            local_name: local_name.trim().to_string(),
            remote_name: remote_name.trim().to_string(),
            password,
            status: 0,
            assignment_type: if assignment_type == 0 {
                USE_DISKDEV
            } else {
                assignment_type
            },
            ref_count: 1,
            use_count: 1,
            user_name: if user_name.trim().is_empty() {
                self.environment_profile.machine.user_name.clone()
            } else {
                user_name.trim().to_string()
            },
            domain_name: if domain_name.trim().is_empty() {
                self.netapi_join_name()
            } else {
                domain_name.trim().to_string()
            },
            provider: NetworkUseProfile::default().provider,
            comment: String::new(),
        })
    }

    fn netapi_commit_network_use(&mut self, network_use: NetworkUseProfile) -> u64 {
        self.ensure_materialized_netapi_network_uses();
        let uses = &mut self.environment_profile.network_uses;
        if !network_use.local_name.trim().is_empty() {
            if let Some(existing) = uses.iter_mut().find(|current| {
                current
                    .local_name
                    .eq_ignore_ascii_case(&network_use.local_name)
            }) {
                if !existing
                    .remote_name
                    .eq_ignore_ascii_case(&network_use.remote_name)
                {
                    return ERROR_ALREADY_ASSIGNED;
                }
                existing.ref_count = existing.ref_count.saturating_add(1);
                existing.use_count = existing.use_count.saturating_add(1);
                if !network_use.password.is_empty() {
                    existing.password = network_use.password;
                }
                if !network_use.user_name.is_empty() {
                    existing.user_name = network_use.user_name;
                }
                if !network_use.domain_name.is_empty() {
                    existing.domain_name = network_use.domain_name;
                }
                existing.assignment_type = network_use.assignment_type;
                return ERROR_SUCCESS;
            }
        } else if let Some(existing) = uses.iter_mut().find(|current| {
            current.local_name.trim().is_empty()
                && current
                    .remote_name
                    .eq_ignore_ascii_case(&network_use.remote_name)
        }) {
            existing.ref_count = existing.ref_count.saturating_add(1);
            existing.use_count = existing.use_count.saturating_add(1);
            if !network_use.password.is_empty() {
                existing.password = network_use.password;
            }
            if !network_use.user_name.is_empty() {
                existing.user_name = network_use.user_name;
            }
            if !network_use.domain_name.is_empty() {
                existing.domain_name = network_use.domain_name;
            }
            existing.assignment_type = network_use.assignment_type;
            return ERROR_SUCCESS;
        }

        uses.push(network_use);
        ERROR_SUCCESS
    }

    fn netapi_use_del_by_name(&mut self, use_name: &str) -> u64 {
        self.ensure_materialized_netapi_network_uses();
        let requested = use_name.trim();
        let uses = &mut self.environment_profile.network_uses;
        let original_len = uses.len();
        uses.retain(|network_use| {
            !network_use.local_name.eq_ignore_ascii_case(requested)
                && !network_use.remote_name.eq_ignore_ascii_case(requested)
        });
        if uses.len() == original_len {
            ERROR_NOT_CONNECTED
        } else {
            ERROR_SUCCESS
        }
    }

    fn netapi_is_valid_drive_name(&self, local_name: &str) -> bool {
        let bytes = local_name.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    }

    fn netapi_is_plausible_remote_name(&self, remote_name: &str) -> bool {
        let normalized = remote_name.trim();
        if !normalized.starts_with(r"\\") {
            return false;
        }
        let mut segments = normalized[2..]
            .split(['\\', '/'])
            .filter(|segment| !segment.trim().is_empty());
        segments.next().is_some() && segments.next().is_some()
    }

    fn netapi_workstation_users(&self) -> Vec<WorkstationUserProfile> {
        if !self.environment_profile.workstation_users.is_empty() {
            return self.environment_profile.workstation_users.clone();
        }

        let user_name = self.environment_profile.machine.user_name.trim();
        if user_name.is_empty() {
            return Vec::new();
        }
        vec![WorkstationUserProfile {
            user_name: user_name.to_string(),
            logon_domain: if self.netapi_domain_joined() {
                self.netapi_join_name()
            } else {
                self.active_computer_name().to_string()
            },
            other_domains: if self.netapi_domain_joined() {
                "BUILTIN".to_string()
            } else {
                String::new()
            },
            logon_server: if self.netapi_domain_joined() {
                self.netapi_domain_controller_name()
            } else {
                format!(r"\\{}", self.active_computer_name())
            },
        }]
    }

    fn netapi_network_sessions(&self) -> Vec<NetworkSessionProfile> {
        if !self.environment_profile.network_sessions.is_empty() {
            return self.environment_profile.network_sessions.clone();
        }

        let derived = self.netapi_sessions_from_configured_open_files();
        if !derived.is_empty() {
            return derived;
        }

        self.netapi_default_network_sessions()
    }

    fn netapi_open_files(&self) -> Vec<OpenFileProfile> {
        if !self.environment_profile.open_files.is_empty() {
            return self.environment_profile.open_files.clone();
        }

        let sessions = self.netapi_network_sessions();
        if sessions.is_empty() {
            return Vec::new();
        }
        let share_paths = self
            .netapi_shares()
            .into_iter()
            .filter_map(|share| {
                let path = share.path.trim();
                if path.is_empty() {
                    None
                } else {
                    Some(path.to_string())
                }
            })
            .collect::<Vec<_>>();

        sessions
            .into_iter()
            .enumerate()
            .map(|(index, session)| {
                let path_name =
                    if let Some(base_path) = share_paths.get(index % share_paths.len().max(1)) {
                        let leaf = if index == 0 {
                            r"Temp\desktop.ini".to_string()
                        } else {
                            format!(r"Temp\session-{}.dat", index + 1)
                        };
                        format!(r"{}\{}", base_path.trim_end_matches('\\'), leaf)
                    } else if index % 2 == 0 {
                        r"\PIPE\srvsvc".to_string()
                    } else {
                        r"\PIPE\wkssvc".to_string()
                    };
                OpenFileProfile {
                    id: 0x400 + index as u32,
                    permissions: PERM_FILE_READ | PERM_FILE_WRITE,
                    num_locks: (index == 0) as u32,
                    path_name,
                    user_name: session.user_name,
                    client_name: session.client_name,
                }
            })
            .collect()
    }

    fn netapi_sessions_from_configured_open_files(&self) -> Vec<NetworkSessionProfile> {
        if self.environment_profile.open_files.is_empty() {
            return Vec::new();
        }

        let mut sessions =
            std::collections::BTreeMap::<(String, String), NetworkSessionProfile>::new();
        for file in &self.environment_profile.open_files {
            let client_name = file.client_name.trim();
            let user_name = file.user_name.trim();
            if client_name.is_empty() || user_name.is_empty() {
                continue;
            }
            sessions
                .entry((client_name.to_string(), user_name.to_string()))
                .or_insert_with(|| NetworkSessionProfile {
                    client_name: client_name.to_string(),
                    user_name: user_name.to_string(),
                    active_time_secs: 5400,
                    idle_time_secs: 120,
                });
        }
        sessions.into_values().collect()
    }

    fn netapi_default_network_sessions(&self) -> Vec<NetworkSessionProfile> {
        if !self.netapi_should_synthesize_network_session() {
            return Vec::new();
        }

        let user_name = self.netapi_default_session_user_name();
        if user_name.trim().is_empty() {
            return Vec::new();
        }

        vec![NetworkSessionProfile {
            client_name: self.netapi_default_remote_client_name(),
            user_name,
            active_time_secs: 5400,
            idle_time_secs: 120,
        }]
    }

    fn netapi_should_synthesize_network_session(&self) -> bool {
        self.netapi_domain_joined()
            || self
                .environment_profile
                .shares
                .iter()
                .any(|share| share.current_uses > 0)
    }

    fn netapi_default_session_user_name(&self) -> String {
        let user_name = self.active_user_name().trim();
        if user_name.is_empty() {
            return String::new();
        }

        let domain_name = if self.netapi_domain_joined() {
            self.netapi_join_name()
        } else {
            self.active_computer_name().to_string()
        };
        format!(r"{domain_name}\{user_name}")
    }

    fn netapi_default_remote_client_name(&self) -> String {
        let candidate = self
            .environment_profile
            .network
            .adapters
            .iter()
            .flat_map(|adapter| adapter.ipv4_addresses.iter())
            .filter_map(|address| address.address.parse::<Ipv4Addr>().ok())
            .next()
            .map(|address| {
                let mut octets = address.octets();
                octets[3] = if octets[3] <= 249 {
                    octets[3].saturating_add(5).max(2)
                } else {
                    octets[3].saturating_sub(5).max(2)
                };
                Ipv4Addr::from(octets).to_string()
            })
            .or_else(|| {
                self.environment_profile
                    .network
                    .dns_servers
                    .iter()
                    .find_map(|value| value.parse::<Ipv4Addr>().ok())
                    .map(|address| address.to_string())
            })
            .unwrap_or_else(|| "192.168.56.10".to_string());
        format!(r"\\{candidate}")
    }

    fn ensure_materialized_netapi_open_files(&mut self) {
        if !self.environment_profile.open_files.is_empty() {
            return;
        }
        let defaults = self.netapi_open_files();
        if !defaults.is_empty() {
            self.environment_profile.open_files = defaults;
        }
    }

    fn netapi_find_open_file(&self, file_id: u32) -> Option<OpenFileProfile> {
        self.netapi_open_files()
            .into_iter()
            .find(|file| file.id == file_id)
    }

    fn netapi_filter_open_files(&self, base_path: &str, user_name: &str) -> Vec<OpenFileProfile> {
        self.netapi_open_files()
            .into_iter()
            .filter(|file| self.netapi_matches_file_path(&file.path_name, base_path))
            .filter(|file| self.netapi_matches_file_user(&file.user_name, user_name))
            .collect()
    }

    fn netapi_matches_file_path(&self, file_path: &str, base_path: &str) -> bool {
        let requested = base_path.trim();
        if requested.is_empty() {
            return true;
        }
        if file_path.eq_ignore_ascii_case(requested) {
            return true;
        }
        let requested = requested.trim_end_matches(['\\', '/']);
        let candidate = file_path.trim_end_matches(['\\', '/']);
        candidate
            .to_ascii_lowercase()
            .starts_with(&requested.to_ascii_lowercase())
            && candidate
                .chars()
                .nth(requested.len())
                .map(|ch| matches!(ch, '\\' | '/'))
                .unwrap_or(candidate.len() == requested.len())
    }

    fn netapi_matches_file_user(&self, file_user: &str, requested_user: &str) -> bool {
        let requested = requested_user.trim();
        if requested.is_empty() {
            return true;
        }
        if file_user.eq_ignore_ascii_case(requested) {
            return true;
        }
        let requested_short = requested
            .rsplit_once('\\')
            .map(|(_, user)| user)
            .unwrap_or(requested);
        let file_short = file_user
            .rsplit_once('\\')
            .map(|(_, user)| user)
            .unwrap_or(file_user);
        file_short.eq_ignore_ascii_case(requested_short)
    }

    fn netapi_close_open_file(&mut self, file_id: u32) -> u64 {
        self.ensure_materialized_netapi_open_files();
        let files = &mut self.environment_profile.open_files;
        let original_len = files.len();
        files.retain(|file| file.id != file_id);
        if files.len() == original_len {
            NERR_FILE_ID_NOT_FOUND
        } else {
            ERROR_SUCCESS
        }
    }

    fn netapi_connection_inventory(
        &self,
        qualifier: &str,
    ) -> Result<Vec<ConnectionInventoryRecord>, u64> {
        let qualifier = qualifier.trim();
        if qualifier.is_empty() {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let qualifier_is_client = qualifier.starts_with(r"\\");
        if !qualifier_is_client && self.netapi_find_share(qualifier).is_none() {
            return Err(NERR_NET_NAME_NOT_FOUND);
        }

        let shares = self.netapi_shares();
        let sessions = self.netapi_network_sessions();
        let mut grouped =
            std::collections::BTreeMap::<(String, String, String), ConnectionInventoryRecord>::new(
            );

        for file in self.netapi_open_files() {
            let (share_name, share_type) =
                self.netapi_share_for_open_file(&file.path_name, &shares);
            let client_name = if !file.client_name.trim().is_empty() {
                file.client_name.trim().to_string()
            } else {
                sessions
                    .iter()
                    .find(|session| session.user_name.eq_ignore_ascii_case(&file.user_name))
                    .map(|session| session.client_name.clone())
                    .unwrap_or_default()
            };
            if qualifier_is_client {
                if !netapi_matches_unc_name(&client_name, qualifier) {
                    continue;
                }
            } else if !share_name.eq_ignore_ascii_case(qualifier) {
                continue;
            }

            let net_name = if qualifier_is_client {
                share_name.clone()
            } else {
                client_name.clone()
            };
            let time = sessions
                .iter()
                .find(|session| {
                    (!client_name.trim().is_empty()
                        && netapi_matches_unc_name(&session.client_name, &client_name))
                        || session.user_name.eq_ignore_ascii_case(&file.user_name)
                })
                .map(|session| session.active_time_secs)
                .unwrap_or(0);
            let key = (share_name, client_name, file.user_name.clone());
            let entry = grouped
                .entry(key)
                .or_insert_with(|| ConnectionInventoryRecord {
                    id: file.id,
                    connection_type: share_type,
                    num_opens: 0,
                    num_users: 1,
                    active_time_secs: time,
                    user_name: file.user_name.clone(),
                    net_name,
                });
            entry.num_opens = entry.num_opens.saturating_add(1);
            entry.active_time_secs = entry.active_time_secs.max(time);
        }

        if grouped.is_empty() {
            let default_share = if qualifier_is_client {
                if let Some(share) = shares
                    .iter()
                    .find(|share| share.name.eq_ignore_ascii_case("IPC$"))
                {
                    Some((share.name.clone(), share.share_type))
                } else {
                    shares
                        .iter()
                        .find(|share| !share.name.trim().is_empty())
                        .map(|share| (share.name.clone(), share.share_type))
                }
            } else {
                self.netapi_find_share(qualifier)
                    .map(|share| (share.name, share.share_type))
            };

            if let Some((share_name, share_type)) = default_share {
                for (index, session) in sessions.iter().enumerate() {
                    if qualifier_is_client
                        && !netapi_matches_unc_name(&session.client_name, qualifier)
                    {
                        continue;
                    }
                    grouped.insert(
                        (
                            share_name.clone(),
                            session.client_name.clone(),
                            session.user_name.clone(),
                        ),
                        ConnectionInventoryRecord {
                            id: 0x500 + index as u32,
                            connection_type: share_type,
                            num_opens: 0,
                            num_users: 1,
                            active_time_secs: session.active_time_secs,
                            user_name: session.user_name.clone(),
                            net_name: if qualifier_is_client {
                                share_name.clone()
                            } else {
                                session.client_name.clone()
                            },
                        },
                    );
                }
            }
        }

        Ok(grouped.into_values().collect())
    }

    fn netapi_share_for_open_file(
        &self,
        path_name: &str,
        shares: &[ShareProfile],
    ) -> (String, u32) {
        if path_name.trim().starts_with(r"\PIPE\") {
            return ("IPC$".to_string(), STYPE_IPC);
        }
        for share in shares {
            let base_path = share.path.trim();
            if base_path.is_empty() {
                continue;
            }
            if self.netapi_matches_file_path(path_name, base_path) {
                return (share.name.clone(), share.share_type);
            }
        }
        shares
            .iter()
            .find(|share| !share.name.trim().is_empty())
            .map(|share| (share.name.clone(), share.share_type))
            .unwrap_or_else(|| ("IPC$".to_string(), STYPE_IPC))
    }

    fn netapi_share_type_for_device(&self, device: &str) -> Option<u32> {
        let requested = device.trim().trim_end_matches(['\\', '/']);
        if requested.is_empty() {
            return None;
        }
        self.netapi_shares().into_iter().find_map(|share| {
            if share.name.eq_ignore_ascii_case(requested) {
                return Some(share.share_type);
            }
            if share.path.trim().is_empty() {
                return None;
            }
            let share_path = share.path.trim().trim_end_matches(['\\', '/']);
            if share_path.eq_ignore_ascii_case(requested) {
                return Some(share.share_type);
            }
            if share.name.ends_with('$') {
                let drive_root = share_path.chars().take(2).collect::<String>();
                if !drive_root.is_empty() && drive_root.eq_ignore_ascii_case(requested) {
                    return Some(share.share_type);
                }
            }
            None
        })
    }

    fn netapi_local_server_inventory_record(&self) -> ServerInventoryRecord {
        let mut server_type = SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_SERVER_NT;
        if self.netapi_domain_joined() {
            server_type |= SV_TYPE_DOMAIN_MEMBER;
        }
        ServerInventoryRecord {
            name: self.active_computer_name().to_string(),
            comment: self.environment_profile.os_version.product_name.clone(),
            server_type,
        }
    }

    fn netapi_browser_scope_name(&self) -> String {
        self.netapi_join_name()
    }

    fn netapi_server_inventory(&self) -> Vec<ServerInventoryRecord> {
        let mut servers = vec![self.netapi_local_server_inventory_record()];
        if self.netapi_domain_joined() {
            let dc_name = self.netapi_domain_controller_host_name();
            if !dc_name.is_empty() && !dc_name.eq_ignore_ascii_case(self.active_computer_name()) {
                servers.push(ServerInventoryRecord {
                    name: dc_name,
                    comment: format!("{} Domain Controller", self.netapi_join_name()),
                    server_type: SV_TYPE_DOMAIN_CTRL
                        | SV_TYPE_DOMAIN_MEMBER
                        | SV_TYPE_SERVER
                        | SV_TYPE_SERVER_NT,
                });
            }
        }
        servers
    }

    fn netapi_should_emit_domain_enum_entry(
        &self,
        server_type: u32,
        scope: ServerEnumScope,
    ) -> bool {
        scope == ServerEnumScope::Browser
            && server_type != 0
            && server_type != SV_TYPE_ALL
            && (server_type & SV_TYPE_DOMAIN_ENUM) != 0
    }

    fn netapi_server_inventory_for_enum(
        &self,
        requested_scope: &str,
        server_type: u32,
    ) -> Result<Vec<ServerInventoryRecord>, u64> {
        let scope = self.netapi_resolve_server_enum_scope(requested_scope)?;
        let mut servers = if scope == ServerEnumScope::LocalComputer {
            vec![self.netapi_local_server_inventory_record()]
        } else {
            self.netapi_server_inventory()
        };

        if self.netapi_should_emit_domain_enum_entry(server_type, scope) {
            servers.insert(
                0,
                ServerInventoryRecord {
                    name: self.netapi_browser_scope_name(),
                    comment: String::new(),
                    server_type: SV_TYPE_DOMAIN_ENUM,
                },
            );
        }

        if server_type != 0 && server_type != SV_TYPE_ALL {
            servers.retain(|entry| (entry.server_type & server_type) != 0);
        }
        Ok(servers)
    }

    fn netapi_lookup_account_name_record(&self, account_name: &str) -> Option<AccountLookupRecord> {
        let trimmed = account_name.trim();
        if trimmed.is_empty() {
            return None;
        }

        let (requested_domain, requested_name) = split_account_name(trimmed);
        if let Some(user) = self.netapi_find_user(requested_name) {
            let local_domain = self.active_computer_name().to_string();
            let joined_domain = self.netapi_join_name();
            let is_domain_account = self.netapi_domain_joined()
                && requested_domain
                    .map(|domain| {
                        domain.eq_ignore_ascii_case(&joined_domain)
                            || domain.eq_ignore_ascii_case(&self.netapi_dns_domain_name())
                    })
                    .unwrap_or(false);
            let domain = if is_domain_account {
                joined_domain.clone()
            } else {
                local_domain.clone()
            };
            let sid = if is_domain_account {
                domain_sid_bytes(
                    &self.netapi_dns_domain_name(),
                    &self.environment_profile.machine.domain_guid,
                    user.rid,
                )
            } else {
                local_account_sid_bytes(&self.environment_profile.machine.machine_guid, user.rid)
            };
            return Some(AccountLookupRecord::User {
                profile: user,
                domain,
                sid,
            });
        }

        let Some(group) = self
            .netapi_find_local_group(requested_name)
            .or_else(|| self.netapi_find_domain_group(requested_name))
        else {
            return None;
        };
        let group_domain = self.netapi_group_domain(&group);
        if let Some(requested_domain) = requested_domain {
            if !requested_domain.eq_ignore_ascii_case(&group_domain)
                && !(requested_domain.eq_ignore_ascii_case(self.active_computer_name())
                    && !group_domain.eq_ignore_ascii_case("BUILTIN"))
            {
                return None;
            }
        }
        let sid = self.netapi_group_sid(&group);
        Some(AccountLookupRecord::Group {
            profile: group,
            domain: group_domain,
            sid,
        })
    }

    fn netapi_lookup_account_sid_record(&self, sid: &[u8]) -> Option<AccountLookupRecord> {
        for user in self.netapi_users() {
            let local_sid =
                local_account_sid_bytes(&self.environment_profile.machine.machine_guid, user.rid);
            if sid == local_sid {
                return Some(AccountLookupRecord::User {
                    profile: user.clone(),
                    domain: self.active_computer_name().to_string(),
                    sid: local_sid,
                });
            }
            if self.netapi_domain_joined() {
                let domain_sid = domain_sid_bytes(
                    &self.netapi_dns_domain_name(),
                    &self.environment_profile.machine.domain_guid,
                    user.rid,
                );
                if sid == domain_sid {
                    return Some(AccountLookupRecord::User {
                        profile: user.clone(),
                        domain: self.netapi_join_name(),
                        sid: domain_sid,
                    });
                }
            }
        }
        for group in self.netapi_local_groups() {
            let domain = self.netapi_group_domain(group);
            let group_sid = self.netapi_group_sid(group);
            if sid == group_sid {
                return Some(AccountLookupRecord::Group {
                    profile: group.clone(),
                    domain,
                    sid: group_sid,
                });
            }
        }
        for group in self.netapi_domain_groups() {
            let domain = self.netapi_group_domain(&group);
            let group_sid = self.netapi_group_sid(&group);
            if sid == group_sid {
                return Some(AccountLookupRecord::Group {
                    profile: group,
                    domain,
                    sid: group_sid,
                });
            }
        }
        None
    }

    pub(super) fn net_api_buffer_free(&mut self, address: u64) -> u64 {
        if address != 0 {
            let _ = self.heaps.free(self.heaps.process_heap(), address);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        0
    }

    pub(in crate::runtime::engine) fn lookup_account_name(
        &mut self,
        wide: bool,
        _system_name: &str,
        account_name: &str,
        sid_ptr: u64,
        sid_len_ptr: u64,
        domain_ptr: u64,
        domain_len_ptr: u64,
        sid_use_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(record) = self.netapi_lookup_account_name_record(account_name) else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let (_name, domain, sid, sid_use) = match &record {
            AccountLookupRecord::User {
                profile,
                domain,
                sid,
            } => (profile.name.as_str(), domain.as_str(), sid.as_slice(), 1u32),
            AccountLookupRecord::Group {
                profile,
                domain,
                sid,
            } => (profile.name.as_str(), domain.as_str(), sid.as_slice(), 4u32),
        };
        let required_domain = encoded_text_len(wide, domain);
        let sid_capacity = if sid_len_ptr != 0 {
            self.read_u32(sid_len_ptr)? as usize
        } else {
            0
        };
        let domain_capacity = if domain_len_ptr != 0 {
            self.read_u32(domain_len_ptr)? as usize
        } else {
            0
        };
        if sid_len_ptr != 0 {
            self.write_u32(sid_len_ptr, sid.len() as u32)?;
        }
        if domain_len_ptr != 0 {
            self.write_u32(domain_len_ptr, required_domain as u32)?;
        }
        if sid_ptr == 0
            || domain_ptr == 0
            || sid_capacity < sid.len()
            || domain_capacity < required_domain
        {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        self.modules.memory_mut().write(sid_ptr, sid)?;
        write_text(self, wide, domain_ptr, domain_capacity, domain)?;
        if sid_use_ptr != 0 {
            self.write_u32(sid_use_ptr, sid_use)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn lookup_account_sid(
        &mut self,
        wide: bool,
        _system_name: &str,
        sid_ptr: u64,
        name_ptr: u64,
        name_len_ptr: u64,
        domain_ptr: u64,
        domain_len_ptr: u64,
        sid_use_ptr: u64,
    ) -> Result<u64, VmError> {
        let sid = self.read_account_sid_bytes(sid_ptr)?;
        let Some(record) = self.netapi_lookup_account_sid_record(&sid) else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let (name, domain, sid_use) = match &record {
            AccountLookupRecord::User {
                profile, domain, ..
            } => (profile.name.as_str(), domain.as_str(), 1u32),
            AccountLookupRecord::Group {
                profile, domain, ..
            } => (profile.name.as_str(), domain.as_str(), 4u32),
        };
        let required_name = encoded_text_len(wide, name);
        let required_domain = encoded_text_len(wide, domain);
        let name_capacity = if name_len_ptr != 0 {
            self.read_u32(name_len_ptr)? as usize
        } else {
            0
        };
        let domain_capacity = if domain_len_ptr != 0 {
            self.read_u32(domain_len_ptr)? as usize
        } else {
            0
        };
        if name_len_ptr != 0 {
            self.write_u32(name_len_ptr, required_name as u32)?;
        }
        if domain_len_ptr != 0 {
            self.write_u32(domain_len_ptr, required_domain as u32)?;
        }
        if name_ptr == 0
            || domain_ptr == 0
            || name_capacity < required_name
            || domain_capacity < required_domain
        {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        write_text(self, wide, name_ptr, name_capacity, name)?;
        write_text(self, wide, domain_ptr, domain_capacity, domain)?;
        if sid_use_ptr != 0 {
            self.write_u32(sid_use_ptr, sid_use)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(super) fn net_get_join_information(
        &mut self,
        _server_name: &str,
        name_buffer_ptr: u64,
        status_ptr: u64,
    ) -> Result<u64, VmError> {
        if name_buffer_ptr == 0 || status_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let join_name = self.netapi_join_name();
        let required = wide_storage_size(&join_name);
        let allocation =
            self.alloc_process_heap_block(required, "netapi32:NetGetJoinInformation")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_wide_string_to_memory(
            allocation,
            join_name.encode_utf16().count() + 1,
            &join_name,
        )?;
        self.write_pointer_value(name_buffer_ptr, allocation)?;
        self.write_u32(status_ptr, self.netapi_join_status())?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_get_dc_name(
        &mut self,
        _server_name: &str,
        domain_name: &str,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !self.netapi_domain_joined() || !self.netapi_matches_requested_domain(domain_name) {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }

        let controller = self.netapi_domain_controller_name();
        let required = wide_storage_size(&controller);
        let allocation = self.alloc_process_heap_block(required, "netapi32:NetGetDCName")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_wide_string_to_memory(
            allocation,
            controller.encode_utf16().count() + 1,
            &controller,
        )?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_wksta_get_info(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(layout) = self.wksta_info_layout(level) else {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        };

        let computer_name = self.active_computer_name().to_string();
        let langroup = self.netapi_join_name();
        let lanroot = self.windows_directory_path();
        let mut required = align_up(layout.size, self.arch.pointer_size as u64);
        required += wide_storage_size(&computer_name);
        required += wide_storage_size(&langroup);
        if layout.lanroot_offset.is_some() {
            required += wide_storage_size(&lanroot);
        }

        let allocation = self.alloc_process_heap_block(required, "netapi32:NetWkstaGetInfo")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, PLATFORM_ID_NT)?;
        let mut cursor = align_up(allocation + layout.size, self.arch.pointer_size as u64);
        let computer_name_ptr = write_inline_wide_string(self, &mut cursor, &computer_name)?;
        let langroup_ptr = write_inline_wide_string(self, &mut cursor, &langroup)?;
        self.write_pointer_value(allocation + layout.computer_name_offset, computer_name_ptr)?;
        self.write_pointer_value(allocation + layout.langroup_offset, langroup_ptr)?;
        self.write_u32(
            allocation + layout.ver_major_offset,
            self.environment_profile.os_version.major,
        )?;
        self.write_u32(
            allocation + layout.ver_minor_offset,
            self.environment_profile.os_version.minor,
        )?;
        if let Some(offset) = layout.lanroot_offset {
            let lanroot_ptr = write_inline_wide_string(self, &mut cursor, &lanroot)?;
            self.write_pointer_value(allocation + offset, lanroot_ptr)?;
        }
        if let Some(offset) = layout.logged_on_users_offset {
            self.write_u32(allocation + offset, 1)?;
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_user_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        _filter: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != USER_INFO_LEVEL_0 && level != USER_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let users = self.netapi_users().to_vec();
        let required = self.net_user_enum_required_size(level, &users);
        self.write_u32(total_entries_ptr, users.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation = self.alloc_process_heap_block(required.max(1), "netapi32:NetUserEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        match level {
            USER_INFO_LEVEL_0 => self.write_user_info_0_entries(allocation, &users)?,
            USER_INFO_LEVEL_1 => self.write_user_info_1_entries(allocation, &users)?,
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, users.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_user_get_info(
        &mut self,
        _server_name: &str,
        user_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(user) = self.netapi_find_user(user_name) else {
            self.set_last_error(NERR_USER_NOT_FOUND as u32);
            return Ok(NERR_USER_NOT_FOUND);
        };

        let required = match level {
            USER_INFO_LEVEL_0 => {
                align_up(self.arch.pointer_size as u64, self.arch.pointer_size as u64)
                    + wide_storage_size(&user.name)
            }
            USER_INFO_LEVEL_1 => {
                let layout = self.user_info_1_layout();
                let mut required = align_up(layout.size, self.arch.pointer_size as u64);
                required += optional_wide_storage_size(&user.name);
                required += optional_wide_storage_size(&user.home_dir);
                required += optional_wide_storage_size(&user.comment);
                required += optional_wide_storage_size(&user.script_path);
                required
            }
            USER_INFO_LEVEL_23 => {
                let layout = self.user_info_23_layout();
                let mut required = align_up(layout.size, self.arch.pointer_size as u64);
                required += optional_wide_storage_size(&user.name);
                required += optional_wide_storage_size(&user.full_name);
                required += optional_wide_storage_size(&user.comment);
                required += user_sid_bytes(&self.environment_profile.machine.machine_guid, user.rid)
                    .len() as u64;
                required
            }
            _ => {
                self.set_last_error(ERROR_INVALID_LEVEL as u32);
                return Ok(ERROR_INVALID_LEVEL);
            }
        };

        let allocation = self.alloc_process_heap_block(required, "netapi32:NetUserGetInfo")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        match level {
            USER_INFO_LEVEL_0 => self.write_user_info_0_entries(allocation, &[user.clone()])?,
            USER_INFO_LEVEL_1 => self.write_single_user_info_1(allocation, &user)?,
            USER_INFO_LEVEL_23 => self.write_single_user_info_23(allocation, &user)?,
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_group_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != GROUP_INFO_LEVEL_0 && level != GROUP_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        if !self.netapi_domain_joined() {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }

        let groups = self.netapi_domain_groups();
        let required = self.net_local_group_required_size(level, &groups);
        self.write_u32(total_entries_ptr, groups.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation = self.alloc_process_heap_block(required.max(1), "netapi32:NetGroupEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        match level {
            GROUP_INFO_LEVEL_0 => self.write_local_group_info_0_entries(allocation, &groups)?,
            GROUP_INFO_LEVEL_1 => self.write_local_group_info_1_entries(allocation, &groups)?,
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, groups.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_group_get_info(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != GROUP_INFO_LEVEL_0 && level != GROUP_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        if !self.netapi_domain_joined() {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }
        let Some(group) = self.netapi_find_domain_group(group_name) else {
            self.set_last_error(NERR_GROUP_NOT_FOUND as u32);
            return Ok(NERR_GROUP_NOT_FOUND);
        };
        let groups = [group];
        let required = self.net_local_group_required_size(level, &groups);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetGroupGetInfo")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        match level {
            GROUP_INFO_LEVEL_0 => self.write_local_group_info_0_entries(allocation, &groups)?,
            GROUP_INFO_LEVEL_1 => self.write_local_group_info_1_entries(allocation, &groups)?,
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_user_get_groups(
        &mut self,
        _server_name: &str,
        user_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != GROUP_USERS_INFO_LEVEL_0 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        if !self.netapi_domain_joined() {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }
        if self.netapi_find_user(user_name).is_none() {
            self.set_last_error(NERR_USER_NOT_FOUND as u32);
            return Ok(NERR_USER_NOT_FOUND);
        }

        let group_names = self
            .netapi_domain_groups()
            .into_iter()
            .filter(|group| {
                group
                    .members
                    .iter()
                    .any(|member| member.eq_ignore_ascii_case(user_name))
            })
            .map(|group| group.name)
            .collect::<Vec<_>>();
        let required = self.name_pointer_list_required_size(&group_names);
        self.write_u32(total_entries_ptr, group_names.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetUserGetGroups")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_name_pointer_entries(allocation, &group_names)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, group_names.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_group_get_users(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != GROUP_USERS_INFO_LEVEL_0 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        if !self.netapi_domain_joined() {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }
        let Some(group) = self.netapi_find_domain_group(group_name) else {
            self.set_last_error(NERR_GROUP_NOT_FOUND as u32);
            return Ok(NERR_GROUP_NOT_FOUND);
        };

        let members = group.members;
        let required = self.name_pointer_list_required_size(&members);
        self.write_u32(total_entries_ptr, members.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetGroupGetUsers")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_name_pointer_entries(allocation, &members)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, members.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_use_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            level,
            USE_INFO_LEVEL_0 | USE_INFO_LEVEL_1 | USE_INFO_LEVEL_2
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let uses = self.netapi_network_uses();
        let required = self.net_use_required_size(level, &uses);
        self.write_u32(total_entries_ptr, uses.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if uses.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation = self.alloc_process_heap_block(required.max(1), "netapi32:NetUseEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_use_entries(level, allocation, &uses)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, uses.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_use_add(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        parm_error_ptr: u64,
    ) -> Result<u64, VmError> {
        if parm_error_ptr != 0 {
            self.write_u32(parm_error_ptr, 0)?;
        }
        if !matches!(level, USE_INFO_LEVEL_1 | USE_INFO_LEVEL_2) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let network_use = match self.netapi_parse_use_add_input(level, buffer_ptr) {
            Ok(network_use) => network_use,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        if !network_use.local_name.trim().is_empty()
            && !self.netapi_is_valid_drive_name(&network_use.local_name)
        {
            if parm_error_ptr != 0 {
                self.write_u32(parm_error_ptr, 1)?;
            }
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !self.netapi_is_plausible_remote_name(&network_use.remote_name) {
            if parm_error_ptr != 0 {
                self.write_u32(parm_error_ptr, 2)?;
            }
            self.set_last_error(NERR_NET_NAME_NOT_FOUND as u32);
            return Ok(NERR_NET_NAME_NOT_FOUND);
        }

        let status = self.netapi_use_add_conflict_status(&network_use);
        if status != ERROR_SUCCESS {
            self.set_last_error(status as u32);
            return Ok(status);
        }

        let status = self.netapi_commit_network_use(network_use);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn net_use_del(
        &mut self,
        _server_name: &str,
        use_name: &str,
        _force_cond: u32,
    ) -> Result<u64, VmError> {
        let status = self.netapi_use_del_by_name(use_name);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn net_use_get_info(
        &mut self,
        _server_name: &str,
        use_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            level,
            USE_INFO_LEVEL_0 | USE_INFO_LEVEL_1 | USE_INFO_LEVEL_2
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let Some(network_use) = self.netapi_find_network_use(use_name) else {
            self.set_last_error(ERROR_NOT_CONNECTED as u32);
            return Ok(ERROR_NOT_CONNECTED);
        };

        let uses = [network_use];
        let required = self.net_use_required_size(level, &uses);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetUseGetInfo")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_use_entries(level, allocation, &uses)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_share_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            level,
            SHARE_INFO_LEVEL_0 | SHARE_INFO_LEVEL_1 | SHARE_INFO_LEVEL_2
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let shares = self.netapi_shares();
        let required = self.net_share_required_size(level, &shares);
        self.write_u32(total_entries_ptr, shares.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        if shares.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation = self.alloc_process_heap_block(required.max(1), "netapi32:NetShareEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_share_entries(level, allocation, &shares)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, shares.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_share_get_info(
        &mut self,
        _server_name: &str,
        share_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            level,
            SHARE_INFO_LEVEL_0 | SHARE_INFO_LEVEL_1 | SHARE_INFO_LEVEL_2
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let Some(share) = self.netapi_find_share(share_name) else {
            self.set_last_error(NERR_NET_NAME_NOT_FOUND as u32);
            return Ok(NERR_NET_NAME_NOT_FOUND);
        };
        let shares = [share];
        let required = self.net_share_required_size(level, &shares);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetShareGetInfo")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_share_entries(level, allocation, &shares)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_file_enum(
        &mut self,
        _server_name: &str,
        base_path: &str,
        user_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(level, FILE_INFO_LEVEL_2 | FILE_INFO_LEVEL_3) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let files = self.netapi_filter_open_files(base_path, user_name);
        let required = self.net_file_required_size(level, &files);
        self.write_u32(total_entries_ptr, files.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if files.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation = self.alloc_process_heap_block(required.max(1), "netapi32:NetFileEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_file_entries(level, allocation, &files)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, files.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_file_get_info(
        &mut self,
        _server_name: &str,
        file_id: u32,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(level, FILE_INFO_LEVEL_2 | FILE_INFO_LEVEL_3) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let Some(file) = self.netapi_find_open_file(file_id) else {
            self.set_last_error(NERR_FILE_ID_NOT_FOUND as u32);
            return Ok(NERR_FILE_ID_NOT_FOUND);
        };

        let files = [file];
        let required = self.net_file_required_size(level, &files);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetFileGetInfo")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_file_entries(level, allocation, &files)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_file_close(
        &mut self,
        _server_name: &str,
        file_id: u32,
    ) -> Result<u64, VmError> {
        let status = self.netapi_close_open_file(file_id);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub(super) fn net_connection_enum(
        &mut self,
        _server_name: &str,
        qualifier: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(level, CONNECTION_INFO_LEVEL_0 | CONNECTION_INFO_LEVEL_1) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let connections = match self.netapi_connection_inventory(qualifier) {
            Ok(connections) => connections,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let required = self.net_connection_required_size(level, &connections);
        self.write_u32(total_entries_ptr, connections.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if connections.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetConnectionEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_connection_entries(level, allocation, &connections)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, connections.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_share_check(
        &mut self,
        _server_name: &str,
        device_name: &str,
        share_type_ptr: u64,
    ) -> Result<u64, VmError> {
        if share_type_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(share_type) = self.netapi_share_type_for_device(device_name) else {
            self.set_last_error(NERR_DEVICE_NOT_SHARED as u32);
            return Ok(NERR_DEVICE_NOT_SHARED);
        };
        self.write_u32(share_type_ptr, share_type)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_remote_tod(
        &mut self,
        _server_name: &str,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let layout = self.time_of_day_info_layout();
        let allocation = self.alloc_process_heap_block(layout.size, "netapi32:NetRemoteTOD")?;
        self.fill_memory_pattern(allocation, layout.size, 0)?;
        self.write_time_of_day_info(allocation)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_session_enum(
        &mut self,
        _server_name: &str,
        client_name: &str,
        user_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != SESSION_INFO_LEVEL_10 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let sessions = self
            .netapi_network_sessions()
            .into_iter()
            .filter(|session| netapi_matches_unc_name(&session.client_name, client_name))
            .filter(|session| {
                user_name.trim().is_empty() || session.user_name.eq_ignore_ascii_case(user_name)
            })
            .collect::<Vec<_>>();
        let required = self.net_session_required_size(&sessions);
        self.write_u32(total_entries_ptr, sessions.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if sessions.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetSessionEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_session_entries(allocation, &sessions)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, sessions.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_wksta_user_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != WKSTA_USER_INFO_LEVEL_0 && level != WKSTA_USER_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let users = self.netapi_workstation_users();
        let required = self.net_wksta_user_required_size(level, &users);
        self.write_u32(total_entries_ptr, users.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if users.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetWkstaUserEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_wksta_user_entries(level, allocation, &users)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, users.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_local_group_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != LOCALGROUP_INFO_LEVEL_0 && level != LOCALGROUP_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let groups = self.netapi_local_groups().to_vec();
        let required = self.net_local_group_required_size(level, &groups);
        self.write_u32(total_entries_ptr, groups.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetLocalGroupEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        match level {
            LOCALGROUP_INFO_LEVEL_0 => {
                self.write_local_group_info_0_entries(allocation, &groups)?
            }
            LOCALGROUP_INFO_LEVEL_1 => {
                self.write_local_group_info_1_entries(allocation, &groups)?
            }
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, groups.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_user_get_local_groups(
        &mut self,
        _server_name: &str,
        user_name: &str,
        level: u32,
        _flags: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != LOCALGROUP_USERS_INFO_LEVEL_0 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        if self.netapi_find_user(user_name).is_none() {
            self.set_last_error(NERR_USER_NOT_FOUND as u32);
            return Ok(NERR_USER_NOT_FOUND);
        }

        let groups = self
            .netapi_local_groups()
            .iter()
            .filter(|group| {
                group
                    .members
                    .iter()
                    .any(|member| member.eq_ignore_ascii_case(user_name))
            })
            .cloned()
            .collect::<Vec<_>>();
        let required = self.net_local_group_required_size(LOCALGROUP_USERS_INFO_LEVEL_0, &groups);
        self.write_u32(total_entries_ptr, groups.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetUserGetLocalGroups")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_local_group_info_0_entries(allocation, &groups)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, groups.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_local_group_get_members(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !matches!(
            level,
            LOCALGROUP_MEMBERS_INFO_LEVEL_0
                | LOCALGROUP_MEMBERS_INFO_LEVEL_1
                | LOCALGROUP_MEMBERS_INFO_LEVEL_2
                | LOCALGROUP_MEMBERS_INFO_LEVEL_3
        ) {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let Some(group) = self.netapi_find_local_group(group_name) else {
            self.set_last_error(NERR_GROUP_NOT_FOUND as u32);
            return Ok(NERR_GROUP_NOT_FOUND);
        };
        let members = group
            .members
            .iter()
            .filter_map(|member| self.netapi_lookup_account_name_record(member))
            .collect::<Vec<_>>();
        let required = self.net_local_group_members_required_size(level, &members);
        self.write_u32(total_entries_ptr, members.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetLocalGroupGetMembers")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_local_group_member_entries(level, allocation, &members)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, members.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_local_group_get_info(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != LOCALGROUP_INFO_LEVEL_0 && level != LOCALGROUP_INFO_LEVEL_1 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let Some(group) = self.netapi_find_local_group(group_name) else {
            self.set_last_error(NERR_GROUP_NOT_FOUND as u32);
            return Ok(NERR_GROUP_NOT_FOUND);
        };
        let groups = [group];
        let required = self.net_local_group_required_size(level, &groups);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetLocalGroupGetInfo")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        match level {
            LOCALGROUP_INFO_LEVEL_0 => {
                self.write_local_group_info_0_entries(allocation, &groups)?
            }
            LOCALGROUP_INFO_LEVEL_1 => {
                self.write_local_group_info_1_entries(allocation, &groups)?
            }
            _ => unreachable!(),
        }
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn ds_get_dc_name(
        &mut self,
        wide: bool,
        _computer_name: &str,
        domain_name: &str,
        domain_guid_ptr: u64,
        site_name: &str,
        _flags: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let requested_guid_matches = if domain_guid_ptr == 0 {
            true
        } else {
            self.read_bytes_from_memory(domain_guid_ptr, 16)? == self.netapi_domain_guid_bytes()
        };
        if !self.netapi_domain_joined()
            || !self.netapi_matches_requested_domain(domain_name)
            || !requested_guid_matches
        {
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }

        let prefer_dns = domain_name.contains('.');
        let controller_name = if prefer_dns {
            format!(r"\\{}", self.netapi_domain_controller_dns_name())
        } else {
            self.netapi_domain_controller_name()
        };
        let domain_name_text = if prefer_dns {
            self.netapi_dns_domain_name()
        } else {
            self.netapi_join_name()
        };
        let forest_name = self.netapi_forest_name();
        let controller_address = self.netapi_domain_controller_address();
        let site_name_text = if site_name.trim().is_empty() {
            self.netapi_client_site_name()
        } else {
            site_name.trim().to_string()
        };
        let client_site_name = self.netapi_client_site_name();
        let layout = self.domain_controller_info_layout();
        let required = layout.size
            + inline_text_storage_size(wide, &controller_name)
            + inline_text_storage_size(wide, &controller_address)
            + inline_text_storage_size(wide, &domain_name_text)
            + inline_text_storage_size(wide, &forest_name)
            + inline_text_storage_size(wide, &site_name_text)
            + inline_text_storage_size(wide, &client_site_name);
        let allocation = self.alloc_process_heap_block(required, "netapi32:DsGetDcName")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        let mut cursor = align_up(allocation + layout.size, if wide { 2 } else { 1 });
        let controller_name_ptr =
            write_inline_text_string(self, wide, &mut cursor, &controller_name)?;
        let controller_address_ptr =
            write_inline_text_string(self, wide, &mut cursor, &controller_address)?;
        let domain_name_ptr = write_inline_text_string(self, wide, &mut cursor, &domain_name_text)?;
        let forest_name_ptr = write_inline_text_string(self, wide, &mut cursor, &forest_name)?;
        let dc_site_name_ptr = write_inline_text_string(self, wide, &mut cursor, &site_name_text)?;
        let client_site_name_ptr =
            write_inline_text_string(self, wide, &mut cursor, &client_site_name)?;
        let domain_guid = self.netapi_domain_guid_bytes();
        self.write_pointer_value(allocation + layout.name_offset, controller_name_ptr)?;
        self.write_pointer_value(allocation + layout.address_offset, controller_address_ptr)?;
        self.write_u32(
            allocation + layout.address_type_offset,
            DOMAIN_CONTROLLER_ADDRESS_TYPE_INET,
        )?;
        self.modules
            .memory_mut()
            .write(allocation + layout.domain_guid_offset, &domain_guid)?;
        self.write_pointer_value(allocation + layout.domain_name_offset, domain_name_ptr)?;
        self.write_pointer_value(allocation + layout.forest_name_offset, forest_name_ptr)?;
        self.write_u32(allocation + layout.flags_offset, DOMAIN_CONTROLLER_FLAGS)?;
        self.write_pointer_value(allocation + layout.dc_site_name_offset, dc_site_name_ptr)?;
        self.write_pointer_value(
            allocation + layout.client_site_name_offset,
            client_site_name_ptr,
        )?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn ds_enumerate_domain_trusts(
        &mut self,
        wide: bool,
        _server_name: &str,
        flags: u32,
        domains_ptr: u64,
        domain_count_ptr: u64,
    ) -> Result<u64, VmError> {
        if domains_ptr == 0 || domain_count_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if !self.netapi_domain_joined() {
            self.write_pointer_value(domains_ptr, 0)?;
            self.write_u32(domain_count_ptr, 0)?;
            self.set_last_error(ERROR_NO_SUCH_DOMAIN as u32);
            return Ok(ERROR_NO_SUCH_DOMAIN);
        }

        let trust = DomainTrustRecord {
            netbios_name: self.netapi_join_name(),
            dns_name: self.netapi_dns_domain_name(),
            flags: DOMAIN_TRUST_FLAGS_IN_FOREST
                | DOMAIN_TRUST_FLAGS_DIRECT_OUTBOUND
                | DOMAIN_TRUST_FLAGS_TREE_ROOT
                | DOMAIN_TRUST_FLAGS_PRIMARY
                | DOMAIN_TRUST_FLAGS_NATIVE_MODE
                | DOMAIN_TRUST_FLAGS_DIRECT_INBOUND,
            parent_index: u32::MAX,
            trust_type: DOMAIN_TRUST_TYPE_UPLEVEL,
            trust_attributes: 0,
            sid: self.netapi_domain_sid_bytes(),
            guid: self.netapi_domain_guid_bytes(),
        };
        let trusts = if flags == 0 || (trust.flags & flags) != 0 {
            vec![trust]
        } else {
            Vec::new()
        };
        self.write_u32(domain_count_ptr, trusts.len() as u32)?;
        if trusts.is_empty() {
            self.write_pointer_value(domains_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let layout = self.domain_trust_info_layout();
        let required = self.domain_trusts_required_size(wide, &trusts);
        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:DsEnumerateDomainTrusts")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        let mut cursor = align_up(
            allocation + trusts.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, trust) in trusts.iter().enumerate() {
            let entry = allocation + index as u64 * layout.size;
            let netbios_name_ptr =
                write_inline_text_string(self, wide, &mut cursor, &trust.netbios_name)?;
            let dns_name_ptr = write_inline_text_string(self, wide, &mut cursor, &trust.dns_name)?;
            let sid_ptr = cursor;
            self.modules.memory_mut().write(sid_ptr, &trust.sid)?;
            cursor += trust.sid.len() as u64;
            self.write_pointer_value(entry + layout.netbios_name_offset, netbios_name_ptr)?;
            self.write_pointer_value(entry + layout.dns_name_offset, dns_name_ptr)?;
            self.write_u32(entry + layout.flags_offset, trust.flags)?;
            self.write_u32(entry + layout.parent_index_offset, trust.parent_index)?;
            self.write_u32(entry + layout.trust_type_offset, trust.trust_type)?;
            self.write_u32(
                entry + layout.trust_attributes_offset,
                trust.trust_attributes,
            )?;
            self.write_pointer_value(entry + layout.sid_offset, sid_ptr)?;
            self.modules
                .memory_mut()
                .write(entry + layout.guid_offset, &trust.guid)?;
        }
        self.write_pointer_value(domains_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    fn read_account_sid_bytes(&self, sid_ptr: u64) -> Result<Vec<u8>, VmError> {
        if sid_ptr == 0 {
            return Ok(Vec::new());
        }
        let sub_auth_count = self.read_bytes_from_memory(sid_ptr + 1, 1)?[0] as usize;
        let sid_len = 8 + sub_auth_count.saturating_mul(4);
        self.read_bytes_from_memory(sid_ptr, sid_len)
    }

    fn name_pointer_list_required_size(&self, names: &[String]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        let mut required = align_up(names.len() as u64 * pointer_size, pointer_size);
        for name in names {
            required += wide_storage_size(name);
        }
        required
    }

    fn net_share_required_size(&self, level: u32, shares: &[ShareProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            SHARE_INFO_LEVEL_0 => {
                let mut required = align_up(shares.len() as u64 * pointer_size, pointer_size);
                for share in shares {
                    required += wide_storage_size(&share.name);
                }
                required
            }
            SHARE_INFO_LEVEL_1 => {
                let layout = self.share_info_1_layout();
                let mut required = align_up(shares.len() as u64 * layout.size, pointer_size);
                for share in shares {
                    required += wide_storage_size(&share.name);
                    required += optional_wide_storage_size(&share.remark);
                }
                required
            }
            SHARE_INFO_LEVEL_2 => {
                let layout = self.share_info_2_layout();
                let mut required = align_up(shares.len() as u64 * layout.size, pointer_size);
                for share in shares {
                    required += wide_storage_size(&share.name);
                    required += optional_wide_storage_size(&share.remark);
                    required += optional_wide_storage_size(&share.path);
                    required += optional_wide_storage_size(&share.password);
                }
                required
            }
            _ => 0,
        }
    }

    fn net_server_info_101_required_size(&self, servers: &[ServerInventoryRecord]) -> u64 {
        let layout = self.server_info_101_layout();
        let mut required = align_up(
            servers.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for server in servers {
            required += wide_storage_size(&server.name);
            required += optional_wide_storage_size(&server.comment);
        }
        required
    }

    fn net_use_required_size(&self, level: u32, uses: &[NetworkUseProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            USE_INFO_LEVEL_0 => {
                let mut required = align_up(uses.len() as u64 * pointer_size, pointer_size);
                for network_use in uses {
                    required += optional_wide_storage_size(&network_use.local_name);
                }
                required
            }
            USE_INFO_LEVEL_1 => {
                let layout = self.use_info_1_layout();
                let mut required = align_up(uses.len() as u64 * layout.size, pointer_size);
                for network_use in uses {
                    required += optional_wide_storage_size(&network_use.local_name);
                    required += optional_wide_storage_size(&network_use.remote_name);
                    required += optional_wide_storage_size(&network_use.password);
                }
                required
            }
            USE_INFO_LEVEL_2 => {
                let layout = self.use_info_2_layout();
                let mut required = align_up(uses.len() as u64 * layout.size, pointer_size);
                for network_use in uses {
                    required += optional_wide_storage_size(&network_use.local_name);
                    required += optional_wide_storage_size(&network_use.remote_name);
                    required += optional_wide_storage_size(&network_use.password);
                    required += optional_wide_storage_size(&network_use.user_name);
                    required += optional_wide_storage_size(&network_use.domain_name);
                }
                required
            }
            _ => 0,
        }
    }

    fn net_session_required_size(&self, sessions: &[NetworkSessionProfile]) -> u64 {
        let layout = self.session_info_10_layout();
        let mut required = align_up(
            sessions.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for session in sessions {
            required += optional_wide_storage_size(&session.client_name);
            required += optional_wide_storage_size(&session.user_name);
        }
        required
    }

    fn net_file_required_size(&self, level: u32, files: &[OpenFileProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            FILE_INFO_LEVEL_2 => files.len() as u64 * 4,
            FILE_INFO_LEVEL_3 => {
                let layout = self.file_info_3_layout();
                let mut required = align_up(files.len() as u64 * layout.size, pointer_size);
                for file in files {
                    required += optional_wide_storage_size(&file.path_name);
                    required += optional_wide_storage_size(&file.user_name);
                }
                required
            }
            _ => 0,
        }
    }

    fn net_connection_required_size(
        &self,
        level: u32,
        connections: &[ConnectionInventoryRecord],
    ) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            CONNECTION_INFO_LEVEL_0 => connections.len() as u64 * 4,
            CONNECTION_INFO_LEVEL_1 => {
                let layout = self.connection_info_1_layout();
                let mut required = align_up(connections.len() as u64 * layout.size, pointer_size);
                for connection in connections {
                    required += optional_wide_storage_size(&connection.user_name);
                    required += optional_wide_storage_size(&connection.net_name);
                }
                required
            }
            _ => 0,
        }
    }

    fn net_wksta_user_required_size(&self, level: u32, users: &[WorkstationUserProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            WKSTA_USER_INFO_LEVEL_0 => {
                let mut required = align_up(users.len() as u64 * pointer_size, pointer_size);
                for user in users {
                    required += optional_wide_storage_size(&user.user_name);
                }
                required
            }
            WKSTA_USER_INFO_LEVEL_1 => {
                let layout = self.wksta_user_info_1_layout();
                let mut required = align_up(users.len() as u64 * layout.size, pointer_size);
                for user in users {
                    required += optional_wide_storage_size(&user.user_name);
                    required += optional_wide_storage_size(&user.logon_domain);
                    required += optional_wide_storage_size(&user.other_domains);
                    required += optional_wide_storage_size(&user.logon_server);
                }
                required
            }
            _ => 0,
        }
    }

    fn net_local_group_required_size(&self, level: u32, groups: &[LocalGroupProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            0 => {
                let mut required = align_up(groups.len() as u64 * pointer_size, pointer_size);
                for group in groups {
                    required += wide_storage_size(&group.name);
                }
                required
            }
            LOCALGROUP_INFO_LEVEL_1 => {
                let layout = self.local_group_info_1_layout();
                let mut required = align_up(groups.len() as u64 * layout.size, pointer_size);
                for group in groups {
                    required += wide_storage_size(&group.name);
                    required += optional_wide_storage_size(&group.comment);
                }
                required
            }
            _ => 0,
        }
    }

    fn write_local_group_info_0_entries(
        &mut self,
        base: u64,
        groups: &[LocalGroupProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        let mut cursor = align_up(base + groups.len() as u64 * pointer_size, pointer_size);
        for (index, group) in groups.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &group.name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    fn write_local_group_info_1_entries(
        &mut self,
        base: u64,
        groups: &[LocalGroupProfile],
    ) -> Result<(), VmError> {
        let layout = self.local_group_info_1_layout();
        let mut cursor = align_up(
            base + groups.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, group) in groups.iter().enumerate() {
            let entry = base + index as u64 * layout.size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &group.name)?;
            let comment_ptr = write_optional_inline_wide_string(self, &mut cursor, &group.comment)?;
            self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
            self.write_pointer_value(entry + layout.comment_offset, comment_ptr)?;
        }
        Ok(())
    }

    fn write_name_pointer_entries(&mut self, base: u64, names: &[String]) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        let mut cursor = align_up(base + names.len() as u64 * pointer_size, pointer_size);
        for (index, name) in names.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    fn write_share_entries(
        &mut self,
        level: u32,
        base: u64,
        shares: &[ShareProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            SHARE_INFO_LEVEL_0 => {
                let mut cursor = align_up(base + shares.len() as u64 * pointer_size, pointer_size);
                for (index, share) in shares.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let name_ptr = write_inline_wide_string(self, &mut cursor, &share.name)?;
                    self.write_pointer_value(entry, name_ptr)?;
                }
            }
            SHARE_INFO_LEVEL_1 => {
                let layout = self.share_info_1_layout();
                let mut cursor = align_up(base + shares.len() as u64 * layout.size, pointer_size);
                for (index, share) in shares.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let name_ptr = write_inline_wide_string(self, &mut cursor, &share.name)?;
                    let remark_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &share.remark)?;
                    self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
                    self.write_u32(entry + layout.share_type_offset, share.share_type)?;
                    self.write_pointer_value(entry + layout.remark_offset, remark_ptr)?;
                }
            }
            SHARE_INFO_LEVEL_2 => {
                let layout = self.share_info_2_layout();
                let mut cursor = align_up(base + shares.len() as u64 * layout.size, pointer_size);
                for (index, share) in shares.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let name_ptr = write_inline_wide_string(self, &mut cursor, &share.name)?;
                    let remark_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &share.remark)?;
                    let path_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &share.path)?;
                    let password_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &share.password)?;
                    self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
                    self.write_u32(entry + layout.share_type_offset, share.share_type)?;
                    self.write_pointer_value(entry + layout.remark_offset, remark_ptr)?;
                    self.write_u32(entry + layout.permissions_offset, share.permissions)?;
                    self.write_u32(entry + layout.max_uses_offset, share.max_uses)?;
                    self.write_u32(entry + layout.current_uses_offset, share.current_uses)?;
                    self.write_pointer_value(entry + layout.path_offset, path_ptr)?;
                    self.write_pointer_value(entry + layout.password_offset, password_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_server_info_101_entries(
        &mut self,
        base: u64,
        servers: &[ServerInventoryRecord],
    ) -> Result<(), VmError> {
        let layout = self.server_info_101_layout();
        let mut cursor = align_up(
            base + servers.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, server) in servers.iter().enumerate() {
            let entry = base + index as u64 * layout.size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &server.name)?;
            let comment_ptr =
                write_optional_inline_wide_string(self, &mut cursor, &server.comment)?;
            self.write_u32(entry, PLATFORM_ID_NT)?;
            self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
            self.write_u32(
                entry + layout.ver_major_offset,
                self.environment_profile.os_version.major,
            )?;
            self.write_u32(
                entry + layout.ver_minor_offset,
                self.environment_profile.os_version.minor,
            )?;
            self.write_u32(entry + layout.server_type_offset, server.server_type)?;
            self.write_pointer_value(entry + layout.comment_offset, comment_ptr)?;
        }
        Ok(())
    }

    fn write_use_entries(
        &mut self,
        level: u32,
        base: u64,
        uses: &[NetworkUseProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            USE_INFO_LEVEL_0 => {
                let mut cursor = align_up(base + uses.len() as u64 * pointer_size, pointer_size);
                for (index, network_use) in uses.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let local_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.local_name,
                    )?;
                    self.write_pointer_value(entry, local_name_ptr)?;
                }
            }
            USE_INFO_LEVEL_1 => {
                let layout = self.use_info_1_layout();
                let mut cursor = align_up(base + uses.len() as u64 * layout.size, pointer_size);
                for (index, network_use) in uses.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let local_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.local_name,
                    )?;
                    let remote_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.remote_name,
                    )?;
                    let password_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.password,
                    )?;
                    self.write_pointer_value(entry + layout.local_name_offset, local_name_ptr)?;
                    self.write_pointer_value(entry + layout.remote_name_offset, remote_name_ptr)?;
                    self.write_pointer_value(entry + layout.password_offset, password_ptr)?;
                    self.write_u32(entry + layout.status_offset, network_use.status)?;
                    self.write_u32(
                        entry + layout.assignment_type_offset,
                        network_use.assignment_type,
                    )?;
                    self.write_u32(entry + layout.ref_count_offset, network_use.ref_count)?;
                    self.write_u32(entry + layout.use_count_offset, network_use.use_count)?;
                }
            }
            USE_INFO_LEVEL_2 => {
                let layout = self.use_info_2_layout();
                let mut cursor = align_up(base + uses.len() as u64 * layout.size, pointer_size);
                for (index, network_use) in uses.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let local_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.local_name,
                    )?;
                    let remote_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.remote_name,
                    )?;
                    let password_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.password,
                    )?;
                    let user_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.user_name,
                    )?;
                    let domain_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &network_use.domain_name,
                    )?;
                    self.write_pointer_value(entry + layout.local_name_offset, local_name_ptr)?;
                    self.write_pointer_value(entry + layout.remote_name_offset, remote_name_ptr)?;
                    self.write_pointer_value(entry + layout.password_offset, password_ptr)?;
                    self.write_u32(entry + layout.status_offset, network_use.status)?;
                    self.write_u32(
                        entry + layout.assignment_type_offset,
                        network_use.assignment_type,
                    )?;
                    self.write_u32(entry + layout.ref_count_offset, network_use.ref_count)?;
                    self.write_u32(entry + layout.use_count_offset, network_use.use_count)?;
                    self.write_pointer_value(entry + layout.user_name_offset, user_name_ptr)?;
                    self.write_pointer_value(entry + layout.domain_name_offset, domain_name_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_session_entries(
        &mut self,
        base: u64,
        sessions: &[NetworkSessionProfile],
    ) -> Result<(), VmError> {
        let layout = self.session_info_10_layout();
        let mut cursor = align_up(
            base + sessions.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, session) in sessions.iter().enumerate() {
            let entry = base + index as u64 * layout.size;
            let client_name_ptr =
                write_optional_inline_wide_string(self, &mut cursor, &session.client_name)?;
            let user_name_ptr =
                write_optional_inline_wide_string(self, &mut cursor, &session.user_name)?;
            self.write_pointer_value(entry + layout.client_name_offset, client_name_ptr)?;
            self.write_pointer_value(entry + layout.user_name_offset, user_name_ptr)?;
            self.write_u32(entry + layout.active_time_offset, session.active_time_secs)?;
            self.write_u32(entry + layout.idle_time_offset, session.idle_time_secs)?;
        }
        Ok(())
    }

    fn write_file_entries(
        &mut self,
        level: u32,
        base: u64,
        files: &[OpenFileProfile],
    ) -> Result<(), VmError> {
        match level {
            FILE_INFO_LEVEL_2 => {
                for (index, file) in files.iter().enumerate() {
                    self.write_u32(base + index as u64 * 4, file.id)?;
                }
            }
            FILE_INFO_LEVEL_3 => {
                let layout = self.file_info_3_layout();
                let mut cursor = align_up(
                    base + files.len() as u64 * layout.size,
                    self.arch.pointer_size as u64,
                );
                for (index, file) in files.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let path_name_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &file.path_name)?;
                    let user_name_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &file.user_name)?;
                    self.write_u32(entry + layout.id_offset, file.id)?;
                    self.write_u32(entry + layout.permissions_offset, file.permissions)?;
                    self.write_u32(entry + layout.num_locks_offset, file.num_locks)?;
                    self.write_pointer_value(entry + layout.path_name_offset, path_name_ptr)?;
                    self.write_pointer_value(entry + layout.user_name_offset, user_name_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_connection_entries(
        &mut self,
        level: u32,
        base: u64,
        connections: &[ConnectionInventoryRecord],
    ) -> Result<(), VmError> {
        match level {
            CONNECTION_INFO_LEVEL_0 => {
                for (index, connection) in connections.iter().enumerate() {
                    self.write_u32(base + index as u64 * 4, connection.id)?;
                }
            }
            CONNECTION_INFO_LEVEL_1 => {
                let layout = self.connection_info_1_layout();
                let mut cursor = align_up(
                    base + connections.len() as u64 * layout.size,
                    self.arch.pointer_size as u64,
                );
                for (index, connection) in connections.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let user_name_ptr = write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &connection.user_name,
                    )?;
                    let net_name_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &connection.net_name)?;
                    self.write_u32(entry + layout.id_offset, connection.id)?;
                    self.write_u32(entry + layout.type_offset, connection.connection_type)?;
                    self.write_u32(entry + layout.num_opens_offset, connection.num_opens)?;
                    self.write_u32(entry + layout.num_users_offset, connection.num_users)?;
                    self.write_u32(entry + layout.time_offset, connection.active_time_secs)?;
                    self.write_pointer_value(entry + layout.user_name_offset, user_name_ptr)?;
                    self.write_pointer_value(entry + layout.net_name_offset, net_name_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_time_of_day_info(&mut self, base: u64) -> Result<(), VmError> {
        let layout = self.time_of_day_info_layout();
        let current = self.time.current();
        let unix_100ns = current.filetime.saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS);
        let elapsed_time = (unix_100ns / 10_000_000) as u32;
        let (year, month, weekday, day, hour, minute, second, milliseconds) =
            Self::system_time_components_from_filetime(current.filetime);
        self.write_u32(base + layout.elapsed_time_offset, elapsed_time)?;
        self.write_u32(base + layout.msecs_offset, current.tick_ms as u32)?;
        self.write_u32(base + layout.hours_offset, hour as u32)?;
        self.write_u32(base + layout.mins_offset, minute as u32)?;
        self.write_u32(base + layout.secs_offset, second as u32)?;
        self.write_u32(base + layout.hunds_offset, (milliseconds / 10) as u32)?;
        self.write_u32(base + layout.timezone_offset, 0)?;
        self.write_u32(base + layout.interval_offset, TIME_OF_DAY_TICK_INTERVAL)?;
        self.write_u32(base + layout.day_offset, day as u32)?;
        self.write_u32(base + layout.month_offset, month as u32)?;
        self.write_u32(base + layout.year_offset, year as u32)?;
        self.write_u32(base + layout.weekday_offset, weekday as u32)?;
        Ok(())
    }

    fn write_wksta_user_entries(
        &mut self,
        level: u32,
        base: u64,
        users: &[WorkstationUserProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            WKSTA_USER_INFO_LEVEL_0 => {
                let mut cursor = align_up(base + users.len() as u64 * pointer_size, pointer_size);
                for (index, user) in users.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let user_name_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &user.user_name)?;
                    self.write_pointer_value(entry, user_name_ptr)?;
                }
            }
            WKSTA_USER_INFO_LEVEL_1 => {
                let layout = self.wksta_user_info_1_layout();
                let mut cursor = align_up(base + users.len() as u64 * layout.size, pointer_size);
                for (index, user) in users.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let user_name_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &user.user_name)?;
                    let logon_domain_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &user.logon_domain)?;
                    let other_domains_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &user.other_domains)?;
                    let logon_server_ptr =
                        write_optional_inline_wide_string(self, &mut cursor, &user.logon_server)?;
                    self.write_pointer_value(entry + layout.user_name_offset, user_name_ptr)?;
                    self.write_pointer_value(entry + layout.logon_domain_offset, logon_domain_ptr)?;
                    self.write_pointer_value(
                        entry + layout.other_domains_offset,
                        other_domains_ptr,
                    )?;
                    self.write_pointer_value(entry + layout.logon_server_offset, logon_server_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn net_local_group_members_required_size(
        &self,
        level: u32,
        members: &[AccountLookupRecord],
    ) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            LOCALGROUP_MEMBERS_INFO_LEVEL_0 => {
                let mut required = align_up(members.len() as u64 * pointer_size, pointer_size);
                for member in members {
                    required += account_lookup_sid(member).len() as u64;
                }
                required
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_1 | LOCALGROUP_MEMBERS_INFO_LEVEL_2 => {
                let layout = self.local_group_members_info_12_layout();
                let mut required = align_up(members.len() as u64 * layout.size, pointer_size);
                for member in members {
                    required += account_lookup_sid(member).len() as u64;
                    required += wide_storage_size(&account_lookup_qualified_name(member));
                }
                required
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_3 => {
                let mut required = align_up(members.len() as u64 * pointer_size, pointer_size);
                for member in members {
                    required += wide_storage_size(&account_lookup_qualified_name(member));
                }
                required
            }
            _ => 0,
        }
    }

    fn domain_trusts_required_size(&self, wide: bool, trusts: &[DomainTrustRecord]) -> u64 {
        let layout = self.domain_trust_info_layout();
        let mut required = align_up(
            trusts.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for trust in trusts {
            required += inline_text_storage_size(wide, &trust.netbios_name);
            required += inline_text_storage_size(wide, &trust.dns_name);
            required += trust.sid.len() as u64;
        }
        required
    }

    fn write_local_group_member_entries(
        &mut self,
        level: u32,
        base: u64,
        members: &[AccountLookupRecord],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            LOCALGROUP_MEMBERS_INFO_LEVEL_0 => {
                let mut cursor = align_up(base + members.len() as u64 * pointer_size, pointer_size);
                for (index, member) in members.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let sid = account_lookup_sid(member);
                    let sid_ptr = cursor;
                    self.modules.memory_mut().write(sid_ptr, sid)?;
                    cursor += sid.len() as u64;
                    self.write_pointer_value(entry, sid_ptr)?;
                }
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_1 | LOCALGROUP_MEMBERS_INFO_LEVEL_2 => {
                let layout = self.local_group_members_info_12_layout();
                let mut cursor = align_up(base + members.len() as u64 * layout.size, pointer_size);
                for (index, member) in members.iter().enumerate() {
                    let entry = base + index as u64 * layout.size;
                    let sid = account_lookup_sid(member);
                    let sid_ptr = cursor;
                    self.modules.memory_mut().write(sid_ptr, sid)?;
                    cursor += sid.len() as u64;
                    let name_ptr = write_inline_wide_string(
                        self,
                        &mut cursor,
                        &account_lookup_qualified_name(member),
                    )?;
                    self.write_pointer_value(entry + layout.sid_offset, sid_ptr)?;
                    self.write_u32(
                        entry + layout.sid_use_offset,
                        account_lookup_sid_use(member),
                    )?;
                    self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
                }
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_3 => {
                let mut cursor = align_up(base + members.len() as u64 * pointer_size, pointer_size);
                for (index, member) in members.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let name_ptr = write_inline_wide_string(
                        self,
                        &mut cursor,
                        &account_lookup_qualified_name(member),
                    )?;
                    self.write_pointer_value(entry, name_ptr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn net_server_get_info(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != 101 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let layout = self.server_info_101_layout();
        let name = self.active_computer_name().to_string();
        let comment = self.environment_profile.os_version.product_name.clone();
        let mut required = align_up(layout.size, self.arch.pointer_size as u64);
        required += wide_storage_size(&name);
        required += wide_storage_size(&comment);

        let allocation = self.alloc_process_heap_block(required, "netapi32:NetServerGetInfo")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, PLATFORM_ID_NT)?;
        let mut cursor = align_up(allocation + layout.size, self.arch.pointer_size as u64);
        let name_ptr = write_inline_wide_string(self, &mut cursor, &name)?;
        let comment_ptr = write_inline_wide_string(self, &mut cursor, &comment)?;
        self.write_pointer_value(allocation + layout.name_offset, name_ptr)?;
        self.write_u32(
            allocation + layout.ver_major_offset,
            self.environment_profile.os_version.major,
        )?;
        self.write_u32(
            allocation + layout.ver_minor_offset,
            self.environment_profile.os_version.minor,
        )?;
        self.write_u32(
            allocation + layout.server_type_offset,
            SV_TYPE_WORKSTATION | SV_TYPE_SERVER_NT,
        )?;
        self.write_pointer_value(allocation + layout.comment_offset, comment_ptr)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub(super) fn net_server_enum(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
        preferred_max_len: u32,
        entries_read_ptr: u64,
        total_entries_ptr: u64,
        server_type: u32,
        domain_name: &str,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 || entries_read_ptr == 0 || total_entries_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != 101 {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }
        let servers = match self.netapi_server_inventory_for_enum(domain_name, server_type) {
            Ok(servers) => servers,
            Err(status) => {
                self.set_last_error(status as u32);
                return Ok(status);
            }
        };
        let required = self.net_server_info_101_required_size(&servers);
        self.write_u32(total_entries_ptr, servers.len() as u32)?;
        self.write_u32(entries_read_ptr, 0)?;
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }
        if preferred_max_len != MAX_PREFERRED_LENGTH && (preferred_max_len as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(ERROR_MORE_DATA);
        }
        if servers.is_empty() {
            self.write_pointer_value(buffer_ptr, 0)?;
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(0);
        }

        let allocation =
            self.alloc_process_heap_block(required.max(1), "netapi32:NetServerEnum")?;
        self.fill_memory_pattern(allocation, required.max(1), 0)?;
        self.write_server_info_101_entries(allocation, &servers)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(entries_read_ptr, servers.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    fn net_user_enum_required_size(&self, level: u32, users: &[UserAccountProfile]) -> u64 {
        let pointer_size = self.arch.pointer_size as u64;
        match level {
            USER_INFO_LEVEL_0 => {
                let mut required = align_up(users.len() as u64 * pointer_size, pointer_size);
                for user in users {
                    required += wide_storage_size(&user.name);
                }
                required
            }
            USER_INFO_LEVEL_1 => {
                let layout = self.user_info_1_layout();
                let mut required = align_up(users.len() as u64 * layout.size, pointer_size);
                for user in users {
                    required += optional_wide_storage_size(&user.name);
                    required += optional_wide_storage_size(&user.home_dir);
                    required += optional_wide_storage_size(&user.comment);
                    required += optional_wide_storage_size(&user.script_path);
                }
                required
            }
            _ => 0,
        }
    }

    fn write_user_info_0_entries(
        &mut self,
        base: u64,
        users: &[UserAccountProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.arch.pointer_size as u64;
        let mut cursor = align_up(base + users.len() as u64 * pointer_size, pointer_size);
        for (index, user) in users.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &user.name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    fn write_user_info_1_entries(
        &mut self,
        base: u64,
        users: &[UserAccountProfile],
    ) -> Result<(), VmError> {
        let layout = self.user_info_1_layout();
        let mut cursor = align_up(
            base + users.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, user) in users.iter().enumerate() {
            let entry = base + index as u64 * layout.size;
            self.write_user_info_1_at(entry, &mut cursor, user)?;
        }
        Ok(())
    }

    fn write_single_user_info_1(
        &mut self,
        base: u64,
        user: &UserAccountProfile,
    ) -> Result<(), VmError> {
        let layout = self.user_info_1_layout();
        let mut cursor = align_up(base + layout.size, self.arch.pointer_size as u64);
        self.write_user_info_1_at(base, &mut cursor, user)
    }

    fn write_user_info_1_at(
        &mut self,
        entry: u64,
        cursor: &mut u64,
        user: &UserAccountProfile,
    ) -> Result<(), VmError> {
        let layout = self.user_info_1_layout();
        let name_ptr = write_optional_inline_wide_string(self, cursor, &user.name)?;
        let home_dir_ptr = write_optional_inline_wide_string(self, cursor, &user.home_dir)?;
        let comment_ptr = write_optional_inline_wide_string(self, cursor, &user.comment)?;
        let script_path_ptr = write_optional_inline_wide_string(self, cursor, &user.script_path)?;
        self.write_pointer_value(entry + layout.name_offset, name_ptr)?;
        self.write_u32(entry + layout.password_age_offset, 0)?;
        self.write_u32(entry + layout.privilege_offset, user.privilege_level)?;
        self.write_pointer_value(entry + layout.home_dir_offset, home_dir_ptr)?;
        self.write_pointer_value(entry + layout.comment_offset, comment_ptr)?;
        self.write_u32(entry + layout.flags_offset, user.flags)?;
        self.write_pointer_value(entry + layout.script_path_offset, script_path_ptr)?;
        Ok(())
    }

    fn write_single_user_info_23(
        &mut self,
        base: u64,
        user: &UserAccountProfile,
    ) -> Result<(), VmError> {
        let layout = self.user_info_23_layout();
        let mut cursor = align_up(base + layout.size, self.arch.pointer_size as u64);
        let name_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.name)?;
        let full_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.full_name)?;
        let comment_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.comment)?;
        let sid = user_sid_bytes(&self.environment_profile.machine.machine_guid, user.rid);
        let sid_ptr = cursor;
        self.modules.memory_mut().write(sid_ptr, &sid)?;
        self.write_pointer_value(base + layout.name_offset, name_ptr)?;
        self.write_pointer_value(base + layout.full_name_offset, full_name_ptr)?;
        self.write_pointer_value(base + layout.comment_offset, comment_ptr)?;
        self.write_u32(base + layout.flags_offset, user.flags)?;
        self.write_pointer_value(base + layout.sid_offset, sid_ptr)?;
        Ok(())
    }

    pub(super) fn ds_role_get_primary_domain_information(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if level != DSROLE_PRIMARY_DOMAIN_INFO_BASIC {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(ERROR_INVALID_LEVEL);
        }

        let layout = self.ds_role_primary_domain_info_basic_layout();
        let flat_name = if self.netapi_domain_joined() {
            self.netapi_join_name()
        } else {
            String::new()
        };
        let dns_name = self.netapi_dns_domain_name();
        let forest_name = self.netapi_forest_name();
        let mut required = align_up(layout.size, self.arch.pointer_size as u64);
        required += optional_wide_storage_size(&flat_name);
        required += optional_wide_storage_size(&dns_name);
        required += optional_wide_storage_size(&forest_name);

        let allocation =
            self.alloc_process_heap_block(required, "netapi32:DsRoleGetPrimaryDomainInformation")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, self.ds_role_machine_role())?;
        self.write_u32(allocation + layout.flags_offset, 0)?;
        let mut cursor = align_up(allocation + layout.size, self.arch.pointer_size as u64);
        let flat_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &flat_name)?;
        let dns_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &dns_name)?;
        let forest_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &forest_name)?;
        self.write_pointer_value(allocation + layout.flat_name_offset, flat_name_ptr)?;
        self.write_pointer_value(allocation + layout.dns_name_offset, dns_name_ptr)?;
        self.write_pointer_value(allocation + layout.forest_name_offset, forest_name_ptr)?;
        let domain_guid = self.netapi_domain_guid_bytes();
        self.modules
            .memory_mut()
            .write(allocation + layout.domain_guid_offset, &domain_guid)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

fn wide_storage_size(value: &str) -> u64 {
    ((value.encode_utf16().count() + 1) * 2) as u64
}

fn optional_wide_storage_size(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        wide_storage_size(value)
    }
}

fn write_optional_inline_wide_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    if value.is_empty() {
        Ok(0)
    } else {
        write_inline_wide_string(engine, cursor, value)
    }
}

fn write_inline_wide_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    *cursor = align_up(*cursor, 2);
    let address = *cursor;
    let capacity = value.encode_utf16().count() + 1;
    engine.write_wide_string_to_memory(address, capacity, value)?;
    *cursor += (capacity * 2) as u64;
    Ok(address)
}

fn write_inline_ansi_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    let address = *cursor;
    let capacity = value.len() + 1;
    engine.write_c_string_to_memory(address, capacity, value)?;
    *cursor += capacity as u64;
    Ok(address)
}

fn write_inline_text_string(
    engine: &mut VirtualExecutionEngine,
    wide: bool,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    if wide {
        write_inline_wide_string(engine, cursor, value)
    } else {
        write_inline_ansi_string(engine, cursor, value)
    }
}

fn inline_text_storage_size(wide: bool, value: &str) -> u64 {
    if wide {
        wide_storage_size(value)
    } else {
        (value.len() + 1) as u64
    }
}

fn deterministic_guid_le(seed: &str) -> [u8; 16] {
    let mut state0 = 0xCBF2_9CE4_8422_2325u64;
    let mut state1 = 0x9E37_79B9_7F4A_7C15u64;
    for byte in seed.bytes() {
        state0 ^= byte as u64;
        state0 = state0.wrapping_mul(0x1000_0000_01B3);
        state1 ^= state0.rotate_left(17) ^ byte as u64;
        state1 = state1.wrapping_mul(0x1000_0000_01B3);
    }
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&state0.to_le_bytes());
    bytes[8..16].copy_from_slice(&state1.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes
}

fn is_builtin_alias_rid(rid: u32) -> bool {
    matches!(
        rid,
        544 | 545 | 546 | 547 | 548 | 549 | 550 | 551 | 552 | 554 | 555
    )
}

fn encoded_text_len(wide: bool, value: &str) -> usize {
    if wide {
        value.encode_utf16().count() + 1
    } else {
        value.len() + 1
    }
}

fn write_text(
    engine: &mut VirtualExecutionEngine,
    wide: bool,
    address: u64,
    capacity: usize,
    value: &str,
) -> Result<(), VmError> {
    if wide {
        let _ = engine.write_wide_string_to_memory(address, capacity, value)?;
    } else {
        let _ = engine.write_c_string_to_memory(address, capacity, value)?;
    }
    Ok(())
}

fn split_account_name(account_name: &str) -> (Option<&str>, &str) {
    if let Some((domain, name)) = account_name.split_once('\\') {
        (Some(domain), name)
    } else {
        (None, account_name)
    }
}

fn netapi_matches_unc_name(candidate: &str, requested: &str) -> bool {
    let requested = requested.trim();
    if requested.is_empty() {
        return true;
    }
    let normalized_candidate = candidate.trim().trim_start_matches('\\');
    let normalized_requested = requested.trim_start_matches('\\');
    normalized_candidate.eq_ignore_ascii_case(normalized_requested)
}

fn account_sid_base_bytes(seed_source: &str) -> Vec<u8> {
    let seed = deterministic_guid_le(seed_source);
    let subauth0 = u32::from_le_bytes(seed[0..4].try_into().unwrap());
    let subauth1 = u32::from_le_bytes(seed[4..8].try_into().unwrap());
    let subauth2 = u32::from_le_bytes(seed[8..12].try_into().unwrap());
    let mut sid = vec![1u8, 4, 0, 0, 0, 0, 0, 5];
    for value in [21u32, subauth0, subauth1, subauth2] {
        sid.extend_from_slice(&value.to_le_bytes());
    }
    sid
}

fn local_account_sid_bytes(machine_guid: &str, rid: u32) -> Vec<u8> {
    let mut sid = account_sid_base_bytes(machine_guid);
    sid[1] = 5;
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn domain_sid_base_bytes(dns_domain_name: &str, domain_guid: &str) -> Vec<u8> {
    let seed_source = if !domain_guid.trim().is_empty() {
        domain_guid.trim()
    } else {
        dns_domain_name.trim()
    };
    account_sid_base_bytes(seed_source)
}

fn domain_sid_bytes(dns_domain_name: &str, domain_guid: &str, rid: u32) -> Vec<u8> {
    let mut sid = domain_sid_base_bytes(dns_domain_name, domain_guid);
    sid[1] = 5;
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn builtin_alias_sid_bytes(rid: u32) -> Vec<u8> {
    let mut sid = vec![1u8, 2, 0, 0, 0, 0, 0, 5];
    sid.extend_from_slice(&32u32.to_le_bytes());
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn account_lookup_sid(record: &AccountLookupRecord) -> &[u8] {
    match record {
        AccountLookupRecord::User { sid, .. } | AccountLookupRecord::Group { sid, .. } => sid,
    }
}

fn account_lookup_sid_use(record: &AccountLookupRecord) -> u32 {
    match record {
        AccountLookupRecord::User { .. } => 1,
        AccountLookupRecord::Group { .. } => 4,
    }
}

fn account_lookup_qualified_name(record: &AccountLookupRecord) -> String {
    match record {
        AccountLookupRecord::User {
            profile, domain, ..
        } => format!(r"{domain}\{}", profile.name),
        AccountLookupRecord::Group {
            profile, domain, ..
        } => format!(r"{domain}\{}", profile.name),
    }
}

fn user_sid_bytes(machine_guid: &str, rid: u32) -> Vec<u8> {
    local_account_sid_bytes(machine_guid, rid)
}

fn parse_guid_string_le(guid: &str) -> Option<[u8; 16]> {
    let trimmed = guid.trim().trim_matches(|ch| ch == '{' || ch == '}');
    let parts = trimmed.split('-').collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    let time_low = u32::from_str_radix(parts[0], 16).ok()?;
    let time_mid = u16::from_str_radix(parts[1], 16).ok()?;
    let time_hi = u16::from_str_radix(parts[2], 16).ok()?;
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
    bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
    bytes[6..8].copy_from_slice(&time_hi.to_le_bytes());
    bytes[8] = u8::from_str_radix(&parts[3][0..2], 16).ok()?;
    bytes[9] = u8::from_str_radix(&parts[3][2..4], 16).ok()?;
    for index in 0..6 {
        let start = index * 2;
        bytes[10 + index] = u8::from_str_radix(&parts[4][start..start + 2], 16).ok()?;
    }
    Some(bytes)
}

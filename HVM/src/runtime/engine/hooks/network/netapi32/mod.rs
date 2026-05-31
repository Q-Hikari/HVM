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
        ctx: &HookContext<'_>,
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
                | "NetUserAdd"
                | "NetUserSetInfo"
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
                | "NetLocalGroupAddMembers"
                | "NetLocalGroupDelMembers"
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
                    let ncb = ctx.raw(0);
                    if ncb == 0 {
                        Ok(0x01)
                    } else {
                        let command = self.read_bytes_from_memory(ncb, 1)?[0];
                        let buffer = self.read_u32(ncb + 4)? as u64;
                        let length = self.read_u16(ncb + 8)? as usize;
                        if command == 0x37 {
                            self.write_netbios_lana_enum(buffer, length)?;
                        }
                        self.core.modules.memory_mut().write(ncb + 1, &[0])?;
                        self.core.modules.memory_mut().write(ncb + 49, &[0])?;
                        Ok(0)
                    }
                }
                "NetApiBufferFree" => Ok(self.net_api_buffer_free(ctx.raw(0))),
                "NetGetJoinInformation" => self.net_get_join_information(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                ),
                "NetGetDCName" | "NetGetAnyDCName" => self.net_get_dc_name(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "NetWkstaGetInfo" => self.net_wksta_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                ),
                "NetUserEnum" => self.net_user_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "NetUserGetInfo" => self.net_user_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetUserAdd" => self.net_user_add(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "NetUserSetInfo" => self.net_user_set_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4),
                ),
                "NetGroupEnum" => self.net_group_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetGroupGetInfo" => self.net_group_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetUserGetGroups" => self.net_user_get_groups(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetGroupGetUsers" => self.net_group_get_users(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetUseEnum" => self.net_use_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetUseAdd" => self.net_use_add(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "NetUseDel" => self.net_use_del(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                ),
                "NetUseGetInfo" => self.net_use_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetFileEnum" => self.net_file_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    &self.read_wide_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5) as u32,
                    ctx.raw(6),
                    ctx.raw(7),
                    ctx.raw(8),
                ),
                "NetFileGetInfo" => self.net_file_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetFileClose" => self.net_file_close(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                ),
                "NetConnectionEnum" => self.net_connection_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "NetShareCheck" => self.net_share_check(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "NetRemoteTOD" => {
                    self.net_remote_tod(&self.read_wide_string_from_memory(ctx.raw(0))?, ctx.raw(1))
                }
                "NetShareEnum" => self.net_share_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetShareGetInfo" => self.net_share_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetSessionEnum" => self.net_session_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    &self.read_wide_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5) as u32,
                    ctx.raw(6),
                    ctx.raw(7),
                    ctx.raw(8),
                ),
                "NetWkstaUserEnum" => self.net_wksta_user_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetLocalGroupEnum" => self.net_local_group_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "NetUserGetLocalGroups" => self.net_user_get_local_groups(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5) as u32,
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "NetLocalGroupGetMembers" => self.net_local_group_get_members(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "NetLocalGroupAddMembers" => self.net_local_group_add_members(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "NetLocalGroupDelMembers" => self.net_local_group_del_members(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                ),
                "NetLocalGroupGetInfo" => self.net_local_group_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "NetServerGetInfo" => self.net_server_get_info(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                ),
                "NetServerEnum" => self.net_server_enum(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6) as u32,
                    &self.read_wide_string_from_memory(ctx.raw(7))?,
                    ctx.raw(8),
                ),
                "DsRoleGetPrimaryDomainInformation" => self.ds_role_get_primary_domain_information(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                ),
                "DsGetDcNameA" => self.ds_get_dc_name(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                    &self.read_c_string_from_memory(ctx.raw(3))?,
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                ),
                "DsGetDcNameW" => self.ds_get_dc_name(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                    &self.read_wide_string_from_memory(ctx.raw(3))?,
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                ),
                "DsEnumerateDomainTrustsA" => self.ds_enumerate_domain_trusts(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "DsEnumerateDomainTrustsW" => self.ds_enumerate_domain_trusts(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "DsRoleFreeMemory" => Ok(self.net_api_buffer_free(ctx.raw(0))),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WkstaInfoLayout {
    size: u64,
    computer_name_offset: u64,
    langroup_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    lanroot_offset: Option<u64>,
    logged_on_users_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct ServerInfo101Layout {
    size: u64,
    name_offset: u64,
    ver_major_offset: u64,
    ver_minor_offset: u64,
    server_type_offset: u64,
    comment_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DsRolePrimaryDomainInfoBasicLayout {
    size: u64,
    flags_offset: u64,
    flat_name_offset: u64,
    dns_name_offset: u64,
    forest_name_offset: u64,
    domain_guid_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct UserInfo1Layout {
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
pub struct UserInfo23Layout {
    size: u64,
    name_offset: u64,
    full_name_offset: u64,
    comment_offset: u64,
    flags_offset: u64,
    sid_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct LocalGroupInfo1Layout {
    size: u64,
    name_offset: u64,
    comment_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct LocalGroupMembersInfo12Layout {
    size: u64,
    sid_offset: u64,
    sid_use_offset: u64,
    name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ShareInfo1Layout {
    size: u64,
    name_offset: u64,
    share_type_offset: u64,
    remark_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct UseInfo1Layout {
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
pub struct UseInfo2Layout {
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
pub struct ShareInfo2Layout {
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
pub struct SessionInfo10Layout {
    size: u64,
    client_name_offset: u64,
    user_name_offset: u64,
    active_time_offset: u64,
    idle_time_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FileInfo3Layout {
    size: u64,
    id_offset: u64,
    permissions_offset: u64,
    num_locks_offset: u64,
    path_name_offset: u64,
    user_name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectionInfo1Layout {
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
pub struct TimeOfDayInfoLayout {
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
pub struct WkstaUserInfo1Layout {
    size: u64,
    user_name_offset: u64,
    logon_domain_offset: u64,
    other_domains_offset: u64,
    logon_server_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DomainControllerInfoLayout {
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
pub struct DomainTrustInfoLayout {
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
pub enum AccountLookupRecord {
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
pub struct DomainTrustRecord {
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
pub struct ServerInventoryRecord {
    name: String,
    comment: String,
    server_type: u32,
}

#[derive(Debug, Clone)]
pub struct ConnectionInventoryRecord {
    id: u32,
    connection_type: u32,
    num_opens: u32,
    num_users: u32,
    active_time_secs: u32,
    user_name: String,
    net_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEnumScope {
    Browser,
    LocalComputer,
}

mod netapi_layout;
mod netapi_query;
mod netapi_write;

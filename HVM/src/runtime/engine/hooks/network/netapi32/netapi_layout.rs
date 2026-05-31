use super::netapi_write::{
    builtin_alias_sid_bytes, deterministic_guid_le, domain_sid_base_bytes, domain_sid_bytes,
    is_builtin_alias_rid, local_account_sid_bytes, parse_guid_string_le,
};
use super::*;

impl VirtualExecutionEngine {
    pub fn wksta_info_layout(&self, level: u32) -> Option<WkstaInfoLayout> {
        if self.core.arch.is_x86() {
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

    pub fn server_info_101_layout(&self) -> ServerInfo101Layout {
        if self.core.arch.is_x86() {
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

    pub fn ds_role_primary_domain_info_basic_layout(&self) -> DsRolePrimaryDomainInfoBasicLayout {
        if self.core.arch.is_x86() {
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

    pub fn user_info_1_layout(&self) -> UserInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn user_info_23_layout(&self) -> UserInfo23Layout {
        if self.core.arch.is_x86() {
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

    pub fn local_group_info_1_layout(&self) -> LocalGroupInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn local_group_members_info_12_layout(&self) -> LocalGroupMembersInfo12Layout {
        if self.core.arch.is_x86() {
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

    pub fn share_info_1_layout(&self) -> ShareInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn use_info_1_layout(&self) -> UseInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn use_info_2_layout(&self) -> UseInfo2Layout {
        if self.core.arch.is_x86() {
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

    pub fn share_info_2_layout(&self) -> ShareInfo2Layout {
        if self.core.arch.is_x86() {
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

    pub fn session_info_10_layout(&self) -> SessionInfo10Layout {
        if self.core.arch.is_x86() {
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

    pub fn file_info_3_layout(&self) -> FileInfo3Layout {
        if self.core.arch.is_x86() {
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

    pub fn connection_info_1_layout(&self) -> ConnectionInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn time_of_day_info_layout(&self) -> TimeOfDayInfoLayout {
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

    pub fn wksta_user_info_1_layout(&self) -> WkstaUserInfo1Layout {
        if self.core.arch.is_x86() {
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

    pub fn domain_controller_info_layout(&self) -> DomainControllerInfoLayout {
        if self.core.arch.is_x86() {
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

    pub fn domain_trust_info_layout(&self) -> DomainTrustInfoLayout {
        if self.core.arch.is_x86() {
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

    pub fn netapi_domain_joined(&self) -> bool {
        !self.netapi_join_name().eq_ignore_ascii_case("WORKGROUP")
    }

    pub fn netapi_join_name(&self) -> String {
        let domain = self.core.environment_profile.machine.user_domain.trim();
        if domain.is_empty() {
            "WORKGROUP".to_string()
        } else {
            domain.to_string()
        }
    }

    pub fn netapi_join_status(&self) -> u32 {
        if self.netapi_domain_joined() {
            NETSETUP_DOMAIN_NAME
        } else {
            NETSETUP_WORKGROUP_NAME
        }
    }

    pub fn netapi_dns_domain_name(&self) -> String {
        if !self
            .core
            .environment_profile
            .machine
            .dns_domain_name
            .trim()
            .is_empty()
        {
            return self
                .core
                .environment_profile
                .machine
                .dns_domain_name
                .clone();
        }
        if !self.netapi_domain_joined() {
            return String::new();
        }
        let network_domain = self.core.environment_profile.network.domain_name.trim();
        if !network_domain.is_empty() && !network_domain.eq_ignore_ascii_case("lan") {
            return network_domain.to_string();
        }
        let dns_suffix = self.core.environment_profile.network.dns_suffix.trim();
        if !dns_suffix.is_empty() && !dns_suffix.eq_ignore_ascii_case("lan") {
            return dns_suffix.to_string();
        }
        format!("{}.local", self.netapi_join_name().to_ascii_lowercase())
    }

    pub fn netapi_forest_name(&self) -> String {
        if !self
            .core
            .environment_profile
            .machine
            .forest_name
            .trim()
            .is_empty()
        {
            return self.core.environment_profile.machine.forest_name.clone();
        }
        self.netapi_dns_domain_name()
    }

    pub fn netapi_domain_controller_name(&self) -> String {
        if !self.netapi_domain_joined() {
            return String::new();
        }
        let configured = self
            .core
            .environment_profile
            .machine
            .domain_controller
            .trim();
        if configured.is_empty() {
            format!(r"\\{}-DC01", self.netapi_join_name().to_ascii_uppercase())
        } else if configured.starts_with(r"\\") {
            configured.to_string()
        } else {
            format!(r"\\{configured}")
        }
    }

    pub fn netapi_domain_controller_host_name(&self) -> String {
        self.netapi_domain_controller_name()
            .trim_start_matches('\\')
            .to_string()
    }

    pub fn netapi_domain_controller_dns_name(&self) -> String {
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

    pub fn netapi_active_computer_dns_name(&self) -> String {
        let dns_domain = self.netapi_dns_domain_name();
        if dns_domain.is_empty() {
            self.active_computer_name().to_string()
        } else {
            format!("{}.{}", self.active_computer_name(), dns_domain)
        }
    }

    pub fn netapi_domain_controller_address(&self) -> String {
        let address = self
            .core
            .environment_profile
            .network
            .dns_servers
            .iter()
            .find(|value| !value.trim().is_empty())
            .cloned()
            .or_else(|| {
                self.core
                    .environment_profile
                    .network
                    .adapters
                    .iter()
                    .flat_map(|adapter| adapter.dns_servers.iter())
                    .find(|value| !value.trim().is_empty())
                    .cloned()
            })
            .or_else(|| {
                self.core
                    .environment_profile
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

    pub fn netapi_client_site_name(&self) -> String {
        "Default-First-Site-Name".to_string()
    }

    pub fn netapi_domain_guid_bytes(&self) -> [u8; 16] {
        if !self
            .core
            .environment_profile
            .machine
            .domain_guid
            .trim()
            .is_empty()
        {
            if let Some(bytes) =
                parse_guid_string_le(&self.core.environment_profile.machine.domain_guid)
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
            self.core.environment_profile.machine.machine_guid
        ))
    }

    pub fn netapi_domain_sid_bytes(&self) -> Vec<u8> {
        domain_sid_base_bytes(
            &self.netapi_dns_domain_name(),
            &self.core.environment_profile.machine.domain_guid,
        )
    }

    pub fn netapi_matches_requested_domain(&self, requested: &str) -> bool {
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

    pub fn netapi_matches_local_computer_scope(&self, requested: &str) -> bool {
        let requested = requested.trim().trim_start_matches('\\');
        !requested.is_empty()
            && (requested.eq_ignore_ascii_case(self.active_computer_name())
                || requested.eq_ignore_ascii_case(&self.netapi_active_computer_dns_name()))
    }

    pub fn netapi_resolve_server_enum_scope(
        &self,
        requested: &str,
    ) -> Result<ServerEnumScope, u64> {
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

    pub fn ds_role_machine_role(&self) -> u32 {
        match (
            self.core.environment_profile.os_version.product_type,
            self.netapi_domain_joined(),
        ) {
            (1, false) => DSROLE_ROLE_STANDALONE_WORKSTATION,
            (1, true) => DSROLE_ROLE_MEMBER_WORKSTATION,
            (_, false) => DSROLE_ROLE_STANDALONE_SERVER,
            (_, true) => DSROLE_ROLE_MEMBER_SERVER,
        }
    }

    pub fn netapi_users(&self) -> &[UserAccountProfile] {
        &self.core.environment_profile.users
    }

    pub fn netapi_find_user(&self, name: &str) -> Option<UserAccountProfile> {
        self.netapi_users()
            .iter()
            .find(|user| user.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    pub fn netapi_local_groups(&self) -> &[LocalGroupProfile] {
        &self.core.environment_profile.local_groups
    }

    pub fn netapi_find_local_group(&self, name: &str) -> Option<LocalGroupProfile> {
        self.netapi_local_groups()
            .iter()
            .find(|group| group.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    pub fn netapi_domain_groups(&self) -> Vec<LocalGroupProfile> {
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

    pub fn netapi_find_domain_group(&self, name: &str) -> Option<LocalGroupProfile> {
        self.netapi_domain_groups()
            .into_iter()
            .find(|group| group.name.eq_ignore_ascii_case(name))
    }

    pub fn netapi_group_domain(&self, group: &LocalGroupProfile) -> String {
        if !group.domain.trim().is_empty() {
            group.domain.clone()
        } else if is_builtin_alias_rid(group.rid) {
            "BUILTIN".to_string()
        } else {
            self.active_computer_name().to_string()
        }
    }

    pub fn netapi_group_sid(&self, group: &LocalGroupProfile) -> Vec<u8> {
        let group_domain = self.netapi_group_domain(group);
        if group_domain.eq_ignore_ascii_case("BUILTIN") {
            builtin_alias_sid_bytes(group.rid)
        } else if self.netapi_domain_joined()
            && (group_domain.eq_ignore_ascii_case(&self.netapi_join_name())
                || group_domain.eq_ignore_ascii_case(&self.netapi_dns_domain_name()))
        {
            domain_sid_bytes(
                &self.netapi_dns_domain_name(),
                &self.core.environment_profile.machine.domain_guid,
                group.rid,
            )
        } else {
            local_account_sid_bytes(
                &self.core.environment_profile.machine.machine_guid,
                group.rid,
            )
        }
    }
}

use super::netapi_write::{
    align_up, domain_sid_bytes, encoded_text_len, inline_text_storage_size,
    local_account_sid_bytes, netapi_matches_unc_name, optional_wide_storage_size,
    split_account_name, user_sid_bytes, wide_storage_size, write_inline_text_string,
    write_inline_wide_string, write_text,
};
use super::*;

impl VirtualExecutionEngine {
    fn read_optional_wide_string_pointer(&self, address: u64) -> Result<String, VmError> {
        if address == 0 || !self.core.modules.memory().is_range_mapped(address, 2) {
            Ok(String::new())
        } else {
            self.read_wide_string_from_memory(address)
        }
    }

    pub fn netapi_shares(&self) -> Vec<ShareProfile> {
        if !self.core.environment_profile.shares.is_empty() {
            return self.core.environment_profile.shares.clone();
        }

        let admin_share = ShareProfile {
            name: "ADMIN$".to_string(),
            share_type: STYPE_SPECIAL,
            remark: "Remote Admin".to_string(),
            path: self.core.environment_profile.machine.system_root.clone(),
            ..ShareProfile::default()
        };
        let drive_name = self
            .core
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
            path: self.core.environment_profile.volume.root_path.clone(),
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

    pub fn netapi_find_share(&self, name: &str) -> Option<ShareProfile> {
        self.netapi_shares()
            .into_iter()
            .find(|share| share.name.eq_ignore_ascii_case(name))
    }

    pub fn netapi_network_uses(&self) -> Vec<NetworkUseProfile> {
        if !self.core.environment_profile.network_uses.is_empty() {
            return self.core.environment_profile.network_uses.clone();
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
            user_name: self.core.environment_profile.machine.user_name.clone(),
            domain_name: self.netapi_join_name(),
            comment: "Default domain policy share".to_string(),
            ..NetworkUseProfile::default()
        }]
    }

    pub fn netapi_find_network_use(&self, use_name: &str) -> Option<NetworkUseProfile> {
        let requested = use_name.trim();
        self.netapi_network_uses().into_iter().find(|network_use| {
            network_use.local_name.eq_ignore_ascii_case(requested)
                || network_use.remote_name.eq_ignore_ascii_case(requested)
        })
    }

    pub fn ensure_materialized_netapi_network_uses(&mut self) {
        if !self.core.environment_profile.network_uses.is_empty() {
            return;
        }
        let defaults = self.netapi_network_uses();
        if !defaults.is_empty() {
            self.core.environment_profile.network_uses = defaults;
        }
    }

    pub fn netapi_use_add_conflict_status(&self, network_use: &NetworkUseProfile) -> u64 {
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

    pub fn netapi_parse_use_add_input(
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
                self.core.environment_profile.machine.user_name.clone()
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

    pub fn netapi_commit_network_use(&mut self, network_use: NetworkUseProfile) -> u64 {
        self.ensure_materialized_netapi_network_uses();
        let uses = &mut self.core.environment_profile.network_uses;
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

    pub fn netapi_use_del_by_name(&mut self, use_name: &str) -> u64 {
        self.ensure_materialized_netapi_network_uses();
        let requested = use_name.trim();
        let uses = &mut self.core.environment_profile.network_uses;
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

    pub fn netapi_is_valid_drive_name(&self, local_name: &str) -> bool {
        let bytes = local_name.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    }

    pub fn netapi_is_plausible_remote_name(&self, remote_name: &str) -> bool {
        let normalized = remote_name.trim();
        if !normalized.starts_with(r"\\") {
            return false;
        }
        let mut segments = normalized[2..]
            .split(['\\', '/'])
            .filter(|segment| !segment.trim().is_empty());
        segments.next().is_some() && segments.next().is_some()
    }

    pub fn netapi_workstation_users(&self) -> Vec<WorkstationUserProfile> {
        if !self.core.environment_profile.workstation_users.is_empty() {
            return self.core.environment_profile.workstation_users.clone();
        }

        let user_name = self.core.environment_profile.machine.user_name.trim();
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

    pub fn netapi_network_sessions(&self) -> Vec<NetworkSessionProfile> {
        if !self.core.environment_profile.network_sessions.is_empty() {
            return self.core.environment_profile.network_sessions.clone();
        }

        let derived = self.netapi_sessions_from_configured_open_files();
        if !derived.is_empty() {
            return derived;
        }

        self.netapi_default_network_sessions()
    }

    pub fn netapi_open_files(&self) -> Vec<OpenFileProfile> {
        if !self.core.environment_profile.open_files.is_empty() {
            return self.core.environment_profile.open_files.clone();
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

    pub fn netapi_sessions_from_configured_open_files(&self) -> Vec<NetworkSessionProfile> {
        if self.core.environment_profile.open_files.is_empty() {
            return Vec::new();
        }

        let mut sessions =
            std::collections::BTreeMap::<(String, String), NetworkSessionProfile>::new();
        for file in &self.core.environment_profile.open_files {
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

    pub fn netapi_default_network_sessions(&self) -> Vec<NetworkSessionProfile> {
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

    pub fn netapi_should_synthesize_network_session(&self) -> bool {
        self.netapi_domain_joined()
            || self
                .core
                .environment_profile
                .shares
                .iter()
                .any(|share| share.current_uses > 0)
    }

    pub fn netapi_default_session_user_name(&self) -> String {
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

    pub fn netapi_default_remote_client_name(&self) -> String {
        let candidate = self
            .core
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
                self.core
                    .environment_profile
                    .network
                    .dns_servers
                    .iter()
                    .find_map(|value| value.parse::<Ipv4Addr>().ok())
                    .map(|address| address.to_string())
            })
            .unwrap_or_else(|| "192.168.56.10".to_string());
        format!(r"\\{candidate}")
    }

    pub fn ensure_materialized_netapi_open_files(&mut self) {
        if !self.core.environment_profile.open_files.is_empty() {
            return;
        }
        let defaults = self.netapi_open_files();
        if !defaults.is_empty() {
            self.core.environment_profile.open_files = defaults;
        }
    }

    pub fn netapi_find_open_file(&self, file_id: u32) -> Option<OpenFileProfile> {
        self.netapi_open_files()
            .into_iter()
            .find(|file| file.id == file_id)
    }

    pub fn netapi_filter_open_files(
        &self,
        base_path: &str,
        user_name: &str,
    ) -> Vec<OpenFileProfile> {
        self.netapi_open_files()
            .into_iter()
            .filter(|file| self.netapi_matches_file_path(&file.path_name, base_path))
            .filter(|file| self.netapi_matches_file_user(&file.user_name, user_name))
            .collect()
    }

    pub fn netapi_matches_file_path(&self, file_path: &str, base_path: &str) -> bool {
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

    pub fn netapi_matches_file_user(&self, file_user: &str, requested_user: &str) -> bool {
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

    pub fn netapi_close_open_file(&mut self, file_id: u32) -> u64 {
        self.ensure_materialized_netapi_open_files();
        let files = &mut self.core.environment_profile.open_files;
        let original_len = files.len();
        files.retain(|file| file.id != file_id);
        if files.len() == original_len {
            NERR_FILE_ID_NOT_FOUND
        } else {
            ERROR_SUCCESS
        }
    }

    pub fn netapi_connection_inventory(
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

    pub fn netapi_share_for_open_file(
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

    pub fn netapi_share_type_for_device(&self, device: &str) -> Option<u32> {
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

    pub fn netapi_local_server_inventory_record(&self) -> ServerInventoryRecord {
        let mut server_type = SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_SERVER_NT;
        if self.netapi_domain_joined() {
            server_type |= SV_TYPE_DOMAIN_MEMBER;
        }
        ServerInventoryRecord {
            name: self.active_computer_name().to_string(),
            comment: self
                .core
                .environment_profile
                .os_version
                .product_name
                .clone(),
            server_type,
        }
    }

    pub fn netapi_browser_scope_name(&self) -> String {
        self.netapi_join_name()
    }

    pub fn netapi_server_inventory(&self) -> Vec<ServerInventoryRecord> {
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

    pub fn netapi_should_emit_domain_enum_entry(
        &self,
        server_type: u32,
        scope: ServerEnumScope,
    ) -> bool {
        scope == ServerEnumScope::Browser
            && server_type != 0
            && server_type != SV_TYPE_ALL
            && (server_type & SV_TYPE_DOMAIN_ENUM) != 0
    }

    pub fn netapi_server_inventory_for_enum(
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

    pub fn netapi_lookup_account_name_record(
        &self,
        account_name: &str,
    ) -> Option<AccountLookupRecord> {
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
                    &self.core.environment_profile.machine.domain_guid,
                    user.rid,
                )
            } else {
                local_account_sid_bytes(
                    &self.core.environment_profile.machine.machine_guid,
                    user.rid,
                )
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

    pub fn netapi_lookup_account_sid_record(&self, sid: &[u8]) -> Option<AccountLookupRecord> {
        for user in self.netapi_users() {
            let local_sid = local_account_sid_bytes(
                &self.core.environment_profile.machine.machine_guid,
                user.rid,
            );
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
                    &self.core.environment_profile.machine.domain_guid,
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

    pub fn net_api_buffer_free(&mut self, address: u64) -> u64 {
        if address != 0 {
            let _ = self
                .process_memory
                .heaps
                .free(self.process_memory.heaps.process_heap(), address);
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
        self.core.modules.memory_mut().write(sid_ptr, sid)?;
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

    pub fn net_get_join_information(
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

    pub fn net_get_dc_name(
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

    pub fn net_wksta_get_info(
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
        let mut required = align_up(layout.size, self.core.arch.pointer_size as u64);
        required += wide_storage_size(&computer_name);
        required += wide_storage_size(&langroup);
        if layout.lanroot_offset.is_some() {
            required += wide_storage_size(&lanroot);
        }

        let allocation = self.alloc_process_heap_block(required, "netapi32:NetWkstaGetInfo")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, PLATFORM_ID_NT)?;
        let mut cursor = align_up(allocation + layout.size, self.core.arch.pointer_size as u64);
        let computer_name_ptr = write_inline_wide_string(self, &mut cursor, &computer_name)?;
        let langroup_ptr = write_inline_wide_string(self, &mut cursor, &langroup)?;
        self.write_pointer_value(allocation + layout.computer_name_offset, computer_name_ptr)?;
        self.write_pointer_value(allocation + layout.langroup_offset, langroup_ptr)?;
        self.write_u32(
            allocation + layout.ver_major_offset,
            self.core.environment_profile.os_version.major,
        )?;
        self.write_u32(
            allocation + layout.ver_minor_offset,
            self.core.environment_profile.os_version.minor,
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

    pub fn net_user_enum(
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

    pub fn net_user_get_info(
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
                align_up(
                    self.core.arch.pointer_size as u64,
                    self.core.arch.pointer_size as u64,
                ) + wide_storage_size(&user.name)
            }
            USER_INFO_LEVEL_1 => {
                let layout = self.user_info_1_layout();
                let mut required = align_up(layout.size, self.core.arch.pointer_size as u64);
                required += optional_wide_storage_size(&user.name);
                required += optional_wide_storage_size(&user.home_dir);
                required += optional_wide_storage_size(&user.comment);
                required += optional_wide_storage_size(&user.script_path);
                required
            }
            USER_INFO_LEVEL_23 => {
                let layout = self.user_info_23_layout();
                let mut required = align_up(layout.size, self.core.arch.pointer_size as u64);
                required += optional_wide_storage_size(&user.name);
                required += optional_wide_storage_size(&user.full_name);
                required += optional_wide_storage_size(&user.comment);
                required += user_sid_bytes(
                    &self.core.environment_profile.machine.machine_guid,
                    user.rid,
                )
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

    pub fn net_user_add(
        &mut self,
        _server_name: &str,
        level: u32,
        buffer: u64,
        parm_err_ptr: u64,
    ) -> Result<u64, VmError> {
        if buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if parm_err_ptr != 0 {
            self.write_u32(parm_err_ptr, 0)?;
        }

        let profile = match level {
            USER_INFO_LEVEL_1 => {
                let layout = self.user_info_1_layout();
                let name_ptr = self.read_pointer_value(buffer + layout.name_offset)?;
                let name = self.read_optional_wide_string_pointer(name_ptr)?;
                let name = if name.trim().is_empty() {
                    self.core.environment_profile.machine.user_name.clone()
                } else {
                    name.trim().to_string()
                };
                UserAccountProfile {
                    name,
                    comment: self.read_optional_wide_string_pointer(
                        self.read_pointer_value(buffer + layout.comment_offset)?,
                    )?,
                    flags: self.read_u32(buffer + layout.flags_offset)?,
                    privilege_level: self.read_u32(buffer + layout.privilege_offset)?,
                    home_dir: self.read_optional_wide_string_pointer(
                        self.read_pointer_value(buffer + layout.home_dir_offset)?,
                    )?,
                    script_path: self.read_optional_wide_string_pointer(
                        self.read_pointer_value(buffer + layout.script_path_offset)?,
                    )?,
                    ..UserAccountProfile::default()
                }
            }
            USER_INFO_LEVEL_23 => {
                let layout = self.user_info_23_layout();
                let name_ptr = self.read_pointer_value(buffer + layout.name_offset)?;
                let name = self.read_optional_wide_string_pointer(name_ptr)?;
                let name = if name.trim().is_empty() {
                    self.core.environment_profile.machine.user_name.clone()
                } else {
                    name.trim().to_string()
                };
                let sid = self.read_pointer_value(buffer + layout.sid_offset)?;
                let rid = if sid != 0 && self.core.modules.memory().is_range_mapped(sid, 8) {
                    let sub_auth_count = self.read_bytes_from_memory(sid + 1, 1)?[0] as u64;
                    if sub_auth_count == 0 {
                        0
                    } else {
                        self.read_u32(sid + 8 + (sub_auth_count - 1) * 4)?
                    }
                } else {
                    0
                };
                UserAccountProfile {
                    name,
                    full_name: self.read_optional_wide_string_pointer(
                        self.read_pointer_value(buffer + layout.full_name_offset)?,
                    )?,
                    comment: self.read_optional_wide_string_pointer(
                        self.read_pointer_value(buffer + layout.comment_offset)?,
                    )?,
                    flags: self.read_u32(buffer + layout.flags_offset)?,
                    rid,
                    ..UserAccountProfile::default()
                }
            }
            _ => {
                self.set_last_error(ERROR_INVALID_LEVEL as u32);
                return Ok(ERROR_INVALID_LEVEL);
            }
        };

        let users = &mut self.core.environment_profile.users;
        if let Some(existing) = users
            .iter_mut()
            .find(|user| user.name.eq_ignore_ascii_case(&profile.name))
        {
            let rid = if profile.rid != 0 {
                profile.rid
            } else {
                existing.rid
            };
            *existing = UserAccountProfile { rid, ..profile };
        } else {
            let rid = if profile.rid != 0 {
                profile.rid
            } else {
                users.iter().map(|user| user.rid).max().unwrap_or(1000) + 1
            };
            users.push(UserAccountProfile { rid, ..profile });
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub fn net_user_set_info(
        &mut self,
        _server_name: &str,
        user_name: &str,
        level: u32,
        buffer: u64,
        parm_err_ptr: u64,
    ) -> Result<u64, VmError> {
        if parm_err_ptr != 0 {
            self.write_u32(parm_err_ptr, 0)?;
        }
        if buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(ERROR_INVALID_PARAMETER);
        }

        let target_name = if user_name.trim().is_empty() {
            self.core.environment_profile.machine.user_name.clone()
        } else {
            user_name.trim().to_string()
        };
        let mut full_name = String::new();
        let mut comment = String::new();
        let mut home_dir = String::new();
        let mut script_path = String::new();
        let mut flags = None;
        let mut privilege_level = None;

        match level {
            USER_INFO_LEVEL_1 => {
                let layout = self.user_info_1_layout();
                comment = self.read_optional_wide_string_pointer(
                    self.read_pointer_value(buffer + layout.comment_offset)?,
                )?;
                home_dir = self.read_optional_wide_string_pointer(
                    self.read_pointer_value(buffer + layout.home_dir_offset)?,
                )?;
                script_path = self.read_optional_wide_string_pointer(
                    self.read_pointer_value(buffer + layout.script_path_offset)?,
                )?;
                flags = self.read_u32(buffer + layout.flags_offset).ok();
                privilege_level = self.read_u32(buffer + layout.privilege_offset).ok();
            }
            USER_INFO_LEVEL_23 => {
                let layout = self.user_info_23_layout();
                full_name = self.read_optional_wide_string_pointer(
                    self.read_pointer_value(buffer + layout.full_name_offset)?,
                )?;
                comment = self.read_optional_wide_string_pointer(
                    self.read_pointer_value(buffer + layout.comment_offset)?,
                )?;
                flags = self.read_u32(buffer + layout.flags_offset).ok();
            }
            _ => {}
        }

        let users = &mut self.core.environment_profile.users;
        let user = if let Some(user) = users
            .iter_mut()
            .find(|user| user.name.eq_ignore_ascii_case(&target_name))
        {
            user
        } else {
            users.push(UserAccountProfile {
                name: target_name.clone(),
                home_dir: format!(r"C:\Users\{target_name}"),
                ..UserAccountProfile::default()
            });
            users.last_mut().unwrap()
        };
        if !full_name.trim().is_empty() {
            user.full_name = full_name;
        }
        if !comment.trim().is_empty() {
            user.comment = comment;
        }
        if !home_dir.trim().is_empty() {
            user.home_dir = home_dir;
        }
        if !script_path.trim().is_empty() {
            user.script_path = script_path;
        }
        if let Some(flags) = flags {
            user.flags = flags;
        }
        if let Some(privilege_level) = privilege_level {
            user.privilege_level = privilege_level;
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub fn net_group_enum(
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

    pub fn net_group_get_info(
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

    pub fn net_user_get_groups(
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

    pub fn net_group_get_users(
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

    pub fn net_use_enum(
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

    pub fn net_use_add(
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

    pub fn net_use_del(
        &mut self,
        _server_name: &str,
        use_name: &str,
        _force_cond: u32,
    ) -> Result<u64, VmError> {
        let status = self.netapi_use_del_by_name(use_name);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub fn net_use_get_info(
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

    pub fn net_share_enum(
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

    pub fn net_share_get_info(
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

    pub fn net_file_enum(
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

    pub fn net_file_get_info(
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

    pub fn net_file_close(&mut self, _server_name: &str, file_id: u32) -> Result<u64, VmError> {
        let status = self.netapi_close_open_file(file_id);
        self.set_last_error(status as u32);
        Ok(status)
    }

    pub fn net_connection_enum(
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

    pub fn net_share_check(
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

    pub fn net_remote_tod(&mut self, _server_name: &str, buffer_ptr: u64) -> Result<u64, VmError> {
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

    pub fn net_session_enum(
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

    pub fn net_wksta_user_enum(
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

    pub fn net_local_group_enum(
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

    pub fn net_user_get_local_groups(
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

    pub fn net_local_group_get_members(
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

    fn netapi_read_local_group_member_names(
        &self,
        level: u32,
        buffer_ptr: u64,
        total_entries: u32,
    ) -> Result<Vec<String>, VmError> {
        if buffer_ptr == 0 || total_entries == 0 {
            return Ok(Vec::new());
        }

        let mut member_names = Vec::new();
        let total_entries = total_entries.min(64) as u64;
        let pointer_size = self.core.arch.pointer_size as u64;
        match level {
            LOCALGROUP_MEMBERS_INFO_LEVEL_0 => {
                for index in 0..total_entries {
                    let sid_ptr = self.read_pointer_value(buffer_ptr + index * pointer_size)?;
                    let sid = self.read_account_sid_bytes(sid_ptr)?;
                    if let Some(record) = self.netapi_lookup_account_sid_record(&sid) {
                        let member_name = match record {
                            AccountLookupRecord::User { profile, .. } => profile.name,
                            AccountLookupRecord::Group { profile, .. } => profile.name,
                        };
                        if !member_name.trim().is_empty() {
                            member_names.push(member_name);
                        }
                    }
                }
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_1 | LOCALGROUP_MEMBERS_INFO_LEVEL_2 => {
                let layout = self.local_group_members_info_12_layout();
                for index in 0..total_entries {
                    let entry = buffer_ptr + index * layout.size;
                    let member_name = self.read_optional_wide_string_pointer(
                        self.read_pointer_value(entry + layout.name_offset)?,
                    )?;
                    if !member_name.trim().is_empty() {
                        let (_, requested_name) = split_account_name(member_name.trim());
                        member_names.push(requested_name.to_string());
                        continue;
                    }
                    let sid_ptr = self.read_pointer_value(entry + layout.sid_offset)?;
                    let sid = self.read_account_sid_bytes(sid_ptr)?;
                    if let Some(record) = self.netapi_lookup_account_sid_record(&sid) {
                        let member_name = match record {
                            AccountLookupRecord::User { profile, .. } => profile.name,
                            AccountLookupRecord::Group { profile, .. } => profile.name,
                        };
                        if !member_name.trim().is_empty() {
                            member_names.push(member_name);
                        }
                    }
                }
            }
            LOCALGROUP_MEMBERS_INFO_LEVEL_3 => {
                for index in 0..total_entries {
                    let name_ptr = self.read_pointer_value(buffer_ptr + index * pointer_size)?;
                    let member_name = self.read_optional_wide_string_pointer(name_ptr)?;
                    if !member_name.trim().is_empty() {
                        let (_, requested_name) = split_account_name(member_name.trim());
                        member_names.push(requested_name.to_string());
                    }
                }
            }
            _ => {}
        }
        Ok(member_names)
    }

    pub fn net_local_group_add_members(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
        total_entries: u32,
    ) -> Result<u64, VmError> {
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

        let mut member_names =
            self.netapi_read_local_group_member_names(level, buffer_ptr, total_entries)?;
        if member_names.is_empty() && !self.core.environment_profile.machine.user_name.is_empty() {
            member_names.push(self.core.environment_profile.machine.user_name.clone());
        }

        let groups = &mut self.core.environment_profile.local_groups;
        let group = if let Some(group) = groups
            .iter_mut()
            .find(|group| group.name.eq_ignore_ascii_case(group_name))
        {
            group
        } else {
            let rid = groups.iter().map(|group| group.rid).max().unwrap_or(1000) + 1;
            groups.push(LocalGroupProfile {
                name: group_name.trim().to_string(),
                comment: String::new(),
                domain: "BUILTIN".to_string(),
                rid,
                members: Vec::new(),
            });
            groups.last_mut().unwrap()
        };
        for member_name in member_names {
            if !group
                .members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(&member_name))
            {
                group.members.push(member_name);
            }
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub fn net_local_group_del_members(
        &mut self,
        _server_name: &str,
        group_name: &str,
        level: u32,
        buffer_ptr: u64,
        total_entries: u32,
    ) -> Result<u64, VmError> {
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

        let member_names =
            self.netapi_read_local_group_member_names(level, buffer_ptr, total_entries)?;
        if let Some(group) = self
            .core
            .environment_profile
            .local_groups
            .iter_mut()
            .find(|group| group.name.eq_ignore_ascii_case(group_name))
        {
            group.members.retain(|member| {
                !member_names
                    .iter()
                    .any(|member_name| member_name.eq_ignore_ascii_case(member))
            });
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }

    pub fn net_local_group_get_info(
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

    pub fn ds_get_dc_name(
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
        self.core
            .modules
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

    pub fn ds_enumerate_domain_trusts(
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
            self.core.arch.pointer_size as u64,
        );
        for (index, trust) in trusts.iter().enumerate() {
            let entry = allocation + index as u64 * layout.size;
            let netbios_name_ptr =
                write_inline_text_string(self, wide, &mut cursor, &trust.netbios_name)?;
            let dns_name_ptr = write_inline_text_string(self, wide, &mut cursor, &trust.dns_name)?;
            let sid_ptr = cursor;
            self.core.modules.memory_mut().write(sid_ptr, &trust.sid)?;
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
            self.core
                .modules
                .memory_mut()
                .write(entry + layout.guid_offset, &trust.guid)?;
        }
        self.write_pointer_value(domains_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }
}

use super::*;

impl VirtualExecutionEngine {
    pub fn read_account_sid_bytes(&self, sid_ptr: u64) -> Result<Vec<u8>, VmError> {
        if sid_ptr == 0 {
            return Ok(Vec::new());
        }
        let sub_auth_count = self.read_bytes_from_memory(sid_ptr + 1, 1)?[0] as usize;
        let sid_len = 8 + sub_auth_count.saturating_mul(4);
        self.read_bytes_from_memory(sid_ptr, sid_len)
    }

    pub fn name_pointer_list_required_size(&self, names: &[String]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
        let mut required = align_up(names.len() as u64 * pointer_size, pointer_size);
        for name in names {
            required += wide_storage_size(name);
        }
        required
    }

    pub fn net_share_required_size(&self, level: u32, shares: &[ShareProfile]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_server_info_101_required_size(&self, servers: &[ServerInventoryRecord]) -> u64 {
        let layout = self.server_info_101_layout();
        let mut required = align_up(
            servers.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
        );
        for server in servers {
            required += wide_storage_size(&server.name);
            required += optional_wide_storage_size(&server.comment);
        }
        required
    }

    pub fn net_use_required_size(&self, level: u32, uses: &[NetworkUseProfile]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_session_required_size(&self, sessions: &[NetworkSessionProfile]) -> u64 {
        let layout = self.session_info_10_layout();
        let mut required = align_up(
            sessions.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
        );
        for session in sessions {
            required += optional_wide_storage_size(&session.client_name);
            required += optional_wide_storage_size(&session.user_name);
        }
        required
    }

    pub fn net_file_required_size(&self, level: u32, files: &[OpenFileProfile]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_connection_required_size(
        &self,
        level: u32,
        connections: &[ConnectionInventoryRecord],
    ) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_wksta_user_required_size(
        &self,
        level: u32,
        users: &[WorkstationUserProfile],
    ) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_local_group_required_size(&self, level: u32, groups: &[LocalGroupProfile]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn write_local_group_info_0_entries(
        &mut self,
        base: u64,
        groups: &[LocalGroupProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
        let mut cursor = align_up(base + groups.len() as u64 * pointer_size, pointer_size);
        for (index, group) in groups.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &group.name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    pub fn write_local_group_info_1_entries(
        &mut self,
        base: u64,
        groups: &[LocalGroupProfile],
    ) -> Result<(), VmError> {
        let layout = self.local_group_info_1_layout();
        let mut cursor = align_up(
            base + groups.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
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

    pub fn write_name_pointer_entries(
        &mut self,
        base: u64,
        names: &[String],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
        let mut cursor = align_up(base + names.len() as u64 * pointer_size, pointer_size);
        for (index, name) in names.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    pub fn write_share_entries(
        &mut self,
        level: u32,
        base: u64,
        shares: &[ShareProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn write_server_info_101_entries(
        &mut self,
        base: u64,
        servers: &[ServerInventoryRecord],
    ) -> Result<(), VmError> {
        let layout = self.server_info_101_layout();
        let mut cursor = align_up(
            base + servers.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
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
                self.core.environment_profile.os_version.major,
            )?;
            self.write_u32(
                entry + layout.ver_minor_offset,
                self.core.environment_profile.os_version.minor,
            )?;
            self.write_u32(entry + layout.server_type_offset, server.server_type)?;
            self.write_pointer_value(entry + layout.comment_offset, comment_ptr)?;
        }
        Ok(())
    }

    pub fn write_use_entries(
        &mut self,
        level: u32,
        base: u64,
        uses: &[NetworkUseProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn write_session_entries(
        &mut self,
        base: u64,
        sessions: &[NetworkSessionProfile],
    ) -> Result<(), VmError> {
        let layout = self.session_info_10_layout();
        let mut cursor = align_up(
            base + sessions.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
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

    pub fn write_file_entries(
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
                    self.core.arch.pointer_size as u64,
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

    pub fn write_connection_entries(
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
                    self.core.arch.pointer_size as u64,
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

    pub fn write_time_of_day_info(&mut self, base: u64) -> Result<(), VmError> {
        let layout = self.time_of_day_info_layout();
        let current = self.dispatch.time.current();
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

    pub fn write_wksta_user_entries(
        &mut self,
        level: u32,
        base: u64,
        users: &[WorkstationUserProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn net_local_group_members_required_size(
        &self,
        level: u32,
        members: &[AccountLookupRecord],
    ) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn domain_trusts_required_size(&self, wide: bool, trusts: &[DomainTrustRecord]) -> u64 {
        let layout = self.domain_trust_info_layout();
        let mut required = align_up(
            trusts.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
        );
        for trust in trusts {
            required += inline_text_storage_size(wide, &trust.netbios_name);
            required += inline_text_storage_size(wide, &trust.dns_name);
            required += trust.sid.len() as u64;
        }
        required
    }

    pub fn write_local_group_member_entries(
        &mut self,
        level: u32,
        base: u64,
        members: &[AccountLookupRecord],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
        match level {
            LOCALGROUP_MEMBERS_INFO_LEVEL_0 => {
                let mut cursor = align_up(base + members.len() as u64 * pointer_size, pointer_size);
                for (index, member) in members.iter().enumerate() {
                    let entry = base + index as u64 * pointer_size;
                    let sid = account_lookup_sid(member);
                    let sid_ptr = cursor;
                    self.core.modules.memory_mut().write(sid_ptr, sid)?;
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
                    self.core.modules.memory_mut().write(sid_ptr, sid)?;
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

    pub fn net_server_get_info(
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
        let comment = self
            .core
            .environment_profile
            .os_version
            .product_name
            .clone();
        let mut required = align_up(layout.size, self.core.arch.pointer_size as u64);
        required += wide_storage_size(&name);
        required += wide_storage_size(&comment);

        let allocation = self.alloc_process_heap_block(required, "netapi32:NetServerGetInfo")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, PLATFORM_ID_NT)?;
        let mut cursor = align_up(allocation + layout.size, self.core.arch.pointer_size as u64);
        let name_ptr = write_inline_wide_string(self, &mut cursor, &name)?;
        let comment_ptr = write_inline_wide_string(self, &mut cursor, &comment)?;
        self.write_pointer_value(allocation + layout.name_offset, name_ptr)?;
        self.write_u32(
            allocation + layout.ver_major_offset,
            self.core.environment_profile.os_version.major,
        )?;
        self.write_u32(
            allocation + layout.ver_minor_offset,
            self.core.environment_profile.os_version.minor,
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

    pub fn net_server_enum(
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

    pub fn net_user_enum_required_size(&self, level: u32, users: &[UserAccountProfile]) -> u64 {
        let pointer_size = self.core.arch.pointer_size as u64;
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

    pub fn write_user_info_0_entries(
        &mut self,
        base: u64,
        users: &[UserAccountProfile],
    ) -> Result<(), VmError> {
        let pointer_size = self.core.arch.pointer_size as u64;
        let mut cursor = align_up(base + users.len() as u64 * pointer_size, pointer_size);
        for (index, user) in users.iter().enumerate() {
            let entry = base + index as u64 * pointer_size;
            let name_ptr = write_inline_wide_string(self, &mut cursor, &user.name)?;
            self.write_pointer_value(entry, name_ptr)?;
        }
        Ok(())
    }

    pub fn write_user_info_1_entries(
        &mut self,
        base: u64,
        users: &[UserAccountProfile],
    ) -> Result<(), VmError> {
        let layout = self.user_info_1_layout();
        let mut cursor = align_up(
            base + users.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
        );
        for (index, user) in users.iter().enumerate() {
            let entry = base + index as u64 * layout.size;
            self.write_user_info_1_at(entry, &mut cursor, user)?;
        }
        Ok(())
    }

    pub fn write_single_user_info_1(
        &mut self,
        base: u64,
        user: &UserAccountProfile,
    ) -> Result<(), VmError> {
        let layout = self.user_info_1_layout();
        let mut cursor = align_up(base + layout.size, self.core.arch.pointer_size as u64);
        self.write_user_info_1_at(base, &mut cursor, user)
    }

    pub fn write_user_info_1_at(
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

    pub fn write_single_user_info_23(
        &mut self,
        base: u64,
        user: &UserAccountProfile,
    ) -> Result<(), VmError> {
        let layout = self.user_info_23_layout();
        let mut cursor = align_up(base + layout.size, self.core.arch.pointer_size as u64);
        let name_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.name)?;
        let full_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.full_name)?;
        let comment_ptr = write_optional_inline_wide_string(self, &mut cursor, &user.comment)?;
        let sid = user_sid_bytes(
            &self.core.environment_profile.machine.machine_guid,
            user.rid,
        );
        let sid_ptr = cursor;
        self.core.modules.memory_mut().write(sid_ptr, &sid)?;
        self.write_pointer_value(base + layout.name_offset, name_ptr)?;
        self.write_pointer_value(base + layout.full_name_offset, full_name_ptr)?;
        self.write_pointer_value(base + layout.comment_offset, comment_ptr)?;
        self.write_u32(base + layout.flags_offset, user.flags)?;
        self.write_pointer_value(base + layout.sid_offset, sid_ptr)?;
        Ok(())
    }

    pub fn ds_role_get_primary_domain_information(
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
        let mut required = align_up(layout.size, self.core.arch.pointer_size as u64);
        required += optional_wide_storage_size(&flat_name);
        required += optional_wide_storage_size(&dns_name);
        required += optional_wide_storage_size(&forest_name);

        let allocation =
            self.alloc_process_heap_block(required, "netapi32:DsRoleGetPrimaryDomainInformation")?;
        self.fill_memory_pattern(allocation, required, 0)?;
        self.write_u32(allocation, self.ds_role_machine_role())?;
        self.write_u32(allocation + layout.flags_offset, 0)?;
        let mut cursor = align_up(allocation + layout.size, self.core.arch.pointer_size as u64);
        let flat_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &flat_name)?;
        let dns_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &dns_name)?;
        let forest_name_ptr = write_optional_inline_wide_string(self, &mut cursor, &forest_name)?;
        self.write_pointer_value(allocation + layout.flat_name_offset, flat_name_ptr)?;
        self.write_pointer_value(allocation + layout.dns_name_offset, dns_name_ptr)?;
        self.write_pointer_value(allocation + layout.forest_name_offset, forest_name_ptr)?;
        let domain_guid = self.netapi_domain_guid_bytes();
        self.core
            .modules
            .memory_mut()
            .write(allocation + layout.domain_guid_offset, &domain_guid)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(0)
    }
}

pub fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

pub fn wide_storage_size(value: &str) -> u64 {
    ((value.encode_utf16().count() + 1) * 2) as u64
}

pub fn optional_wide_storage_size(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        wide_storage_size(value)
    }
}

pub fn write_optional_inline_wide_string(
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

pub fn write_inline_wide_string(
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

pub fn write_inline_ansi_string(
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

pub fn write_inline_text_string(
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

pub fn inline_text_storage_size(wide: bool, value: &str) -> u64 {
    if wide {
        wide_storage_size(value)
    } else {
        (value.len() + 1) as u64
    }
}

pub fn deterministic_guid_le(seed: &str) -> [u8; 16] {
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

pub fn is_builtin_alias_rid(rid: u32) -> bool {
    matches!(
        rid,
        544 | 545 | 546 | 547 | 548 | 549 | 550 | 551 | 552 | 554 | 555
    )
}

pub fn encoded_text_len(wide: bool, value: &str) -> usize {
    if wide {
        value.encode_utf16().count() + 1
    } else {
        value.len() + 1
    }
}

pub fn write_text(
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

pub fn split_account_name(account_name: &str) -> (Option<&str>, &str) {
    if let Some((domain, name)) = account_name.split_once('\\') {
        (Some(domain), name)
    } else {
        (None, account_name)
    }
}

pub fn netapi_matches_unc_name(candidate: &str, requested: &str) -> bool {
    let requested = requested.trim();
    if requested.is_empty() {
        return true;
    }
    let normalized_candidate = candidate.trim().trim_start_matches('\\');
    let normalized_requested = requested.trim_start_matches('\\');
    normalized_candidate.eq_ignore_ascii_case(normalized_requested)
}

pub fn account_sid_base_bytes(seed_source: &str) -> Vec<u8> {
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

pub fn local_account_sid_bytes(machine_guid: &str, rid: u32) -> Vec<u8> {
    let mut sid = account_sid_base_bytes(machine_guid);
    sid[1] = 5;
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

pub fn domain_sid_base_bytes(dns_domain_name: &str, domain_guid: &str) -> Vec<u8> {
    let seed_source = if !domain_guid.trim().is_empty() {
        domain_guid.trim()
    } else {
        dns_domain_name.trim()
    };
    account_sid_base_bytes(seed_source)
}

pub fn domain_sid_bytes(dns_domain_name: &str, domain_guid: &str, rid: u32) -> Vec<u8> {
    let mut sid = domain_sid_base_bytes(dns_domain_name, domain_guid);
    sid[1] = 5;
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

pub fn builtin_alias_sid_bytes(rid: u32) -> Vec<u8> {
    let mut sid = vec![1u8, 2, 0, 0, 0, 0, 0, 5];
    sid.extend_from_slice(&32u32.to_le_bytes());
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

pub fn account_lookup_sid(record: &AccountLookupRecord) -> &[u8] {
    match record {
        AccountLookupRecord::User { sid, .. } | AccountLookupRecord::Group { sid, .. } => sid,
    }
}

pub fn account_lookup_sid_use(record: &AccountLookupRecord) -> u32 {
    match record {
        AccountLookupRecord::User { .. } => 1,
        AccountLookupRecord::Group { .. } => 4,
    }
}

pub fn account_lookup_qualified_name(record: &AccountLookupRecord) -> String {
    match record {
        AccountLookupRecord::User {
            profile, domain, ..
        } => format!(r"{domain}\{}", profile.name),
        AccountLookupRecord::Group {
            profile, domain, ..
        } => format!(r"{domain}\{}", profile.name),
    }
}

pub fn user_sid_bytes(machine_guid: &str, rid: u32) -> Vec<u8> {
    local_account_sid_bytes(machine_guid, rid)
}

pub fn parse_guid_string_le(guid: &str) -> Option<[u8; 16]> {
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

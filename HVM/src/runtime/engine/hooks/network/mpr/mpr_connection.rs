use super::mpr_resource::{
    align_up_local, inline_text_storage_size_local, inline_text_storage_size_required_local,
    write_inline_text_string_local,
};
use super::*;

impl VirtualExecutionEngine {
    pub(super) fn mpr_net_resource_layout(&self) -> NetResourceLayout {
        if self.core.arch.is_x86() {
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

    pub(super) fn mpr_net_info_layout(&self) -> NetInfoStructLayout {
        if self.core.arch.is_x86() {
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

    pub(super) fn mpr_net_connect_info_layout(&self) -> NetConnectInfoLayout {
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
                &self.core.environment_profile.machine.user_name,
                &self.mpr_default_user_domain(),
            )
        } else if let Some(network_use) = self.netapi_network_uses().into_iter().find(|entry| {
            entry.local_name.eq_ignore_ascii_case(requested)
                || entry.remote_name.eq_ignore_ascii_case(requested)
        }) {
            self.qualified_network_user_name(&network_use.user_name, &network_use.domain_name)
        } else {
            self.qualified_network_user_name(
                &self.core.environment_profile.machine.user_name,
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
        let pointer_size = self.core.arch.pointer_size as u64;
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
        let uses = &mut self.core.environment_profile.network_uses;
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
        let handle = self.network_state.network.allocate_custom(
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
        let Some(kind) = self.network_state.network.kind(enum_handle) else {
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
            .network_state
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
            .network_state
            .network
            .with_payload_mut::<MprEnumContext, _, _>(enum_handle, |context| {
                context.cursor = new_cursor;
            });
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn wnet_close_enum(&mut self, enum_handle: u32) -> u64 {
        if self.network_state.network.kind(enum_handle) != Some("mpr_enum") {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return ERROR_INVALID_HANDLE;
        }
        self.network_state.network.close_handle(enum_handle);
        self.set_last_error(ERROR_SUCCESS as u32);
        ERROR_SUCCESS
    }

    pub(super) fn qualified_network_user_name(&self, user_name: &str, domain_name: &str) -> String {
        if user_name.trim().is_empty() {
            String::new()
        } else if domain_name.trim().is_empty() {
            user_name.to_string()
        } else {
            format!(r"{}\{}", domain_name.trim(), user_name.trim())
        }
    }

    pub(super) fn mpr_default_user_domain(&self) -> String {
        let domain = self.core.environment_profile.machine.user_domain.trim();
        if domain.is_empty() || domain.eq_ignore_ascii_case("WORKGROUP") {
            self.active_computer_name().to_string()
        } else {
            domain.to_string()
        }
    }

    pub(super) fn mpr_default_provider_name(&self) -> String {
        NetworkUseProfile::default().provider
    }

    pub(super) fn mpr_is_supported_provider(&self, provider_name: &str) -> bool {
        let provider_name = provider_name.trim();
        !provider_name.is_empty()
            && provider_name.eq_ignore_ascii_case(&self.mpr_default_provider_name())
    }

    pub(super) fn mpr_matches_network_type(&self, net_type: u32) -> bool {
        net_type == WNNC_NET_LANMAN || net_type == u32::from(WNNC_NET_LANMAN_WORD)
    }

    pub(super) fn mpr_mapped_drive_count(&self) -> usize {
        self.netapi_network_uses()
            .into_iter()
            .filter(|network_use| self.is_valid_drive_name(&network_use.local_name))
            .count()
    }
}

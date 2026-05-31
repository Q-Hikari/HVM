use super::*;

impl VirtualExecutionEngine {
    pub(super) fn prepare_mpr_connection_request(
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

    pub(super) fn prepare_legacy_mpr_connection_request(
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
            user_name: self.core.environment_profile.machine.user_name.clone(),
            domain_name: self.mpr_default_user_domain(),
            provider: NetworkUseProfile::default().provider,
            comment: String::new(),
            assignment_type: USE_DISKDEV,
        })
    }

    pub(super) fn commit_mpr_connection(&mut self, request: MprConnectionRequest) -> u64 {
        self.ensure_materialized_network_uses();
        let uses = &mut self.core.environment_profile.network_uses;

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

    pub(super) fn mpr_connection_conflict_status(&self, request: &MprConnectionRequest) -> u64 {
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

    pub(super) fn ensure_materialized_network_uses(&mut self) {
        if !self.core.environment_profile.network_uses.is_empty() {
            return;
        }
        let defaults = self.netapi_network_uses();
        if !defaults.is_empty() {
            self.core.environment_profile.network_uses = defaults;
        }
    }

    pub(super) fn read_mpr_net_resource(
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

    pub(super) fn read_mpr_input_text(&self, wide: bool, address: u64) -> Result<String, u64> {
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

    pub(super) fn parse_network_user_identity(&self, user_id: &str) -> (String, String) {
        let requested = user_id.trim();
        if requested.is_empty() {
            return (
                self.core.environment_profile.machine.user_name.clone(),
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

    pub(super) fn next_available_network_drive_name(&self) -> Option<String> {
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

    pub(super) fn is_plausible_unc_path(&self, remote_name: &str) -> bool {
        let normalized = remote_name.trim();
        if !normalized.starts_with(r"\\") {
            return false;
        }
        let mut segments = normalized[2..]
            .split(['\\', '/'])
            .filter(|segment| !segment.trim().is_empty());
        segments.next().is_some() && segments.next().is_some()
    }

    pub(super) fn is_valid_drive_name(&self, local_name: &str) -> bool {
        let bytes = local_name.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    }

    pub(super) fn resolve_mpr_resource_information(
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

    pub(super) fn resolve_mpr_resource_parent(
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

    pub(super) fn write_mpr_resource_query_result(
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

    pub(super) fn write_output_net_resource(
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

    pub(super) fn mpr_output_net_resource_required_size(
        &self,
        wide: bool,
        resolved: &MprResolvedResourceInfo,
    ) -> u64 {
        let layout = self.mpr_net_resource_layout();
        align_up_local(layout.size, self.core.arch.pointer_size as u64)
            + inline_text_storage_size_local(wide, &resolved.resource.local_name)
            + inline_text_storage_size_local(wide, &resolved.resource.remote_name)
            + inline_text_storage_size_local(wide, &resolved.resource.comment)
            + inline_text_storage_size_local(wide, &resolved.resource.provider)
            + inline_text_storage_size_local(wide, &resolved.system)
    }

    pub(super) fn resolve_mpr_requested_remote_name(
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

    pub(super) fn parse_unc_resource_path(
        &self,
        remote_name: &str,
    ) -> Option<(String, String, String)> {
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

    pub(super) fn find_matching_network_use_for_remote(
        &self,
        remote_name: &str,
    ) -> Option<NetworkUseProfile> {
        self.netapi_network_uses()
            .into_iter()
            .filter(|network_use| {
                self.mpr_remote_path_matches_prefix(remote_name, &network_use.remote_name)
            })
            .max_by_key(|network_use| network_use.remote_name.len())
    }

    pub(super) fn mpr_remote_path_matches_prefix(&self, requested: &str, prefix: &str) -> bool {
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

    pub(super) fn mpr_resolve_provider_name(&self, provider_name: &str) -> Result<String, u64> {
        if provider_name.trim().is_empty() {
            return Ok(self.mpr_default_provider_name());
        }
        if self.mpr_is_supported_provider(provider_name) {
            return Ok(self.mpr_default_provider_name());
        }
        Err(ERROR_BAD_PROVIDER)
    }

    pub(super) fn mpr_share_comment(
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

    pub(super) fn mpr_server_comment(&self, server_name: &str) -> String {
        if self.mpr_server_matches_active_host(server_name) {
            return self
                .core
                .environment_profile
                .os_version
                .product_name
                .clone();
        }

        let domain_controller = self
            .core
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
            let domain_name = self.core.environment_profile.machine.user_domain.trim();
            if !domain_name.is_empty() && !domain_name.eq_ignore_ascii_case("WORKGROUP") {
                return format!("{domain_name} Domain Controller");
            }
            return "Domain Controller".to_string();
        }

        String::new()
    }

    pub(super) fn mpr_server_matches_active_host(&self, server_name: &str) -> bool {
        if server_name.eq_ignore_ascii_case(self.active_computer_name()) {
            return true;
        }
        let dns_domain = self.core.environment_profile.machine.dns_domain_name.trim();
        !dns_domain.is_empty()
            && server_name.eq_ignore_ascii_case(&format!(
                "{}.{}",
                self.active_computer_name(),
                dns_domain
            ))
    }

    pub(super) fn map_local_path_to_universal_name(
        &self,
        local_path: &str,
    ) -> Option<UniversalNameMapping> {
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

    pub(super) fn write_text_result(
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

    pub(super) fn write_text_buffer_fixed(
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

    pub(super) fn mpr_error_message(&self, code: u64) -> String {
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

    pub(super) fn net_resource_required_size(
        &self,
        wide: bool,
        entries: &[NetworkUseProfile],
    ) -> u64 {
        let layout = self.mpr_net_resource_layout();
        let mut required = align_up_local(
            entries.len() as u64 * layout.size,
            self.core.arch.pointer_size as u64,
        );
        for entry in entries {
            required += inline_text_storage_size_local(wide, &entry.local_name);
            required += inline_text_storage_size_local(wide, &entry.remote_name);
            required += inline_text_storage_size_local(wide, &entry.comment);
            required += inline_text_storage_size_local(wide, &entry.provider);
        }
        required
    }

    pub(super) fn write_net_resource_entries(
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

pub(super) fn write_optional_inline_text_string(
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

pub(super) fn write_inline_text_string_local(
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

pub(super) fn align_up_local(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

pub(super) fn inline_text_storage_size_local(wide: bool, value: &str) -> u64 {
    if value.is_empty() {
        0
    } else if wide {
        ((value.encode_utf16().count() + 1) * 2) as u64
    } else {
        (value.len() + 1) as u64
    }
}

pub(super) fn inline_text_storage_size_required_local(wide: bool, value: &str) -> u64 {
    if wide {
        ((value.encode_utf16().count() + 1) * 2) as u64
    } else {
        (value.len() + 1) as u64
    }
}

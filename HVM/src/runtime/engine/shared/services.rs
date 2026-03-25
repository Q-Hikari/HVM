use super::*;

use crate::environment_profile::ServiceProfile;

#[derive(Debug, Clone, Copy)]
struct EnumServiceStatusProcessLayout {
    size: u64,
    service_name_offset: u64,
    display_name_offset: u64,
    status_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct QueryServiceConfigLayout {
    size: u64,
    binary_path_offset: u64,
    load_order_group_offset: u64,
    tag_id_offset: u64,
    dependencies_offset: u64,
    service_start_name_offset: u64,
    display_name_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct FailureActionsLayout {
    size: u64,
    reboot_msg_offset: u64,
    command_offset: u64,
    actions_count_offset: u64,
    actions_offset: u64,
}

impl VirtualExecutionEngine {
    fn service_state_name(state: u32) -> &'static str {
        match state {
            SERVICE_STOPPED => "SERVICE_STOPPED",
            0x0000_0002 => "SERVICE_START_PENDING",
            0x0000_0003 => "SERVICE_STOP_PENDING",
            SERVICE_RUNNING => "SERVICE_RUNNING",
            0x0000_0005 => "SERVICE_CONTINUE_PENDING",
            0x0000_0006 => "SERVICE_PAUSE_PENDING",
            0x0000_0007 => "SERVICE_PAUSED",
            _ => "SERVICE_STATE_UNKNOWN",
        }
    }

    fn service_control_name(control: u32) -> &'static str {
        match control {
            SERVICE_CONTROL_STOP => "SERVICE_CONTROL_STOP",
            SERVICE_CONTROL_PAUSE => "SERVICE_CONTROL_PAUSE",
            SERVICE_CONTROL_CONTINUE => "SERVICE_CONTROL_CONTINUE",
            SERVICE_CONTROL_INTERROGATE => "SERVICE_CONTROL_INTERROGATE",
            SERVICE_CONTROL_SHUTDOWN => "SERVICE_CONTROL_SHUTDOWN",
            SERVICE_CONTROL_PRESHUTDOWN => "SERVICE_CONTROL_PRESHUTDOWN",
            _ => "SERVICE_CONTROL_UNKNOWN",
        }
    }

    fn log_service_manager_event(
        &mut self,
        machine_name: &str,
        database_name: &str,
        access: u32,
        handle: u32,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("machine_name".to_string(), json!(machine_name));
        fields.insert("database_name".to_string(), json!(database_name));
        fields.insert("access".to_string(), json!(access));
        fields.insert("manager_handle".to_string(), json!(handle));
        self.log_runtime_event("SERVICE_OPEN_MANAGER", fields)
    }

    fn log_service_open_event(
        &mut self,
        manager_handle: u32,
        service_name: &str,
        access: u32,
        handle: u32,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("manager_handle".to_string(), json!(manager_handle));
        fields.insert("service_name".to_string(), json!(service_name));
        fields.insert("access".to_string(), json!(access));
        fields.insert("service_handle".to_string(), json!(handle));
        self.log_runtime_event("SERVICE_OPEN", fields)
    }

    fn log_service_state_transition(
        &mut self,
        marker: &str,
        service_name: &str,
        handle: u32,
        control: Option<u32>,
        previous_state: u32,
        next_state: u32,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("service_name".to_string(), json!(service_name));
        fields.insert("service_handle".to_string(), json!(handle));
        fields.insert("previous_state".to_string(), json!(previous_state));
        fields.insert(
            "previous_state_name".to_string(),
            json!(Self::service_state_name(previous_state)),
        );
        fields.insert("next_state".to_string(), json!(next_state));
        fields.insert(
            "next_state_name".to_string(),
            json!(Self::service_state_name(next_state)),
        );
        if let Some(control) = control {
            fields.insert("control".to_string(), json!(control));
            fields.insert(
                "control_name".to_string(),
                json!(Self::service_control_name(control)),
            );
        }
        self.log_runtime_event(marker, fields)
    }

    fn enum_service_status_process_layout(&self) -> EnumServiceStatusProcessLayout {
        if self.arch.is_x86() {
            EnumServiceStatusProcessLayout {
                size: 44,
                service_name_offset: 0,
                display_name_offset: 4,
                status_offset: 8,
            }
        } else {
            EnumServiceStatusProcessLayout {
                size: 56,
                service_name_offset: 0,
                display_name_offset: 8,
                status_offset: 16,
            }
        }
    }

    fn query_service_config_layout(&self) -> QueryServiceConfigLayout {
        if self.arch.is_x86() {
            QueryServiceConfigLayout {
                size: 36,
                binary_path_offset: 12,
                load_order_group_offset: 16,
                tag_id_offset: 20,
                dependencies_offset: 24,
                service_start_name_offset: 28,
                display_name_offset: 32,
            }
        } else {
            QueryServiceConfigLayout {
                size: 64,
                binary_path_offset: 16,
                load_order_group_offset: 24,
                tag_id_offset: 32,
                dependencies_offset: 40,
                service_start_name_offset: 48,
                display_name_offset: 56,
            }
        }
    }

    fn failure_actions_layout(&self) -> FailureActionsLayout {
        if self.arch.is_x86() {
            FailureActionsLayout {
                size: 20,
                reboot_msg_offset: 4,
                command_offset: 8,
                actions_count_offset: 12,
                actions_offset: 16,
            }
        } else {
            FailureActionsLayout {
                size: 40,
                reboot_msg_offset: 8,
                command_offset: 16,
                actions_count_offset: 24,
                actions_offset: 32,
            }
        }
    }

    pub(in crate::runtime::engine) fn open_sc_manager(
        &mut self,
        machine_name: &str,
        database_name: &str,
        access: u32,
    ) -> Result<u64, VmError> {
        let database_name = if database_name.trim().is_empty() {
            "ServicesActive"
        } else {
            database_name
        };
        let handle = self
            .services
            .open_manager(machine_name, database_name, access);
        self.set_last_error(ERROR_SUCCESS as u32);
        self.log_service_manager_event(machine_name, database_name, access, handle)?;
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn open_service_handle(
        &mut self,
        manager_handle: u32,
        service_name: &str,
        access: u32,
    ) -> Result<u64, VmError> {
        let Some(handle) = self
            .services
            .open_service(manager_handle, service_name, access)
        else {
            self.set_last_error(if self.services.is_manager_handle(manager_handle) {
                ERROR_SERVICE_DOES_NOT_EXIST as u32
            } else {
                ERROR_INVALID_HANDLE as u32
            });
            return Ok(0);
        };
        self.set_last_error(ERROR_SUCCESS as u32);
        self.log_service_open_event(manager_handle, service_name, access, handle)?;
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn close_service_handle(&mut self, handle: u32) -> u64 {
        let ok = self.services.close_handle(handle);
        self.set_last_error(if ok {
            ERROR_SUCCESS as u32
        } else {
            ERROR_INVALID_HANDLE as u32
        });
        ok as u64
    }

    pub(in crate::runtime::engine) fn query_service_status(
        &mut self,
        handle: u32,
        status_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        if status_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        self.write_service_status(status_ptr, &service)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn query_service_status_ex(
        &mut self,
        handle: u32,
        info_level: u64,
        buffer: u64,
        buffer_size: u32,
        bytes_needed_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        if info_level != SC_STATUS_PROCESS_INFO {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(0);
        }

        const SERVICE_STATUS_PROCESS_SIZE: u32 = 36;
        if bytes_needed_ptr != 0 {
            self.write_u32(bytes_needed_ptr, SERVICE_STATUS_PROCESS_SIZE)?;
        }
        if buffer == 0 || buffer_size < SERVICE_STATUS_PROCESS_SIZE {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        self.write_service_status_process(buffer, &service)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn query_service_config(
        &mut self,
        wide: bool,
        handle: u32,
        buffer: u64,
        buffer_size: u32,
        bytes_needed_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };

        let layout = self.query_service_config_layout();
        let mut required = align_up(layout.size, self.arch.pointer_size as u64);
        required += optional_text_storage_size(wide, &service.binary_path);
        required += optional_text_storage_size(wide, &service.load_order_group);
        required += optional_multi_storage_size(wide, &service.dependencies);
        required += optional_text_storage_size(wide, &service.start_name);
        required += optional_text_storage_size(wide, &service.display_name);

        if bytes_needed_ptr != 0 {
            self.write_u32(bytes_needed_ptr, required.min(u32::MAX as u64) as u32)?;
        }
        if buffer == 0 || (buffer_size as u64) < required {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        self.write_u32(buffer, service.service_type)?;
        self.write_u32(buffer + 4, service.start_type)?;
        self.write_u32(buffer + 8, service.error_control)?;

        let mut cursor = align_up(buffer + layout.size, self.arch.pointer_size as u64);
        let binary_path = if wide {
            write_optional_inline_wide_string(self, &mut cursor, &service.binary_path)?
        } else {
            write_optional_inline_ansi_string(self, &mut cursor, &service.binary_path)?
        };
        let load_order_group = if wide {
            write_optional_inline_wide_string(self, &mut cursor, &service.load_order_group)?
        } else {
            write_optional_inline_ansi_string(self, &mut cursor, &service.load_order_group)?
        };
        let dependencies = if wide {
            write_optional_inline_wide_multi_string(self, &mut cursor, &service.dependencies)?
        } else {
            write_optional_inline_ansi_multi_string(self, &mut cursor, &service.dependencies)?
        };
        let start_name = if wide {
            write_optional_inline_wide_string(self, &mut cursor, &service.start_name)?
        } else {
            write_optional_inline_ansi_string(self, &mut cursor, &service.start_name)?
        };
        let display_name = if wide {
            write_optional_inline_wide_string(self, &mut cursor, &service.display_name)?
        } else {
            write_optional_inline_ansi_string(self, &mut cursor, &service.display_name)?
        };

        self.write_pointer_value(buffer + layout.binary_path_offset, binary_path)?;
        self.write_pointer_value(buffer + layout.load_order_group_offset, load_order_group)?;
        self.write_u32(buffer + layout.tag_id_offset, service.tag_id)?;
        self.write_pointer_value(buffer + layout.dependencies_offset, dependencies)?;
        self.write_pointer_value(buffer + layout.service_start_name_offset, start_name)?;
        self.write_pointer_value(buffer + layout.display_name_offset, display_name)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn query_service_config2(
        &mut self,
        wide: bool,
        handle: u32,
        info_level: u64,
        buffer: u64,
        buffer_size: u32,
        bytes_needed_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };

        let required = match info_level {
            SERVICE_CONFIG_DESCRIPTION => {
                self.arch.pointer_size as u64
                    + optional_text_storage_size(wide, &service.description)
            }
            SERVICE_CONFIG_FAILURE_ACTIONS => {
                let layout = self.failure_actions_layout();
                align_up(layout.size, self.arch.pointer_size as u64)
                    + optional_text_storage_size(wide, &service.failure_reboot_message)
                    + optional_text_storage_size(wide, &service.failure_command)
            }
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO
            | SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
            | SERVICE_CONFIG_SERVICE_SID_INFO
            | SERVICE_CONFIG_PRESHUTDOWN_INFO => 4,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO => {
                self.arch.pointer_size as u64
                    + optional_multi_storage_size(wide, &service.required_privileges)
            }
            _ => {
                self.set_last_error(ERROR_INVALID_LEVEL as u32);
                return Ok(0);
            }
        };

        if bytes_needed_ptr != 0 {
            self.write_u32(bytes_needed_ptr, required.min(u32::MAX as u64) as u32)?;
        }
        if buffer == 0 || (buffer_size as u64) < required {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        match info_level {
            SERVICE_CONFIG_DESCRIPTION => {
                let mut cursor = align_up(
                    buffer + self.arch.pointer_size as u64,
                    self.arch.pointer_size as u64,
                );
                let description = if wide {
                    write_optional_inline_wide_string(self, &mut cursor, &service.description)?
                } else {
                    write_optional_inline_ansi_string(self, &mut cursor, &service.description)?
                };
                self.write_pointer_value(buffer, description)?;
            }
            SERVICE_CONFIG_FAILURE_ACTIONS => {
                let layout = self.failure_actions_layout();
                let mut cursor = align_up(buffer + layout.size, self.arch.pointer_size as u64);
                let reboot_message = if wide {
                    write_optional_inline_wide_string(
                        self,
                        &mut cursor,
                        &service.failure_reboot_message,
                    )?
                } else {
                    write_optional_inline_ansi_string(
                        self,
                        &mut cursor,
                        &service.failure_reboot_message,
                    )?
                };
                let command = if wide {
                    write_optional_inline_wide_string(self, &mut cursor, &service.failure_command)?
                } else {
                    write_optional_inline_ansi_string(self, &mut cursor, &service.failure_command)?
                };
                self.write_u32(buffer, service.failure_reset_period_secs)?;
                self.write_pointer_value(buffer + layout.reboot_msg_offset, reboot_message)?;
                self.write_pointer_value(buffer + layout.command_offset, command)?;
                self.write_u32(buffer + layout.actions_count_offset, 0)?;
                self.write_pointer_value(buffer + layout.actions_offset, 0)?;
            }
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO => {
                self.write_u32(buffer, service.delayed_auto_start as u32)?;
            }
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG => {
                self.write_u32(buffer, service.failure_actions_on_non_crash_failures as u32)?;
            }
            SERVICE_CONFIG_SERVICE_SID_INFO => {
                self.write_u32(buffer, service.service_sid_type)?;
            }
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO => {
                let mut cursor = align_up(
                    buffer + self.arch.pointer_size as u64,
                    self.arch.pointer_size as u64,
                );
                let privileges = if wide {
                    write_optional_inline_wide_multi_string(
                        self,
                        &mut cursor,
                        &service.required_privileges,
                    )?
                } else {
                    write_optional_inline_ansi_multi_string(
                        self,
                        &mut cursor,
                        &service.required_privileges,
                    )?
                };
                self.write_pointer_value(buffer, privileges)?;
            }
            SERVICE_CONFIG_PRESHUTDOWN_INFO => {
                self.write_u32(buffer, service.pre_shutdown_timeout_ms)?;
            }
            _ => unreachable!(),
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn enum_services_status_ex(
        &mut self,
        wide: bool,
        manager_handle: u32,
        info_level: u64,
        service_type: u32,
        service_state: u32,
        buffer: u64,
        buffer_size: u32,
        bytes_needed_ptr: u64,
        services_returned_ptr: u64,
        resume_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.services.is_manager_handle(manager_handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        if info_level != SC_STATUS_PROCESS_INFO {
            self.set_last_error(ERROR_INVALID_LEVEL as u32);
            return Ok(0);
        }

        let services = self.filtered_services(service_type, service_state);
        let layout = self.enum_service_status_process_layout();
        let mut required = services.len() as u64 * layout.size;
        required = align_up(required, self.arch.pointer_size as u64);
        for service in &services {
            required += optional_text_storage_size(wide, &service.name);
            required += optional_text_storage_size(wide, &service.display_name);
        }

        if bytes_needed_ptr != 0 {
            self.write_u32(bytes_needed_ptr, required.min(u32::MAX as u64) as u32)?;
        }
        if services_returned_ptr != 0 {
            self.write_u32(services_returned_ptr, 0)?;
        }
        if resume_handle_ptr != 0 {
            self.write_u32(resume_handle_ptr, 0)?;
        }

        if buffer == 0 || (buffer_size as u64) < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(0);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        let mut string_cursor = align_up(
            buffer + services.len() as u64 * layout.size,
            self.arch.pointer_size as u64,
        );
        for (index, service) in services.iter().enumerate() {
            let entry = buffer + index as u64 * layout.size;
            let service_name = if wide {
                write_inline_wide_string(self, &mut string_cursor, &service.name)?
            } else {
                write_inline_ansi_string(self, &mut string_cursor, &service.name)?
            };
            let display_name = if wide {
                write_inline_wide_string(self, &mut string_cursor, &service.display_name)?
            } else {
                write_inline_ansi_string(self, &mut string_cursor, &service.display_name)?
            };
            self.write_pointer_value(entry + layout.service_name_offset, service_name)?;
            self.write_pointer_value(entry + layout.display_name_offset, display_name)?;
            self.write_service_status_process(entry + layout.status_offset, service)?;
        }

        if services_returned_ptr != 0 {
            self.write_u32(services_returned_ptr, services.len() as u32)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn start_service(
        &mut self,
        handle: u32,
        num_args: u32,
        args_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.services.is_service_handle(handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        if num_args != 0 && args_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        if service.current_state != SERVICE_STOPPED {
            self.set_last_error(ERROR_SERVICE_ALREADY_RUNNING as u32);
            return Ok(0);
        }

        self.services.update_service(handle, |stored| {
            stored.current_state = SERVICE_RUNNING;
            stored.win32_exit_code = 0;
            stored.service_specific_exit_code = 0;
            stored.check_point = 0;
            stored.wait_hint = 0;
            if stored.process_id == 0 {
                stored.process_id = synthetic_service_process_id(&stored.name);
            }
        });
        self.log_service_state_transition(
            "SERVICE_START",
            &service.name,
            handle,
            None,
            service.current_state,
            SERVICE_RUNNING,
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn control_service(
        &mut self,
        handle: u32,
        control: u32,
        status_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(service) = self.services.get_service(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };

        let previous_state = service.current_state;
        let accepted = effective_controls_accepted(&service);
        let next_state = match control {
            SERVICE_CONTROL_INTERROGATE => Some(previous_state),
            SERVICE_CONTROL_STOP => {
                if previous_state == SERVICE_STOPPED {
                    self.set_last_error(ERROR_SERVICE_NOT_ACTIVE as u32);
                    return Ok(0);
                }
                if accepted & SERVICE_ACCEPT_STOP == 0 {
                    self.set_last_error(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as u32);
                    return Ok(0);
                }
                Some(SERVICE_STOPPED)
            }
            SERVICE_CONTROL_PAUSE => {
                if previous_state == SERVICE_STOPPED {
                    self.set_last_error(ERROR_SERVICE_NOT_ACTIVE as u32);
                    return Ok(0);
                }
                if previous_state != SERVICE_RUNNING
                    || accepted & SERVICE_ACCEPT_PAUSE_CONTINUE == 0
                {
                    self.set_last_error(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as u32);
                    return Ok(0);
                }
                Some(SERVICE_PAUSED)
            }
            SERVICE_CONTROL_CONTINUE => {
                if previous_state == SERVICE_STOPPED {
                    self.set_last_error(ERROR_SERVICE_NOT_ACTIVE as u32);
                    return Ok(0);
                }
                if previous_state != SERVICE_PAUSED || accepted & SERVICE_ACCEPT_PAUSE_CONTINUE == 0
                {
                    self.set_last_error(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as u32);
                    return Ok(0);
                }
                Some(SERVICE_RUNNING)
            }
            SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
                if previous_state == SERVICE_STOPPED {
                    self.set_last_error(ERROR_SERVICE_NOT_ACTIVE as u32);
                    return Ok(0);
                }
                if accepted & SERVICE_ACCEPT_SHUTDOWN == 0 {
                    self.set_last_error(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as u32);
                    return Ok(0);
                }
                Some(SERVICE_STOPPED)
            }
            _ => {
                self.set_last_error(ERROR_INVALID_SERVICE_CONTROL as u32);
                return Ok(0);
            }
        };

        if let Some(next_state) = next_state {
            self.services.update_service(handle, |stored| {
                stored.current_state = next_state;
                stored.win32_exit_code = 0;
                stored.service_specific_exit_code = 0;
                stored.check_point = 0;
                stored.wait_hint = 0;
                if next_state == SERVICE_STOPPED {
                    stored.process_id = 0;
                } else if stored.process_id == 0 {
                    stored.process_id = synthetic_service_process_id(&stored.name);
                }
            });
        }

        let service = self.services.get_service(handle).unwrap_or(service);
        if status_ptr != 0 {
            self.write_service_status(status_ptr, &service)?;
        }
        self.log_service_state_transition(
            "SERVICE_CONTROL",
            &service.name,
            handle,
            Some(control),
            previous_state,
            service.current_state,
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn filtered_services(&self, service_type: u32, service_state: u32) -> Vec<ServiceProfile> {
        self.services
            .enumerate_services()
            .into_iter()
            .filter(|service| service_type == 0 || (service.service_type & service_type) != 0)
            .filter(|service| match service_state {
                SERVICE_ACTIVE => service.current_state != SERVICE_STOPPED,
                SERVICE_INACTIVE => service.current_state == SERVICE_STOPPED,
                SERVICE_STATE_ALL | 0 => true,
                _ => true,
            })
            .collect()
    }

    fn write_service_status(
        &mut self,
        address: u64,
        service: &ServiceProfile,
    ) -> Result<(), VmError> {
        for (index, value) in [
            service.service_type,
            service.current_state,
            effective_controls_accepted(service),
            service.win32_exit_code,
            service.service_specific_exit_code,
            service.check_point,
            service.wait_hint,
        ]
        .into_iter()
        .enumerate()
        {
            self.write_u32(address + index as u64 * 4, value)?;
        }
        Ok(())
    }

    fn write_service_status_process(
        &mut self,
        address: u64,
        service: &ServiceProfile,
    ) -> Result<(), VmError> {
        for (index, value) in [
            service.service_type,
            service.current_state,
            effective_controls_accepted(service),
            service.win32_exit_code,
            service.service_specific_exit_code,
            service.check_point,
            service.wait_hint,
            service.process_id,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            self.write_u32(address + index as u64 * 4, value)?;
        }
        Ok(())
    }
}

fn effective_controls_accepted(service: &ServiceProfile) -> u32 {
    match service.current_state {
        SERVICE_RUNNING | SERVICE_PAUSED => service.controls_accepted,
        _ => 0,
    }
}

fn synthetic_service_process_id(service_name: &str) -> u32 {
    let mut value = 0x1400u32;
    for byte in service_name.bytes() {
        value = value.rotate_left(5) ^ byte as u32;
    }
    0x1400 + (value & 0x0FFF)
}

fn optional_text_storage_size(wide: bool, value: &str) -> u64 {
    if value.is_empty() {
        0
    } else if wide {
        wide_storage_size(value)
    } else {
        ansi_storage_size(value)
    }
}

fn optional_multi_storage_size(wide: bool, values: &[String]) -> u64 {
    if values.is_empty() {
        0
    } else if wide {
        wide_multi_storage_size(values)
    } else {
        ansi_multi_storage_size(values)
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

fn ansi_storage_size(value: &str) -> u64 {
    (value.len() + 1) as u64
}

fn wide_multi_storage_size(values: &[String]) -> u64 {
    let words = values
        .iter()
        .map(|value| value.encode_utf16().count() + 1)
        .sum::<usize>()
        + 1;
    (words * 2) as u64
}

fn ansi_multi_storage_size(values: &[String]) -> u64 {
    values.iter().map(|value| value.len() + 1).sum::<usize>() as u64 + 1
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

fn write_optional_inline_ansi_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    if value.is_empty() {
        Ok(0)
    } else {
        write_inline_ansi_string(engine, cursor, value)
    }
}

fn write_optional_inline_wide_multi_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    values: &[String],
) -> Result<u64, VmError> {
    if values.is_empty() {
        return Ok(0);
    }
    *cursor = align_up(*cursor, 2);
    let address = *cursor;
    let bytes = encode_wide_multi_string(values);
    engine.modules.memory_mut().write(address, &bytes)?;
    *cursor += bytes.len() as u64;
    Ok(address)
}

fn write_optional_inline_ansi_multi_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    values: &[String],
) -> Result<u64, VmError> {
    if values.is_empty() {
        return Ok(0);
    }
    let address = *cursor;
    let bytes = encode_ansi_multi_string(values);
    engine.modules.memory_mut().write(address, &bytes)?;
    *cursor += bytes.len() as u64;
    Ok(address)
}

fn encode_wide_multi_string(values: &[String]) -> Vec<u8> {
    let mut words = Vec::new();
    for value in values {
        words.extend(value.encode_utf16());
        words.push(0);
    }
    words.push(0);
    words.into_iter().flat_map(u16::to_le_bytes).collect()
}

fn encode_ansi_multi_string(values: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    bytes.push(0);
    bytes
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

use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_wtsapi32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("wtsapi32.dll", "WTSOpenServerA") => true,
            ("wtsapi32.dll", "WTSOpenServerW") => true,
            ("wtsapi32.dll", "WTSCloseServer") => true,
            ("wtsapi32.dll", "WTSEnumerateSessionsA") => true,
            ("wtsapi32.dll", "WTSEnumerateSessionsW") => true,
            ("wtsapi32.dll", "WTSQuerySessionInformationA") => true,
            ("wtsapi32.dll", "WTSQuerySessionInformationW") => true,
            ("wtsapi32.dll", "WTSFreeMemory") => true,
            ("wtsapi32.dll", "WTSQueryUserToken") => true,
            ("wtsapi32.dll", "WTSSendMessageA") | ("wtsapi32.dll", "WTSSendMessageW") => true,
            ("wtsapi32.dll", "WTSRegisterSessionNotification")
            | ("wtsapi32.dll", "WTSUnRegisterSessionNotification")
            | ("wtsapi32.dll", "WTSDisconnectSession")
            | ("wtsapi32.dll", "WTSLogoffSession") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("wtsapi32.dll", "WTSOpenServerA") => {
                    Ok(self.wts_open_server(&self.read_c_string_from_memory(arg(args, 0))?))
                }
                ("wtsapi32.dll", "WTSOpenServerW") => {
                    Ok(self.wts_open_server(&self.read_wide_string_from_memory(arg(args, 0))?))
                }
                ("wtsapi32.dll", "WTSCloseServer") => {
                    Ok(self.wts_close_server(arg(args, 0) as u32))
                }
                ("wtsapi32.dll", "WTSEnumerateSessionsA") => self.wts_enumerate_sessions(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 3),
                    arg(args, 4),
                ),
                ("wtsapi32.dll", "WTSEnumerateSessionsW") => self.wts_enumerate_sessions(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 3),
                    arg(args, 4),
                ),
                ("wtsapi32.dll", "WTSQuerySessionInformationA") => self
                    .wts_query_session_information(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1) as u32,
                        arg(args, 2) as u32,
                        arg(args, 3),
                        arg(args, 4),
                    ),
                ("wtsapi32.dll", "WTSQuerySessionInformationW") => self
                    .wts_query_session_information(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1) as u32,
                        arg(args, 2) as u32,
                        arg(args, 3),
                        arg(args, 4),
                    ),
                ("wtsapi32.dll", "WTSFreeMemory") => Ok(self.wts_free_memory(arg(args, 0))),
                ("wtsapi32.dll", "WTSQueryUserToken") => {
                    self.wts_query_user_token(arg(args, 0) as u32, arg(args, 1))
                }
                ("wtsapi32.dll", "WTSSendMessageA") | ("wtsapi32.dll", "WTSSendMessageW") => {
                    if arg(args, 8) != 0 {
                        self.write_u32(arg(args, 8), 1)?;
                    }
                    Ok(1)
                }
                ("wtsapi32.dll", "WTSRegisterSessionNotification")
                | ("wtsapi32.dll", "WTSUnRegisterSessionNotification")
                | ("wtsapi32.dll", "WTSDisconnectSession")
                | ("wtsapi32.dll", "WTSLogoffSession") => Ok(1),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

const WTS_CURRENT_SERVER_HANDLE: u32 = 0;
const WTS_CURRENT_SESSION: u32 = u32::MAX;
const WTS_ACTIVE: u32 = 0;
const WTS_SESSION_ID_CLASS: u32 = 4;
const WTS_USER_NAME_CLASS: u32 = 5;
const WTS_WINSTATION_NAME_CLASS: u32 = 6;
const WTS_DOMAIN_NAME_CLASS: u32 = 7;
const WTS_CONNECT_STATE_CLASS: u32 = 8;
const WTS_CLIENT_NAME_CLASS: u32 = 10;
const WTS_CLIENT_PROTOCOL_TYPE_CLASS: u32 = 16;

#[derive(Debug, Clone, Copy)]
struct WtsSessionInfoLayout {
    size: u64,
    station_name_offset: u64,
    state_offset: u64,
}

impl VirtualExecutionEngine {
    fn wts_session_info_layout(&self) -> WtsSessionInfoLayout {
        if self.arch.is_x86() {
            WtsSessionInfoLayout {
                size: 12,
                station_name_offset: 4,
                state_offset: 8,
            }
        } else {
            WtsSessionInfoLayout {
                size: 24,
                station_name_offset: 8,
                state_offset: 16,
            }
        }
    }

    fn wts_validate_server_handle(&self, handle: u32) -> bool {
        handle == WTS_CURRENT_SERVER_HANDLE || self.wts_server_handles.contains(&handle)
    }

    fn wts_validate_session_id(&self, session_id: u32) -> bool {
        session_id == 1 || session_id == WTS_CURRENT_SESSION
    }

    pub(super) fn wts_open_server(&mut self, _server_name: &str) -> u64 {
        let handle = self.allocate_object_handle();
        self.wts_server_handles.insert(handle);
        handle as u64
    }

    pub(super) fn wts_close_server(&mut self, handle: u32) -> u64 {
        if handle == WTS_CURRENT_SERVER_HANDLE {
            return 0;
        }
        self.wts_server_handles.remove(&handle);
        0
    }

    pub(super) fn wts_enumerate_sessions(
        &mut self,
        wide: bool,
        server_handle: u32,
        buffer_ptr: u64,
        count_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.wts_validate_server_handle(server_handle) || buffer_ptr == 0 || count_ptr == 0 {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        let layout = self.wts_session_info_layout();
        let station_name = "Console";
        let storage_size = if wide {
            wide_storage_size(station_name)
        } else {
            ansi_storage_size(station_name)
        };
        let allocation = self.alloc_process_heap_block(
            layout.size + storage_size,
            if wide {
                "wts:WTSEnumerateSessionsW"
            } else {
                "wts:WTSEnumerateSessionsA"
            },
        )?;
        self.fill_memory_pattern(allocation, layout.size + storage_size, 0)?;
        self.write_u32(allocation, 1)?;
        let name_address = allocation + layout.size;
        if wide {
            let _ = self.write_wide_string_to_memory(
                name_address,
                station_name.encode_utf16().count() + 1,
                station_name,
            )?;
        } else {
            let _ =
                self.write_c_string_to_memory(name_address, station_name.len() + 1, station_name)?;
        }
        self.write_pointer_value(allocation + layout.station_name_offset, name_address)?;
        self.write_u32(allocation + layout.state_offset, WTS_ACTIVE)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(count_ptr, 1)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(super) fn wts_query_session_information(
        &mut self,
        wide: bool,
        server_handle: u32,
        session_id: u32,
        info_class: u32,
        buffer_ptr: u64,
        bytes_returned_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.wts_validate_server_handle(server_handle)
            || !self.wts_validate_session_id(session_id)
        {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        if buffer_ptr == 0 || bytes_returned_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let station_name = "Console".to_string();
        let user_name = self.active_user_name().to_string();
        let domain_name = self.environment_profile.machine.user_domain.clone();
        let client_name = if self.environment_profile.display.remote_session {
            self.active_computer_name().to_string()
        } else {
            String::new()
        };

        let payload = match info_class {
            WTS_SESSION_ID_CLASS => 1u32.to_le_bytes().to_vec(),
            WTS_USER_NAME_CLASS => encode_text_payload(&user_name, wide),
            WTS_WINSTATION_NAME_CLASS => encode_text_payload(&station_name, wide),
            WTS_DOMAIN_NAME_CLASS => encode_text_payload(&domain_name, wide),
            WTS_CONNECT_STATE_CLASS => WTS_ACTIVE.to_le_bytes().to_vec(),
            WTS_CLIENT_NAME_CLASS => encode_text_payload(&client_name, wide),
            WTS_CLIENT_PROTOCOL_TYPE_CLASS => {
                let value = if self.environment_profile.display.remote_session {
                    2u16
                } else {
                    0u16
                };
                value.to_le_bytes().to_vec()
            }
            _ => encode_text_payload("", wide),
        };

        let allocation = self.alloc_process_heap_block(
            payload.len().max(1) as u64,
            if wide {
                "wts:WTSQuerySessionInformationW"
            } else {
                "wts:WTSQuerySessionInformationA"
            },
        )?;
        self.modules.memory_mut().write(allocation, &payload)?;
        self.write_pointer_value(buffer_ptr, allocation)?;
        self.write_u32(bytes_returned_ptr, payload.len() as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(super) fn wts_free_memory(&mut self, address: u64) -> u64 {
        if address != 0 {
            let _ = self.heaps.free(self.heaps.process_heap(), address);
        }
        0
    }

    pub(super) fn wts_query_user_token(
        &mut self,
        session_id: u32,
        token_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.wts_validate_session_id(session_id) || token_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let handle = self.allocate_object_handle();
        self.token_handles.insert(handle);
        self.write_pointer_value(token_ptr, handle as u64)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }
}

fn wide_storage_size(value: &str) -> u64 {
    ((value.encode_utf16().count() + 1) * 2) as u64
}

fn ansi_storage_size(value: &str) -> u64 {
    (value.len() + 1) as u64
}

fn encode_text_payload(value: &str, wide: bool) -> Vec<u8> {
    if wide {
        let mut bytes = value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&[0, 0]);
        bytes
    } else {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }
}

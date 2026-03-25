use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_advapi32_hook(
        &mut self,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        if !matches!(
            function,
            "OpenSCManagerA"
                | "OpenSCManagerW"
                | "OpenServiceA"
                | "OpenServiceW"
                | "CloseServiceHandle"
                | "QueryServiceStatus"
                | "QueryServiceStatusEx"
                | "QueryServiceConfigA"
                | "QueryServiceConfigW"
                | "QueryServiceConfig2A"
                | "QueryServiceConfig2W"
                | "StartServiceA"
                | "StartServiceW"
                | "ControlService"
                | "EnumServicesStatusExA"
                | "EnumServicesStatusExW"
                | "RegOpenKeyExA"
                | "RegOpenKeyExW"
                | "RegCreateKeyExA"
                | "RegCreateKeyExW"
                | "RegCreateKeyW"
                | "RegQueryValueExA"
                | "RegQueryValueExW"
                | "RegGetValueA"
                | "RegGetValueW"
                | "RegSetValueExW"
                | "RegDeleteValueW"
                | "RegDeleteKeyW"
                | "RegEnumKeyExW"
                | "RegQueryInfoKeyW"
                | "OpenProcessToken"
                | "OpenThreadToken"
                | "GetTokenInformation"
                | "ImpersonateSelf"
                | "RevertToSelf"
                | "AdjustTokenPrivileges"
                | "CreateWellKnownSid"
                | "CopySid"
                | "AllocateAndInitializeSid"
                | "FreeSid"
                | "GetLengthSid"
                | "DuplicateToken"
                | "ImpersonateLoggedOnUser"
                | "LookupAccountNameA"
                | "LookupAccountNameW"
                | "LookupAccountSidA"
                | "LookupAccountSidW"
                | "BuildTrusteeWithSidW"
                | "GetEffectiveRightsFromAclW"
                | "GetNamedSecurityInfoW"
                | "SetNamedSecurityInfoW"
                | "SetEntriesInAclW"
                | "GetUserNameA"
                | "GetUserNameW"
                | "CreateProcessAsUserW"
                | "CreateProcessWithLogonW"
                | "CryptAcquireContextA"
                | "CryptAcquireContextW"
                | "CryptGenRandom"
                | "CryptHashData"
                | "CryptReleaseContext"
                | "RegCloseKey"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "OpenSCManagerA" => self.open_sc_manager(
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    &self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                ),
                "OpenSCManagerW" => self.open_sc_manager(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                ),
                "OpenServiceA" => self.open_service_handle(
                    arg(args, 0) as u32,
                    &self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                ),
                "OpenServiceW" => self.open_service_handle(
                    arg(args, 0) as u32,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2) as u32,
                ),
                "CloseServiceHandle" => Ok(self.close_service_handle(arg(args, 0) as u32)),
                "QueryServiceStatus" => {
                    self.query_service_status(arg(args, 0) as u32, arg(args, 1))
                }
                "QueryServiceStatusEx" => self.query_service_status_ex(
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                ),
                "QueryServiceConfigA" => self.query_service_config(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "QueryServiceConfigW" => self.query_service_config(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3),
                ),
                "QueryServiceConfig2A" => self.query_service_config2(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                ),
                "QueryServiceConfig2W" => self.query_service_config2(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                ),
                "StartServiceA" | "StartServiceW" => {
                    self.start_service(arg(args, 0) as u32, arg(args, 1) as u32, arg(args, 2))
                }
                "ControlService" => {
                    self.control_service(arg(args, 0) as u32, arg(args, 1) as u32, arg(args, 2))
                }
                "EnumServicesStatusExA" => {
                    let _ = self.read_c_string_from_memory(arg(args, 9))?;
                    self.enum_services_status_ex(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2) as u32,
                        arg(args, 3) as u32,
                        arg(args, 4),
                        arg(args, 5) as u32,
                        arg(args, 6),
                        arg(args, 7),
                        arg(args, 8),
                    )
                }
                "EnumServicesStatusExW" => {
                    let _ = self.read_wide_string_from_memory(arg(args, 9))?;
                    self.enum_services_status_ex(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2) as u32,
                        arg(args, 3) as u32,
                        arg(args, 4),
                        arg(args, 5) as u32,
                        arg(args, 6),
                        arg(args, 7),
                        arg(args, 8),
                    )
                }
                "RegOpenKeyExA" => self.reg_open_key(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 4),
                ),
                "RegOpenKeyExW" => self.reg_open_key(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 4),
                ),
                "RegCreateKeyExA" => self.reg_create_key(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 7),
                    arg(args, 8),
                ),
                "RegCreateKeyExW" => self.reg_create_key(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 7),
                    arg(args, 8),
                ),
                "RegCreateKeyW" => self.reg_create_key_simple(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                ),
                "RegQueryValueExA" => self.reg_query_value(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                ),
                "RegQueryValueExW" => self.reg_query_value(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                ),
                "RegGetValueA" => self.sh_get_value(
                    arg(args, 0) as u32,
                    self.read_c_string_from_memory(arg(args, 1))?,
                    self.read_c_string_from_memory(arg(args, 2))?,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "RegGetValueW" => self.sh_get_value(
                    arg(args, 0) as u32,
                    self.read_wide_string_from_memory(arg(args, 1))?,
                    self.read_wide_string_from_memory(arg(args, 2))?,
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "RegSetValueExW" => {
                    let name = self.read_wide_string_from_memory(arg(args, 1))?;
                    let data = if arg(args, 4) != 0 && arg(args, 5) != 0 {
                        self.read_bytes_from_memory(arg(args, 4), arg(args, 5) as usize)?
                    } else {
                        Vec::new()
                    };
                    self.reg_set_value(arg(args, 0) as u32, name, arg(args, 3) as u32, data)
                }
                "RegDeleteValueW" => {
                    let name = self.read_wide_string_from_memory(arg(args, 1))?;
                    self.reg_delete_value(arg(args, 0) as u32, name)
                }
                "RegDeleteKeyW" => {
                    let subkey = self.read_wide_string_from_memory(arg(args, 1))?;
                    self.reg_delete_key(arg(args, 0) as u32, subkey)
                }
                "RegEnumKeyExW" => {
                    let Some(subkey) = self
                        .registry
                        .enum_subkey(arg(args, 0) as u32, arg(args, 1) as u32)
                        .map(str::to_string)
                    else {
                        return Ok(ERROR_NO_MORE_ITEMS);
                    };
                    let required_chars = subkey.encode_utf16().count() as u32;
                    if arg(args, 3) != 0 {
                        let available_chars = self.read_u32(arg(args, 3))?;
                        self.write_u32(arg(args, 3), required_chars)?;
                        if available_chars != 0 && available_chars <= required_chars {
                            return Ok(ERROR_MORE_DATA);
                        }
                    }
                    if arg(args, 2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 2),
                            required_chars as usize + 1,
                            &subkey,
                        )?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "RegQueryInfoKeyW" => {
                    let (subkeys, values, max_subkey_len, max_value_name_len, max_value_len) =
                        self.registry.query_info(arg(args, 0) as u32);
                    for (address, value) in [
                        (arg(args, 4), subkeys),
                        (arg(args, 5), max_subkey_len),
                        (arg(args, 7), values),
                        (arg(args, 8), max_value_name_len),
                        (arg(args, 9), max_value_len),
                    ] {
                        if address != 0 {
                            self.write_u32(address, value)?;
                        }
                    }
                    if arg(args, 11) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 11), &0u64.to_le_bytes())?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "OpenProcessToken" => {
                    let token_ptr = arg(args, 2);
                    if token_ptr == 0 {
                        return Ok(0);
                    }
                    let handle = self.next_object_handle;
                    self.next_object_handle = self.next_object_handle.saturating_add(4);
                    self.token_handles.insert(handle);
                    self.write_pointer_value(token_ptr, handle as u64)?;
                    Ok(1)
                }
                "OpenThreadToken" => {
                    let token_ptr = arg(args, 3);
                    if token_ptr == 0 {
                        return Ok(0);
                    }
                    let handle = self.next_object_handle;
                    self.next_object_handle = self.next_object_handle.saturating_add(4);
                    self.token_handles.insert(handle);
                    self.write_pointer_value(token_ptr, handle as u64)?;
                    Ok(1)
                }
                "GetTokenInformation" => {
                    let handle = arg(args, 0) as u32;
                    if !self.token_handles.contains(&handle) {
                        Ok(0)
                    } else {
                        let buffer = arg(args, 2);
                        let buffer_size = arg(args, 3) as usize;
                        let needed = buffer_size.max(4);
                        if arg(args, 4) != 0 {
                            self.write_u32(arg(args, 4), needed as u32)?;
                        }
                        if buffer != 0 && buffer_size != 0 {
                            self.modules
                                .memory_mut()
                                .write(buffer, &vec![0u8; buffer_size])?;
                            Ok(1)
                        } else {
                            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                            Ok(0)
                        }
                    }
                }
                "ImpersonateSelf" | "RevertToSelf" => Ok(1),
                "AdjustTokenPrivileges" => Ok(1),
                "CreateWellKnownSid" => {
                    const SID_SIZE: u32 = 12;
                    let available = if arg(args, 3) != 0 {
                        self.read_u32(arg(args, 3)).unwrap_or(0)
                    } else {
                        SID_SIZE
                    };
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), SID_SIZE)?;
                    }
                    if arg(args, 2) == 0 {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    if available < SID_SIZE {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    let sid = [1u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                    self.modules.memory_mut().write(arg(args, 2), &sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CopySid" => {
                    let source = arg(args, 2);
                    if arg(args, 1) == 0 || source == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let sub_auth_count = self.read_bytes_from_memory(source + 1, 1)?[0] as usize;
                    let sid_len = 8 + sub_auth_count.saturating_mul(4);
                    if (arg(args, 0) as usize) < sid_len {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    let sid = self.read_bytes_from_memory(source, sid_len)?;
                    self.modules.memory_mut().write(arg(args, 1), &sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "AllocateAndInitializeSid" => {
                    let sid_ptr = arg(args, 10);
                    if sid_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let sub_auth_count = (arg(args, 1) as usize).min(8);
                    let sid_len = 8 + sub_auth_count.saturating_mul(4);
                    let sid = self.alloc_process_heap_block(
                        sid_len as u64,
                        "advapi32:AllocateAndInitializeSid",
                    )?;
                    let identifier_authority = if arg(args, 0) != 0 {
                        self.read_bytes_from_memory(arg(args, 0), 6)?
                    } else {
                        vec![0u8; 6]
                    };
                    let mut payload = vec![0u8; sid_len];
                    payload[0] = 1;
                    payload[1] = sub_auth_count as u8;
                    payload[2..8].copy_from_slice(&identifier_authority[..6]);
                    for index in 0..sub_auth_count {
                        let value = (arg(args, 2 + index) as u32).to_le_bytes();
                        let start = 8 + index * 4;
                        payload[start..start + 4].copy_from_slice(&value);
                    }
                    self.modules.memory_mut().write(sid, &payload)?;
                    self.write_pointer_value(sid_ptr, sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "FreeSid" => {
                    let sid = arg(args, 0);
                    let freed = sid != 0 && self.heaps.free(self.heaps.process_heap(), sid);
                    self.set_last_error(if freed {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_PARAMETER as u32
                    });
                    Ok(if freed { 0 } else { sid })
                }
                "GetLengthSid" => {
                    let sid = arg(args, 0);
                    if sid == 0 {
                        return Ok(0);
                    }
                    let sub_auth_count = self.read_bytes_from_memory(sid + 1, 1)?[0] as u64;
                    Ok(8 + sub_auth_count * 4)
                }
                "DuplicateToken" => {
                    let source = arg(args, 0) as u32;
                    let target = arg(args, 2);
                    if !self.token_handles.contains(&source) || target == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let duplicate = self.allocate_object_handle();
                    self.token_handles.insert(duplicate);
                    self.write_pointer_value(target, duplicate as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "ImpersonateLoggedOnUser" => {
                    let ok = self.token_handles.contains(&(arg(args, 0) as u32));
                    self.set_last_error(if ok {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_HANDLE as u32
                    });
                    Ok(ok as u64)
                }
                "LookupAccountNameA" => self.lookup_account_name(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    &self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "LookupAccountNameW" => self.lookup_account_name(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "LookupAccountSidA" => self.lookup_account_sid(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "LookupAccountSidW" => self.lookup_account_sid(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                "BuildTrusteeWithSidW" => {
                    let trustee = arg(args, 0);
                    if trustee != 0 {
                        let size = if self.arch.is_x86() { 20 } else { 32 };
                        self.modules.memory_mut().write(trustee, &vec![0u8; size])?;
                        let name_offset = if self.arch.is_x86() { 16 } else { 24 };
                        self.write_pointer_value(trustee + name_offset, arg(args, 1))?;
                    }
                    Ok(0)
                }
                "GetEffectiveRightsFromAclW" => {
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), 0x001F_01FF)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "GetNamedSecurityInfoW" => {
                    let sid_payload = [1u8, 1, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2];
                    for output in [arg(args, 3), arg(args, 4)] {
                        if output != 0 {
                            let sid =
                                self.alloc_process_heap_block(sid_payload.len() as u64, "acl:sid")?;
                            self.modules.memory_mut().write(sid, &sid_payload)?;
                            self.write_pointer_value(output, sid)?;
                        }
                    }
                    for output in [arg(args, 5), arg(args, 6)] {
                        if output != 0 {
                            let acl = self.alloc_process_heap_block(8, "acl:acl")?;
                            self.modules.memory_mut().write(acl, &[0u8; 8])?;
                            self.write_pointer_value(output, acl)?;
                        }
                    }
                    if arg(args, 7) != 0 {
                        let descriptor = self.alloc_process_heap_block(32, "acl:descriptor")?;
                        self.modules.memory_mut().write(descriptor, &[0u8; 32])?;
                        self.write_pointer_value(arg(args, 7), descriptor)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "SetNamedSecurityInfoW" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "SetEntriesInAclW" => {
                    if arg(args, 3) != 0 {
                        let acl = self.alloc_process_heap_block(8, "acl:SetEntriesInAclW")?;
                        self.modules.memory_mut().write(acl, &[0u8; 8])?;
                        self.write_pointer_value(arg(args, 3), acl)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "GetUserNameA" => {
                    let user = self.active_user_name().to_string();
                    if arg(args, 1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(arg(args, 1))? as usize;
                    let required = user.len() + 1;
                    self.write_u32(arg(args, 1), required as u32)?;
                    if arg(args, 0) == 0 || capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_c_string_to_memory(arg(args, 0), capacity, &user)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "GetUserNameW" => {
                    let user = self.active_user_name().to_string();
                    if arg(args, 1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(arg(args, 1))? as usize;
                    let required = user.encode_utf16().count() + 1;
                    self.write_u32(arg(args, 1), required as u32)?;
                    if arg(args, 0) == 0 || capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_wide_string_to_memory(arg(args, 0), capacity, &user)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "CreateProcessAsUserW" => {
                    let application_name = self.read_wide_string_from_memory(arg(args, 1))?;
                    let command_line = self.read_wide_string_from_memory(arg(args, 2))?;
                    let current_directory = if arg(args, 7) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_wide_string_from_memory(arg(args, 7))?,
                        )
                    } else {
                        self.current_directory_display_text()
                    };
                    let image = if !application_name.is_empty() {
                        application_name.clone()
                    } else {
                        command_line
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string()
                    };
                    if image.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let parameters = if !command_line.is_empty() && command_line != image {
                        command_line
                            .strip_prefix(&image)
                            .unwrap_or(&command_line)
                            .trim_start()
                            .to_string()
                    } else {
                        String::new()
                    };
                    let Some(handle) = self.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&current_directory),
                    ) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    self.write_process_information(arg(args, 10), handle, 0, handle, 0)?;
                    self.log_process_spawn(
                        "CreateProcessAsUserW",
                        handle,
                        &image,
                        if command_line.is_empty() {
                            &image
                        } else {
                            &command_line
                        },
                        &current_directory,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CreateProcessWithLogonW" => {
                    let _ = self.read_wide_string_from_memory(arg(args, 0))?;
                    let _ = self.read_wide_string_from_memory(arg(args, 1))?;
                    let _ = self.read_wide_string_from_memory(arg(args, 2))?;
                    let application_name = self.read_wide_string_from_memory(arg(args, 4))?;
                    let command_line = self.read_wide_string_from_memory(arg(args, 5))?;
                    let current_directory = if arg(args, 8) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_wide_string_from_memory(arg(args, 8))?,
                        )
                    } else {
                        self.current_directory_display_text()
                    };
                    let image = if !application_name.is_empty() {
                        application_name.clone()
                    } else {
                        command_line
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string()
                    };
                    if image.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let parameters = if !command_line.is_empty() && command_line != image {
                        command_line
                            .strip_prefix(&image)
                            .unwrap_or(&command_line)
                            .trim_start()
                            .to_string()
                    } else {
                        String::new()
                    };
                    let Some(handle) = self.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&current_directory),
                    ) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    self.write_process_information(arg(args, 10), handle, 0, handle, 0)?;
                    self.log_process_spawn(
                        "CreateProcessWithLogonW",
                        handle,
                        &image,
                        if command_line.is_empty() {
                            &image
                        } else {
                            &command_line
                        },
                        &current_directory,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptAcquireContextA" => {
                    if arg(args, 0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let _ = self.read_c_string_from_memory(arg(args, 1))?;
                    let _ = self.read_c_string_from_memory(arg(args, 2))?;
                    let handle = self.allocate_object_handle() as u64;
                    self.write_pointer_value(arg(args, 0), handle)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptAcquireContextW" => {
                    if arg(args, 0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let _ = self.read_wide_string_from_memory(arg(args, 1))?;
                    let _ = self.read_wide_string_from_memory(arg(args, 2))?;
                    let handle = self.allocate_object_handle() as u64;
                    self.write_pointer_value(arg(args, 0), handle)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptGenRandom" => {
                    let size = arg(args, 1) as usize;
                    let buffer = arg(args, 2);
                    if size != 0 && buffer == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    if size != 0 {
                        let mut bytes = vec![0u8; size];
                        self.guid_rng.fill_bytes(&mut bytes);
                        self.modules.memory_mut().write(buffer, &bytes)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptHashData" => {
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.read_bytes_from_memory(arg(args, 1), arg(args, 2) as usize)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptReleaseContext" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "RegCloseKey" => {
                    self.registry.close(arg(args, 0) as u32);
                    Ok(ERROR_SUCCESS)
                }
                _ => unreachable!("validated handled hook name"),
            }
        })())
    }
}

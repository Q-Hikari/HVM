use super::*;
use crate::managers::crypto_manager::CryptoError;
use serde_json::{json, Map};

const NTE_BAD_KEY: u32 = 0x8009_0003;
const NTE_BAD_DATA: u32 = 0x8009_0005;
const NTE_BAD_ALGID: u32 = 0x8009_0008;
const NTE_BAD_FLAGS: u32 = 0x8009_0009;
const NTE_BAD_TYPE: u32 = 0x8009_000A;

fn crypto_last_error(error: &CryptoError) -> u32 {
    match error {
        CryptoError::InvalidHandle => NTE_BAD_KEY,
        CryptoError::InvalidBlob
        | CryptoError::InvalidLength
        | CryptoError::InvalidPadding
        | CryptoError::InvalidParameter => NTE_BAD_DATA,
        CryptoError::UnsupportedAlg(_) => NTE_BAD_ALGID,
        CryptoError::UnsupportedFlags(_) => NTE_BAD_FLAGS,
        CryptoError::UnsupportedBlobType(_)
        | CryptoError::UnsupportedOpaqueBlob(_)
        | CryptoError::UnsupportedMode(_)
        | CryptoError::UnsupportedParam(_) => NTE_BAD_TYPE,
    }
}

impl VirtualExecutionEngine {
    fn add_active_hook_return_to(&self, fields: &mut Map<String, serde_json::Value>) {
        let Some(return_to) = self
            .dispatch
            .active_hook_context
            .and_then(|hook| hook.return_address)
        else {
            return;
        };
        fields.insert("return_to".to_string(), json!(return_to));
        fields.insert(
            "return_to_ref".to_string(),
            self.address_ref(return_to).to_json_value(),
        );
    }

    fn get_service_display_name_a(
        &mut self,
        manager_handle: u32,
        service_name: &str,
        display_name_ptr: u64,
        display_name_len_ptr: u64,
    ) -> Result<u64, VmError> {
        if display_name_len_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        if !self.dispatch.services.is_manager_handle(manager_handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        let Some(display_name) = self
            .dispatch
            .services
            .find_service(service_name)
            .map(|service| service.display_name.clone())
        else {
            self.set_last_error(ERROR_SERVICE_DOES_NOT_EXIST as u32);
            return Ok(0);
        };

        let required = display_name.len().saturating_add(1) as u32;
        let available = self.read_u32(display_name_len_ptr).unwrap_or(0);
        self.write_u32(display_name_len_ptr, required)?;
        if display_name_ptr == 0 || available < required {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        let _ =
            self.write_c_string_to_memory(display_name_ptr, available as usize, &display_name)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn start_service_ctrl_dispatcher(&mut self, service_table: u64) -> Result<u64, VmError> {
        if service_table == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let pointer_size = self.core.arch.pointer_size as u64;
        let service_name_ptr = self.read_pointer_value(service_table)?;
        let service_proc_ptr = self.read_pointer_value(service_table + pointer_size)?;
        if service_proc_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let argv_ptr = self
            .core
            .modules
            .memory_mut()
            .reserve(pointer_size * 2, None, "advapi32:service_argv", false)
            .map_err(VmError::from)?;
        self.write_pointer_value(argv_ptr, service_name_ptr)?;
        self.write_pointer_value(argv_ptr + pointer_size, 0)?;

        let _ = self.call_native_with_entry_frame(service_proc_ptr, &[1, argv_ptr])?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn set_service_status(
        &mut self,
        service_status_handle: u64,
        service_status: u64,
    ) -> Result<u64, VmError> {
        if service_status_handle == 0 || service_status == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let _ = self.read_u32(service_status)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn dispatch_advapi32_hook(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        if let Some(retval) = self.dispatch_advapi32_eventing_forward(function, ctx) {
            return Some(retval);
        }

        if !matches!(
            function,
            "OpenSCManagerA"
                | "OpenSCManagerW"
                | "CreateServiceA"
                | "CreateServiceW"
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
                | "StartServiceCtrlDispatcherW"
                | "GetServiceDisplayNameA"
                | "RegisterServiceCtrlHandlerW"
                | "SetServiceStatus"
                | "ControlService"
                | "EnumServicesStatusExA"
                | "EnumServicesStatusExW"
                | "EnumServicesStatusW"
                | "RegOpenKeyA"
                | "RegOpenKeyW"
                | "RegOpenKeyExA"
                | "RegOpenKeyExW"
                | "RegCreateKeyExA"
                | "RegCreateKeyExW"
                | "RegCreateKeyW"
                | "RegCreateKeyA"
                | "RegQueryValueExA"
                | "RegQueryValueExW"
                | "RegGetValueA"
                | "RegGetValueW"
                | "RegSetValueExW"
                | "RegSetValueExA"
                | "RegDeleteValueW"
                | "RegDeleteValueA"
                | "RegDeleteKeyW"
                | "RegEnumKeyExW"
                | "RegQueryInfoKeyW"
                | "RegEnumValueA"
                | "RegEnumValueW"
                | "RegOverridePredefKey"
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
                | "LogonUserA"
                | "LogonUserW"
                | "LookupAccountNameA"
                | "LookupAccountNameW"
                | "LookupAccountSidA"
                | "LookupAccountSidW"
                | "ConvertStringSidToSidA"
                | "ConvertSidToStringSidA"
                | "BuildTrusteeWithSidW"
                | "GetEffectiveRightsFromAclW"
                | "GetNamedSecurityInfoW"
                | "InitializeSecurityDescriptor"
                | "InitializeAcl"
                | "AddAccessAllowedAce"
                | "SetSecurityDescriptorDacl"
                | "SetNamedSecurityInfoW"
                | "SetEntriesInAclW"
                | "GetUserNameA"
                | "GetUserNameW"
                | "CreateProcessAsUserW"
                | "CreateProcessWithLogonW"
                | "CryptCreateHash"
                | "CryptDecrypt"
                | "CryptDeriveKey"
                | "CryptDestroyHash"
                | "CryptDestroyKey"
                | "CryptEncrypt"
                | "CryptExportKey"
                | "CryptGetHashParam"
                | "CryptGetKeyParam"
                | "CryptImportKey"
                | "CryptSetHashParam"
                | "CryptSetKeyParam"
                | "CryptSignHashW"
                | "CryptVerifySignatureW"
                | "CryptAcquireContextA"
                | "CryptAcquireContextW"
                | "CryptGenRandom"
                | "CryptHashData"
                | "CryptReleaseContext"
                | "RegisterTraceGuidsW"
                | "EventRegister"
                | "EventSetInformation"
                | "RegCloseKey"
        ) {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "OpenSCManagerA" => self.open_sc_manager(
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                ),
                "OpenSCManagerW" => self.open_sc_manager(
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                ),
                "CreateServiceA" => self.create_service(
                    ctx.raw(0) as u32,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    &self.read_c_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4) as u32,
                    ctx.raw(5) as u32,
                    ctx.raw(6) as u32,
                    &self.read_c_string_from_memory(ctx.raw(7))?,
                    &self.read_c_string_from_memory(ctx.raw(8))?,
                    ctx.raw(9),
                    &self.read_c_string_from_memory(ctx.raw(10))?,
                    &self.read_c_string_from_memory(ctx.raw(11))?,
                ),
                "CreateServiceW" => self.create_service(
                    ctx.raw(0) as u32,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    &self.read_wide_string_from_memory(ctx.raw(2))?,
                    ctx.raw(3) as u32,
                    ctx.raw(4) as u32,
                    ctx.raw(5) as u32,
                    ctx.raw(6) as u32,
                    &self.read_wide_string_from_memory(ctx.raw(7))?,
                    &self.read_wide_string_from_memory(ctx.raw(8))?,
                    ctx.raw(9),
                    &self.read_wide_string_from_memory(ctx.raw(10))?,
                    &self.read_wide_string_from_memory(ctx.raw(11))?,
                ),
                "EventSetInformation" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "OpenServiceA" => self.open_service_handle(
                    ctx.raw(0) as u32,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                ),
                "OpenServiceW" => self.open_service_handle(
                    ctx.raw(0) as u32,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2) as u32,
                ),
                "CloseServiceHandle" => Ok(self.close_service_handle(ctx.raw(0) as u32)),
                "QueryServiceStatus" => self.query_service_status(ctx.raw(0) as u32, ctx.raw(1)),
                "QueryServiceStatusEx" => self.query_service_status_ex(
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                ),
                "QueryServiceConfigA" => self.query_service_config(
                    false,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "QueryServiceConfigW" => self.query_service_config(
                    true,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                ),
                "QueryServiceConfig2A" => self.query_service_config2(
                    false,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                ),
                "QueryServiceConfig2W" => self.query_service_config2(
                    true,
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                ),
                "StartServiceA" | "StartServiceW" => {
                    self.start_service(ctx.raw(0) as u32, ctx.raw(1) as u32, ctx.raw(2))
                }
                "StartServiceCtrlDispatcherW" => self.start_service_ctrl_dispatcher(ctx.raw(0)),
                "GetServiceDisplayNameA" => self.get_service_display_name_a(
                    ctx.raw(0) as u32,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                    ctx.raw(3),
                ),
                "RegisterServiceCtrlHandlerW" => {
                    let _ = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        let handler = u64::from(self.allocate_object_handle());
                        Ok(self.sign_extend_win32_handle_for_arch(handler))
                    }
                }
                "SetServiceStatus" => self.set_service_status(ctx.raw(0), ctx.raw(1)),
                "ControlService" => {
                    self.control_service(ctx.raw(0) as u32, ctx.raw(1) as u32, ctx.raw(2))
                }
                "EnumServicesStatusW" => self.enum_services_status(
                    true,
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "EnumServicesStatusExA" => {
                    let _ = self.read_c_string_from_memory(ctx.raw(9))?;
                    self.enum_services_status_ex(
                        false,
                        ctx.raw(0) as u32,
                        ctx.raw(1),
                        ctx.raw(2) as u32,
                        ctx.raw(3) as u32,
                        ctx.raw(4),
                        ctx.raw(5) as u32,
                        ctx.raw(6),
                        ctx.raw(7),
                        ctx.raw(8),
                    )
                }
                "EnumServicesStatusExW" => {
                    let _ = self.read_wide_string_from_memory(ctx.raw(9))?;
                    self.enum_services_status_ex(
                        true,
                        ctx.raw(0) as u32,
                        ctx.raw(1),
                        ctx.raw(2) as u32,
                        ctx.raw(3) as u32,
                        ctx.raw(4),
                        ctx.raw(5) as u32,
                        ctx.raw(6),
                        ctx.raw(7),
                        ctx.raw(8),
                    )
                }
                "RegOpenKeyExA" => self.reg_open_key(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(4),
                ),
                "RegOpenKeyExW" => self.reg_open_key(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(4),
                ),
                "RegOpenKeyA" => self.reg_open_key(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "RegOpenKeyW" => self.reg_open_key(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "RegCreateKeyExA" => self.reg_create_key(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(7),
                    ctx.raw(8),
                ),
                "RegCreateKeyExW" => self.reg_create_key(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(7),
                    ctx.raw(8),
                ),
                "RegCreateKeyW" => self.reg_create_key_simple(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "RegCreateKeyA" => self.reg_create_key_simple(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                ),
                "RegQueryValueExA" => self.reg_query_value(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    false,
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                "RegQueryValueExW" => self.reg_query_value(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    true,
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                ),
                "RegGetValueA" => self.reg_get_value(
                    ctx.raw(0) as u32,
                    self.read_c_string_from_memory(ctx.raw(1))?,
                    self.read_c_string_from_memory(ctx.raw(2))?,
                    false,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "RegGetValueW" => self.reg_get_value(
                    ctx.raw(0) as u32,
                    self.read_wide_string_from_memory(ctx.raw(1))?,
                    self.read_wide_string_from_memory(ctx.raw(2))?,
                    true,
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "RegSetValueExW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let data = if ctx.raw(4) != 0 && ctx.raw(5) != 0 {
                        self.read_bytes_from_memory(ctx.raw(4), ctx.raw(5) as usize)?
                    } else {
                        Vec::new()
                    };
                    self.reg_set_value(ctx.raw(0) as u32, name, ctx.raw(3) as u32, data)
                }
                "RegSetValueExA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(1))?;
                    let data = if ctx.raw(4) != 0 && ctx.raw(5) != 0 {
                        self.read_bytes_from_memory(ctx.raw(4), ctx.raw(5) as usize)?
                    } else {
                        Vec::new()
                    };
                    self.reg_set_value(ctx.raw(0) as u32, name, ctx.raw(3) as u32, data)
                }
                "RegDeleteValueW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(1))?;
                    self.reg_delete_value(ctx.raw(0) as u32, name)
                }
                "RegDeleteValueA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(1))?;
                    self.reg_delete_value(ctx.raw(0) as u32, name)
                }
                "RegDeleteKeyW" => {
                    let subkey = self.read_wide_string_from_memory(ctx.raw(1))?;
                    self.reg_delete_key(ctx.raw(0) as u32, subkey)
                }
                "RegEnumValueA" => self.reg_enum_value(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    false,
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "RegEnumValueW" => self.reg_enum_value(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    true,
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(7),
                ),
                "RegEnumKeyExW" => {
                    let Some(subkey) = self
                        .core
                        .registry
                        .enum_subkey(ctx.raw(0) as u32, ctx.raw(1) as u32)
                        .map(str::to_string)
                    else {
                        return Ok(ERROR_NO_MORE_ITEMS);
                    };
                    let required_chars = subkey.encode_utf16().count() as u32;
                    if ctx.raw(3) != 0 {
                        let available_chars = self.read_u32(ctx.raw(3))?;
                        self.write_u32(ctx.raw(3), required_chars)?;
                        if available_chars != 0 && available_chars <= required_chars {
                            return Ok(ERROR_MORE_DATA);
                        }
                    }
                    if ctx.raw(2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(2),
                            required_chars as usize + 1,
                            &subkey,
                        )?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "RegQueryInfoKeyW" => {
                    let (subkeys, values, max_subkey_len, max_value_name_len, max_value_len) =
                        self.core.registry.query_info(ctx.raw(0) as u32);
                    for (address, value) in [
                        (ctx.raw(4), subkeys),
                        (ctx.raw(5), max_subkey_len),
                        (ctx.raw(7), values),
                        (ctx.raw(8), max_value_name_len),
                        (ctx.raw(9), max_value_len),
                    ] {
                        if address != 0 {
                            self.write_u32(address, value)?;
                        }
                    }
                    if ctx.raw(11) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(11), &0u64.to_le_bytes())?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                "OpenProcessToken" => {
                    let token_ptr = ctx.raw(2);
                    if token_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let handle = self.allocate_object_handle();
                    self.handles.token_handles.insert(handle);
                    self.write_pointer_value(token_ptr, handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "OpenThreadToken" => {
                    let token_ptr = ctx.raw(3);
                    if token_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let handle = self.allocate_object_handle();
                    self.handles.token_handles.insert(handle);
                    self.write_pointer_value(token_ptr, handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetTokenInformation" => {
                    let handle = ctx.raw(0) as u32;
                    if !self.handles.token_handles.contains(&handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        let info_class = ctx.raw(1) as u32;
                        let buffer = ctx.raw(2);
                        let buffer_size = ctx.raw(3) as usize;
                        let payload = if info_class == 25 {
                            self.token_integrity_information_bytes(buffer)
                        } else {
                            vec![0u8; buffer_size.max(4)]
                        };
                        let needed = payload.len();
                        if ctx.raw(4) != 0 {
                            self.write_u32(ctx.raw(4), needed as u32)?;
                        }
                        if buffer == 0 || buffer_size < needed {
                            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                            return Ok(0);
                        }
                        self.core.modules.memory_mut().write(buffer, &payload)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "ImpersonateSelf" | "RevertToSelf" => Ok(1),
                "AdjustTokenPrivileges" => Ok(1),
                "CreateWellKnownSid" => {
                    const SID_SIZE: u32 = 12;
                    let available = if ctx.raw(3) != 0 {
                        self.read_u32(ctx.raw(3)).unwrap_or(0)
                    } else {
                        SID_SIZE
                    };
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), SID_SIZE)?;
                    }
                    if ctx.raw(2) == 0 {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    if available < SID_SIZE {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    let sid = [1u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                    self.core.modules.memory_mut().write(ctx.raw(2), &sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CopySid" => {
                    let source = ctx.raw(2);
                    if ctx.raw(1) == 0 || source == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let sub_auth_count = self.read_bytes_from_memory(source + 1, 1)?[0] as usize;
                    let sid_len = 8 + sub_auth_count.saturating_mul(4);
                    if (ctx.raw(0) as usize) < sid_len {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        return Ok(0);
                    }
                    let sid = self.read_bytes_from_memory(source, sid_len)?;
                    self.core.modules.memory_mut().write(ctx.raw(1), &sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "AllocateAndInitializeSid" => {
                    let sid_ptr = ctx.raw(10);
                    if sid_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let sub_auth_count = (ctx.raw(1) as usize).min(8);
                    let sid_len = 8 + sub_auth_count.saturating_mul(4);
                    let sid = self.alloc_process_heap_block(
                        sid_len as u64,
                        "advapi32:AllocateAndInitializeSid",
                    )?;
                    let identifier_authority = if ctx.raw(0) != 0 {
                        self.read_bytes_from_memory(ctx.raw(0), 6)?
                    } else {
                        vec![0u8; 6]
                    };
                    let mut payload = vec![0u8; sid_len];
                    payload[0] = 1;
                    payload[1] = sub_auth_count as u8;
                    payload[2..8].copy_from_slice(&identifier_authority[..6]);
                    for index in 0..sub_auth_count {
                        let value = (ctx.raw(2 + index) as u32).to_le_bytes();
                        let start = 8 + index * 4;
                        payload[start..start + 4].copy_from_slice(&value);
                    }
                    self.core.modules.memory_mut().write(sid, &payload)?;
                    self.write_pointer_value(sid_ptr, sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "FreeSid" => {
                    let sid = ctx.raw(0);
                    let freed = sid != 0
                        && self
                            .process_memory
                            .heaps
                            .free(self.process_memory.heaps.process_heap(), sid);
                    self.set_last_error(if freed {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_PARAMETER as u32
                    });
                    Ok(if freed { 0 } else { sid })
                }
                "GetLengthSid" => {
                    let sid = ctx.raw(0);
                    if sid == 0 {
                        return Ok(0);
                    }
                    let sub_auth_count = self.read_bytes_from_memory(sid + 1, 1)?[0] as u64;
                    Ok(8 + sub_auth_count * 4)
                }
                "DuplicateToken" => {
                    let source = ctx.raw(0) as u32;
                    let target = ctx.raw(2);
                    if !self.handles.token_handles.contains(&source) || target == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let duplicate = self.allocate_object_handle();
                    self.handles.token_handles.insert(duplicate);
                    self.write_pointer_value(target, duplicate as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "ImpersonateLoggedOnUser" => {
                    let ok = self.handles.token_handles.contains(&(ctx.raw(0) as u32));
                    self.set_last_error(if ok {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_HANDLE as u32
                    });
                    Ok(ok as u64)
                }
                "LogonUserA" | "LogonUserW" => {
                    let ph_token = ctx.raw(5);
                    if ph_token == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let _ = self.read_c_string_from_memory(ctx.raw(0));
                    let _ = self.read_wide_string_from_memory(ctx.raw(0));
                    let _ = self.read_c_string_from_memory(ctx.raw(1));
                    let _ = self.read_wide_string_from_memory(ctx.raw(1));
                    let _ = self.read_c_string_from_memory(ctx.raw(2));
                    let _ = self.read_wide_string_from_memory(ctx.raw(2));
                    let handle = self.allocate_object_handle();
                    self.handles.token_handles.insert(handle);
                    self.write_pointer_value(ph_token, handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "LookupAccountNameA" => self.lookup_account_name(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    &self.read_c_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "LookupAccountNameW" => self.lookup_account_name(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    &self.read_wide_string_from_memory(ctx.raw(1))?,
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "LookupAccountSidA" => self.lookup_account_sid(
                    false,
                    &self.read_c_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "LookupAccountSidW" => self.lookup_account_sid(
                    true,
                    &self.read_wide_string_from_memory(ctx.raw(0))?,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "ConvertStringSidToSidA" => {
                    let string_sid = self.read_c_string_from_memory(ctx.raw(0))?;
                    if ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(sid_bytes) = Self::parse_string_sid(&string_sid) else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    let sid = self.alloc_process_heap_block(
                        sid_bytes.len() as u64,
                        "advapi32:ConvertStringSidToSidA",
                    )?;
                    self.core.modules.memory_mut().write(sid, &sid_bytes)?;
                    self.write_pointer_value(ctx.raw(1), sid)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "ConvertSidToStringSidA" => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let sid = self.read_account_sid_bytes(ctx.raw(0))?;
                    let Some(string_sid) = Self::stringify_sid(&sid) else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    let mut bytes = string_sid.into_bytes();
                    bytes.push(0);
                    let allocation = self.alloc_process_heap_block(
                        bytes.len() as u64,
                        "advapi32:ConvertSidToStringSidA",
                    )?;
                    self.core.modules.memory_mut().write(allocation, &bytes)?;
                    self.write_pointer_value(ctx.raw(1), allocation)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "BuildTrusteeWithSidW" => {
                    let trustee = ctx.raw(0);
                    if trustee != 0 {
                        let size = if self.core.arch.is_x86() { 20 } else { 32 };
                        self.core
                            .modules
                            .memory_mut()
                            .write(trustee, &vec![0u8; size])?;
                        let name_offset = if self.core.arch.is_x86() { 16 } else { 24 };
                        self.write_pointer_value(trustee + name_offset, ctx.raw(1))?;
                    }
                    Ok(0)
                }
                "GetEffectiveRightsFromAclW" => {
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 0x001F_01FF)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "GetNamedSecurityInfoW" => {
                    let sid_payload = [1u8, 1, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2];
                    for output in [ctx.raw(3), ctx.raw(4)] {
                        if output != 0 {
                            let sid =
                                self.alloc_process_heap_block(sid_payload.len() as u64, "acl:sid")?;
                            self.core.modules.memory_mut().write(sid, &sid_payload)?;
                            self.write_pointer_value(output, sid)?;
                        }
                    }
                    for output in [ctx.raw(5), ctx.raw(6)] {
                        if output != 0 {
                            let acl = self.alloc_process_heap_block(8, "acl:acl")?;
                            self.core.modules.memory_mut().write(acl, &[0u8; 8])?;
                            self.write_pointer_value(output, acl)?;
                        }
                    }
                    if ctx.raw(7) != 0 {
                        let descriptor = self.alloc_process_heap_block(32, "acl:descriptor")?;
                        self.core
                            .modules
                            .memory_mut()
                            .write(descriptor, &[0u8; 32])?;
                        self.write_pointer_value(ctx.raw(7), descriptor)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "InitializeSecurityDescriptor" => {
                    let descriptor = ctx.raw(0);
                    let revision = ctx.raw(1) as u32;
                    if descriptor == 0 || revision != 1 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    self.initialize_security_descriptor(descriptor)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "InitializeAcl" => {
                    let acl = ctx.raw(0);
                    let acl_length = ctx.raw(1) as u32;
                    let revision = ctx.raw(2) as u32;
                    if acl == 0 || acl_length < 8 || revision == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let mut header = [0u8; 8];
                    header[0] = revision as u8;
                    header[2..4].copy_from_slice(&(acl_length as u16).to_le_bytes());
                    self.core.modules.memory_mut().write(acl, &header)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "AddAccessAllowedAce" => Ok(self.add_access_allowed_ace(
                    ctx.raw(0),
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                )? as u64),
                "SetSecurityDescriptorDacl" => {
                    let descriptor = ctx.raw(0);
                    if descriptor == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let ok = self.set_security_descriptor_dacl(
                        descriptor,
                        ctx.raw(1) != 0,
                        ctx.raw(2),
                        ctx.raw(3) != 0,
                    )?;
                    Ok(ok as u64)
                }
                "SetNamedSecurityInfoW" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "SetEntriesInAclW" => {
                    if ctx.raw(3) != 0 {
                        let acl = self.alloc_process_heap_block(8, "acl:SetEntriesInAclW")?;
                        self.core.modules.memory_mut().write(acl, &[0u8; 8])?;
                        self.write_pointer_value(ctx.raw(3), acl)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "GetUserNameA" => {
                    let user = self.active_user_name().to_string();
                    if ctx.raw(1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(ctx.raw(1))? as usize;
                    let required = user.len() + 1;
                    self.write_u32(ctx.raw(1), required as u32)?;
                    if ctx.raw(0) == 0 || capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_c_string_to_memory(ctx.raw(0), capacity, &user)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "GetUserNameW" => {
                    let user = self.active_user_name().to_string();
                    if ctx.raw(1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(ctx.raw(1))? as usize;
                    let required = user.encode_utf16().count() + 1;
                    self.write_u32(ctx.raw(1), required as u32)?;
                    if ctx.raw(0) == 0 || capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_wide_string_to_memory(ctx.raw(0), capacity, &user)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "CreateProcessAsUserW" => {
                    let application_name = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let command_line = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let current_directory = if ctx.raw(7) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_wide_string_from_memory(ctx.raw(7))?,
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
                    let Some(handle) = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&current_directory),
                    ) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    self.write_process_information(ctx.raw(10), handle, 0, handle, 0)?;
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
                    let _ = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let _ = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let application_name = self.read_wide_string_from_memory(ctx.raw(4))?;
                    let command_line = self.read_wide_string_from_memory(ctx.raw(5))?;
                    let current_directory = if ctx.raw(8) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_wide_string_from_memory(ctx.raw(8))?,
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
                    let Some(handle) = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&parameters),
                        Some(&current_directory),
                    ) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    self.write_process_information(ctx.raw(10), handle, 0, handle, 0)?;
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
                    if ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let _ = self.read_c_string_from_memory(ctx.raw(1))?;
                    let _ = self.read_c_string_from_memory(ctx.raw(2))?;
                    let handle = self.allocate_object_handle();
                    self.write_pointer_value(ctx.raw(0), handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptAcquireContextW" => {
                    if ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let _ = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let _ = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let handle = self.allocate_object_handle();
                    self.write_pointer_value(ctx.raw(0), handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptGenRandom" => {
                    let size = ctx.raw(1) as usize;
                    let buffer = ctx.raw(2);
                    if size != 0 && buffer == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    if size != 0 {
                        let mut bytes = vec![0u8; size];
                        self.dispatch.guid_rng.fill_bytes(&mut bytes);
                        self.core.modules.memory_mut().write(buffer, &bytes)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptHashData" => {
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.read_bytes_from_memory(ctx.raw(1), ctx.raw(2) as usize)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "EventRegister" => {
                    if ctx.raw(3) != 0 {
                        let handle = u64::from(self.allocate_object_handle());
                        self.write_pointer_value(ctx.raw(3), handle)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "RegisterTraceGuidsW" => {
                    if ctx.raw(7) != 0 {
                        let handle = u64::from(self.allocate_object_handle());
                        self.write_pointer_value(ctx.raw(7), handle)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                "CryptReleaseContext" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptCreateHash" => {
                    // CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash)
                    if ctx.raw(4) != 0 {
                        let hash_handle = self.allocate_object_handle();
                        self.write_pointer_value(ctx.raw(4), hash_handle as u64)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptDeriveKey" => {
                    // CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey)
                    if ctx.raw(4) != 0 {
                        let key_handle = self.allocate_object_handle();
                        self.write_pointer_value(ctx.raw(4), key_handle as u64)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptDestroyHash" | "CryptDestroyKey" => {
                    let handle = ctx.raw(0) as u32;
                    if handle == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if function == "CryptDestroyKey" {
                        let _ = self.network_state.crypto.close_key(handle);
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptEncrypt" => {
                    let handle = ctx.raw(0) as u32;
                    if handle == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let buffer = ctx.raw(4);
                    let len_ptr = ctx.raw(5);
                    if buffer == 0 || len_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let current_len = self.read_u32(len_ptr)? as usize;
                    let input = self.read_bytes_from_memory(buffer, current_len)?;
                    match self.network_state.crypto.encrypt_buffer(
                        handle,
                        ctx.raw(2) != 0,
                        ctx.raw(3) as u32,
                        &input,
                    ) {
                        Ok(output) => {
                            let buf_len = ctx.raw(6) as usize;
                            if output.len() > buf_len {
                                self.write_u32(len_ptr, output.len() as u32)?;
                                self.set_last_error(ERROR_MORE_DATA as u32);
                                return Ok(0);
                            }
                            self.core.modules.memory_mut().write(buffer, &output)?;
                            self.write_u32(len_ptr, output.len() as u32)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        }
                        Err(CryptoError::InvalidHandle) => {
                            if self
                                .network_state
                                .crypto
                                .imported_key_kind(handle)
                                .is_some()
                            {
                                self.set_last_error(NTE_BAD_KEY);
                                Ok(0)
                            } else {
                                self.set_last_error(ERROR_SUCCESS as u32);
                                Ok(1)
                            }
                        }
                        Err(error) => {
                            self.set_last_error(crypto_last_error(&error));
                            Ok(0)
                        }
                    }
                }
                "CryptDecrypt" => {
                    let handle = ctx.raw(0) as u32;
                    let buffer = ctx.raw(4);
                    let len_ptr = ctx.raw(5);
                    let current_len = if len_ptr != 0 {
                        self.read_u32(len_ptr).ok().map(|len| len as usize)
                    } else {
                        None
                    };
                    let mut fields = Map::new();
                    fields.insert("handle".to_string(), json!(handle));
                    fields.insert(
                        "handle_kind".to_string(),
                        json!(self.network_state.crypto.imported_key_kind(handle)),
                    );
                    fields.insert("final".to_string(), json!(ctx.raw(2) != 0));
                    fields.insert("flags".to_string(), json!(ctx.raw(3) as u32));
                    fields.insert("buffer".to_string(), json!(buffer));
                    fields.insert(
                        "buffer_ref".to_string(),
                        self.address_ref(buffer).to_json_value(),
                    );
                    fields.insert("len_ptr".to_string(), json!(len_ptr));
                    fields.insert(
                        "len_ptr_ref".to_string(),
                        self.address_ref(len_ptr).to_json_value(),
                    );
                    if let Some(current_len) = current_len {
                        fields.insert("current_len".to_string(), json!(current_len));
                    }
                    self.add_active_hook_return_to(&mut fields);
                    let _ = self.log_runtime_event("CRYPTO_DECRYPT_REQUEST", fields);
                    if handle == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if buffer == 0 || len_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let current_len = current_len.unwrap_or(self.read_u32(len_ptr)? as usize);
                    let input = self.read_bytes_from_memory(buffer, current_len)?;
                    match self.network_state.crypto.decrypt_buffer(
                        handle,
                        ctx.raw(2) != 0,
                        ctx.raw(3) as u32,
                        &input,
                    ) {
                        Ok(output) => {
                            self.core.modules.memory_mut().write(buffer, &output)?;
                            self.write_u32(len_ptr, output.len() as u32)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        }
                        Err(CryptoError::InvalidHandle) => {
                            if self
                                .network_state
                                .crypto
                                .imported_key_kind(handle)
                                .is_some()
                            {
                                self.set_last_error(NTE_BAD_KEY);
                                Ok(0)
                            } else {
                                self.set_last_error(ERROR_SUCCESS as u32);
                                Ok(1)
                            }
                        }
                        Err(error) => {
                            self.set_last_error(crypto_last_error(&error));
                            Ok(0)
                        }
                    }
                }
                "CryptExportKey" => {
                    self.set_last_error(0x103u32);
                    Ok(0)
                }
                "CryptGetHashParam" => {
                    // CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags)
                    let param_id = ctx.raw(1) as u32;
                    let data_buf = ctx.raw(2);
                    let len_ptr = ctx.raw(3);
                    if data_buf != 0 && len_ptr != 0 {
                        let len = self.read_u32(len_ptr)? as usize;
                        match param_id {
                            1 => {
                                // HP_ALGID → CALG_SHA1
                                if len >= 4 {
                                    self.write_u32(data_buf, 0x8004)?;
                                }
                            }
                            2 => {
                                // HP_HASHSIZE → 20 bytes for SHA-1
                                if len >= 4 {
                                    self.write_u32(data_buf, 20)?;
                                }
                            }
                            _ => {}
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptGetKeyParam" => {
                    let handle = ctx.raw(0) as u32;
                    if handle == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if ctx.raw(3) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    match self
                        .network_state
                        .crypto
                        .get_key_param(handle, ctx.raw(1) as u32)
                    {
                        Ok(bytes) => {
                            let available = self.read_u32(ctx.raw(3)).unwrap_or(0);
                            self.write_u32(ctx.raw(3), bytes.len() as u32)?;
                            if ctx.raw(2) == 0 {
                                self.set_last_error(ERROR_SUCCESS as u32);
                                return Ok(1);
                            }
                            if available < bytes.len() as u32 {
                                self.set_last_error(ERROR_MORE_DATA as u32);
                                return Ok(0);
                            }
                            self.core.modules.memory_mut().write(ctx.raw(2), &bytes)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        }
                        Err(error) => {
                            self.set_last_error(crypto_last_error(&error));
                            Ok(0)
                        }
                    }
                }
                "CryptImportKey" => {
                    if ctx.raw(1) == 0 || ctx.raw(5) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let blob = self.read_bytes_from_memory(ctx.raw(1), ctx.raw(2) as usize)?;
                    let mut fields = Map::new();
                    fields.insert("api".to_string(), json!("CryptImportKey"));
                    fields.insert("blob_len".to_string(), json!(blob.len()));
                    fields.insert(
                        "preview_hex".to_string(),
                        json!(Self::format_runtime_bytes(&blob[..blob.len().min(32)],)),
                    );
                    if blob.len() >= 8 {
                        fields.insert("blob_type".to_string(), json!(blob[0]));
                        fields.insert("blob_version".to_string(), json!(blob[1]));
                        fields.insert(
                            "alg_id".to_string(),
                            json!(u32::from_le_bytes(blob[4..8].try_into().unwrap())),
                        );
                    }
                    let _ = self.log_runtime_event("CRYPTO_BLOB", fields);
                    match self.network_state.crypto.import_key(&blob) {
                        Ok(handle) => {
                            self.write_pointer_value(ctx.raw(5), handle as u64)?;
                            let mut fields = Map::new();
                            fields.insert("provider_handle".to_string(), json!(ctx.raw(0)));
                            fields.insert("phkey_ptr".to_string(), json!(ctx.raw(5)));
                            fields.insert(
                                "phkey_ptr_ref".to_string(),
                                self.address_ref(ctx.raw(5)).to_json_value(),
                            );
                            fields.insert("imported_handle".to_string(), json!(handle));
                            fields.insert(
                                "imported_kind".to_string(),
                                json!(self.network_state.crypto.imported_key_kind(handle)),
                            );
                            if let Ok(written_back) = self.read_pointer_value(ctx.raw(5)) {
                                fields.insert("written_back".to_string(), json!(written_back));
                            }
                            self.add_active_hook_return_to(&mut fields);
                            let _ = self.log_runtime_event("CRYPTO_IMPORT_RESULT", fields);
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        }
                        Err(error) => {
                            self.set_last_error(crypto_last_error(&error));
                            Ok(0)
                        }
                    }
                }
                "CryptSetHashParam" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CryptSetKeyParam" => {
                    let handle = ctx.raw(0) as u32;
                    let param = ctx.raw(1) as u32;
                    let data_ptr = ctx.raw(2);
                    let flags = ctx.raw(3) as u32;
                    if handle == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if data_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    if flags != 0 {
                        self.set_last_error(NTE_BAD_FLAGS);
                        return Ok(0);
                    }
                    let Some(key_len) = self
                        .network_state
                        .crypto
                        .get_key(handle)
                        .map(|key| key.iv.len())
                    else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    let data_len = match param {
                        1 => key_len,
                        4 => 4,
                        _ => 4,
                    };
                    let bytes = self.read_bytes_from_memory(data_ptr, data_len)?;
                    match self
                        .network_state
                        .crypto
                        .set_key_param(handle, param, &bytes)
                    {
                        Ok(()) => {
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        }
                        Err(error) => {
                            self.set_last_error(crypto_last_error(&error));
                            Ok(0)
                        }
                    }
                }
                "CryptSignHashW" | "CryptVerifySignatureW" => {
                    self.set_last_error(0x103u32);
                    Ok(0)
                }
                "RegCloseKey" => {
                    self.core.registry.close(ctx.raw(0) as u32);
                    Ok(ERROR_SUCCESS)
                }
                "RegOverridePredefKey" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(ERROR_SUCCESS)
                }
                _ => unreachable!("validated handled hook name"),
            }
        })())
    }
}

impl VirtualExecutionEngine {
    fn stringify_sid(sid: &[u8]) -> Option<String> {
        if sid.len() < 8 {
            return None;
        }
        let sub_authority_count = sid[1] as usize;
        let expected_len = 8 + sub_authority_count.saturating_mul(4);
        if sid.len() < expected_len {
            return None;
        }
        let authority = sid[2..8]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let mut text = format!("S-{}-{}", sid[0], authority);
        for index in 0..sub_authority_count {
            let offset = 8 + index * 4;
            let sub_authority = u32::from_le_bytes(sid[offset..offset + 4].try_into().ok()?);
            text.push('-');
            text.push_str(&sub_authority.to_string());
        }
        Some(text)
    }

    fn parse_string_sid(text: &str) -> Option<Vec<u8>> {
        let mut parts = text.trim().split('-');
        let prefix = parts.next()?;
        if !prefix.eq_ignore_ascii_case("S") {
            return None;
        }
        let revision = parts.next()?.parse::<u8>().ok()?;
        let authority_text = parts.next()?;
        let authority = if let Some(hex) = authority_text
            .strip_prefix("0x")
            .or_else(|| authority_text.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()?
        } else {
            authority_text.parse::<u64>().ok()?
        };
        if authority > 0xFFFF_FFFF_FFFF {
            return None;
        }
        let sub_authorities = parts
            .map(|part| {
                if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    part.parse::<u32>().ok()
                }
            })
            .collect::<Option<Vec<_>>>()?;
        if sub_authorities.len() > u8::MAX as usize {
            return None;
        }

        let mut sid = Vec::with_capacity(8 + sub_authorities.len() * 4);
        sid.push(revision);
        sid.push(sub_authorities.len() as u8);
        sid.extend_from_slice(&[
            ((authority >> 40) & 0xFF) as u8,
            ((authority >> 32) & 0xFF) as u8,
            ((authority >> 24) & 0xFF) as u8,
            ((authority >> 16) & 0xFF) as u8,
            ((authority >> 8) & 0xFF) as u8,
            (authority & 0xFF) as u8,
        ]);
        for sub_authority in sub_authorities {
            sid.extend_from_slice(&sub_authority.to_le_bytes());
        }
        Some(sid)
    }

    fn security_descriptor_layout(&self) -> (u64, u64, u64, u64, usize) {
        if self.core.arch.is_x86() {
            (2, 4, 8, 16, 20)
        } else {
            (2, 8, 16, 32, 40)
        }
    }

    fn initialize_security_descriptor(&mut self, descriptor: u64) -> Result<(), VmError> {
        let (control_offset, owner_offset, group_offset, dacl_offset, descriptor_size) =
            self.security_descriptor_layout();
        self.core
            .modules
            .memory_mut()
            .write(descriptor, &vec![0u8; descriptor_size])?;
        self.core
            .modules
            .memory_mut()
            .write(descriptor, &[1u8, 0u8])?;
        self.write_u16(descriptor + control_offset, 0)?;
        self.write_pointer_value(descriptor + owner_offset, 0)?;
        self.write_pointer_value(descriptor + group_offset, 0)?;
        self.write_pointer_value(descriptor + dacl_offset - self.pointer_size() as u64, 0)?;
        self.write_pointer_value(descriptor + dacl_offset, 0)?;
        Ok(())
    }

    fn add_access_allowed_ace(
        &mut self,
        acl: u64,
        ace_revision: u32,
        access_mask: u32,
        sid: u64,
    ) -> Result<bool, VmError> {
        const ACL_HEADER_SIZE: usize = 8;
        const ACE_MIN_HEADER_SIZE: usize = 4;
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
        const ERROR_INVALID_ACL: u32 = 1336;
        const ERROR_INVALID_SID: u32 = 1337;
        const ERROR_ALLOTTED_SPACE_EXCEEDED: u32 = 1344;

        if acl == 0 || sid == 0 || ace_revision == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(false);
        }

        let acl_revision = self.read_u8(acl)?;
        let acl_size = self.read_u16(acl + 2)? as usize;
        let ace_count = self.read_u16(acl + 4)? as usize;
        if acl_revision == 0 || acl_size < ACL_HEADER_SIZE {
            self.set_last_error(ERROR_INVALID_ACL);
            return Ok(false);
        }

        let sid_len = self.sid_length_from_memory(sid)?;
        if sid_len < 8 {
            self.set_last_error(ERROR_INVALID_SID);
            return Ok(false);
        }
        let sid_bytes = self.read_bytes_with_guest_fault(sid, sid_len)?;

        let mut next_ace_offset = ACL_HEADER_SIZE;
        for _ in 0..ace_count {
            if next_ace_offset + ACE_MIN_HEADER_SIZE > acl_size {
                self.set_last_error(ERROR_INVALID_ACL);
                return Ok(false);
            }
            let ace_size = self.read_u16(acl + next_ace_offset as u64 + 2)? as usize;
            if ace_size < 8 || next_ace_offset.saturating_add(ace_size) > acl_size {
                self.set_last_error(ERROR_INVALID_ACL);
                return Ok(false);
            }
            next_ace_offset = next_ace_offset.saturating_add(ace_size);
        }

        let ace_size = Self::align_up(8usize.saturating_add(sid_len), 4);
        if next_ace_offset.saturating_add(ace_size) > acl_size || ace_size > u16::MAX as usize {
            self.set_last_error(ERROR_ALLOTTED_SPACE_EXCEEDED);
            return Ok(false);
        }

        let mut ace = vec![0u8; ace_size];
        ace[0] = ACCESS_ALLOWED_ACE_TYPE;
        ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
        ace[4..8].copy_from_slice(&access_mask.to_le_bytes());
        ace[8..8 + sid_len].copy_from_slice(&sid_bytes);
        self.core
            .modules
            .memory_mut()
            .write(acl + next_ace_offset as u64, &ace)?;
        self.write_u16(
            acl + 4,
            ace_count.saturating_add(1).min(u16::MAX as usize) as u16,
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(true)
    }

    fn set_security_descriptor_dacl(
        &mut self,
        descriptor: u64,
        dacl_present: bool,
        dacl: u64,
        dacl_defaulted: bool,
    ) -> Result<bool, VmError> {
        const SE_DACL_PRESENT: u16 = 0x0004;
        const SE_DACL_DEFAULTED: u16 = 0x0008;

        let (control_offset, _owner_offset, _group_offset, dacl_offset, _descriptor_size) =
            self.security_descriptor_layout();
        if self.read_u8(descriptor)? != 1 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(false);
        }

        let mut control = self.read_u16(descriptor + control_offset)?;
        if dacl_present {
            control |= SE_DACL_PRESENT;
        } else {
            control &= !SE_DACL_PRESENT;
        }
        if dacl_defaulted {
            control |= SE_DACL_DEFAULTED;
        } else {
            control &= !SE_DACL_DEFAULTED;
        }
        self.write_u16(descriptor + control_offset, control)?;
        self.write_pointer_value(descriptor + dacl_offset, dacl)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(true)
    }

    fn sid_length_from_memory(&self, sid: u64) -> Result<usize, VmError> {
        if sid == 0 {
            return Ok(0);
        }
        let revision = self.read_u8(sid)?;
        let sub_authority_count = self.read_u8(sid + 1)? as usize;
        if revision == 0 {
            return Ok(0);
        }
        Ok(8usize.saturating_add(sub_authority_count.saturating_mul(4)))
    }

    fn align_up(value: usize, alignment: usize) -> usize {
        if alignment == 0 {
            return value;
        }
        let remainder = value % alignment;
        if remainder == 0 {
            value
        } else {
            value.saturating_add(alignment - remainder)
        }
    }

    fn pointer_size(&self) -> usize {
        if self.core.arch.is_x86() {
            4
        } else {
            8
        }
    }
}

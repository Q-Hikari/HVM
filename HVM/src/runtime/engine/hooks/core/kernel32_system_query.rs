use super::*;

impl VirtualExecutionEngine {
    /// System query / locale / information dispatch -- arms 86-170.
    pub(in crate::runtime::engine) fn dispatch_k32_system_query(
        &mut self,
        function: &str,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let _ = (stub_address, signature);
        // Check that the function belongs to this group before entering the closure.
        match function {
            "GetACP"
            | "GetOEMCP"
            | "GetCommandLineA"
            | "GetCommandLineW"
            | "GetCPInfo"
            | "GetConsoleCP"
            | "GetConsoleOutputCP"
            | "GetConsoleMode"
            | "GetComputerNameA"
            | "GetComputerNameW"
            | "GetCurrentProcess"
            | "GetCurrentProcessId"
            | "GetProcessId"
            | "GetPriorityClass"
            | "GetExitCodeProcess"
            | "GetExitCodeThread"
            | "GetProcessTimes"
            | "GetProcessWorkingSetSize"
            | "ProcessIdToSessionId"
            | "GetCurrentThread"
            | "GetCurrentThreadId"
            | "GetThreadTimes"
            | "GetEnvironmentStringsA"
            | "GetEnvironmentStringsW"
            | "GetEnvironmentVariableA"
            | "GetDiskFreeSpaceExW"
            | "GetDriveTypeA"
            | "GetDriveTypeW"
            | "GetEnvironmentVariableW"
            | "GetFileAttributesExW"
            | "GetFileAttributesA"
            | "GetFileSize"
            | "GetFileSizeEx"
            | "GetFileInformationByHandle"
            | "GetFileInformationByHandleEx"
            | "GetFileType"
            | "GetLastError"
            | "GetLogicalDriveStringsW"
            | "GetLocaleInfoA"
            | "GetLocaleInfoW"
            | "GetLocaleInfoEx"
            | "GetModuleFileNameA"
            | "GetModuleFileNameW"
            | "GetModuleHandleA"
            | "GetModuleHandleW"
            | "GetModuleHandleExW"
            | "OpenProcess"
            | "OpenThread"
            | "OpenFileMappingA"
            | "OpenFileMappingW"
            | "OpenMutexA"
            | "OpenMutexW"
            | "OpenSemaphoreW"
            | "PeekNamedPipe"
            | "GetOverlappedResult"
            | "GetQueuedCompletionStatus"
            | "Process32First"
            | "Process32FirstW"
            | "Process32FirstA"
            | "Process32Next"
            | "Process32NextW"
            | "Process32NextA"
            | "K32EnumProcessModules"
            | "K32EnumProcessModulesEx"
            | "K32GetModuleBaseNameA"
            | "K32GetModuleBaseNameW"
            | "K32GetModuleFileNameExA"
            | "K32GetModuleFileNameExW"
            | "K32GetModuleInformation"
            | "K32GetProcessMemoryInfo"
            | "GetProcAddress"
            | "GetProcessHeap"
            | "GetNativeSystemInfo"
            | "GetSystemInfo"
            | "GetSystemDirectoryA"
            | "GetSystemDirectoryW"
            | "GetSystemWow64DirectoryW"
            | "GetSystemFirmwareTable"
            | "GetSystemWindowsDirectoryA"
            | "GetWindowsDirectoryA"
            | "GetSystemWindowsDirectoryW"
            | "GetWindowsDirectoryW"
            | "GetStringTypeA"
            | "GetStringTypeW"
            | "GetStartupInfoA"
            | "GetStartupInfoW"
            | "GetStdHandle"
            | "GetLocalTime"
            | "GetSystemTime" => {}
            _ => return None,
        }
        Some((|| -> Result<u64, VmError> {
            match function {
                "GetACP" => Ok(self.ansi_code_page()),
                "GetOEMCP" => Ok(self.oem_code_page()),
                "GetCommandLineA" => Ok(self.core.process_env.layout().command_line_ansi_buffer),
                "GetCommandLineW" => Ok(self.core.process_env.layout().command_line_buffer),
                "GetCPInfo" => {
                    let info = ctx.raw(1);
                    if info == 0 {
                        return Ok(0);
                    }
                    let mut bytes = [0u8; 16];
                    bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
                    bytes[4] = b'?';
                    self.core.modules.memory_mut().write(info, &bytes)?;
                    Ok(1)
                }
                "GetConsoleCP" => Ok(self.console_code_page()),
                "GetConsoleOutputCP" => Ok(self.console_output_code_page()),
                "GetConsoleMode" => {
                    let handle = ctx.raw(0);
                    let mode_ptr = ctx.raw(1);
                    if !is_std_handle(handle) || mode_ptr == 0 {
                        return Ok(0);
                    }
                    self.write_u32(mode_ptr, DEFAULT_CONSOLE_MODE)?;
                    Ok(1)
                }
                "GetComputerNameA" => {
                    let name = self.active_computer_name().to_string();
                    if ctx.raw(1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(ctx.raw(1))? as usize;
                    let required = name.len();
                    self.write_u32(ctx.raw(1), required as u32)?;
                    if ctx.raw(0) == 0 || capacity <= required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_c_string_to_memory(ctx.raw(0), capacity, &name)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "GetComputerNameW" => {
                    let name = self.active_computer_name().to_string();
                    if ctx.raw(1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(ctx.raw(1))? as usize;
                    let required = name.encode_utf16().count();
                    self.write_u32(ctx.raw(1), required as u32)?;
                    if ctx.raw(0) == 0 || capacity <= required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_wide_string_to_memory(ctx.raw(0), capacity, &name)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "GetCurrentProcess" => Ok(self.current_process_pseudo_handle()),
                "GetCurrentProcessId" => Ok(self.current_process_id() as u64),
                "GetProcessId" => Ok(self
                    .process_identity_for_handle(ctx.raw(0))
                    .map(|process| process.pid as u64)
                    .unwrap_or(0)),
                "GetPriorityClass" => {
                    if self.process_identity_for_handle(ctx.raw(0)).is_none()
                        && !self.is_current_process_handle(ctx.raw(0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(0x20)
                    }
                }
                "GetExitCodeProcess" => {
                    let exit_code = if self.is_current_process_handle(ctx.raw(0)) {
                        self.core.exit_code.map(u64::from).unwrap_or(STILL_ACTIVE)
                    } else if self
                        .core
                        .processes
                        .find_process_by_handle(ctx.raw(0) as u32)
                        .is_some()
                    {
                        STILL_ACTIVE
                    } else if self.process_identity_for_handle(ctx.raw(0)).is_some() {
                        STILL_ACTIVE
                    } else {
                        return Ok(0);
                    };
                    if ctx.raw(1) != 0 {
                        self.write_u32(ctx.raw(1), exit_code as u32)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetExitCodeThread" => {
                    let Some(tid) = self.core.scheduler.thread_tid_for_handle(ctx.raw(0) as u32)
                    else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    let Some(thread) = self.core.scheduler.thread_snapshot(tid) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    if ctx.raw(1) != 0 {
                        self.write_u32(
                            ctx.raw(1),
                            thread.exit_code.unwrap_or(STILL_ACTIVE as u32),
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetProcessTimes" => {
                    if self.process_identity_for_handle(ctx.raw(0)).is_none()
                        && !self.is_current_process_handle(ctx.raw(0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let now = self.dispatch.time.current().filetime;
                    let creation = now.saturating_sub(30_000_000);
                    if ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), &creation.to_le_bytes())?;
                    }
                    if ctx.raw(2) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &[0u8; 8])?;
                    }
                    if ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &10_000_000u64.to_le_bytes())?;
                    }
                    if ctx.raw(4) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(4), &20_000_000u64.to_le_bytes())?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetProcessWorkingSetSize" => {
                    if self.process_identity_for_handle(ctx.raw(0)).is_none()
                        && !self.is_current_process_handle(ctx.raw(0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), 0x0010_0000)?;
                    }
                    if ctx.raw(2) != 0 {
                        self.write_pointer_value(ctx.raw(2), 0x0080_0000)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "ProcessIdToSessionId" => {
                    let pid = ctx.raw(0) as u32;
                    if ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    if pid == self.current_process_id()
                        || self.process_identity_by_pid(pid).is_some()
                    {
                        self.write_u32(ctx.raw(1), 1)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    }
                }
                "GetCurrentThread" => Ok(self
                    .core
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
                    .or_else(|| {
                        self.core
                            .main_thread_tid
                            .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
                    })
                    .map(|thread| thread.handle as u64)
                    .unwrap_or(0)),
                "GetCurrentThreadId" => {
                    let tid = self
                        .core
                        .scheduler
                        .current_tid()
                        .or(self.core.main_thread_tid)
                        .unwrap_or(0);
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[HOOK] GetCurrentThreadId tid={} teb=0x{:X}",
                            tid,
                            self.core.process_env.current_teb(),
                        );
                    }
                    Ok(tid as u64)
                }
                "GetThreadTimes" => {
                    let Some(tid) = self.core.scheduler.thread_tid_for_handle(ctx.raw(0) as u32)
                    else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    if self.core.scheduler.thread_snapshot(tid).is_none() {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let now = self.dispatch.time.current().filetime;
                    let creation = now.saturating_sub(10_000_000);
                    if ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), &creation.to_le_bytes())?;
                    }
                    if ctx.raw(2) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &[0u8; 8])?;
                    }
                    if ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &[0u8; 8])?;
                    }
                    if ctx.raw(4) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(4), &[0u8; 8])?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetEnvironmentStringsA" => Ok(self.core.process_env.layout().environment_a_buffer),
                "GetEnvironmentStringsW" => Ok(self.core.process_env.layout().environment_w_buffer),
                "GetEnvironmentVariableA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let Some(value) = self.runtime_environment_value(&name) else {
                        self.set_last_error(ERROR_ENVVAR_NOT_FOUND as u32);
                        return Ok(0);
                    };
                    let required = value.len();
                    let capacity = ctx.raw(2) as usize;
                    if ctx.raw(1) == 0 || capacity == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    if capacity <= required {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    let written = self.write_c_string_to_memory(ctx.raw(1), capacity, &value)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(written)
                }
                "GetDiskFreeSpaceExW" => {
                    let path = self.read_optional_wide_text(ctx.raw(0))?;
                    if !path.is_empty() {
                        self.ensure_runtime_path_backing(&path)?;
                    }
                    let (mut available, mut total, mut free) = self.disk_capacity_triplet();
                    // Apply system interception overrides.
                    if let Some(rule) = self
                        .core
                        .config
                        .interception_rule_for_system("GetDiskFreeSpaceEx.availableBytes")
                    {
                        available = rule.value;
                    }
                    if let Some(rule) = self
                        .core
                        .config
                        .interception_rule_for_system("GetDiskFreeSpaceEx.totalBytes")
                    {
                        total = rule.value;
                    }
                    if let Some(rule) = self
                        .core
                        .config
                        .interception_rule_for_system("GetDiskFreeSpaceEx.freeBytes")
                    {
                        free = rule.value;
                    }
                    if ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), &available.to_le_bytes())?;
                    }
                    if ctx.raw(2) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &total.to_le_bytes())?;
                    }
                    if ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &free.to_le_bytes())?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetDriveTypeA" => {
                    if ctx.raw(0) == 0 {
                        Ok(self.drive_type_for_path(&self.volume_profile().root_path))
                    } else {
                        let path = self.read_c_string_from_memory(ctx.raw(0))?;
                        Ok(self.drive_type_for_path(&path))
                    }
                }
                "GetDriveTypeW" => {
                    let path = self.read_optional_wide_text(ctx.raw(0))?;
                    if path.is_empty() {
                        Ok(self.drive_type_for_path(&self.volume_profile().root_path))
                    } else {
                        Ok(self.drive_type_for_path(&path))
                    }
                }
                "GetEnvironmentVariableW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let Some(value) = self.runtime_environment_value(&name) else {
                        self.set_last_error(ERROR_ENVVAR_NOT_FOUND as u32);
                        return Ok(0);
                    };
                    let required = value.encode_utf16().count();
                    let capacity = ctx.raw(2) as usize;
                    if ctx.raw(1) == 0 || capacity == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    if capacity <= required {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    let written = self.write_wide_string_to_memory(ctx.raw(1), capacity, &value)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(written)
                }
                "GetFileAttributesExW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    self.write_file_attributes_ex(&path, ctx.raw(2))
                }
                "GetFileAttributesA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(INVALID_FILE_ATTRIBUTES);
                    }
                    let Some(target) =
                        self.prepare_runtime_read_target(&path, "GetFileAttributesA")?
                    else {
                        return Ok(INVALID_FILE_ATTRIBUTES);
                    };
                    if !target.exists() {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        Ok(INVALID_FILE_ATTRIBUTES)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(if target.is_dir() {
                            FILE_ATTRIBUTE_DIRECTORY as u64
                        } else {
                            FILE_ATTRIBUTE_NORMAL as u64
                        })
                    }
                }
                "GetFileSize" => {
                    let Some(state) = self.handles.file_handles.get_mut(&(ctx.raw(0) as u32))
                    else {
                        return Ok(u32::MAX as u64);
                    };
                    let size = state.file.metadata().map(|meta| meta.len()).unwrap_or(0);
                    if ctx.raw(1) != 0 {
                        self.write_u32(ctx.raw(1), (size >> 32) as u32)?;
                    }
                    Ok((size & 0xFFFF_FFFF) as u64)
                }
                "GetFileSizeEx" => {
                    let Some(state) = self.handles.file_handles.get_mut(&(ctx.raw(0) as u32))
                    else {
                        return Ok(0);
                    };
                    let size = state.file.metadata().map(|meta| meta.len()).unwrap_or(0);
                    if ctx.raw(1) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(1), &size.to_le_bytes())?;
                    }
                    Ok(1)
                }
                "GetFileInformationByHandle" => {
                    let handle = ctx.raw(0) as u32;
                    let buffer = ctx.raw(1);
                    if buffer == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(state) = self.handles.file_handles.get_mut(&handle) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    let metadata = state.file.metadata().ok();
                    let path = std::path::Path::new(&state.path);
                    let is_directory = metadata
                        .as_ref()
                        .map(|meta| meta.is_dir())
                        .unwrap_or_else(|| path.is_dir());
                    let file_size = metadata.as_ref().map(|meta| meta.len()).unwrap_or(0);
                    let attributes = if is_directory {
                        FILE_ATTRIBUTE_DIRECTORY
                    } else {
                        FILE_ATTRIBUTE_NORMAL
                    };
                    let now = self.dispatch.time.current().filetime;
                    let mut payload = vec![0u8; 52];
                    payload[0..4].copy_from_slice(&attributes.to_le_bytes());
                    payload[4..12].copy_from_slice(&now.to_le_bytes());
                    payload[12..20].copy_from_slice(&now.to_le_bytes());
                    payload[20..28].copy_from_slice(&now.to_le_bytes());
                    payload[28..32].copy_from_slice(&self.volume_profile().serial.to_le_bytes());
                    payload[32..36].copy_from_slice(&((file_size >> 32) as u32).to_le_bytes());
                    payload[36..40].copy_from_slice(&(file_size as u32).to_le_bytes());
                    payload[40..44].copy_from_slice(&1u32.to_le_bytes());
                    payload[44..48].copy_from_slice(&(0u32).to_le_bytes());
                    payload[48..52].copy_from_slice(&handle.to_le_bytes());
                    self.core.modules.memory_mut().write(buffer, &payload)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetFileInformationByHandleEx" => {
                    let handle = ctx.raw(0) as u32;
                    let class = ctx.raw(1) as u32;
                    let buffer = ctx.raw(2);
                    let buffer_size = ctx.raw(3) as usize;
                    if buffer == 0 || buffer_size == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(state) = self.handles.file_handles.get_mut(&handle) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    let metadata = state.file.metadata().ok();
                    let path = std::path::Path::new(&state.path);
                    let is_directory = metadata
                        .as_ref()
                        .map(|meta| meta.is_dir())
                        .unwrap_or_else(|| path.is_dir());
                    let file_size = metadata.as_ref().map(|meta| meta.len()).unwrap_or(0);
                    let payload = match class {
                        0 => {
                            // FILE_BASIC_INFO
                            let mut bytes = vec![0u8; 40];
                            let attributes = if is_directory {
                                FILE_ATTRIBUTE_DIRECTORY
                            } else {
                                FILE_ATTRIBUTE_NORMAL
                            };
                            bytes[32..36].copy_from_slice(&attributes.to_le_bytes());
                            bytes
                        }
                        1 => {
                            // FILE_STANDARD_INFO
                            let mut bytes = vec![0u8; 24];
                            bytes[0..8].copy_from_slice(&file_size.to_le_bytes());
                            bytes[8..16].copy_from_slice(&file_size.to_le_bytes());
                            bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
                            bytes[21] = is_directory as u8;
                            bytes
                        }
                        2 => {
                            // FILE_NAME_INFO
                            let encoded = state
                                .path
                                .encode_utf16()
                                .flat_map(u16::to_le_bytes)
                                .collect::<Vec<_>>();
                            let mut bytes = Vec::with_capacity(4 + encoded.len());
                            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                            bytes.extend_from_slice(&encoded);
                            bytes
                        }
                        _ => vec![0u8; buffer_size.min(64)],
                    };
                    if payload.len() > buffer_size {
                        self.set_last_error(ERROR_MORE_DATA as u32);
                        return Ok(0);
                    }
                    self.core.modules.memory_mut().write(buffer, &payload)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetFileType" => Ok(if is_std_handle(ctx.raw(0)) {
                    FILE_TYPE_CHAR
                } else {
                    0
                }),
                "GetLastError" => Ok(self.core.last_error as u64),
                "GetLogicalDriveStringsW" => {
                    let mut payload_text = self.logical_drive_roots().join("\0");
                    payload_text.push('\0');
                    payload_text.push('\0');
                    let payload = payload_text
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>();
                    let required_chars = payload_text.encode_utf16().count() as u64;
                    if ctx.raw(1) == 0 || ctx.raw(0) < required_chars {
                        Ok(required_chars)
                    } else {
                        self.core.modules.memory_mut().write(ctx.raw(1), &payload)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(required_chars - 1)
                    }
                }
                "GetLocaleInfoA" => {
                    let data = b"936\0";
                    if ctx.raw(3) == 0 || ctx.raw(2) == 0 {
                        Ok(data.len() as u64)
                    } else {
                        self.write_raw_bytes_to_memory(ctx.raw(2), ctx.raw(3) as usize, data)
                    }
                }
                "GetLocaleInfoW" | "GetLocaleInfoEx" => {
                    let data = "936\0"
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>();
                    let required = data.len() / 2;
                    if ctx.raw(3) == 0 || ctx.raw(2) == 0 {
                        Ok(required as u64)
                    } else {
                        let writable = (ctx.raw(3) as usize).min(required) * 2;
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &data[..writable])?;
                        Ok(required.min(ctx.raw(3) as usize) as u64)
                    }
                }
                "GetModuleFileNameA" => {
                    let module_handle = ctx.raw(0);
                    let buffer = ctx.raw(1);
                    let capacity = ctx.raw(2) as usize;
                    let path = self
                        .module_path_for_handle(module_handle)
                        .unwrap_or_default();
                    self.write_c_string_to_memory(buffer, capacity, &path)
                }
                "GetModuleFileNameW" => {
                    let module_handle = ctx.raw(0);
                    let buffer = ctx.raw(1);
                    let capacity = ctx.raw(2) as usize;
                    let path = self
                        .module_path_for_handle(module_handle)
                        .unwrap_or_default();
                    self.write_wide_string_to_memory(buffer, capacity, &path)
                }
                "GetModuleHandleA" => {
                    if ctx.raw(0) == 0 {
                        return Ok(self
                            .core
                            .main_module
                            .as_ref()
                            .map(|module| module.visible_base)
                            .unwrap_or(0));
                    }
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    Ok(self
                        .core
                        .modules
                        .get_loaded(&name)
                        .map(|module| module.visible_base)
                        .unwrap_or(0))
                }
                "GetModuleHandleW" => {
                    if ctx.raw(0) == 0 {
                        return Ok(self
                            .core
                            .main_module
                            .as_ref()
                            .map(|module| module.visible_base)
                            .unwrap_or(0));
                    }
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    Ok(self
                        .core
                        .modules
                        .get_loaded(&name)
                        .map(|module| module.visible_base)
                        .unwrap_or(0))
                }
                "GetModuleHandleExW" => {
                    let module = if ctx.raw(0) & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
                        self.core.modules.get_by_address(ctx.raw(1)).cloned()
                    } else if ctx.raw(1) == 0 {
                        self.core.main_module.clone()
                    } else {
                        let name = self.read_wide_string_from_memory(ctx.raw(1))?;
                        self.core.modules.get_loaded(&name).cloned()
                    };
                    let Some(module) = module else {
                        self.set_last_error(ERROR_MOD_NOT_FOUND as u32);
                        return Ok(0);
                    };
                    if ctx.raw(2) != 0 {
                        if self.core.arch.is_x86() {
                            self.write_u32(ctx.raw(2), module.visible_base as u32)?;
                        } else {
                            self.core
                                .modules
                                .memory_mut()
                                .write(ctx.raw(2), &module.visible_base.to_le_bytes())?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "OpenProcess" => {
                    let pid = ctx.raw(2) as u32;
                    if let Some(handle) = self.open_process_handle_by_pid(pid) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(handle)
                    } else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    }
                }
                "OpenThread" => Ok(self
                    .core
                    .scheduler
                    .thread_snapshots()
                    .into_iter()
                    .find(|thread| thread.tid == ctx.raw(2) as u32)
                    .map(|thread| {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        thread.handle as u64
                    })
                    .unwrap_or_else(|| {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        0
                    })),
                "OpenFileMappingA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(2))?;
                    Ok(self.open_file_mapping_handle(&name))
                }
                "OpenFileMappingW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(2))?;
                    Ok(self.open_file_mapping_handle(&name))
                }
                "OpenMutexA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(2))?;
                    Ok(self.open_mutex_handle(&name))
                }
                "OpenMutexW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(2))?;
                    Ok(self.open_mutex_handle(&name))
                }
                "OpenSemaphoreW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(2))?;
                    Ok(self.open_semaphore_handle(&name))
                }
                "PeekNamedPipe" => {
                    if !self
                        .handles
                        .device_handles
                        .contains_key(&(ctx.raw(0) as u32))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    for pointer in [ctx.raw(3), ctx.raw(4), ctx.raw(5)] {
                        if pointer != 0 {
                            self.write_u32(pointer, 0)?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetOverlappedResult" => {
                    let handle = ctx.raw(0) as u32;
                    if !self.handles.file_handles.contains_key(&handle)
                        && !self.handles.device_handles.contains_key(&handle)
                        && !self.handles.io_completion_ports.contains_key(&handle)
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 0)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetQueuedCompletionStatus" => {
                    let handle = ctx.raw(0) as u32;
                    let Some(queue) = self.handles.io_completion_ports.get_mut(&handle) else {
                        if ctx.raw(1) != 0 {
                            self.write_u32(ctx.raw(1), 0)?;
                        }
                        if ctx.raw(2) != 0 {
                            self.write_pointer_value(ctx.raw(2), 0)?;
                        }
                        if ctx.raw(3) != 0 {
                            self.write_pointer_value(ctx.raw(3), 0)?;
                        }
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    if let Some(packet) = queue.pop_front() {
                        if ctx.raw(1) != 0 {
                            self.write_u32(ctx.raw(1), packet.bytes_transferred)?;
                        }
                        if ctx.raw(2) != 0 {
                            self.write_pointer_value(ctx.raw(2), packet.completion_key)?;
                        }
                        if ctx.raw(3) != 0 {
                            self.write_pointer_value(ctx.raw(3), packet.overlapped)?;
                        }
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        if ctx.raw(1) != 0 {
                            self.write_u32(ctx.raw(1), 0)?;
                        }
                        if ctx.raw(2) != 0 {
                            self.write_pointer_value(ctx.raw(2), 0)?;
                        }
                        if ctx.raw(3) != 0 {
                            self.write_pointer_value(ctx.raw(3), 0)?;
                        }
                        self.set_last_error(ERROR_TIMEOUT as u32);
                        Ok(0)
                    }
                }
                "Process32First" | "Process32FirstW" | "Process32FirstA" => self
                    .process32_first_next(
                        ctx.raw(0),
                        ctx.raw(1),
                        !signature.function.ends_with('A'),
                        true,
                    ),
                "Process32Next" | "Process32NextW" | "Process32NextA" => self.process32_first_next(
                    ctx.raw(0),
                    ctx.raw(1),
                    !signature.function.ends_with('A'),
                    false,
                ),
                "K32EnumProcessModules" | "K32EnumProcessModulesEx" => self.enum_process_modules(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as usize,
                    ctx.raw(3),
                ),
                "K32GetModuleBaseNameA" => self.get_module_base_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    false,
                ),
                "K32GetModuleBaseNameW" => self.get_module_base_name_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    true,
                ),
                "K32GetModuleFileNameExA" => self.get_module_file_name_ex_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    false,
                ),
                "K32GetModuleFileNameExW" => self.get_module_file_name_ex_result(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    true,
                ),
                "K32GetModuleInformation" => self.write_module_information(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                ),
                "K32GetProcessMemoryInfo" => {
                    self.write_process_memory_info(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize)
                }
                "GetProcAddress" => {
                    let module_base = ctx.raw(0);
                    let symbol = ctx.raw(1);
                    let address = if symbol <= 0xFFFF {
                        self.core.modules.resolve_export(
                            module_base,
                            &self.core.config,
                            &mut self.core.hooks,
                            None,
                            Some(symbol as u16),
                        )
                    } else {
                        let name = self.read_c_string_from_memory(symbol)?;
                        self.core.modules.resolve_export(
                            module_base,
                            &self.core.config,
                            &mut self.core.hooks,
                            Some(&name),
                            None,
                        )
                    };
                    if address != 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                    }
                    Ok(address)
                }
                "GetProcessHeap" => Ok(self.process_memory.heaps.process_heap() as u64),
                "GetNativeSystemInfo" => {
                    let info = ctx.raw(0);
                    if info == 0 {
                        return Ok(0);
                    }
                    // SYSTEM_INFO layout:
                    //   x86: 36 bytes, x64: 48 bytes
                    let is_x86 = self.core.arch.is_x86();
                    let ptr_size = if is_x86 { 4 } else { 8 };
                    let struct_size = if is_x86 { 36 } else { 48 };
                    let mut bytes = vec![0u8; struct_size];

                    // +0x00: wProcessorArchitecture (WORD)
                    //   On x86: PROCESSOR_ARCHITECTURE_INTEL (0)
                    //   On x64: PROCESSOR_ARCHITECTURE_AMD64 (9)
                    let arch_val: u16 = if is_x86 { 0 } else { 9 };
                    bytes[0..2].copy_from_slice(&arch_val.to_le_bytes());

                    // +0x04: dwPageSize (DWORD)
                    bytes[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());

                    // +0x08: lpMinimumApplicationAddress (PVOID)
                    let min_addr: u64 = 0x1_0000;
                    bytes[8..(8 + ptr_size)].copy_from_slice(&min_addr.to_le_bytes()[..ptr_size]);

                    // +0x08+ptr_size: lpMaximumApplicationAddress (PVOID)
                    let max_addr_offset = 8 + ptr_size;
                    // x86: 0x7FFEFFFF, x64: 0x7FFEFFFF
                    let max_addr: u64 = 0x7FFE_FFFF;
                    bytes[max_addr_offset..(max_addr_offset + ptr_size)]
                        .copy_from_slice(&max_addr.to_le_bytes()[..ptr_size]);

                    // +0x08+2*ptr_size: dwActiveProcessorMask (DWORD_PTR)
                    let mask_offset = max_addr_offset + ptr_size;
                    let active_mask: u64 = 1;
                    bytes[mask_offset..(mask_offset + ptr_size)]
                        .copy_from_slice(&active_mask.to_le_bytes()[..ptr_size]);

                    // dwNumberOfProcessors (DWORD) -- after processor mask
                    let num_proc_offset = mask_offset + ptr_size;
                    let num_processors = self
                        .core
                        .config
                        .interception_rule_for_system("GetSystemInfo.numberOfProcessors")
                        .map(|rule| rule.value as u32)
                        .unwrap_or(1);
                    bytes[num_proc_offset..(num_proc_offset + 4)]
                        .copy_from_slice(&num_processors.to_le_bytes());

                    // dwProcessorType (DWORD) -- Pentium = 586 for x86
                    let proc_type_offset = num_proc_offset + 4;
                    let proc_type: u32 = if is_x86 { 586 } else { 8664 };
                    bytes[proc_type_offset..(proc_type_offset + 4)]
                        .copy_from_slice(&proc_type.to_le_bytes());

                    // dwAllocationGranularity (DWORD) = 0x10000
                    let alloc_offset = proc_type_offset + 4;
                    bytes[alloc_offset..(alloc_offset + 4)]
                        .copy_from_slice(&0x1_0000u32.to_le_bytes());

                    // wProcessorLevel (WORD) = 6, wProcessorRevision (WORD) = 0x9E0A
                    let level_offset = alloc_offset + 4;
                    bytes[level_offset..(level_offset + 2)].copy_from_slice(&6u16.to_le_bytes());
                    bytes[(level_offset + 2)..(level_offset + 4)]
                        .copy_from_slice(&0x9E0Au16.to_le_bytes());

                    self.core.modules.memory_mut().write(info, &bytes)?;
                    Ok(0)
                }
                "GetSystemInfo" => {
                    let info = ctx.raw(0);
                    if info == 0 {
                        return Ok(0);
                    }
                    let mut bytes = vec![0u8; if self.core.arch.is_x86() { 36 } else { 48 }];
                    bytes[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
                    // Check interception rules for processor count override.
                    let num_processors = self
                        .core
                        .config
                        .interception_rule_for_system("GetSystemInfo.numberOfProcessors")
                        .map(|rule| rule.value as u32)
                        .unwrap_or(1);
                    if self.core.arch.is_x86() {
                        bytes[20..24].copy_from_slice(&num_processors.to_le_bytes());
                        bytes[28..32].copy_from_slice(&0x1_0000u32.to_le_bytes());
                    } else {
                        bytes[20..28].copy_from_slice(&(num_processors as u64).to_le_bytes());
                        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
                        bytes[40..44].copy_from_slice(&0x1_0000u32.to_le_bytes());
                    }
                    self.core.modules.memory_mut().write(info, &bytes)?;
                    Ok(0)
                }
                "GetSystemDirectoryA" => {
                    let path = format!("{}\\", self.system_directory_path());
                    self.write_ascii_path_result(ctx.raw(0), ctx.raw(1) as usize, &path)
                }
                "GetSystemDirectoryW" => {
                    let path = format!("{}\\", self.system_directory_path());
                    self.write_wide_path_result(ctx.raw(0), ctx.raw(1) as usize, &path)
                }
                "GetSystemWow64DirectoryW" => {
                    let path = format!(
                        "{}\\SysWOW64",
                        self.windows_directory_path()
                            .trim_end_matches(|ch| ch == '\\' || ch == '/')
                    );
                    self.write_wide_path_result(ctx.raw(0), ctx.raw(1) as usize, &path)
                }
                "GetSystemFirmwareTable" => {
                    let data = self.synthetic_firmware_table(ctx.raw(0) as u32, ctx.raw(1) as u32);
                    if ctx.raw(2) != 0 && ctx.raw(3) as usize >= data.len() {
                        self.core.modules.memory_mut().write(ctx.raw(2), &data)?;
                    }
                    Ok(data.len() as u64)
                }
                "GetSystemWindowsDirectoryA" | "GetWindowsDirectoryA" => {
                    let path = self.windows_directory_path();
                    self.write_ascii_path_result(ctx.raw(0), ctx.raw(1) as usize, &path)
                }
                "GetSystemWindowsDirectoryW" | "GetWindowsDirectoryW" => {
                    let path = self.windows_directory_path();
                    self.write_wide_path_result(ctx.raw(0), ctx.raw(1) as usize, &path)
                }
                "GetStringTypeA" => {
                    if ctx.raw(4) != 0 && ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(4), &vec![0u8; ctx.raw(3) as usize * 2])?;
                    }
                    Ok(1)
                }
                "GetStringTypeW" => {
                    if ctx.raw(3) != 0 && ctx.raw(2) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &vec![0u8; ctx.raw(2) as usize * 2])?;
                    }
                    Ok(1)
                }
                "GetStartupInfoA" | "GetStartupInfoW" => {
                    self.write_startup_info(ctx.raw(0))?;
                    Ok(0)
                }
                "GetStdHandle" => Ok(self.std_handle_value_for_arch(ctx.raw(0))),
                "GetLocalTime" => {
                    self.write_systemtime_struct(
                        ctx.raw(0),
                        Self::system_time_components_from_filetime(
                            self.dispatch.time.current().filetime,
                        ),
                    )?;
                    Ok(0)
                }
                "GetSystemTime" => {
                    self.write_systemtime_struct(
                        ctx.raw(0),
                        Self::system_time_components_from_filetime(
                            self.dispatch.time.current().filetime,
                        ),
                    )?;
                    Ok(0)
                }
                _ => unreachable!(),
            }
        })())
    }
}

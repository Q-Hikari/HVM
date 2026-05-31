use super::*;

impl VirtualExecutionEngine {
    /// Heap/TLS/Memory/Misc dispatch — arms 256-366.
    pub(in crate::runtime::engine) fn dispatch_k32_heap_memory(
        &mut self,
        function: &str,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let _ = stub_address;
        match function {
            "SetProcessWorkingSetSize"
            | "InitializeProcThreadAttributeList"
            | "UpdateProcThreadAttribute"
            | "DeleteProcThreadAttributeList"
            | "SetFilePointer"
            | "SetFilePointerEx"
            | "SetEndOfFile"
            | "SetFileTime"
            | "SetFileAttributesW"
            | "SetFileAttributesA"
            | "SetCurrentDirectoryW"
            | "SetDllDirectoryW"
            | "SetEnvironmentVariableA"
            | "SetEnvironmentVariableW"
            | "SetErrorMode"
            | "SetThreadContext"
            | "SetThreadPriority"
            | "SetUnhandledExceptionFilter"
            | "SetWaitableTimer"
            | "SetPriorityClass"
            | "GetCurrentDirectoryW"
            | "GetDllDirectoryW"
            | "GetFileAttributesW"
            | "GetFileTime"
            | "GetFullPathNameA"
            | "GetFullPathNameW"
            | "GetLongPathNameW"
            | "GetTempFileNameA"
            | "GetTempFileNameW"
            | "GetTempPathA"
            | "GetTempPathW"
            | "GetThreadContext"
            | "GetThreadLocale"
            | "GetThreadPreferredUILanguages"
            | "GetTimeZoneInformation"
            | "GetSystemDefaultLangID"
            | "GetUserDefaultUILanguage"
            | "GetSystemDefaultUILanguage"
            | "GetVolumeInformationA"
            | "GetVolumeInformationW"
            | "GetPrivateProfileIntW"
            | "GetPrivateProfileStringW"
            | "GetPrivateProfileStringA"
            | "GetProfileIntW"
            | "GlobalAddAtomW"
            | "GlobalAlloc"
            | "GlobalDeleteAtom"
            | "GlobalFindAtomW"
            | "GlobalFlags"
            | "GlobalFree"
            | "GlobalGetAtomNameW"
            | "GlobalHandle"
            | "GlobalLock"
            | "GlobalReAlloc"
            | "GlobalSize"
            | "GlobalUnlock"
            | "HeapAlloc"
            | "HeapCreate"
            | "HeapDestroy"
            | "HeapFree"
            | "HeapLock"
            | "HeapQueryInformation"
            | "HeapReAlloc"
            | "HeapSetInformation"
            | "HeapSize"
            | "HeapWalk"
            | "HeapValidate"
            | "LocalAlloc"
            | "LocalFree"
            | "LocalReAlloc"
            | "LocalLock"
            | "LocalHandle"
            | "LocalFlags"
            | "LocalUnlock"
            | "LocalSize"
            | "VirtualAlloc"
            | "VirtualAllocEx"
            | "VirtualFree"
            | "VirtualFreeEx"
            | "VirtualProtect"
            | "VirtualProtectEx"
            | "VirtualQuery"
            | "VirtualQueryEx"
            | "MapViewOfFile"
            | "UnmapViewOfFile"
            | "TlsAlloc"
            | "TlsFree"
            | "TlsGetValue"
            | "TlsSetValue"
            | "LoadResource"
            | "LockResource"
            | "SizeofResource"
            | "FindResourceExW"
            | "LockFile"
            | "UnlockFile"
            | "WideCharToMultiByte"
            | "WriteFile"
            | "WriteConsoleA"
            | "WriteConsoleW"
            | "WritePrivateProfileStringW"
            | "WritePrivateProfileStringA"
            | "WriteProcessMemory"
            | "ReadProcessMemory"
            | "FormatMessageA"
            | "FormatMessageW"
            | "MulDiv"
            | "WaitForSingleObject"
            | "WaitForSingleObjectEx"
            | "WaitForMultipleObjects"
            | "WaitForMultipleObjectsEx"
            | "WaitNamedPipeW"
            | "WaitForDebugEvent"
            | "TerminateProcess"
            | "ContinueDebugEvent"
            | "UnhandledExceptionFilter"
            | "AddVectoredExceptionHandler"
            | "RemoveVectoredExceptionHandler"
            | "RtlCaptureContext"
            | "RtlLookupFunctionEntry"
            | "RtlPcToFileHeader"
            | "RtlRestoreContext"
            | "RtlUnwind"
            | "RtlUnwindEx"
            | "RtlVirtualUnwind"
            | "InterlockedCompareExchange"
            | "InterlockedDecrement"
            | "InterlockedExchange"
            | "InterlockedExchangeAdd"
            | "InterlockedFlushSList"
            | "InterlockedIncrement"
            | "InterlockedPushEntrySList"
            | "InitializeSListHead"
            | "FreeLibraryAndExitThread"
            | "TryEnterCriticalSection"
            | "SearchPathW"
            | "UnregisterWaitEx"
            | "VerLanguageNameW"
            | "VerSetConditionMask"
            | "VerifyVersionInfoA"
            | "VerifyVersionInfoW"
            | "QueryPerformanceCounter"
            | "QueryPerformanceFrequency"
            | "SystemTimeToFileTime"
            | "SystemTimeToTzSpecificLocalTime"
            | "FileTimeToLocalFileTime"
            | "FileTimeToSystemTime"
            | "PostQueuedCompletionStatus"
            | "QueueUserAPC"
            | "QueueUserWorkItem"
            | "RegisterApplicationRestart"
            | "ApplicationRecoveryFinished"
            | "ApplicationRecoveryInProgress"
            | "lstrcmpA"
            | "lstrcmpW"
            | "lstrcmpiA"
            | "lstrcmpiW"
            | "lstrcpynA"
            | "lstrcpyA"
            | "lstrcpyW"
            | "lstrcatA"
            | "lstrcatW"
            | "ConnectNamedPipe"
            | "QueryDosDeviceA"
            | "QueryDosDeviceW"
            | "ReplaceFileW"
            | "ResetEvent"
            | "ResumeThread"
            | "RaiseException"
            | "MultiByteToWideChar"
            | "CompareStringW"
            | "IsValidCodePage"
            | "IsValidLocale"
            | "EnumSystemLocalesW"
            | "GetStringTypeA"
            | "GetStringTypeW"
            | "LCMapStringA"
            | "LCMapStringEx"
            | "LCMapStringW"
            | "QueryFullProcessImageNameA"
            | "QueryFullProcessImageNameW"
            | "GetStartupInfoA"
            | "GetStdHandle"
            | "GetVersion"
            | "GetVersionExA"
            | "GetVersionExW"
            | "IsDebuggerPresent"
            | "IsProcessorFeaturePresent"
            | "IsWow64Process"
            | "GetNativeSystemInfo"
            | "GetSystemInfo"
            | "ActivateActCtx"
            | "DeactivateActCtx"
            | "FindActCtxSectionStringW"
            | "QueryActCtxW"
            | "RemoveDirectoryW"
            | "MoveFileA"
            | "MoveFileW"
            | "CxIZKa"
            | "ReadFile"
            | "ReadConsoleW"
            | "GetOverlappedResult"
            | "GetQueuedCompletionStatus"
            | "PeekNamedPipe"
            | "DeviceIoControl"
            | "GetDiskFreeSpaceExW"
            | "GetLogicalDriveStringsW" => {}
            _ => return None,
        }
        Some((|| -> Result<u64, VmError> {
            match function {
                "SetProcessWorkingSetSize" => {
                    if self.process_identity_for_handle(ctx.raw(0)).is_none()
                        && !self.is_current_process_handle(ctx.raw(0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "InitializeProcThreadAttributeList" => {
                    const PROC_THREAD_ATTRIBUTE_LIST_SIZE: u64 = 0x30;
                    if ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(3), &PROC_THREAD_ATTRIBUTE_LIST_SIZE.to_le_bytes())?;
                    }
                    if ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        self.core.modules.memory_mut().write(
                            ctx.raw(0),
                            &vec![0u8; PROC_THREAD_ATTRIBUTE_LIST_SIZE as usize],
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "UpdateProcThreadAttribute" => Ok(1),
                "DeleteProcThreadAttributeList" => Ok(0),
                "SetFilePointer" => {
                    let handle = ctx.raw(0) as u32;
                    let low = ctx.raw(1) as u32 as u64;
                    let high_ptr = ctx.raw(2);
                    let method = ctx.raw(3);
                    let high = if high_ptr != 0 {
                        self.read_u32(high_ptr)? as u64
                    } else {
                        0
                    };
                    let offset = (high << 32) | low;
                    if let Some(position) = self.set_device_file_pointer(handle, offset, method) {
                        return Ok((position & 0xFFFF_FFFF) as u64);
                    }
                    let Some(state) = self.handles.file_handles.get_mut(&handle) else {
                        return Ok(u32::MAX as u64);
                    };
                    let position = seek_file(&mut state.file, offset, method)?;
                    Ok((position & 0xFFFF_FFFF) as u64)
                }
                "SetFilePointerEx" => {
                    let handle = ctx.raw(0) as u32;
                    let (distance, new_position_ptr, method) = if self.core.arch.is_x86() {
                        let low = ctx.raw(1) as u32 as u64;
                        let high = ctx.raw(2) as u32 as u64;
                        ((high << 32) | low, ctx.raw(3), ctx.raw(4))
                    } else {
                        (ctx.raw(1), ctx.raw(2), ctx.raw(3))
                    };
                    if let Some(position) = self.set_device_file_pointer(handle, distance, method) {
                        if new_position_ptr != 0 {
                            self.core
                                .modules
                                .memory_mut()
                                .write(new_position_ptr, &position.to_le_bytes())?;
                        }
                        return Ok(1);
                    }
                    let Some(state) = self.handles.file_handles.get_mut(&handle) else {
                        return Ok(0);
                    };
                    let position = seek_file(&mut state.file, distance, method)?;
                    if new_position_ptr != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(new_position_ptr, &position.to_le_bytes())?;
                    }
                    Ok(1)
                }
                "SetEndOfFile" => self.set_end_of_file(ctx.raw(0) as u32),
                "SetErrorMode" => Ok(0),
                "SetEnvironmentVariableA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let value = if ctx.raw(1) == 0 {
                        None
                    } else {
                        Some(self.read_c_string_from_memory(ctx.raw(1))?)
                    };
                    self.set_runtime_environment_variable(&name, value.clone())?;
                    let mut fields = Map::new();
                    fields.insert("name".to_string(), json!(name));
                    fields.insert("value".to_string(), json!(value));
                    self.log_runtime_event("ENV_SET", fields)?;
                    Ok(1)
                }
                "SetEnvironmentVariableW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let value = if ctx.raw(1) == 0 {
                        None
                    } else {
                        Some(self.read_wide_string_from_memory(ctx.raw(1))?)
                    };
                    self.set_runtime_environment_variable(&name, value.clone())?;
                    let mut fields = Map::new();
                    fields.insert("name".to_string(), json!(name));
                    fields.insert("value".to_string(), json!(value));
                    self.log_runtime_event("ENV_SET", fields)?;
                    Ok(1)
                }
                "SetFileTime" => {
                    if self.handles.file_handles.contains_key(&(ctx.raw(0) as u32)) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                "SetWaitableTimer" => {
                    Ok(self.core.scheduler.set_event(ctx.raw(0) as u32).is_some() as u64)
                }
                "UnregisterWaitEx" => {
                    if ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "SetUnhandledExceptionFilter" => {
                    let previous = self.exception.top_level_exception_filter;
                    self.exception.top_level_exception_filter = ctx.raw(0);
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(previous)
                }
                "SystemTimeToFileTime" => {
                    if ctx.raw(1) != 0 {
                        self.core.modules.memory_mut().write(
                            ctx.raw(1),
                            &self.dispatch.time.current().filetime.to_le_bytes(),
                        )?;
                    }
                    Ok(1)
                }
                "TerminateProcess" => {
                    let process = ctx.raw(0);
                    if self.is_current_process_handle(process) || process == 0 {
                        self.core.exit_code = Some(ctx.raw(1) as u32);
                        self.core.process_exit_requested = true;
                        self.dispatch.force_native_return = true;
                    }
                    Ok(1)
                }
                "TryEnterCriticalSection" => Ok(1),
                "RtlCaptureContext" => self.rtl_capture_context(ctx.raw(0)),
                "RtlRestoreContext" => self.rtl_restore_context(ctx.raw(0)),
                "RtlLookupFunctionEntry" => self.rtl_lookup_function_entry(ctx.raw(0), ctx.raw(1)),
                "RtlPcToFileHeader" => self.rtl_pc_to_file_header(ctx.raw(0), ctx.raw(1)),
                "RtlUnwind" => self.rtl_unwind(ctx.raw(0), ctx.raw(1), ctx.raw(3)),
                "RtlUnwindEx" => self.rtl_unwind_ex(ctx.raw(0), ctx.raw(1), ctx.raw(3)),
                "RtlVirtualUnwind" => self.rtl_virtual_unwind(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4),
                    ctx.raw(5),
                    ctx.raw(6),
                ),
                "GetThreadContext" => {
                    if ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else if self.write_thread_context(ctx.raw(0) as u32, ctx.raw(1))? {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                "SetThreadContext" => {
                    if ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else if self.read_thread_context(ctx.raw(0) as u32, ctx.raw(1))? {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                "TlsAlloc" => {
                    let slot = self
                        .dispatch
                        .tls
                        .alloc_for_thread(self.current_tls_thread_id())
                        .unwrap_or(usize::MAX);
                    if slot == usize::MAX {
                        return Ok(u32::MAX as u64);
                    }
                    let mirrored = self.core.process_env.allocate_tls_slot()?;
                    if mirrored != slot {
                        return Err(VmError::RuntimeInvariant("tls slot allocator drifted"));
                    }
                    self.sync_native_support_state()?;
                    Ok(slot as u64)
                }
                "TlsFree" => {
                    if !self.dispatch.tls.free(ctx.raw(0) as usize) {
                        return Ok(0);
                    }
                    let _ = self.core.process_env.free_tls_slot(ctx.raw(0) as usize)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                "TlsGetValue" => Ok(self
                    .dispatch
                    .tls
                    .get_value_for_thread(self.current_tls_thread_id(), ctx.raw(0) as usize)),
                "TlsSetValue" => {
                    let slot = ctx.raw(0) as usize;
                    let value = ctx.raw(1);
                    if !self.dispatch.tls.set_value_for_thread(
                        self.current_tls_thread_id(),
                        slot,
                        value,
                    ) {
                        return Ok(0);
                    }
                    self.core.process_env.set_tls_value(slot, value)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                "UnmapViewOfFile" => self.unmap_view_of_file(ctx.raw(0)),
                "UnhandledExceptionFilter" => Ok(0),
                "WaitNamedPipeW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else if self
                        .handles
                        .device_handles
                        .values()
                        .any(|state| state.path.eq_ignore_ascii_case(&path))
                    {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        Ok(0)
                    }
                }
                "WaitForMultipleObjectsEx" => {
                    let count = (ctx.raw(0) as usize).min(64);
                    let handles = self.read_wait_handles(count, ctx.raw(1))?;
                    self.wait_for_objects(
                        &handles,
                        ctx.raw(2) != 0,
                        ctx.raw(3) as u32,
                        ctx.raw(4) != 0,
                    )
                }
                "WaitForMultipleObjects" => {
                    let count = (ctx.raw(0) as usize).min(64);
                    let handles = self.read_wait_handles(count, ctx.raw(1))?;
                    self.wait_for_objects(&handles, ctx.raw(2) != 0, ctx.raw(3) as u32, false)
                }
                "WaitForSingleObject" => {
                    self.wait_for_objects(&[ctx.raw(0) as u32], false, ctx.raw(1) as u32, false)
                }
                "WaitForDebugEvent" => Ok(0),
                "ContinueDebugEvent" => Ok(1),
                "VirtualAlloc" => self.allocate_virtual_region(
                    self.current_process_space_key(),
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3) as u32,
                    "VirtualAlloc",
                    false,
                ),
                "VirtualAllocEx" => {
                    if !self.is_known_process_target(ctx.raw(0)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let address = self.allocate_virtual_region(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2),
                        ctx.raw(3) as u32,
                        ctx.raw(4) as u32,
                        "VirtualAllocEx",
                        true,
                    )?;
                    if address != 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                    }
                    Ok(address)
                }
                "VirtualFree" => self.free_virtual_region(
                    self.current_process_space_key(),
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    "VirtualFree",
                ),
                "VirtualFreeEx" => {
                    if !self.is_known_process_target(ctx.raw(0)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    self.free_virtual_region(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2),
                        ctx.raw(3),
                        "VirtualFreeEx",
                    )
                }
                "VirtualProtectEx" => self.virtual_protect(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as u32,
                    ctx.raw(4),
                    "VirtualProtectEx",
                ),
                "ReadProcessMemory" => self.read_process_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    ctx.raw(4),
                ),
                "WriteProcessMemory" => self.write_process_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    ctx.raw(4),
                ),
                "WriteConsoleA" => {
                    let handle = ctx.raw(0);
                    let buffer = ctx.raw(1);
                    let count = ctx.raw(2) as usize;
                    let written_ptr = ctx.raw(3);
                    let text =
                        String::from_utf8_lossy(&self.read_bytes_from_memory(buffer, count)?)
                            .into_owned();
                    self.emit_console_text("WriteConsoleA", handle, &text)?;
                    if written_ptr != 0 {
                        self.write_u32(written_ptr, count as u32)?;
                    }
                    Ok(1)
                }
                "WideCharToMultiByte" => {
                    let text = self.read_wide_input_string(ctx.raw(2), ctx.raw(3))?;
                    let mut encoded = self.encode_code_page_string(ctx.raw(0), &text);
                    encoded.push(0);
                    let required = encoded.len();
                    if ctx.raw(4) == 0 || ctx.raw(5) == 0 {
                        Ok(required as u64)
                    } else {
                        self.write_raw_bytes_to_memory(ctx.raw(4), ctx.raw(5) as usize, &encoded)
                    }
                }
                "WriteConsoleW" => {
                    let handle = ctx.raw(0);
                    let buffer = ctx.raw(1);
                    let count = ctx.raw(2) as usize;
                    let written_ptr = ctx.raw(3);
                    let text = self.read_wide_counted_string_from_memory(buffer, count)?;
                    self.emit_console_text("WriteConsoleW", handle, &text)?;
                    if written_ptr != 0 {
                        self.write_u32(written_ptr, count as u32)?;
                    }
                    Ok(1)
                }
                "WriteFile" => {
                    let handle = ctx.raw(0) as u32;
                    let data = self.read_bytes_from_memory(ctx.raw(1), ctx.raw(2) as usize)?;
                    let written = if is_std_handle(handle as u64) {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        self.emit_console_text("WriteFile", handle as u64, &text)?;
                        data.len()
                    } else if let Some(written) = self.write_device_handle(handle, &data)? {
                        written
                    } else if let Some(state) = self.handles.file_handles.get_mut(&handle) {
                        let path = state.path.clone();
                        let written = state.file.write(&data).unwrap_or(0);
                        self.log_file_write_event(handle, &path, &data[..written])?;
                        written
                    } else {
                        0
                    };
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), written as u32)?;
                    }
                    Ok(1)
                }
                "FindResourceExW" => self.find_resource_common(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    true,
                    Some(ctx.raw(3) as u16),
                ),
                "FreeLibraryAndExitThread" => {
                    let module_handle = ctx.raw(0);
                    if let Some(module) = self.module_record_for_handle(module_handle).cloned() {
                        if self
                            .core
                            .main_module
                            .as_ref()
                            .map(|main_module| main_module.base)
                            != Some(module.base)
                        {
                            let _ = self.run_dynamic_library_detach(&module);
                            if self.core.modules.unload_module(module.base) {
                                self.unregister_process_virtual_allocation(
                                    self.current_process_space_key(),
                                    module.base,
                                );
                            }
                        }
                    }
                    self.dispatch.force_native_return = true;
                    Ok(ctx.raw(1))
                }
                "GetFileAttributesW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(INVALID_FILE_ATTRIBUTES);
                    }
                    let Some(target) =
                        self.prepare_runtime_read_target(&path, "GetFileAttributesW")?
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
                "GetFileTime" => {
                    if !self.handles.file_handles.contains_key(&(ctx.raw(0) as u32)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let now = self.dispatch.time.current().filetime;
                    for pointer in [ctx.raw(1), ctx.raw(2), ctx.raw(3)] {
                        if pointer != 0 {
                            self.core
                                .modules
                                .memory_mut()
                                .write(pointer, &now.to_le_bytes())?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetProfileIntW" => Ok(ctx.raw(2)),
                "GetSystemDefaultLangID" => Ok(self.system_default_ui_language()),
                "GetSystemDefaultUILanguage" => Ok(self.system_default_ui_language()),
                "GetUserDefaultUILanguage" => Ok(self.user_default_ui_language()),
                "GetThreadLocale" => Ok(self.thread_locale()),
                "GetThreadPreferredUILanguages" => {
                    let flags = ctx.raw(0) as u32;
                    let buffer_len_ptr = ctx.raw(3);
                    if buffer_len_ptr == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }

                    let language = if flags & MUI_LANGUAGE_ID != 0 && flags & MUI_LANGUAGE_NAME == 0
                    {
                        "0804"
                    } else {
                        "zh-CN"
                    };
                    let required = language.encode_utf16().count() + 2;
                    if ctx.raw(1) != 0 {
                        self.write_u32(ctx.raw(1), 1)?;
                    }

                    let capacity = self.read_u32(buffer_len_ptr).unwrap_or(0) as usize;
                    self.write_u32(buffer_len_ptr, required as u32)?;
                    if ctx.raw(2) == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else if capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let written =
                            self.write_wide_string_to_memory(ctx.raw(2), capacity, language)?;
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2) + written * 2 + 2, &[0, 0])?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "GetTempPathW" => {
                    let mut path = self.temporary_directory_path().replace('/', "\\");
                    if !path.ends_with('\\') {
                        path.push('\\');
                    }
                    let path_len = path.encode_utf16().count();
                    let required = path_len + 1;
                    if ctx.raw(1) == 0 || ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(0) as usize,
                            &path,
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(path_len as u64)
                    }
                }
                "GetTempPathA" => {
                    let mut path = self.temporary_directory_path().replace('/', "\\");
                    if !path.ends_with('\\') {
                        path.push('\\');
                    }
                    let required = path.len() + 1;
                    if ctx.raw(1) == 0 || ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(required as u64)
                    } else {
                        let _ =
                            self.write_c_string_to_memory(ctx.raw(1), ctx.raw(0) as usize, &path)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(path.len() as u64)
                    }
                }
                "GetTempFileNameW" => {
                    let display_directory = if ctx.raw(0) != 0 {
                        self.read_wide_string_from_memory(ctx.raw(0))?
                    } else {
                        self.temporary_directory_path()
                    };
                    let prefix = if ctx.raw(1) != 0 {
                        self.read_wide_string_from_memory(ctx.raw(1))?
                    } else {
                        "TMP".to_string()
                    };
                    let unique = if ctx.raw(2) != 0 {
                        ctx.raw(2) as u32
                    } else {
                        (self.dispatch.time.current().tick_ms & 0xFFFF) as u32
                    };
                    let leaf = format!(
                        "{}{:04X}.tmp",
                        prefix.chars().take(3).collect::<String>(),
                        unique & 0xFFFF
                    );
                    let display_target = if Self::is_windows_absolute_path(&display_directory) {
                        Self::join_windows_display_path(&display_directory, &leaf)
                    } else {
                        std::path::PathBuf::from(&display_directory)
                            .join(&leaf)
                            .to_string_lossy()
                            .to_string()
                    };
                    let target = self.resolve_runtime_path(&display_target);
                    if let Some(parent) = target.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&target);
                    if ctx.raw(3) != 0 {
                        let _ =
                            self.write_wide_string_to_memory(ctx.raw(3), 260, &display_target)?;
                    }
                    self.log_file_event("FILE_OPEN", 0, &display_target, Some(0))?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(unique as u64)
                }
                "GetTempFileNameA" => {
                    let display_directory = if ctx.raw(0) != 0 {
                        self.read_c_string_from_memory(ctx.raw(0))?
                    } else {
                        self.temporary_directory_path()
                    };
                    let prefix = if ctx.raw(1) != 0 {
                        self.read_c_string_from_memory(ctx.raw(1))?
                    } else {
                        "TMP".to_string()
                    };
                    let unique = if ctx.raw(2) != 0 {
                        ctx.raw(2) as u32
                    } else {
                        (self.dispatch.time.current().tick_ms & 0xFFFF) as u32
                    };
                    let leaf = format!(
                        "{}{:04X}.tmp",
                        prefix.chars().take(3).collect::<String>(),
                        unique & 0xFFFF
                    );
                    let display_target = if Self::is_windows_absolute_path(&display_directory) {
                        Self::join_windows_display_path(&display_directory, &leaf)
                    } else {
                        std::path::PathBuf::from(&display_directory)
                            .join(&leaf)
                            .to_string_lossy()
                            .to_string()
                    };
                    let target = self.resolve_runtime_path(&display_target);
                    if let Some(parent) = target.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&target);
                    if ctx.raw(3) != 0 {
                        let _ = self.write_c_string_to_memory(ctx.raw(3), 260, &display_target)?;
                    }
                    self.log_file_event("FILE_OPEN", 0, &display_target, Some(0))?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(unique as u64)
                }
                "GetTimeZoneInformation" => {
                    if ctx.raw(0) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &[0u8; 172])?;
                    }
                    Ok(TIME_ZONE_ID_UNKNOWN)
                }
                "GetVolumeInformationA" => {
                    let vol = self.volume_profile();
                    let volume_name = vol.volume_name.clone();
                    let serial = vol.serial;
                    let max_component_length = vol.max_component_length;
                    let flags = vol.flags;
                    let fs_name = vol.fs_name.clone();
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.write_c_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            &volume_name,
                        )?;
                    }
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), serial)?;
                    }
                    if ctx.raw(4) != 0 {
                        self.write_u32(ctx.raw(4), max_component_length)?;
                    }
                    if ctx.raw(5) != 0 {
                        self.write_u32(ctx.raw(5), flags)?;
                    }
                    if ctx.raw(6) != 0 && ctx.raw(7) != 0 {
                        let _ = self.write_c_string_to_memory(
                            ctx.raw(6),
                            ctx.raw(7) as usize,
                            &fs_name,
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetVolumeInformationW" => {
                    let vol = self.volume_profile();
                    let volume_name = vol.volume_name.clone();
                    let serial = vol.serial;
                    let max_component_length = vol.max_component_length;
                    let flags = vol.flags;
                    let fs_name = vol.fs_name.clone();
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            &volume_name,
                        )?;
                    }
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), serial)?;
                    }
                    if ctx.raw(4) != 0 {
                        self.write_u32(ctx.raw(4), max_component_length)?;
                    }
                    if ctx.raw(5) != 0 {
                        self.write_u32(ctx.raw(5), flags)?;
                    }
                    if ctx.raw(6) != 0 && ctx.raw(7) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(6),
                            ctx.raw(7) as usize,
                            &fs_name,
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetCurrentDirectoryW" => {
                    let path = self.current_directory_display_text();
                    let required = path.encode_utf16().count() + 1;
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(0) as usize,
                            &path,
                        )?;
                        Ok(path.encode_utf16().count() as u64)
                    }
                }
                "GetDllDirectoryW" => {
                    let path = self.core.dll_directory.clone().unwrap_or_default();
                    if path.is_empty() {
                        if ctx.raw(0) != 0 && ctx.raw(1) != 0 {
                            let _ = self.write_wide_string_to_memory(
                                ctx.raw(1),
                                ctx.raw(0) as usize,
                                "",
                            )?;
                        }
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(0)
                    } else {
                        let required = path.encode_utf16().count() + 1;
                        if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                            Ok(required as u64)
                        } else {
                            let _ = self.write_wide_string_to_memory(
                                ctx.raw(1),
                                ctx.raw(0) as usize,
                                &path,
                            )?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(path.encode_utf16().count() as u64)
                        }
                    }
                }
                "GetLongPathNameW" => {
                    let input = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let output = self.resolve_runtime_display_path(&input);
                    let required = output.encode_utf16().count() + 1;
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 {
                        Ok(required as u64)
                    } else if (ctx.raw(2) as usize) <= output.encode_utf16().count() {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            &output,
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(output.encode_utf16().count() as u64)
                    }
                }
                "SetCurrentDirectoryW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else {
                        let display_path = self.resolve_runtime_display_path(&path);
                        let Some(target) = self.prepare_runtime_directory_target(
                            &display_path,
                            "SetCurrentDirectoryW",
                        )?
                        else {
                            return Ok(0);
                        };
                        let result = std::fs::create_dir_all(&target).is_ok() as u64;
                        if result != 0 {
                            self.core.current_directory = std::path::PathBuf::from(&display_path);
                            self.core.current_directory_host = target;
                            self.core.process_env.set_current_directory(&display_path)?;
                            self.sync_native_support_state()?;
                            self.log_file_event("FILE_CHDIR", 0, &display_path, None)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                        }
                        Ok(result)
                    }
                }
                "SetDllDirectoryW" => {
                    let path = if ctx.raw(0) == 0 {
                        String::new()
                    } else {
                        self.read_wide_string_from_memory(ctx.raw(0))?
                    };
                    self.core.dll_directory = if path.trim().is_empty() {
                        None
                    } else {
                        Some(path)
                    };
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "GetFullPathNameA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    let output = self.resolve_runtime_display_path(&path);
                    let required = output.len() as u64;
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.write_c_string_to_memory(
                            ctx.raw(2),
                            ctx.raw(1) as usize,
                            &output,
                        )?;
                        if ctx.raw(3) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| index as u64 + 1)
                                .unwrap_or(0);
                            self.write_pointer_value(ctx.raw(3), ctx.raw(2) + offset)?;
                        }
                    }
                    Ok(required)
                }
                "GetFullPathNameW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let output = self.resolve_runtime_display_path(&path);
                    let required = output.encode_utf16().count() as u64;
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(2),
                            ctx.raw(1) as usize,
                            &output,
                        )?;
                        if ctx.raw(3) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| output[..index + 1].encode_utf16().count() as u64 * 2)
                                .unwrap_or(0);
                            self.write_pointer_value(ctx.raw(3), ctx.raw(2) + offset)?;
                        }
                    }
                    Ok(required)
                }
                "GlobalAddAtomW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    Ok(self.allocate_global_atom(&name) as u64)
                }
                "GlobalFindAtomW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    Ok(self.find_global_atom(&name) as u64)
                }
                "GlobalGetAtomNameW" => {
                    let Some(name) = self.objects.global_atoms.get(&(ctx.raw(0) as u16)).cloned()
                    else {
                        return Ok(0);
                    };
                    self.write_wide_string_to_memory(ctx.raw(1), ctx.raw(2) as usize, &name)
                }
                "GlobalDeleteAtom" => Ok(
                    if self
                        .objects
                        .global_atoms
                        .remove(&(ctx.raw(0) as u16))
                        .is_some()
                    {
                        0
                    } else {
                        ctx.raw(0)
                    },
                ),
                "GlobalAlloc" => {
                    let size = ctx.raw(1).max(1);
                    let address = self
                        .process_memory
                        .heaps
                        .alloc(
                            self.core.modules.memory_mut(),
                            self.process_memory.heaps.process_heap(),
                            size,
                        )
                        .unwrap_or(0);
                    if address != 0 {
                        if ctx.raw(0) & LMEM_ZEROINIT != 0 {
                            self.fill_memory_pattern(address, size, 0)?;
                        }
                        self.log_heap_event(
                            "HEAP_ALLOC",
                            self.process_memory.heaps.process_heap(),
                            address,
                            size,
                            "GlobalAlloc",
                        )?;
                    }
                    Ok(address)
                }
                "GlobalFree" => Ok(
                    if self
                        .process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), ctx.raw(0))
                    {
                        let _ = self.log_heap_event(
                            "HEAP_FREE",
                            self.process_memory.heaps.process_heap(),
                            ctx.raw(0),
                            0,
                            "GlobalFree",
                        );
                        0
                    } else {
                        ctx.raw(0)
                    },
                ),
                "GlobalLock" | "GlobalHandle" => Ok(ctx.raw(0)),
                "GlobalUnlock" => Ok(0),
                "GlobalSize" => Ok(self
                    .process_memory
                    .heaps
                    .size(self.process_memory.heaps.process_heap(), ctx.raw(0))),
                "GlobalFlags" => Ok(0),
                "GlobalReAlloc" | "LocalReAlloc" => {
                    let old_address = ctx.raw(0);
                    let new_size = ctx.raw(1).max(1);
                    let old_size = self
                        .process_memory
                        .heaps
                        .size(self.process_memory.heaps.process_heap(), old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let Some(new_address) = self.process_memory.heaps.alloc(
                        self.core.modules.memory_mut(),
                        self.process_memory.heaps.process_heap(),
                        new_size,
                    ) else {
                        return Ok(0);
                    };
                    let bytes = self
                        .core
                        .modules
                        .memory()
                        .read(old_address, old_size.min(new_size) as usize)?;
                    self.core.modules.memory_mut().write(new_address, &bytes)?;
                    if ctx.raw(2) & LMEM_ZEROINIT != 0 && new_size > old_size {
                        self.fill_memory_pattern(
                            new_address + old_size,
                            new_size.saturating_sub(old_size),
                            0,
                        )?;
                    }
                    self.process_memory
                        .heaps
                        .free(self.process_memory.heaps.process_heap(), old_address);
                    self.log_heap_event(
                        "HEAP_REALLOC",
                        self.process_memory.heaps.process_heap(),
                        new_address,
                        new_size,
                        signature.function,
                    )?;
                    Ok(new_address)
                }
                "HeapQueryInformation" => {
                    if ctx.raw(2) != 0 && ctx.raw(3) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(2), &vec![0u8; ctx.raw(3) as usize])?;
                    }
                    if ctx.raw(4) != 0 {
                        self.write_u32(ctx.raw(4), 0)?;
                    }
                    Ok(1)
                }
                "LoadResource" => self.load_resource_handle(ctx.raw(0), ctx.raw(1)),
                "LockResource" => self.lock_resource_data(ctx.raw(0)),
                "SizeofResource" => self.sizeof_resource_data(ctx.raw(0), ctx.raw(1)),
                "LockFile" | "UnlockFile" => Ok(1),
                "lstrcmpA" => {
                    let left = self.read_c_string_from_memory(ctx.raw(0))?;
                    let right = self.read_c_string_from_memory(ctx.raw(1))?;
                    Ok(match left.cmp(&right) {
                        std::cmp::Ordering::Less => (-1i32) as u64,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    })
                }
                "lstrcmpW" => {
                    let left = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let right = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(match left.cmp(&right) {
                        std::cmp::Ordering::Less => (-1i32) as u64,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    })
                }
                "lstrcmpiA" => {
                    let left = self.read_c_string_from_memory(ctx.raw(0))?;
                    let right = self.read_c_string_from_memory(ctx.raw(1))?;
                    Ok(compare_ci(&left, &right) as u64)
                }
                "QueryPerformanceFrequency" => {
                    if ctx.raw(0) != 0 {
                        self.core
                            .modules
                            .memory_mut()
                            .write(ctx.raw(0), &10_000_000u64.to_le_bytes())?;
                    }
                    Ok(1)
                }
                "SearchPathW" => {
                    let directory = if ctx.raw(0) != 0 {
                        self.read_wide_string_from_memory(ctx.raw(0))?
                    } else {
                        self.current_directory_display_text()
                    };
                    let mut file_name = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let extension = self.read_wide_string_from_memory(ctx.raw(2))?;
                    if !extension.is_empty()
                        && std::path::Path::new(&file_name).extension().is_none()
                    {
                        file_name.push_str(&extension);
                    }
                    let output = if Self::is_windows_absolute_path(&file_name) {
                        self.resolve_runtime_display_path(&file_name)
                    } else if Self::is_windows_absolute_path(&directory) {
                        Self::join_windows_display_path(&directory, &file_name)
                    } else if directory.trim().is_empty() {
                        self.resolve_runtime_display_path(&file_name)
                    } else {
                        let joined = std::path::PathBuf::from(&directory)
                            .join(&file_name)
                            .to_string_lossy()
                            .to_string();
                        self.resolve_runtime_display_path(&joined)
                    };
                    let Some(target) = self.prepare_runtime_read_target(&output, "SearchPathW")?
                    else {
                        return Ok(0);
                    };
                    if !target.is_file() {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        return Ok(0);
                    }
                    let required = output.encode_utf16().count() as u64;
                    if ctx.raw(4) != 0 && ctx.raw(3) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(4),
                            ctx.raw(3) as usize,
                            &output,
                        )?;
                        if ctx.raw(5) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| output[..index + 1].encode_utf16().count() as u64 * 2)
                                .unwrap_or(0);
                            self.write_pointer_value(ctx.raw(5), ctx.raw(4) + offset)?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(required)
                }
                "SetFileAttributesW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let Some(_target) =
                        self.prepare_runtime_read_target(&path, "SetFileAttributesW")?
                    else {
                        return Ok(0);
                    };
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "SetFileAttributesA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    let Some(_target) =
                        self.prepare_runtime_read_target(&path, "SetFileAttributesA")?
                    else {
                        return Ok(0);
                    };
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "SetThreadPriority" => Ok(1),
                "SystemTimeToTzSpecificLocalTime" => {
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let bytes = self.read_bytes_from_memory(ctx.raw(1), 16)?;
                        self.core.modules.memory_mut().write(ctx.raw(2), &bytes)?;
                        Ok(1)
                    } else {
                        Ok(0)
                    }
                }
                "FileTimeToLocalFileTime" => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        Ok(0)
                    } else {
                        let bytes = self.read_bytes_from_memory(ctx.raw(0), 8)?;
                        self.core.modules.memory_mut().write(ctx.raw(1), &bytes)?;
                        Ok(1)
                    }
                }
                "FileTimeToSystemTime" => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        Ok(0)
                    } else {
                        let filetime = u64::from_le_bytes(
                            self.read_bytes_from_memory(ctx.raw(0), 8)?
                                .try_into()
                                .unwrap(),
                        );
                        self.write_systemtime_struct(
                            ctx.raw(1),
                            Self::system_time_components_from_filetime(filetime),
                        )?;
                        Ok(1)
                    }
                }
                "FormatMessageA" => {
                    let text = if ctx.raw(2) == 0 {
                        std::borrow::Cow::Borrowed("The operation completed successfully.")
                    } else {
                        std::borrow::Cow::Owned(format!("Sandbox message {}", ctx.raw(2)))
                    };
                    let required = text.len() + 1;
                    if ctx.raw(0) & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
                        let buffer =
                            self.alloc_process_heap_block(required as u64, "FormatMessageA")?;
                        let _ = self.write_c_string_to_memory(buffer, required, &text)?;
                        self.write_pointer_value(ctx.raw(4), buffer)?;
                        Ok((required - 1) as u64)
                    } else if ctx.raw(4) != 0 && ctx.raw(5) != 0 {
                        let _ =
                            self.write_c_string_to_memory(ctx.raw(4), ctx.raw(5) as usize, &text)?;
                        Ok((required - 1) as u64)
                    } else {
                        Ok(0)
                    }
                }
                "FormatMessageW" => {
                    let text = if ctx.raw(2) == 0 {
                        std::borrow::Cow::Borrowed("The operation completed successfully.")
                    } else {
                        std::borrow::Cow::Owned(format!("Sandbox message {}", ctx.raw(2)))
                    };
                    let required = text.encode_utf16().count() + 1;
                    if ctx.raw(0) & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
                        let buffer =
                            self.alloc_process_heap_block((required * 2) as u64, "FormatMessageW")?;
                        let _ = self.write_wide_string_to_memory(buffer, required, &text)?;
                        self.write_pointer_value(ctx.raw(4), buffer)?;
                        Ok((required - 1) as u64)
                    } else if ctx.raw(4) != 0 && ctx.raw(5) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(4),
                            ctx.raw(5) as usize,
                            &text,
                        )?;
                        Ok((required - 1) as u64)
                    } else {
                        Ok(0)
                    }
                }
                "MulDiv" => {
                    if ctx.raw(2) == 0 {
                        Ok((-1i32) as u64)
                    } else {
                        let result =
                            ((ctx.raw(0) as i64 * ctx.raw(1) as i64) / ctx.raw(2) as i64) as i32;
                        Ok(result as u64)
                    }
                }
                "GetPrivateProfileStringW" => {
                    let default = self.read_wide_string_from_memory(ctx.raw(2))?;
                    let written = self.write_wide_string_to_memory(
                        ctx.raw(3),
                        ctx.raw(4) as usize,
                        &default,
                    )?;
                    Ok(written)
                }
                "GetPrivateProfileStringA" => {
                    let default = self.read_c_string_from_memory(ctx.raw(2))?;
                    let written =
                        self.write_c_string_to_memory(ctx.raw(3), ctx.raw(4) as usize, &default)?;
                    Ok(written)
                }
                "GetPrivateProfileIntW" => Ok(ctx.raw(2)),
                "WritePrivateProfileStringW" => Ok(1),
                "WritePrivateProfileStringA" => Ok(1),
                "VerLanguageNameW" => {
                    let language_name = "English (United States)";
                    let required = language_name.encode_utf16().count() + 1;
                    if ctx.raw(1) != 0 && ctx.raw(2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            language_name,
                        )?;
                    }
                    Ok(required as u64)
                }
                "VerSetConditionMask" => {
                    let (current_mask, type_mask, condition) = if self.core.arch.is_x86() {
                        (ctx.raw(0) | (ctx.raw(1) << 32), ctx.raw(2), ctx.raw(3))
                    } else {
                        (ctx.raw(0), ctx.raw(1), ctx.raw(2))
                    };
                    let bit_shift = (type_mask.trailing_zeros().min(20) * 3) as u64;
                    Ok(current_mask | ((condition & 0x7) << bit_shift))
                }
                "VerifyVersionInfoA" | "VerifyVersionInfoW" => Ok(1),
                "AddVectoredExceptionHandler" => {
                    let handle =
                        self.register_vectored_exception_handler(ctx.raw(0) != 0, ctx.raw(1));
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(handle)
                }
                "RemoveVectoredExceptionHandler" => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(self.remove_vectored_exception_handler(ctx.raw(0) as u32) as u64)
                }
                "WaitForSingleObjectEx" => self.wait_for_objects(
                    &[ctx.raw(0) as u32],
                    false,
                    ctx.raw(1) as u32,
                    ctx.raw(2) != 0,
                ),
                "VirtualProtect" => self.virtual_protect(
                    self.current_process_space_key(),
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as u32,
                    ctx.raw(3),
                    "VirtualProtect",
                ),
                "VirtualQuery" => {
                    if ctx.raw(1) == 0 {
                        return Ok(0);
                    }
                    let info = self.query_memory_basic_information(ctx.raw(0));
                    Ok(
                        self.write_memory_basic_information(ctx.raw(1), ctx.raw(2) as usize, info)?
                            as u64,
                    )
                }
                "VirtualQueryEx" => {
                    if ctx.raw(2) == 0 || !self.is_known_process_target(ctx.raw(0)) {
                        return Ok(0);
                    }
                    let Some(info) =
                        self.query_memory_basic_information_for_process(ctx.raw(0), ctx.raw(1))
                    else {
                        return Ok(0);
                    };
                    Ok(
                        self.write_memory_basic_information(ctx.raw(2), ctx.raw(3) as usize, info)?
                            as u64,
                    )
                }
                _ => unreachable!(),
            }
        })())
    }
}

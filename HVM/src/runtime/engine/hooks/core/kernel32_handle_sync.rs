use super::*;

impl VirtualExecutionEngine {
    /// Handle/Process/Thread/Synchronization dispatch — first 85 match arms.
    pub(in crate::runtime::engine) fn dispatch_k32_handle_sync(
        &mut self,
        function: &str,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let _ = (signature, stub_address);
        match function {
            "CancelIo"
            | "CloseHandle"
            | "DuplicateHandle"
            | "EnumSystemFirmwareTables"
            | "CreateMutexA"
            | "CreateMutexExW"
            | "CreateMutexW"
            | "CreateSemaphoreExW"
            | "CreateSemaphoreW"
            | "InitOnceExecuteOnce"
            | "IsBadReadPtr"
            | "CreateActCtxW"
            | "CreateEventA"
            | "CreateEventW"
            | "CreateFileA"
            | "CreateFileW"
            | "CreateFileMappingA"
            | "CreateFileMappingW"
            | "CreateIoCompletionPort"
            | "CreateNamedPipeW"
            | "CreateDirectoryA"
            | "CreateDirectoryW"
            | "CreatePipe"
            | "CreateProcessA"
            | "CreateProcessW"
            | "WinExec"
            | "CreateWaitableTimerW"
            | "CreateThread"
            | "CreateRemoteThread"
            | "CreateRemoteThreadEx"
            | "CreateToolhelp32Snapshot"
            | "CopyFileW"
            | "DeleteFileA"
            | "DeleteFileW"
            | "DecodePointer"
            | "EncodePointer"
            | "DeleteCriticalSection"
            | "AcquireSRWLockExclusive"
            | "EnterCriticalSection"
            | "InitializeConditionVariable"
            | "InitializeCriticalSection"
            | "LeaveCriticalSection"
            | "ReleaseSRWLockExclusive"
            | "WakeAllConditionVariable"
            | "WakeConditionVariable"
            | "OutputDebugStringA"
            | "OutputDebugStringW"
            | "DebugBreak"
            | "InitializeCriticalSectionEx"
            | "InitializeCriticalSectionAndSpinCount"
            | "SetConsoleCtrlHandler"
            | "SetStdHandle"
            | "SetEvent"
            | "SignalObjectAndWait"
            | "SleepConditionVariableCS"
            | "SleepConditionVariableSRW"
            | "ExpandEnvironmentStringsA"
            | "ExpandEnvironmentStringsW"
            | "Sleep"
            | "SleepEx"
            | "SwitchToThread"
            | "SuspendThread"
            | "TerminateThread"
            | "DeviceIoControl"
            | "ExitProcess"
            | "ExitThread"
            | "FindResourceA"
            | "FindResourceW"
            | "FindClose"
            | "FindVolumeClose"
            | "FindFirstFileA"
            | "FindFirstFileW"
            | "FindFirstFileExA"
            | "FindFirstFileExW"
            | "FindFirstVolumeW"
            | "FindNextFileA"
            | "FindNextFileW"
            | "FindNextVolumeW"
            | "FreeConsole"
            | "FreeEnvironmentStringsA"
            | "FreeEnvironmentStringsW"
            | "FlushInstructionCache"
            | "FreeResource"
            | "FreeLibrary"
            | "FlsAlloc"
            | "FlsFree"
            | "FlsGetValue"
            | "FlsGetValue2"
            | "FlsSetValue"
            | "FlushFileBuffers"
            | "FlushViewOfFile"
            | "AreFileApisANSI" => {}
            _ => return None,
        }
        Some((|| -> Result<u64, VmError> {
            match function {
                "CancelIo" => Ok(1),
                "CloseHandle" => {
                    let closed = self.close_object_handle(ctx.raw(0) as u32);
                    self.set_last_error(if closed {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_HANDLE as u32
                    });
                    Ok(closed as u64)
                }
                "DuplicateHandle" => self.duplicate_runtime_handle(
                    ctx.raw(0),
                    ctx.raw(1) as u32,
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(6),
                ),
                "EnumSystemFirmwareTables" => {
                    let entries = Self::synthetic_firmware_table_list(ctx.raw(0) as u32);
                    if ctx.raw(1) != 0 && ctx.raw(2) as usize >= entries.len() {
                        self.core.modules.memory_mut().write(ctx.raw(1), &entries)?;
                    }
                    Ok(entries.len() as u64)
                }
                "CreateMutexA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(2))?;
                    Ok(self.create_mutex_handle(&name, ctx.raw(1) != 0))
                }
                "CreateMutexExW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(1))?;
                    Ok(self.create_mutex_handle(&name, (ctx.raw(2) & 0x1) != 0))
                }
                "CreateMutexW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(2))?;
                    Ok(self.create_mutex_handle(&name, ctx.raw(1) != 0))
                }
                "CreateSemaphoreExW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(3))?;
                    Ok(self.create_semaphore_handle(&name, ctx.raw(1) as u32, ctx.raw(2) as u32))
                }
                "CreateSemaphoreW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(3))?;
                    Ok(self.create_semaphore_handle(&name, ctx.raw(1) as u32, ctx.raw(2) as u32))
                }
                "InitOnceExecuteOnce" => {
                    let init_once = ctx.raw(0);
                    let callback = ctx.raw(1);
                    if init_once == 0 || callback == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    if self.dispatch.completed_init_once.contains(&init_once) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok(1);
                    }
                    self.dispatch.completed_init_once.insert(init_once);
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "IsBadReadPtr" => {
                    let pointer = ctx.raw(0);
                    let size = ctx.raw(1);
                    Ok(if pointer == 0 {
                        1
                    } else if size == 0 {
                        0
                    } else if self.core.modules.memory().is_range_mapped(pointer, size) {
                        0
                    } else {
                        1
                    })
                }
                "CreateActCtxW" => {
                    if ctx.raw(0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(self.invalid_handle_value_for_arch())
                    } else {
                        let handle = self.allocate_object_handle();
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(handle as u64)
                    }
                }
                "CreateEventA" | "CreateEventW" => {
                    let event = self
                        .core
                        .scheduler
                        .create_event(ctx.raw(1) != 0, ctx.raw(2) != 0)
                        .ok_or(VmError::RuntimeInvariant("failed to create event"))?;
                    Ok(event.handle as u64)
                }
                "CreateFileA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    // dwCreationDisposition is a DWORD; upper 32 bits may contain
                    // stack garbage on x64 when the caller uses a 32-bit store.
                    self.create_file_handle(&path, ctx.raw(1), ctx.raw(4) & 0xFFFF_FFFF)
                }
                "CreateFileW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    self.create_file_handle(&path, ctx.raw(1), ctx.raw(4) & 0xFFFF_FFFF)
                }
                "CreateFileMappingA" => {
                    let name = self.read_c_string_from_memory(ctx.raw(5))?;
                    self.create_file_mapping_handle(
                        ctx.raw(0),
                        ctx.raw(2) as u32,
                        (ctx.raw(3) << 32) | ctx.raw(4),
                        &name,
                    )
                }
                "CreateFileMappingW" => {
                    let name = self.read_wide_string_from_memory(ctx.raw(5))?;
                    self.create_file_mapping_handle(
                        ctx.raw(0),
                        ctx.raw(2) as u32,
                        (ctx.raw(3) << 32) | ctx.raw(4),
                        &name,
                    )
                }
                "CreateIoCompletionPort" => {
                    let existing = ctx.raw(1) as u32;
                    if existing != 0 {
                        if self.handles.io_completion_ports.contains_key(&existing) {
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(existing as u64)
                        } else {
                            self.set_last_error(ERROR_INVALID_HANDLE as u32);
                            Ok(0)
                        }
                    } else {
                        let handle = self.allocate_object_handle();
                        self.handles
                            .io_completion_ports
                            .entry(handle)
                            .or_insert_with(VecDeque::new);
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(handle as u64)
                    }
                }
                "CreateNamedPipeW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(self.invalid_handle_value_for_arch());
                    }
                    let handle = self.allocate_file_handle();
                    self.handles.device_handles.insert(
                        handle,
                        DeviceHandleState {
                            path,
                            physical_drive_index: None,
                            position: 0,
                        },
                    );
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(handle as u64)
                }
                "CreateDirectoryA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let target = self.resolve_runtime_path(&path);
                    if target.exists() {
                        self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                        Ok(0)
                    } else {
                        let result = std::fs::create_dir_all(&target).is_ok() as u64;
                        if result != 0 {
                            self.log_file_event("FILE_MKDIR", 0, &target.to_string_lossy(), None)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                        }
                        Ok(result)
                    }
                }
                "CreateDirectoryW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    if path.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let target = self.resolve_runtime_path(&path);
                    if target.exists() {
                        self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                        Ok(0)
                    } else {
                        let result = std::fs::create_dir_all(&target).is_ok() as u64;
                        if result != 0 {
                            self.log_file_event("FILE_MKDIR", 0, &target.to_string_lossy(), None)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                        }
                        Ok(result)
                    }
                }
                "CreatePipe" => {
                    if ctx.raw(0) == 0 || ctx.raw(1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let read_handle = self.allocate_file_handle();
                    let write_handle = self.allocate_file_handle();
                    self.handles.device_handles.insert(
                        read_handle,
                        DeviceHandleState {
                            path: String::from(r"\\.\pipe\anonymous-read"),
                            physical_drive_index: None,
                            position: 0,
                        },
                    );
                    self.handles.device_handles.insert(
                        write_handle,
                        DeviceHandleState {
                            path: String::from(r"\\.\pipe\anonymous-write"),
                            physical_drive_index: None,
                            position: 0,
                        },
                    );
                    self.write_pointer_value(ctx.raw(0), read_handle as u64)?;
                    self.write_pointer_value(ctx.raw(1), write_handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                "CreateProcessA" => {
                    let application_name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let command_line = self.read_c_string_from_memory(ctx.raw(1))?;
                    let current_directory = if ctx.raw(7) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_c_string_from_memory(ctx.raw(7))?,
                        )
                    } else {
                        self.current_directory_display_text()
                    };
                    let image = if !application_name.is_empty() {
                        application_name
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
                    self.write_process_information(ctx.raw(9), handle, 0, handle, 0)?;
                    self.log_process_spawn(
                        "CreateProcessA",
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
                "CreateProcessW" => {
                    let application_name = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let command_line = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let current_directory = if ctx.raw(7) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_wide_string_from_memory(ctx.raw(7))?,
                        )
                    } else {
                        self.current_directory_display_text()
                    };
                    let image = if !application_name.is_empty() {
                        application_name
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
                    self.write_process_information(ctx.raw(9), handle, 0, handle, 0)?;
                    self.log_process_spawn(
                        "CreateProcessW",
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
                "WinExec" => {
                    let command_line = self.read_c_string_from_memory(ctx.raw(0))?;
                    let image = command_line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .trim_matches('"')
                        .to_string();
                    if image.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let current_directory = self.current_directory_display_text();
                    let Some(handle) = self.core.processes.spawn_shell_execute(
                        &image,
                        non_empty(&command_line),
                        Some(&current_directory),
                    ) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    self.log_process_spawn(
                        "WinExec",
                        handle,
                        &image,
                        &command_line,
                        &current_directory,
                    )?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(33)
                }
                "CreateWaitableTimerW" => {
                    let timer = self
                        .core
                        .scheduler
                        .create_event(ctx.raw(1) != 0, false)
                        .ok_or(VmError::RuntimeInvariant("failed to create waitable timer"))?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(timer.handle as u64)
                }
                "CreateThread" => {
                    self.create_runtime_thread(ctx.raw(2), ctx.raw(3), ctx.raw(4), ctx.raw(5))
                }
                "CreateRemoteThread" => {
                    let process_handle = ctx.raw(0);
                    if self.is_current_process_handle(process_handle)
                        || self.is_synthetic_process_handle(process_handle)
                    {
                        return self.create_runtime_thread(
                            ctx.raw(3),
                            ctx.raw(4),
                            ctx.raw(5),
                            ctx.raw(6),
                        );
                    }
                    if !self.is_known_process_target(process_handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let suspended = ctx.raw(5) & 0x4 != 0;
                    let Some(handle) = self.create_remote_shellcode_thread(
                        process_handle,
                        ctx.raw(3),
                        ctx.raw(4),
                        suspended,
                        ctx.raw(6),
                        "CreateRemoteThread",
                    )?
                    else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    Ok(handle)
                }
                "CreateRemoteThreadEx" => {
                    let process_handle = ctx.raw(0);
                    if self.is_current_process_handle(process_handle)
                        || self.is_synthetic_process_handle(process_handle)
                    {
                        return self.create_runtime_thread(
                            ctx.raw(3),
                            ctx.raw(4),
                            ctx.raw(5),
                            ctx.raw(7),
                        );
                    }
                    if !self.is_known_process_target(process_handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let suspended = ctx.raw(5) & 0x4 != 0;
                    let Some(handle) = self.create_remote_shellcode_thread(
                        process_handle,
                        ctx.raw(3),
                        ctx.raw(4),
                        suspended,
                        ctx.raw(7),
                        "CreateRemoteThreadEx",
                    )?
                    else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    Ok(handle)
                }
                "CreateToolhelp32Snapshot" => self.create_toolhelp_snapshot(ctx.raw(0), ctx.raw(1)),
                "CopyFileW" => {
                    let source = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let destination = self.read_wide_string_from_memory(ctx.raw(1))?;
                    let Some(source_path) =
                        self.prepare_runtime_read_target(&source, "CopyFileW")?
                    else {
                        return Ok(0);
                    };
                    self.ensure_runtime_path_backing(&destination)?;
                    let destination_path = self.resolve_runtime_path(&destination);
                    if ctx.raw(2) != 0 && destination_path.exists() {
                        self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                        return Ok(0);
                    }
                    let result = std::fs::copy(&source_path, &destination_path).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event(
                            "FILE_COPY",
                            0,
                            &format!(
                                "{} -> {}",
                                source_path.to_string_lossy(),
                                destination_path.to_string_lossy()
                            ),
                            None,
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    }
                    Ok(result)
                }
                "DeleteFileA" | "DeleteFileW" => {
                    let path = if function == "DeleteFileA" {
                        self.read_c_string_from_memory(ctx.raw(0))?
                    } else {
                        self.read_wide_string_from_memory(ctx.raw(0))?
                    };
                    // Check virtual_fs first — files written by CreateFileW during
                    // emulation land in sandbox/virtual_fs/<drive>/..., but the
                    // normal read-resolution prefers the host volume mapping.
                    // Do NOT physically delete: the file is preserved for analysis.
                    if let Some(vpath) = self.resolve_volume_virtual_fs_path(&path) {
                        if vpath.exists() {
                            self.log_file_event("FILE_DELETE", 0, &vpath.to_string_lossy(), None)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            return Ok(1);
                        }
                    }
                    // Fall back to the normal host resolution path.
                    let Some(target) = self.prepare_runtime_read_target(&path, function)? else {
                        return Ok(0);
                    };
                    if target.exists() {
                        self.log_file_event("FILE_DELETE", 0, &target.to_string_lossy(), None)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        Ok(0)
                    }
                }
                "DecodePointer" | "EncodePointer" => Ok(ctx.raw(0)),
                "DeleteCriticalSection"
                | "AcquireSRWLockExclusive"
                | "EnterCriticalSection"
                | "InitializeConditionVariable"
                | "InitializeCriticalSection"
                | "LeaveCriticalSection"
                | "ReleaseSRWLockExclusive"
                | "WakeAllConditionVariable"
                | "WakeConditionVariable"
                | "OutputDebugStringA"
                | "OutputDebugStringW" => Ok(0),
                "DebugBreak" => Ok(0),
                "InitializeCriticalSectionEx"
                | "InitializeCriticalSectionAndSpinCount"
                | "SetConsoleCtrlHandler"
                | "SetStdHandle" => Ok(1),
                "SetEvent" => Ok(self.core.scheduler.set_event(ctx.raw(0) as u32).is_some() as u64),
                "SignalObjectAndWait" => self.signal_object_and_wait(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as u32,
                    ctx.raw(3) != 0,
                ),
                "SleepConditionVariableCS" | "SleepConditionVariableSRW" => {
                    if ctx.raw(2) == 0 {
                        self.set_last_error(ERROR_TIMEOUT as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                "ExpandEnvironmentStringsA" => {
                    let source = self.read_c_string_from_memory(ctx.raw(0))?;
                    let expanded = self.expand_environment_strings(&source);
                    let required = expanded.len() + 1;
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_c_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            &expanded,
                        )?;
                        Ok(required as u64)
                    }
                }
                "ExpandEnvironmentStringsW" => {
                    let source = self.read_wide_string_from_memory(ctx.raw(0))?;
                    let expanded = self.expand_environment_strings(&source);
                    let required = expanded.encode_utf16().count() + 1;
                    if ctx.raw(1) == 0 || ctx.raw(2) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            ctx.raw(1),
                            ctx.raw(2) as usize,
                            &expanded,
                        )?;
                        Ok(required as u64)
                    }
                }
                "Sleep" => {
                    if let Some(result) = self.core.scheduler.consume_wait_result() {
                        Ok(if result == WAIT_IO_COMPLETION {
                            WAIT_IO_COMPLETION as u64
                        } else {
                            0
                        })
                    } else if self.core.scheduler.current_tid().is_none() {
                        self.dispatch.time.advance(ctx.raw(0));
                        Ok(0)
                    } else {
                        let store_wait_result = self.dispatch.preserve_blocked_api_frame;
                        let _ = self.core.scheduler.sleep_current_thread(
                            self.dispatch.time.current().tick_ms,
                            ctx.raw(0) as u32,
                            false,
                            store_wait_result,
                        );
                        self.request_thread_yield("sleep", false);
                        let _ = self.log_thread_yield_event("sleep", Some(ctx.raw(0)), false);
                        Ok(0)
                    }
                }
                "SleepEx" => {
                    if let Some(result) = self.core.scheduler.consume_wait_result() {
                        Ok(if result == WAIT_IO_COMPLETION {
                            WAIT_IO_COMPLETION as u64
                        } else {
                            0
                        })
                    } else if self.core.scheduler.current_tid().is_none() {
                        self.dispatch.time.advance(ctx.raw(0));
                        Ok(0)
                    } else {
                        let alertable = ctx.raw(1) != 0;
                        let store_wait_result =
                            self.dispatch.preserve_blocked_api_frame || alertable;
                        let _ = self.core.scheduler.sleep_current_thread(
                            self.dispatch.time.current().tick_ms,
                            ctx.raw(0) as u32,
                            alertable,
                            store_wait_result,
                        );
                        self.request_thread_yield("sleep", alertable);
                        let _ =
                            self.log_thread_yield_event("sleep_ex", Some(ctx.raw(0)), alertable);
                        Ok(0)
                    }
                }
                "SwitchToThread" => Ok(1),
                "SuspendThread" => Ok(
                    if self
                        .core
                        .scheduler
                        .thread_tid_for_handle(ctx.raw(0) as u32)
                        .is_some()
                    {
                        0
                    } else {
                        u32::MAX as u64
                    },
                ),
                "TerminateThread" => {
                    let terminated = self.terminate_thread_handle(ctx.raw(0), ctx.raw(1) as u32);
                    self.set_last_error(if terminated {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_HANDLE as u32
                    });
                    Ok(terminated as u64)
                }
                "DeviceIoControl" => {
                    if let Some(result) =
                        self.handle_device_io_control(ctx.raw(0) as u32, ctx.raw(1), ctx.args())?
                    {
                        return Ok(result);
                    }
                    if ctx.raw(6) != 0 {
                        self.write_u32(ctx.raw(6), 0)?;
                    }
                    Ok(0)
                }
                "ExitProcess" => {
                    self.core.exit_code = Some(ctx.raw(0) as u32);
                    self.core.process_exit_requested = true;
                    self.dispatch.force_native_return = true;
                    Ok(ctx.raw(0))
                }
                "ExitThread" => {
                    self.dispatch.force_native_return = true;
                    Ok(ctx.raw(0))
                }
                "FindResourceA" | "FindResourceW" => self.find_resource_common(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    function.ends_with('W'),
                    None,
                ),
                "FindClose" => Ok(self.close_find_handle(ctx.raw(0) as u32)),
                "FindVolumeClose" => Ok(self.close_find_volume_handle(ctx.raw(0) as u32)),
                "FindFirstFileA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    self.find_first_file(&path, ctx.raw(1), false)
                }
                "FindFirstFileW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    self.find_first_file(&path, ctx.raw(1), true)
                }
                "FindFirstFileExA" => {
                    let path = self.read_c_string_from_memory(ctx.raw(0))?;
                    self.find_first_file(&path, ctx.raw(2), false)
                }
                "FindFirstFileExW" => {
                    let path = self.read_wide_string_from_memory(ctx.raw(0))?;
                    self.find_first_file(&path, ctx.raw(2), true)
                }
                "FindFirstVolumeW" => self.find_first_volume(ctx.raw(0), ctx.raw(1) as usize),
                "FindNextFileA" => self.find_next_file(ctx.raw(0) as u32, ctx.raw(1), false),
                "FindNextFileW" => self.find_next_file(ctx.raw(0) as u32, ctx.raw(1), true),
                "FindNextVolumeW" => {
                    self.find_next_volume(ctx.raw(0) as u32, ctx.raw(1), ctx.raw(2) as usize)
                }
                "FreeConsole" => Ok(1),
                "FreeEnvironmentStringsA" | "FreeEnvironmentStringsW" => Ok(1),
                // FlushInstructionCache is a no-op in user-mode on x86/x64;
                // always returns TRUE.
                "FlushInstructionCache" => Ok(1),
                "FreeResource" => Ok(0),
                "FreeLibrary" => {
                    let handle = ctx.raw(0);
                    let Some(module) = self.module_record_for_handle(handle).cloned() else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    if self
                        .core
                        .main_module
                        .as_ref()
                        .map(|main_module| main_module.base)
                        == Some(module.base)
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        if self.objects.startup_pinned_modules.contains(&module.base) {
                            if let Some(count) =
                                self.objects.dynamic_library_refs.get_mut(&module.base)
                            {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    let _ = self.objects.dynamic_library_refs.remove(&module.base);
                                }
                            }
                            self.set_last_error(ERROR_SUCCESS as u32);
                            return Ok(1);
                        }
                        if let Some(count) = self.objects.dynamic_library_refs.get_mut(&module.base)
                        {
                            if *count > 1 {
                                *count -= 1;
                                self.set_last_error(ERROR_SUCCESS as u32);
                                return Ok(1);
                            }
                        }
                        let _ = self.objects.dynamic_library_refs.remove(&module.base);
                        self.run_dynamic_library_detach(&module)?;
                        if self.core.modules.unload_module(module.base) {
                            self.unregister_process_virtual_allocation(
                                self.current_process_space_key(),
                                module.base,
                            );
                            self.sync_process_environment_modules()?;
                            self.log_module_event("MODULE_UNLOAD", &module, "FreeLibrary")?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok(1)
                        } else {
                            self.set_last_error(ERROR_INVALID_HANDLE as u32);
                            Ok(0)
                        }
                    }
                }
                "FlsAlloc" => {
                    let callback = ctx.raw(0);
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
                        return Err(VmError::RuntimeInvariant("fls slot allocator drifted"));
                    }
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[HOOK] FlsAlloc tid={} callback=0x{:X} slot={} teb=0x{:X}",
                            self.current_tls_thread_id(),
                            callback,
                            slot,
                            self.core.process_env.current_teb(),
                        );
                    }
                    self.sync_native_support_state()?;
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[HOOK] FlsAlloc:done tid={} slot={} teb=0x{:X}",
                            self.current_tls_thread_id(),
                            slot,
                            self.core.process_env.current_teb(),
                        );
                    }
                    Ok(slot as u64)
                }
                "FlsFree" => {
                    if !self.dispatch.tls.free(ctx.raw(0) as usize) {
                        return Ok(0);
                    }
                    let _ = self.core.process_env.free_tls_slot(ctx.raw(0) as usize)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                "FlsGetValue" | "FlsGetValue2" => Ok(self
                    .dispatch
                    .tls
                    .get_value_for_thread(self.current_tls_thread_id(), ctx.raw(0) as usize)),
                "FlsSetValue" => {
                    let slot = ctx.raw(0) as usize;
                    let value = ctx.raw(1);
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[HOOK] FlsSetValue tid={} slot={} value=0x{:X} teb=0x{:X}",
                            self.current_tls_thread_id(),
                            slot,
                            value,
                            self.core.process_env.current_teb(),
                        );
                    }
                    if !self.dispatch.tls.set_value_for_thread(
                        self.current_tls_thread_id(),
                        slot,
                        value,
                    ) {
                        return Ok(0);
                    }
                    self.core.process_env.set_tls_value(slot, value)?;
                    self.sync_native_support_state()?;
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[HOOK] FlsSetValue:done tid={} slot={} value=0x{:X}",
                            self.current_tls_thread_id(),
                            slot,
                            value,
                        );
                    }
                    Ok(1)
                }
                "FlushFileBuffers" => {
                    if let Some(result) = self.flush_device_handle(ctx.raw(0) as u32) {
                        return Ok(result);
                    }
                    let Some(state) = self.handles.file_handles.get_mut(&(ctx.raw(0) as u32))
                    else {
                        return Ok(0);
                    };
                    Ok(state.file.sync_all().is_ok() as u64)
                }
                "FlushViewOfFile" => self.flush_view_of_file(ctx.raw(0), ctx.raw(1)),
                "AreFileApisANSI" => Ok(1),
                _ => unreachable!(),
            }
        })())
    }
}

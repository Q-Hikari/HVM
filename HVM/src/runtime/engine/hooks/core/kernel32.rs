use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_kernel32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        definition: &HookDefinition,
        stub_address: u64,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        if module_name != "kernel32.dll" {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("kernel32.dll", "CancelIo") => Ok(1),
                ("kernel32.dll", "CloseHandle") => {
                    let closed = self.close_object_handle(arg(args, 0) as u32);
                    self.set_last_error(if closed {
                        ERROR_SUCCESS as u32
                    } else {
                        ERROR_INVALID_HANDLE as u32
                    });
                    Ok(closed as u64)
                }
                ("kernel32.dll", "DuplicateHandle") => self.duplicate_runtime_handle(
                    arg(args, 0),
                    arg(args, 1) as u32,
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 6),
                ),
                ("kernel32.dll", "EnumSystemFirmwareTables") => {
                    let entries = Self::synthetic_firmware_table_list(arg(args, 0) as u32);
                    if arg(args, 1) != 0 && arg(args, 2) as usize >= entries.len() {
                        self.modules.memory_mut().write(arg(args, 1), &entries)?;
                    }
                    Ok(entries.len() as u64)
                }
                ("kernel32.dll", "CreateMutexA") => {
                    let name = self.read_c_string_from_memory(arg(args, 2))?;
                    Ok(self.create_mutex_handle(&name, arg(args, 1) != 0))
                }
                ("kernel32.dll", "CreateMutexW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 2))?;
                    Ok(self.create_mutex_handle(&name, arg(args, 1) != 0))
                }
                ("kernel32.dll", "IsBadReadPtr") => {
                    let pointer = arg(args, 0);
                    let size = arg(args, 1);
                    Ok(if pointer == 0 {
                        1
                    } else if size == 0 {
                        0
                    } else if self.modules.memory().is_range_mapped(pointer, size) {
                        0
                    } else {
                        1
                    })
                }
                ("kernel32.dll", "CreateActCtxW") => {
                    if arg(args, 0) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(self.invalid_handle_value_for_arch())
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(self.allocate_object_handle() as u64)
                    }
                }
                ("kernel32.dll", "CreateEventA") | ("kernel32.dll", "CreateEventW") => {
                    let event = self
                        .scheduler
                        .create_event(arg(args, 1) != 0, arg(args, 2) != 0)
                        .ok_or(VmError::RuntimeInvariant("failed to create event"))?;
                    Ok(event.handle as u64)
                }
                ("kernel32.dll", "CreateFileA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
                    self.create_file_handle(&path, arg(args, 1), arg(args, 4))
                }
                ("kernel32.dll", "CreateFileW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    self.create_file_handle(&path, arg(args, 1), arg(args, 4))
                }
                ("kernel32.dll", "CreateFileMappingA") => {
                    let name = self.read_c_string_from_memory(arg(args, 5))?;
                    self.create_file_mapping_handle(
                        arg(args, 0),
                        arg(args, 2) as u32,
                        (arg(args, 3) << 32) | arg(args, 4),
                        &name,
                    )
                }
                ("kernel32.dll", "CreateFileMappingW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 5))?;
                    self.create_file_mapping_handle(
                        arg(args, 0),
                        arg(args, 2) as u32,
                        (arg(args, 3) << 32) | arg(args, 4),
                        &name,
                    )
                }
                ("kernel32.dll", "CreateDirectoryA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
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
                ("kernel32.dll", "CreateDirectoryW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
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
                ("kernel32.dll", "CreatePipe") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let read_handle = self.allocate_file_handle();
                    let write_handle = self.allocate_file_handle();
                    self.device_handles.insert(
                        read_handle,
                        DeviceHandleState {
                            path: String::from(r"\\.\pipe\anonymous-read"),
                            physical_drive_index: None,
                            position: 0,
                        },
                    );
                    self.device_handles.insert(
                        write_handle,
                        DeviceHandleState {
                            path: String::from(r"\\.\pipe\anonymous-write"),
                            physical_drive_index: None,
                            position: 0,
                        },
                    );
                    self.write_pointer_value(arg(args, 0), read_handle as u64)?;
                    self.write_pointer_value(arg(args, 1), write_handle as u64)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "CreateProcessA") => {
                    let application_name = self.read_c_string_from_memory(arg(args, 0))?;
                    let command_line = self.read_c_string_from_memory(arg(args, 1))?;
                    let current_directory = if arg(args, 7) != 0 {
                        self.resolve_runtime_display_path(
                            &self.read_c_string_from_memory(arg(args, 7))?,
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
                    self.write_process_information(arg(args, 9), handle, 0, handle, 0)?;
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
                ("kernel32.dll", "CreateProcessW") => {
                    let application_name = self.read_wide_string_from_memory(arg(args, 0))?;
                    let command_line = self.read_wide_string_from_memory(arg(args, 1))?;
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
                    self.write_process_information(arg(args, 9), handle, 0, handle, 0)?;
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
                ("kernel32.dll", "CreateWaitableTimerW") => {
                    let timer = self
                        .scheduler
                        .create_event(arg(args, 1) != 0, false)
                        .ok_or(VmError::RuntimeInvariant("failed to create waitable timer"))?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(timer.handle as u64)
                }
                ("kernel32.dll", "CreateThread") => self.create_runtime_thread(
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                ),
                ("kernel32.dll", "CreateRemoteThread") => {
                    let process_handle = arg(args, 0);
                    if self.is_current_process_handle(process_handle) {
                        return self.create_runtime_thread(
                            arg(args, 3),
                            arg(args, 4),
                            arg(args, 5),
                            arg(args, 6),
                        );
                    }
                    if !self.is_known_process_target(process_handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let suspended = arg(args, 5) & 0x4 != 0;
                    let Some(handle) = self.create_remote_shellcode_thread(
                        process_handle,
                        arg(args, 3),
                        arg(args, 4),
                        suspended,
                        arg(args, 6),
                        "CreateRemoteThread",
                    )?
                    else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    Ok(handle)
                }
                ("kernel32.dll", "CreateRemoteThreadEx") => {
                    let process_handle = arg(args, 0);
                    if self.is_current_process_handle(process_handle) {
                        return self.create_runtime_thread(
                            arg(args, 3),
                            arg(args, 4),
                            arg(args, 5),
                            arg(args, 7),
                        );
                    }
                    if !self.is_known_process_target(process_handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let suspended = arg(args, 5) & 0x4 != 0;
                    let Some(handle) = self.create_remote_shellcode_thread(
                        process_handle,
                        arg(args, 3),
                        arg(args, 4),
                        suspended,
                        arg(args, 7),
                        "CreateRemoteThreadEx",
                    )?
                    else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    Ok(handle)
                }
                ("kernel32.dll", "CreateToolhelp32Snapshot") => {
                    self.create_toolhelp_snapshot(arg(args, 0), arg(args, 1))
                }
                ("kernel32.dll", "CopyFileW") => {
                    let source = self.read_wide_string_from_memory(arg(args, 0))?;
                    let destination = self.read_wide_string_from_memory(arg(args, 1))?;
                    let Some(source_path) =
                        self.prepare_runtime_read_target(&source, "CopyFileW")?
                    else {
                        return Ok(0);
                    };
                    self.ensure_runtime_path_backing(&destination)?;
                    let destination_path = self.resolve_runtime_path(&destination);
                    if arg(args, 2) != 0 && destination_path.exists() {
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
                ("kernel32.dll", "DeleteFileA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
                    let Some(target) = self.prepare_runtime_read_target(&path, "DeleteFileA")?
                    else {
                        return Ok(0);
                    };
                    let result = std::fs::remove_file(&target).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event("FILE_DELETE", 0, &target.to_string_lossy(), None)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    }
                    Ok(result)
                }
                ("kernel32.dll", "DeleteFileW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    let Some(target) = self.prepare_runtime_read_target(&path, "DeleteFileW")?
                    else {
                        return Ok(0);
                    };
                    let result = std::fs::remove_file(&target).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event("FILE_DELETE", 0, &target.to_string_lossy(), None)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    }
                    Ok(result)
                }
                ("kernel32.dll", "DecodePointer") | ("kernel32.dll", "EncodePointer") => {
                    Ok(arg(args, 0))
                }
                ("kernel32.dll", "DeleteCriticalSection")
                | ("kernel32.dll", "EnterCriticalSection")
                | ("kernel32.dll", "InitializeConditionVariable")
                | ("kernel32.dll", "InitializeCriticalSection")
                | ("kernel32.dll", "LeaveCriticalSection")
                | ("kernel32.dll", "WakeAllConditionVariable")
                | ("kernel32.dll", "WakeConditionVariable")
                | ("kernel32.dll", "OutputDebugStringA")
                | ("kernel32.dll", "OutputDebugStringW") => Ok(0),
                ("kernel32.dll", "DebugBreak") => Ok(0),
                ("kernel32.dll", "InitializeCriticalSectionEx")
                | ("kernel32.dll", "InitializeCriticalSectionAndSpinCount")
                | ("kernel32.dll", "SetStdHandle") => Ok(1),
                ("kernel32.dll", "SetEvent") => {
                    Ok(self.scheduler.set_event(arg(args, 0) as u32).is_some() as u64)
                }
                ("kernel32.dll", "SignalObjectAndWait") => self.signal_object_and_wait(
                    arg(args, 0) as u32,
                    arg(args, 1) as u32,
                    arg(args, 2) as u32,
                    arg(args, 3) != 0,
                ),
                ("kernel32.dll", "SleepConditionVariableCS")
                | ("kernel32.dll", "SleepConditionVariableSRW") => {
                    if arg(args, 2) == 0 {
                        self.set_last_error(ERROR_TIMEOUT as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "ExpandEnvironmentStringsA") => {
                    let source = self.read_c_string_from_memory(arg(args, 0))?;
                    let expanded = self.expand_environment_strings(&source);
                    let required = expanded.len() + 1;
                    if arg(args, 1) == 0 || arg(args, 2) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_c_string_to_memory(
                            arg(args, 1),
                            arg(args, 2) as usize,
                            &expanded,
                        )?;
                        Ok(required as u64)
                    }
                }
                ("kernel32.dll", "ExpandEnvironmentStringsW") => {
                    let source = self.read_wide_string_from_memory(arg(args, 0))?;
                    let expanded = self.expand_environment_strings(&source);
                    let required = expanded.encode_utf16().count() + 1;
                    if arg(args, 1) == 0 || arg(args, 2) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 1),
                            arg(args, 2) as usize,
                            &expanded,
                        )?;
                        Ok(required as u64)
                    }
                }
                ("kernel32.dll", "Sleep") => {
                    if let Some(result) = self.scheduler.consume_wait_result() {
                        Ok(if result == WAIT_IO_COMPLETION {
                            WAIT_IO_COMPLETION as u64
                        } else {
                            0
                        })
                    } else if self.scheduler.current_tid().is_none() {
                        self.time.advance(arg(args, 0));
                        Ok(0)
                    } else {
                        let _ = self.scheduler.sleep_current_thread(
                            self.time.current().tick_ms,
                            arg(args, 0) as u32,
                            false,
                        );
                        self.request_thread_yield("sleep", true);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "SleepEx") => {
                    if let Some(result) = self.scheduler.consume_wait_result() {
                        Ok(if result == WAIT_IO_COMPLETION {
                            WAIT_IO_COMPLETION as u64
                        } else {
                            0
                        })
                    } else if self.scheduler.current_tid().is_none() {
                        self.time.advance(arg(args, 0));
                        Ok(0)
                    } else {
                        let _ = self.scheduler.sleep_current_thread(
                            self.time.current().tick_ms,
                            arg(args, 0) as u32,
                            arg(args, 1) != 0,
                        );
                        self.request_thread_yield("sleep", true);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "SwitchToThread") => Ok(1),
                ("kernel32.dll", "SuspendThread") => Ok(
                    if self
                        .scheduler
                        .thread_tid_for_handle(arg(args, 0) as u32)
                        .is_some()
                    {
                        0
                    } else {
                        u32::MAX as u64
                    },
                ),
                ("kernel32.dll", "DeviceIoControl") => {
                    if let Some(result) =
                        self.handle_device_io_control(arg(args, 0) as u32, arg(args, 1), args)?
                    {
                        return Ok(result);
                    }
                    if arg(args, 6) != 0 {
                        self.write_u32(arg(args, 6), 0)?;
                    }
                    Ok(0)
                }
                ("kernel32.dll", "ExitProcess") => {
                    self.exit_code = Some(arg(args, 0) as u32);
                    self.process_exit_requested = true;
                    self.force_native_return = true;
                    Ok(arg(args, 0))
                }
                ("kernel32.dll", "ExitThread") => {
                    self.force_native_return = true;
                    Ok(arg(args, 0))
                }
                ("kernel32.dll", "FindResourceA") | ("kernel32.dll", "FindResourceW") => {
                    self.set_last_error(1813);
                    Ok(0)
                }
                ("kernel32.dll", "FindClose") => Ok(self.close_find_handle(arg(args, 0) as u32)),
                ("kernel32.dll", "FindVolumeClose") => {
                    Ok(self.close_find_volume_handle(arg(args, 0) as u32))
                }
                ("kernel32.dll", "FindFirstFileA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
                    self.find_first_file(&path, arg(args, 1), false)
                }
                ("kernel32.dll", "FindFirstFileW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    self.find_first_file(&path, arg(args, 1), true)
                }
                ("kernel32.dll", "FindFirstFileExA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
                    self.find_first_file(&path, arg(args, 2), false)
                }
                ("kernel32.dll", "FindFirstFileExW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    self.find_first_file(&path, arg(args, 2), true)
                }
                ("kernel32.dll", "FindFirstVolumeW") => {
                    self.find_first_volume(arg(args, 0), arg(args, 1) as usize)
                }
                ("kernel32.dll", "FindNextFileA") => {
                    self.find_next_file(arg(args, 0) as u32, arg(args, 1), false)
                }
                ("kernel32.dll", "FindNextFileW") => {
                    self.find_next_file(arg(args, 0) as u32, arg(args, 1), true)
                }
                ("kernel32.dll", "FindNextVolumeW") => {
                    self.find_next_volume(arg(args, 0) as u32, arg(args, 1), arg(args, 2) as usize)
                }
                ("kernel32.dll", "FreeConsole") => Ok(1),
                ("kernel32.dll", "FreeEnvironmentStringsA")
                | ("kernel32.dll", "FreeEnvironmentStringsW") => Ok(1),
                ("kernel32.dll", "FreeLibrary") => {
                    let handle = arg(args, 0);
                    if self.main_module.as_ref().map(|module| module.base) == Some(handle) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        let Some(module) = self.modules.get_by_base(handle).cloned() else {
                            self.set_last_error(ERROR_INVALID_HANDLE as u32);
                            return Ok(0);
                        };
                        if self.startup_pinned_modules.contains(&module.base) {
                            if let Some(count) = self.dynamic_library_refs.get_mut(&handle) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    let _ = self.dynamic_library_refs.remove(&handle);
                                }
                            }
                            self.set_last_error(ERROR_SUCCESS as u32);
                            return Ok(1);
                        }
                        if let Some(count) = self.dynamic_library_refs.get_mut(&handle) {
                            if *count > 1 {
                                *count -= 1;
                                self.set_last_error(ERROR_SUCCESS as u32);
                                return Ok(1);
                            }
                        }
                        let _ = self.dynamic_library_refs.remove(&handle);
                        self.run_dynamic_library_detach(&module)?;
                        if self.modules.unload_module(handle) {
                            self.unregister_process_virtual_allocation(
                                self.current_process_space_key(),
                                handle,
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
                ("kernel32.dll", "FlsAlloc") => {
                    let slot = self
                        .tls
                        .alloc_for_thread(self.current_tls_thread_id())
                        .unwrap_or(usize::MAX);
                    if slot == usize::MAX {
                        return Ok(u32::MAX as u64);
                    }
                    let mirrored = self.process_env.allocate_tls_slot()?;
                    if mirrored != slot {
                        return Err(VmError::RuntimeInvariant("fls slot allocator drifted"));
                    }
                    self.sync_native_support_state()?;
                    Ok(slot as u64)
                }
                ("kernel32.dll", "FlsFree") => {
                    if !self.tls.free(arg(args, 0) as usize) {
                        return Ok(0);
                    }
                    let _ = self.process_env.free_tls_slot(arg(args, 0) as usize)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                ("kernel32.dll", "FlsGetValue") => Ok(self
                    .tls
                    .get_value_for_thread(self.current_tls_thread_id(), arg(args, 0) as usize)),
                ("kernel32.dll", "FlsSetValue") => {
                    let slot = arg(args, 0) as usize;
                    let value = arg(args, 1);
                    if !self
                        .tls
                        .set_value_for_thread(self.current_tls_thread_id(), slot, value)
                    {
                        return Ok(0);
                    }
                    self.process_env.set_tls_value(slot, value)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                ("kernel32.dll", "FlushFileBuffers") => {
                    if let Some(result) = self.flush_device_handle(arg(args, 0) as u32) {
                        return Ok(result);
                    }
                    let Some(state) = self.file_handles.get_mut(&(arg(args, 0) as u32)) else {
                        return Ok(0);
                    };
                    Ok(state.file.sync_all().is_ok() as u64)
                }
                ("kernel32.dll", "FlushViewOfFile") => {
                    self.flush_view_of_file(arg(args, 0), arg(args, 1))
                }
                ("kernel32.dll", "AreFileApisANSI") => Ok(1),
                ("kernel32.dll", "GetACP") => Ok(self.ansi_code_page()),
                ("kernel32.dll", "GetOEMCP") => Ok(self.oem_code_page()),
                ("kernel32.dll", "GetCommandLineA") => {
                    Ok(self.process_env.layout().command_line_ansi_buffer)
                }
                ("kernel32.dll", "GetCommandLineW") => {
                    Ok(self.process_env.layout().command_line_buffer)
                }
                ("kernel32.dll", "GetCPInfo") => {
                    let info = arg(args, 1);
                    if info == 0 {
                        return Ok(0);
                    }
                    let mut bytes = [0u8; 16];
                    bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
                    bytes[4] = b'?';
                    self.modules.memory_mut().write(info, &bytes)?;
                    Ok(1)
                }
                ("kernel32.dll", "GetConsoleCP") => Ok(self.console_code_page()),
                ("kernel32.dll", "GetConsoleOutputCP") => Ok(self.console_output_code_page()),
                ("kernel32.dll", "GetConsoleMode") => {
                    let handle = arg(args, 0);
                    let mode_ptr = arg(args, 1);
                    if !is_std_handle(handle) || mode_ptr == 0 {
                        return Ok(0);
                    }
                    self.write_u32(mode_ptr, DEFAULT_CONSOLE_MODE)?;
                    Ok(1)
                }
                ("kernel32.dll", "GetComputerNameA") => {
                    let name = self.active_computer_name().to_string();
                    if arg(args, 1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(arg(args, 1))? as usize;
                    let required = name.len();
                    self.write_u32(arg(args, 1), required as u32)?;
                    if arg(args, 0) == 0 || capacity <= required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_c_string_to_memory(arg(args, 0), capacity, &name)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "GetComputerNameW") => {
                    let name = self.active_computer_name().to_string();
                    if arg(args, 1) == 0 {
                        return Ok(0);
                    }
                    let capacity = self.read_u32(arg(args, 1))? as usize;
                    let required = name.encode_utf16().count();
                    self.write_u32(arg(args, 1), required as u32)?;
                    if arg(args, 0) == 0 || capacity <= required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let _ = self.write_wide_string_to_memory(arg(args, 0), capacity, &name)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "GetCurrentProcess") => Ok(self.current_process_pseudo_handle()),
                ("kernel32.dll", "GetCurrentProcessId") => Ok(self.current_process_id() as u64),
                ("kernel32.dll", "GetProcessId") => Ok(self
                    .process_identity_for_handle(arg(args, 0))
                    .map(|process| process.pid as u64)
                    .unwrap_or(0)),
                ("kernel32.dll", "GetPriorityClass") => {
                    if self.process_identity_for_handle(arg(args, 0)).is_none()
                        && !self.is_current_process_handle(arg(args, 0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(0x20)
                    }
                }
                ("kernel32.dll", "GetExitCodeProcess") => {
                    let exit_code = if self.is_current_process_handle(arg(args, 0)) {
                        self.exit_code.map(u64::from).unwrap_or(STILL_ACTIVE)
                    } else if self
                        .processes
                        .find_process_by_handle(arg(args, 0) as u32)
                        .is_some()
                    {
                        STILL_ACTIVE
                    } else if self.process_identity_for_handle(arg(args, 0)).is_some() {
                        STILL_ACTIVE
                    } else {
                        return Ok(0);
                    };
                    if arg(args, 1) != 0 {
                        self.write_u32(arg(args, 1), exit_code as u32)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetExitCodeThread") => {
                    let Some(tid) = self.scheduler.thread_tid_for_handle(arg(args, 0) as u32)
                    else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    let Some(thread) = self.scheduler.thread_snapshot(tid) else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    };
                    if arg(args, 1) != 0 {
                        self.write_u32(
                            arg(args, 1),
                            thread.exit_code.unwrap_or(STILL_ACTIVE as u32),
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetProcessTimes") => {
                    if self.process_identity_for_handle(arg(args, 0)).is_none()
                        && !self.is_current_process_handle(arg(args, 0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let now = self.time.current().filetime;
                    let creation = now.saturating_sub(30_000_000);
                    if arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &creation.to_le_bytes())?;
                    }
                    if arg(args, 2) != 0 {
                        self.modules.memory_mut().write(arg(args, 2), &[0u8; 8])?;
                    }
                    if arg(args, 3) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 3), &10_000_000u64.to_le_bytes())?;
                    }
                    if arg(args, 4) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 4), &20_000_000u64.to_le_bytes())?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetProcessWorkingSetSize") => {
                    if self.process_identity_for_handle(arg(args, 0)).is_none()
                        && !self.is_current_process_handle(arg(args, 0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    if arg(args, 1) != 0 {
                        self.write_pointer_value(arg(args, 1), 0x0010_0000)?;
                    }
                    if arg(args, 2) != 0 {
                        self.write_pointer_value(arg(args, 2), 0x0080_0000)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetCurrentThread") => Ok(self
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.scheduler.thread_snapshot(tid))
                    .or_else(|| {
                        self.main_thread_tid
                            .and_then(|tid| self.scheduler.thread_snapshot(tid))
                    })
                    .map(|thread| thread.handle as u64)
                    .unwrap_or(0)),
                ("kernel32.dll", "GetCurrentThreadId") => Ok(self
                    .scheduler
                    .current_tid()
                    .or(self.main_thread_tid)
                    .unwrap_or(0)
                    as u64),
                ("kernel32.dll", "GetEnvironmentStringsA") => {
                    Ok(self.process_env.layout().environment_a_buffer)
                }
                ("kernel32.dll", "GetEnvironmentStringsW") => {
                    Ok(self.process_env.layout().environment_w_buffer)
                }
                ("kernel32.dll", "GetEnvironmentVariableA") => {
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    let Some(value) = self.runtime_environment_value(&name) else {
                        self.set_last_error(ERROR_ENVVAR_NOT_FOUND as u32);
                        return Ok(0);
                    };
                    let required = value.len();
                    let capacity = arg(args, 2) as usize;
                    if arg(args, 1) == 0 || capacity == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    if capacity <= required {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    let written = self.write_c_string_to_memory(arg(args, 1), capacity, &value)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(written)
                }
                ("kernel32.dll", "GetDiskFreeSpaceExW") => {
                    let path = self.read_optional_wide_text(arg(args, 0))?;
                    if !path.is_empty() {
                        self.ensure_runtime_path_backing(&path)?;
                    }
                    let (available, total, free) = self.disk_capacity_triplet();
                    if arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &available.to_le_bytes())?;
                    }
                    if arg(args, 2) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2), &total.to_le_bytes())?;
                    }
                    if arg(args, 3) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 3), &free.to_le_bytes())?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetDriveTypeA") => {
                    let path = if arg(args, 0) == 0 {
                        self.volume_profile().root_path.clone()
                    } else {
                        self.read_c_string_from_memory(arg(args, 0))?
                    };
                    Ok(self.drive_type_for_path(&path))
                }
                ("kernel32.dll", "GetDriveTypeW") => {
                    let path = self.read_optional_wide_text(arg(args, 0))?;
                    let path = if path.is_empty() {
                        self.volume_profile().root_path.clone()
                    } else {
                        path
                    };
                    Ok(self.drive_type_for_path(&path))
                }
                ("kernel32.dll", "GetEnvironmentVariableW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    let Some(value) = self.runtime_environment_value(&name) else {
                        self.set_last_error(ERROR_ENVVAR_NOT_FOUND as u32);
                        return Ok(0);
                    };
                    let required = value.encode_utf16().count();
                    let capacity = arg(args, 2) as usize;
                    if arg(args, 1) == 0 || capacity == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    if capacity <= required {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        return Ok((required + 1) as u64);
                    }
                    let written =
                        self.write_wide_string_to_memory(arg(args, 1), capacity, &value)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(written)
                }
                ("kernel32.dll", "GetFileAttributesExW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    self.write_file_attributes_ex(&path, arg(args, 2))
                }
                ("kernel32.dll", "GetFileAttributesA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
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
                ("kernel32.dll", "GetFileSize") => {
                    let Some(state) = self.file_handles.get_mut(&(arg(args, 0) as u32)) else {
                        return Ok(u32::MAX as u64);
                    };
                    let size = state.file.metadata().map(|meta| meta.len()).unwrap_or(0);
                    if arg(args, 1) != 0 {
                        self.write_u32(arg(args, 1), (size >> 32) as u32)?;
                    }
                    Ok((size & 0xFFFF_FFFF) as u64)
                }
                ("kernel32.dll", "GetFileSizeEx") => {
                    let Some(state) = self.file_handles.get_mut(&(arg(args, 0) as u32)) else {
                        return Ok(0);
                    };
                    let size = state.file.metadata().map(|meta| meta.len()).unwrap_or(0);
                    if arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &size.to_le_bytes())?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "GetFileInformationByHandle") => {
                    let handle = arg(args, 0) as u32;
                    let buffer = arg(args, 1);
                    if buffer == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(state) = self.file_handles.get_mut(&handle) else {
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
                    let now = self.time.current().filetime;
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
                    self.modules.memory_mut().write(buffer, &payload)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetFileInformationByHandleEx") => {
                    let handle = arg(args, 0) as u32;
                    let class = arg(args, 1) as u32;
                    let buffer = arg(args, 2);
                    let buffer_size = arg(args, 3) as usize;
                    if buffer == 0 || buffer_size == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(state) = self.file_handles.get_mut(&handle) else {
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
                    self.modules.memory_mut().write(buffer, &payload)?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetFileType") => Ok(if is_std_handle(arg(args, 0)) {
                    FILE_TYPE_CHAR
                } else {
                    0
                }),
                ("kernel32.dll", "GetLastError") => Ok(self.last_error as u64),
                ("kernel32.dll", "GetLogicalDriveStringsW") => {
                    let mut payload_text = self.logical_drive_roots().join("\0");
                    payload_text.push('\0');
                    payload_text.push('\0');
                    let payload = payload_text
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>();
                    let required_chars = payload_text.encode_utf16().count() as u64;
                    if arg(args, 1) == 0 || arg(args, 0) < required_chars {
                        Ok(required_chars)
                    } else {
                        self.modules.memory_mut().write(arg(args, 1), &payload)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(required_chars - 1)
                    }
                }
                ("kernel32.dll", "GetLocaleInfoA") => {
                    let data = b"936\0";
                    if arg(args, 3) == 0 || arg(args, 2) == 0 {
                        Ok(data.len() as u64)
                    } else {
                        self.write_raw_bytes_to_memory(arg(args, 2), arg(args, 3) as usize, data)
                    }
                }
                ("kernel32.dll", "GetLocaleInfoW") | ("kernel32.dll", "GetLocaleInfoEx") => {
                    let data = "936\0"
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>();
                    let required = data.len() / 2;
                    if arg(args, 3) == 0 || arg(args, 2) == 0 {
                        Ok(required as u64)
                    } else {
                        let writable = (arg(args, 3) as usize).min(required) * 2;
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2), &data[..writable])?;
                        Ok(required.min(arg(args, 3) as usize) as u64)
                    }
                }
                ("kernel32.dll", "GetModuleFileNameA") => {
                    let module_handle = arg(args, 0);
                    let buffer = arg(args, 1);
                    let capacity = arg(args, 2) as usize;
                    let path = self
                        .module_path_for_handle(module_handle)
                        .unwrap_or_default();
                    self.write_c_string_to_memory(buffer, capacity, &path)
                }
                ("kernel32.dll", "GetModuleFileNameW") => {
                    let module_handle = arg(args, 0);
                    let buffer = arg(args, 1);
                    let capacity = arg(args, 2) as usize;
                    let path = self
                        .module_path_for_handle(module_handle)
                        .unwrap_or_default();
                    self.write_wide_string_to_memory(buffer, capacity, &path)
                }
                ("kernel32.dll", "GetModuleHandleA") => {
                    if arg(args, 0) == 0 {
                        return Ok(self
                            .main_module
                            .as_ref()
                            .map(|module| module.base)
                            .unwrap_or(0));
                    }
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    Ok(self
                        .modules
                        .get_loaded(&name)
                        .map(|module| module.base)
                        .unwrap_or(0))
                }
                ("kernel32.dll", "GetModuleHandleW") => {
                    if arg(args, 0) == 0 {
                        return Ok(self
                            .main_module
                            .as_ref()
                            .map(|module| module.base)
                            .unwrap_or(0));
                    }
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    Ok(self
                        .modules
                        .get_loaded(&name)
                        .map(|module| module.base)
                        .unwrap_or(0))
                }
                ("kernel32.dll", "GetModuleHandleExW") => {
                    let module = if arg(args, 0) & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
                        self.modules.get_by_address(arg(args, 1)).cloned()
                    } else if arg(args, 1) == 0 {
                        self.main_module.clone()
                    } else {
                        let name = self.read_wide_string_from_memory(arg(args, 1))?;
                        self.modules.get_loaded(&name).cloned()
                    };
                    let Some(module) = module else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    };
                    if arg(args, 2) != 0 {
                        if self.arch.is_x86() {
                            self.write_u32(arg(args, 2), module.base as u32)?;
                        } else {
                            self.modules
                                .memory_mut()
                                .write(arg(args, 2), &module.base.to_le_bytes())?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "OpenProcess") => {
                    let pid = arg(args, 2) as u32;
                    if let Some(handle) = self.open_process_handle_by_pid(pid) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(handle)
                    } else {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "OpenThread") => Ok(self
                    .scheduler
                    .thread_snapshots()
                    .into_iter()
                    .find(|thread| thread.tid == arg(args, 2) as u32)
                    .map(|thread| {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        thread.handle as u64
                    })
                    .unwrap_or_else(|| {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        0
                    })),
                ("kernel32.dll", "OpenFileMappingA") => {
                    let name = self.read_c_string_from_memory(arg(args, 2))?;
                    Ok(self.open_file_mapping_handle(&name))
                }
                ("kernel32.dll", "OpenFileMappingW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 2))?;
                    Ok(self.open_file_mapping_handle(&name))
                }
                ("kernel32.dll", "OpenMutexW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 2))?;
                    Ok(self.open_mutex_handle(&name))
                }
                ("kernel32.dll", "PeekNamedPipe") => {
                    if !self.device_handles.contains_key(&(arg(args, 0) as u32)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    for pointer in [arg(args, 3), arg(args, 4), arg(args, 5)] {
                        if pointer != 0 {
                            self.write_u32(pointer, 0)?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "Process32First")
                | ("kernel32.dll", "Process32FirstW")
                | ("kernel32.dll", "Process32FirstA") => self.process32_first_next(
                    arg(args, 0),
                    arg(args, 1),
                    !definition.function.ends_with('A'),
                    true,
                ),
                ("kernel32.dll", "Process32Next")
                | ("kernel32.dll", "Process32NextW")
                | ("kernel32.dll", "Process32NextA") => self.process32_first_next(
                    arg(args, 0),
                    arg(args, 1),
                    !definition.function.ends_with('A'),
                    false,
                ),
                ("kernel32.dll", "K32EnumProcessModules")
                | ("kernel32.dll", "K32EnumProcessModulesEx") => self.enum_process_modules(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as usize,
                    arg(args, 3),
                ),
                ("kernel32.dll", "K32GetModuleBaseNameA") => self.get_module_base_name_result(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    false,
                ),
                ("kernel32.dll", "K32GetModuleBaseNameW") => self.get_module_base_name_result(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    true,
                ),
                ("kernel32.dll", "K32GetModuleFileNameExA") => self.get_module_file_name_ex_result(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    false,
                ),
                ("kernel32.dll", "K32GetModuleFileNameExW") => self.get_module_file_name_ex_result(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    true,
                ),
                ("kernel32.dll", "K32GetModuleInformation") => self.write_module_information(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                ),
                ("kernel32.dll", "K32GetProcessMemoryInfo") => self.write_process_memory_info(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as usize,
                ),
                ("kernel32.dll", "GetProcAddress") => {
                    let module_base = arg(args, 0);
                    let symbol = arg(args, 1);
                    let address = if symbol <= 0xFFFF {
                        self.modules.resolve_export(
                            module_base,
                            &self.config,
                            &mut self.hooks,
                            None,
                            Some(symbol as u16),
                        )
                    } else {
                        let name = self.read_c_string_from_memory(symbol)?;
                        self.modules.resolve_export(
                            module_base,
                            &self.config,
                            &mut self.hooks,
                            Some(&name),
                            None,
                        )
                    };
                    Ok(address)
                }
                ("kernel32.dll", "GetProcessHeap") => Ok(self.heaps.process_heap() as u64),
                ("kernel32.dll", "GetSystemInfo") => {
                    let info = arg(args, 0);
                    if info == 0 {
                        return Ok(0);
                    }
                    let mut bytes = vec![0u8; if self.arch.is_x86() { 36 } else { 48 }];
                    bytes[4..8].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
                    if self.arch.is_x86() {
                        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
                        bytes[28..32].copy_from_slice(&0x1_0000u32.to_le_bytes());
                    } else {
                        bytes[20..28].copy_from_slice(&1u64.to_le_bytes());
                        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
                        bytes[40..44].copy_from_slice(&0x1_0000u32.to_le_bytes());
                    }
                    self.modules.memory_mut().write(info, &bytes)?;
                    Ok(0)
                }
                ("kernel32.dll", "GetSystemDirectoryA") => {
                    let path = format!("{}\\", self.system_directory_path());
                    self.write_ascii_path_result(arg(args, 0), arg(args, 1) as usize, &path)
                }
                ("kernel32.dll", "GetSystemDirectoryW") => {
                    let path = format!("{}\\", self.system_directory_path());
                    self.write_wide_path_result(arg(args, 0), arg(args, 1) as usize, &path)
                }
                ("kernel32.dll", "GetSystemFirmwareTable") => {
                    let data =
                        Self::synthetic_firmware_table(arg(args, 0) as u32, arg(args, 1) as u32);
                    if arg(args, 2) != 0 && arg(args, 3) as usize >= data.len() {
                        self.modules.memory_mut().write(arg(args, 2), &data)?;
                    }
                    Ok(data.len() as u64)
                }
                ("kernel32.dll", "GetSystemWindowsDirectoryA")
                | ("kernel32.dll", "GetWindowsDirectoryA") => {
                    let path = self.windows_directory_path();
                    self.write_ascii_path_result(arg(args, 0), arg(args, 1) as usize, &path)
                }
                ("kernel32.dll", "GetSystemWindowsDirectoryW")
                | ("kernel32.dll", "GetWindowsDirectoryW") => {
                    let path = self.windows_directory_path();
                    self.write_wide_path_result(arg(args, 0), arg(args, 1) as usize, &path)
                }
                ("kernel32.dll", "GetStringTypeA") => {
                    if arg(args, 4) != 0 && arg(args, 3) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 4), &vec![0u8; arg(args, 3) as usize * 2])?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "GetStringTypeW") => {
                    if arg(args, 3) != 0 && arg(args, 2) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 3), &vec![0u8; arg(args, 2) as usize * 2])?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "GetStartupInfoA") | ("kernel32.dll", "GetStartupInfoW") => {
                    self.write_startup_info(arg(args, 0))?;
                    Ok(0)
                }
                ("kernel32.dll", "GetStdHandle") => {
                    Ok(self.std_handle_value_for_arch(arg(args, 0)))
                }
                ("kernel32.dll", "GetLocalTime") => {
                    self.write_systemtime_struct(
                        arg(args, 0),
                        Self::system_time_components_from_filetime(self.time.current().filetime),
                    )?;
                    Ok(0)
                }
                ("kernel32.dll", "GetSystemTimeAsFileTime") => {
                    if arg(args, 0) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 0), &self.time.current().filetime.to_le_bytes())?;
                    }
                    Ok(0)
                }
                ("kernel32.dll", "lstrlenA") => {
                    if arg(args, 0) == 0 {
                        Ok(0)
                    } else {
                        Ok(self.read_c_string_from_memory(arg(args, 0))?.len() as u64)
                    }
                }
                ("kernel32.dll", "lstrlenW") => {
                    if arg(args, 0) == 0 {
                        Ok(0)
                    } else {
                        Ok(self
                            .read_wide_string_from_memory(arg(args, 0))?
                            .encode_utf16()
                            .count() as u64)
                    }
                }
                ("kernel32.dll", "CxIZKa") => {
                    for pointer in [arg(args, 1), arg(args, 3), arg(args, 4)] {
                        if pointer != 0 {
                            self.write_pointer_value(pointer, 0)?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(0)
                }
                ("kernel32.dll", "GetTickCount") => Ok(self.time.current().tick_ms),
                ("kernel32.dll", "EnumSystemLocalesW") | ("kernel32.dll", "EnumSystemLocalesA") => {
                    Ok(1)
                }
                ("kernel32.dll", "GetUserDefaultLCID") => Ok(self.user_default_lcid()),
                ("kernel32.dll", "GetVersion") => Ok(self.version_return_value()),
                ("kernel32.dll", "GetVersionExA") => {
                    Ok(self.write_version_info(arg(args, 0), false)? as u64)
                }
                ("kernel32.dll", "GetVersionExW") => {
                    Ok(self.write_version_info(arg(args, 0), true)? as u64)
                }
                ("kernel32.dll", "HeapAlloc") => {
                    let heap = arg(args, 0) as u32;
                    let size = arg(args, 2).max(1);
                    let address = self
                        .heaps
                        .alloc(self.modules.memory_mut(), heap, size)
                        .unwrap_or(0);
                    if address != 0 {
                        if arg(args, 1) & HEAP_ZERO_MEMORY != 0 {
                            self.fill_memory_pattern(address, size, 0)?;
                        }
                        self.log_heap_event("HEAP_ALLOC", heap, address, size, "HeapAlloc")?;
                    }
                    Ok(address)
                }
                ("kernel32.dll", "HeapCreate") => {
                    Ok(self.heaps.create_heap(self.modules.memory_mut())? as u64)
                }
                ("kernel32.dll", "HeapDestroy") => Ok(self
                    .heaps
                    .destroy(self.modules.memory_mut(), arg(args, 0) as u32)
                    as u64),
                ("kernel32.dll", "HeapFree") => {
                    let result = self.heaps.free(arg(args, 0) as u32, arg(args, 2)) as u64;
                    if result != 0 {
                        self.log_heap_event(
                            "HEAP_FREE",
                            arg(args, 0) as u32,
                            arg(args, 2),
                            0,
                            "HeapFree",
                        )?;
                    }
                    Ok(result)
                }
                ("kernel32.dll", "HeapLock") | ("kernel32.dll", "HeapUnlock") => Ok(1),
                ("kernel32.dll", "HeapReAlloc") => {
                    let heap = arg(args, 0) as u32;
                    let old_address = arg(args, 2);
                    let new_size = arg(args, 3).max(1);
                    let old_size = self.heaps.size(heap, old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let Some(new_address) =
                        self.heaps.alloc(self.modules.memory_mut(), heap, new_size)
                    else {
                        return Ok(0);
                    };
                    let copy_size = old_size.min(new_size) as usize;
                    let bytes = self.modules.memory().read(old_address, copy_size)?;
                    self.modules.memory_mut().write(new_address, &bytes)?;
                    if arg(args, 1) & HEAP_ZERO_MEMORY != 0 && new_size > old_size {
                        self.fill_memory_pattern(
                            new_address + old_size,
                            new_size.saturating_sub(old_size),
                            0,
                        )?;
                    }
                    self.heaps.free(heap, old_address);
                    self.log_heap_event(
                        "HEAP_REALLOC",
                        heap,
                        new_address,
                        new_size,
                        "HeapReAlloc",
                    )?;
                    Ok(new_address)
                }
                ("kernel32.dll", "HeapSetInformation") => Ok(1),
                ("kernel32.dll", "HeapSize") => {
                    Ok(self.heaps.size(arg(args, 0) as u32, arg(args, 2)))
                }
                ("kernel32.dll", "HeapWalk") => Ok(0),
                ("kernel32.dll", "IsDebuggerPresent") => Ok(0),
                ("kernel32.dll", "IsWow64Process") => {
                    if arg(args, 1) != 0 {
                        self.write_u32(arg(args, 1), 1)?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "IsValidCodePage") => Ok(1),
                ("kernel32.dll", "IsValidLocale") => Ok(1),
                ("kernel32.dll", "IsProcessorFeaturePresent") => Ok(1),
                ("kernel32.dll", "LCMapStringA") => {
                    let mut text = self.read_c_string_from_memory(arg(args, 2))?;
                    let source_len = arg(args, 3);
                    if source_len != 0 && source_len != u32::MAX as u64 {
                        text = text.chars().take(source_len as usize).collect();
                    }
                    let mut data = text.into_bytes();
                    data.push(0);
                    if arg(args, 5) == 0 {
                        Ok(data.len() as u64)
                    } else {
                        self.write_raw_bytes_to_memory(arg(args, 4), arg(args, 5) as usize, &data)
                    }
                }
                ("kernel32.dll", "LCMapStringEx") => {
                    let mut text = self.read_wide_string_from_memory(arg(args, 2))?;
                    let source_len = arg(args, 3);
                    if source_len != 0 && source_len != u32::MAX as u64 {
                        text = text.chars().take(source_len as usize).collect();
                    }
                    let data = text
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .chain([0, 0])
                        .collect::<Vec<_>>();
                    let required = data.len() / 2;
                    if arg(args, 4) == 0 || arg(args, 5) == 0 {
                        Ok(required as u64)
                    } else {
                        let written = self.write_raw_bytes_to_memory(
                            arg(args, 4),
                            (arg(args, 5) as usize).saturating_mul(2),
                            &data,
                        )?;
                        Ok((written / 2) as u64)
                    }
                }
                ("kernel32.dll", "LCMapStringW") => {
                    let mut text = self.read_wide_string_from_memory(arg(args, 2))?;
                    let source_len = arg(args, 3);
                    if source_len != 0 && source_len != u32::MAX as u64 {
                        text = text.chars().take(source_len as usize).collect();
                    }
                    let data = text
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .chain([0, 0])
                        .collect::<Vec<_>>();
                    let required = data.len() / 2;
                    if arg(args, 5) == 0 {
                        Ok(required as u64)
                    } else {
                        let written = self.write_raw_bytes_to_memory(
                            arg(args, 4),
                            (arg(args, 5) as usize).saturating_mul(2),
                            &data,
                        )?;
                        Ok((written / 2) as u64)
                    }
                }
                ("kernel32.dll", "CompareStringW") => {
                    let left = self.read_wide_input_string(arg(args, 2), arg(args, 3))?;
                    let right = self.read_wide_input_string(arg(args, 4), arg(args, 5))?;
                    let ordering = if arg(args, 1) & 0x0000_0001 != 0 {
                        compare_ci(&left, &right)
                    } else {
                        match left.cmp(&right) {
                            std::cmp::Ordering::Less => -1,
                            std::cmp::Ordering::Equal => 0,
                            std::cmp::Ordering::Greater => 1,
                        }
                    };
                    Ok(match ordering {
                        value if value < 0 => CSTR_LESS_THAN,
                        0 => CSTR_EQUAL,
                        _ => CSTR_GREATER_THAN,
                    })
                }
                ("kernel32.dll", "LocalAlloc") => {
                    let size = arg(args, 1).max(1);
                    let address = self
                        .heaps
                        .alloc(self.modules.memory_mut(), self.heaps.process_heap(), size)
                        .unwrap_or(0);
                    if address != 0 {
                        if arg(args, 0) & LMEM_ZEROINIT != 0 {
                            self.fill_memory_pattern(address, size, 0)?;
                        }
                        self.log_heap_event(
                            "HEAP_ALLOC",
                            self.heaps.process_heap(),
                            address,
                            size,
                            "LocalAlloc",
                        )?;
                    }
                    Ok(address)
                }
                ("kernel32.dll", "LocalFree") => Ok(
                    if self.heaps.free(self.heaps.process_heap(), arg(args, 0)) {
                        let _ = self.log_heap_event(
                            "HEAP_FREE",
                            self.heaps.process_heap(),
                            arg(args, 0),
                            0,
                            "LocalFree",
                        );
                        0
                    } else {
                        arg(args, 0)
                    },
                ),
                ("kernel32.dll", "LocalFileTimeToFileTime") => {
                    let source = self.read_bytes_from_memory(arg(args, 0), 8)?;
                    self.modules.memory_mut().write(arg(args, 1), &source)?;
                    Ok(1)
                }
                ("kernel32.dll", "LoadLibraryA") | ("kernel32.dll", "LoadLibraryExA") => {
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    let existing = self.modules.get_loaded(&name).cloned();
                    let module = self.modules.load_runtime_dependency(
                        &name,
                        &self.config,
                        &mut self.hooks,
                    )?;
                    if existing.is_none() {
                        self.register_module_image_allocation(
                            self.current_process_space_key(),
                            &module,
                        )?;
                        self.run_dynamic_library_attach(&module)?;
                        self.sync_process_environment_modules()?;
                        self.log_module_event("MODULE_LOAD", &module, definition.function)?;
                    }
                    let refcount = self.dynamic_library_refs.entry(module.base).or_insert(0);
                    *refcount = refcount.saturating_add(1);
                    Ok(module.base)
                }
                ("kernel32.dll", "LoadLibraryW") | ("kernel32.dll", "LoadLibraryExW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    let existing = self.modules.get_loaded(&name).cloned();
                    let module = self.modules.load_runtime_dependency(
                        &name,
                        &self.config,
                        &mut self.hooks,
                    )?;
                    if existing.is_none() {
                        self.register_module_image_allocation(
                            self.current_process_space_key(),
                            &module,
                        )?;
                        self.run_dynamic_library_attach(&module)?;
                        self.sync_process_environment_modules()?;
                        self.log_module_event("MODULE_LOAD", &module, definition.function)?;
                    }
                    let refcount = self.dynamic_library_refs.entry(module.base).or_insert(0);
                    *refcount = refcount.saturating_add(1);
                    Ok(module.base)
                }
                ("kernel32.dll", "lstrcatA") => {
                    let destination = arg(args, 0);
                    let mut left = self.read_c_string_from_memory(destination)?;
                    let right = self.read_c_string_from_memory(arg(args, 1))?;
                    left.push_str(&right);
                    let _ = self.write_c_string_to_memory(destination, 0x1000, &left)?;
                    Ok(destination)
                }
                ("kernel32.dll", "lstrcatW") => {
                    let destination = arg(args, 0);
                    let mut left = self.read_wide_string_from_memory(destination)?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    left.push_str(&right);
                    let _ = self.write_wide_string_to_memory(destination, 0x1000, &left)?;
                    Ok(destination)
                }
                ("kernel32.dll", "lstrcmpiW") => {
                    let left = self.read_wide_string_from_memory(arg(args, 0))?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    Ok(compare_ci(&left, &right) as u32 as u64)
                }
                ("kernel32.dll", "lstrcpyA") => {
                    let destination = arg(args, 0);
                    let text = self.read_c_string_from_memory(arg(args, 1))?;
                    let _ = self.write_c_string_to_memory(destination, 0x1000, &text)?;
                    Ok(destination)
                }
                ("kernel32.dll", "lstrcpyW") => {
                    let destination = arg(args, 0);
                    let text = self.read_wide_string_from_memory(arg(args, 1))?;
                    let _ = self.write_wide_string_to_memory(destination, 0x1000, &text)?;
                    Ok(destination)
                }
                ("kernel32.dll", "MoveFileA") => {
                    let source = self.read_c_string_from_memory(arg(args, 0))?;
                    let destination = self.read_c_string_from_memory(arg(args, 1))?;
                    if source.is_empty() || destination.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(source_path) =
                        self.prepare_runtime_read_target(&source, "MoveFileA")?
                    else {
                        return Ok(0);
                    };
                    self.ensure_runtime_path_backing(&destination)?;
                    let destination_path = self.resolve_runtime_path(&destination);
                    let result = std::fs::rename(&source_path, &destination_path).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event(
                            "FILE_RENAME",
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
                ("kernel32.dll", "MoveFileW") | ("kernel32.dll", "MoveFileExW") => {
                    let source = self.read_wide_string_from_memory(arg(args, 0))?;
                    let destination = self.read_wide_string_from_memory(arg(args, 1))?;
                    if source.is_empty() || destination.is_empty() {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        return Ok(0);
                    }
                    let Some(source_path) =
                        self.prepare_runtime_read_target(&source, "MoveFileW")?
                    else {
                        return Ok(0);
                    };
                    self.ensure_runtime_path_backing(&destination)?;
                    let destination_path = self.resolve_runtime_path(&destination);
                    let result = std::fs::rename(&source_path, &destination_path).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event(
                            "FILE_RENAME",
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
                ("kernel32.dll", "MapViewOfFile") => self.map_view_of_file(
                    arg(args, 0) as u32,
                    arg(args, 1) as u32,
                    (arg(args, 2) << 32) | arg(args, 3),
                    arg(args, 4),
                ),
                ("kernel32.dll", "MultiByteToWideChar") => {
                    let source = self.read_ansi_input(arg(args, 2), arg(args, 3))?;
                    let text = self.decode_code_page_bytes(arg(args, 0), &source);
                    let encoded = text
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .chain([0, 0])
                        .collect::<Vec<_>>();
                    let required = encoded.len() / 2;
                    if arg(args, 4) == 0 || arg(args, 5) == 0 {
                        Ok(required as u64)
                    } else {
                        let writable = (arg(args, 5) as usize).min(required) * 2;
                        self.modules
                            .memory_mut()
                            .write(arg(args, 4), &encoded[..writable])?;
                        Ok(required.min(arg(args, 5) as usize) as u64)
                    }
                }
                ("kernel32.dll", "InitializeSListHead") => {
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &[0; 8])?;
                    }
                    Ok(0)
                }
                ("kernel32.dll", "InterlockedCompareExchange") => {
                    let address = arg(args, 0);
                    let exchange = arg(args, 1) as u32;
                    let comparand = arg(args, 2) as u32;
                    let current = self.read_u32(address)?;
                    if current == comparand {
                        self.write_u32(address, exchange)?;
                    }
                    Ok(current as u64)
                }
                ("kernel32.dll", "InterlockedDecrement") => {
                    let address = arg(args, 0);
                    let value = self.read_u32(address)?.wrapping_sub(1);
                    self.write_u32(address, value)?;
                    Ok(value as u64)
                }
                ("kernel32.dll", "InterlockedExchange") => {
                    let address = arg(args, 0);
                    let value = arg(args, 1) as u32;
                    let current = self.read_u32(address)?;
                    self.write_u32(address, value)?;
                    Ok(current as u64)
                }
                ("kernel32.dll", "InterlockedExchangeAdd") => {
                    let address = arg(args, 0);
                    let delta = arg(args, 1) as u32;
                    let current = self.read_u32(address)?;
                    self.write_u32(address, current.wrapping_add(delta))?;
                    Ok(current as u64)
                }
                ("kernel32.dll", "InterlockedIncrement") => {
                    let address = arg(args, 0);
                    let value = self.read_u32(address)?.wrapping_add(1);
                    self.write_u32(address, value)?;
                    Ok(value as u64)
                }
                ("kernel32.dll", "InterlockedFlushSList") => {
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &[0; 8])?;
                    }
                    Ok(0)
                }
                ("kernel32.dll", "QueryPerformanceCounter") => {
                    if arg(args, 0) == 0 {
                        return Ok(0);
                    }
                    let counter = self.time.current().tick_ms.saturating_mul(10_000);
                    self.modules
                        .memory_mut()
                        .write(arg(args, 0), &counter.to_le_bytes())?;
                    Ok(1)
                }
                ("kernel32.dll", "QueryFullProcessImageNameA") => self
                    .query_full_process_image_name_result(
                        arg(args, 0),
                        arg(args, 2),
                        arg(args, 3),
                        false,
                    ),
                ("kernel32.dll", "QueryFullProcessImageNameW") => self
                    .query_full_process_image_name_result(
                        arg(args, 0),
                        arg(args, 2),
                        arg(args, 3),
                        true,
                    ),
                ("kernel32.dll", "QueryDosDeviceA") => {
                    let entries = if arg(args, 0) == 0 {
                        self.query_dos_device_names()
                    } else {
                        self.query_dos_device_targets(
                            &self.read_c_string_from_memory(arg(args, 0))?,
                        )
                    };
                    if entries.is_empty() {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        Ok(0)
                    } else {
                        let mut payload = entries.join("\0");
                        payload.push('\0');
                        payload.push('\0');
                        let required = payload.len();
                        if arg(args, 1) == 0
                            || arg(args, 2) == 0
                            || (arg(args, 2) as usize) < required
                        {
                            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                            Ok(0)
                        } else {
                            self.modules
                                .memory_mut()
                                .write(arg(args, 1), payload.as_bytes())?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok((required.saturating_sub(1)) as u64)
                        }
                    }
                }
                ("kernel32.dll", "QueryDosDeviceW") => {
                    let entries = if arg(args, 0) == 0 {
                        self.query_dos_device_names()
                    } else {
                        self.query_dos_device_targets(
                            &self.read_wide_string_from_memory(arg(args, 0))?,
                        )
                    };
                    if entries.is_empty() {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                        Ok(0)
                    } else {
                        let mut payload = entries.join("\0");
                        payload.push('\0');
                        payload.push('\0');
                        let units = payload.encode_utf16().collect::<Vec<_>>();
                        let required = units.len();
                        let bytes = units
                            .into_iter()
                            .flat_map(u16::to_le_bytes)
                            .collect::<Vec<_>>();
                        if arg(args, 1) == 0
                            || arg(args, 2) == 0
                            || (arg(args, 2) as usize) < required
                        {
                            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                            Ok(0)
                        } else {
                            self.modules.memory_mut().write(arg(args, 1), &bytes)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                            Ok((required.saturating_sub(1)) as u64)
                        }
                    }
                }
                ("kernel32.dll", "QueueUserAPC") => {
                    if self
                        .scheduler
                        .queue_user_apc(arg(args, 0) as u32, arg(args, 1), arg(args, 2))
                        .is_some()
                    {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "QueryActCtxW") => {
                    let info_class = arg(args, 3);
                    let buffer = arg(args, 4);
                    let buffer_size = arg(args, 5) as usize;
                    let required = match info_class {
                        1 => {
                            if self.arch.is_x86() {
                                8
                            } else {
                                16
                            }
                        }
                        _ => buffer_size.max(1),
                    };
                    if arg(args, 6) != 0 {
                        self.write_u32(arg(args, 6), required as u32)?;
                    }
                    if buffer == 0 || buffer_size < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        self.modules
                            .memory_mut()
                            .write(buffer, &vec![0u8; required])?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "ActivateActCtx") => {
                    let cookie_ptr = arg(args, 1);
                    if cookie_ptr != 0 {
                        let cookie_size = self.arch.pointer_size as u64;
                        if !self.is_writable_guest_range(cookie_ptr, cookie_size) {
                            self.set_last_error(ERROR_SUCCESS as u32);
                        } else if self.arch.is_x86() {
                            self.write_u32(cookie_ptr, arg(args, 0) as u32)?;
                        } else {
                            self.modules
                                .memory_mut()
                                .write(cookie_ptr, &arg(args, 0).to_le_bytes())?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "RegisterApplicationRestart")
                | ("kernel32.dll", "RegisterApplicationRecoveryCallback")
                | ("kernel32.dll", "UnregisterApplicationRestart")
                | ("kernel32.dll", "UnregisterApplicationRecoveryCallback") => Ok(ERROR_SUCCESS),
                ("kernel32.dll", "ApplicationRecoveryInProgress") => {
                    if arg(args, 0) != 0 {
                        self.write_u32(arg(args, 0), 0)?;
                    }
                    Ok(ERROR_SUCCESS)
                }
                ("kernel32.dll", "ApplicationRecoveryFinished") => Ok(0),
                ("kernel32.dll", "DeactivateActCtx") => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "FindActCtxSectionStringW") => {
                    let returned_data = arg(args, 4);
                    if returned_data != 0 {
                        let declared_size =
                            self.read_u32(returned_data).unwrap_or(0x40).max(4) as usize;
                        self.modules
                            .memory_mut()
                            .write(returned_data, &vec![0u8; declared_size])?;
                        self.write_u32(returned_data, declared_size as u32)?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "RaiseException") => Ok(0),
                ("kernel32.dll", "ReadFile") => {
                    let handle = arg(args, 0) as u32;
                    let buffer = arg(args, 1);
                    let size = arg(args, 2) as usize;
                    if handle as u64 == STD_INPUT_HANDLE {
                        if arg(args, 3) != 0 {
                            self.write_u32(arg(args, 3), 0)?;
                        }
                        if buffer != 0 && size == 0 {
                            self.modules.memory_mut().write(buffer, &[])?;
                        }
                        Ok(1)
                    } else if let Some(path) = self
                        .file_handles
                        .get(&handle)
                        .map(|state| state.path.clone())
                    {
                        if !self.ensure_runtime_read_allowed_path(
                            std::path::Path::new(&path),
                            "ReadFile",
                        )? {
                            if arg(args, 3) != 0 {
                                self.write_u32(arg(args, 3), 0)?;
                            }
                            return Ok(0);
                        }
                        let state = self
                            .file_handles
                            .get_mut(&handle)
                            .ok_or(VmError::RuntimeInvariant("file handle disappeared"))?;
                        let mut data = vec![0u8; size];
                        let read = state.file.read(&mut data).unwrap_or(0);
                        data.truncate(read);
                        if buffer != 0 && !data.is_empty() {
                            self.modules.memory_mut().write(buffer, &data)?;
                        }
                        if arg(args, 3) != 0 {
                            self.write_u32(arg(args, 3), read as u32)?;
                        }
                        self.log_file_event("FILE_READ", handle, &path, Some(read as u64))?;
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "ReadConsoleW") => {
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), 0)?;
                    }
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &vec![0u8; arg(args, 2) as usize * 2])?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "ReleaseMutex") => {
                    Ok(self.release_mutex_handle(arg(args, 0) as u32) as u64)
                }
                ("kernel32.dll", "ResetEvent") => {
                    Ok(self.scheduler.reset_event(arg(args, 0) as u32).is_some() as u64)
                }
                ("kernel32.dll", "RemoveDirectoryW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    let Some(target) =
                        self.prepare_runtime_read_target(&path, "RemoveDirectoryW")?
                    else {
                        return Ok(0);
                    };
                    let result = std::fs::remove_dir_all(&target).is_ok() as u64;
                    if result != 0 {
                        self.log_file_event("FILE_RMDIR", 0, &target.to_string_lossy(), None)?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    }
                    Ok(result)
                }
                ("kernel32.dll", "ReplaceFileW") => {
                    let replaced = self.read_wide_string_from_memory(arg(args, 0))?;
                    let replacement = self.read_wide_string_from_memory(arg(args, 1))?;
                    let backup = self.read_optional_wide_text(arg(args, 2))?;
                    let Some(replaced_path) =
                        self.prepare_runtime_read_target(&replaced, "ReplaceFileW")?
                    else {
                        return Ok(0);
                    };
                    let Some(replacement_path) =
                        self.prepare_runtime_read_target(&replacement, "ReplaceFileW")?
                    else {
                        return Ok(0);
                    };
                    if !backup.is_empty() {
                        self.ensure_runtime_path_backing(&backup)?;
                        let backup_path = self.resolve_runtime_path(&backup);
                        let _ = std::fs::copy(&replaced_path, &backup_path);
                    }
                    let result = std::fs::copy(&replacement_path, &replaced_path)
                        .and_then(|_| std::fs::remove_file(&replacement_path))
                        .is_ok() as u64;
                    if result != 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                    } else {
                        self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    }
                    Ok(result)
                }
                ("kernel32.dll", "ResumeThread") => {
                    let handle = arg(args, 0) as u32;
                    let Some(tid) = self.scheduler.thread_tid_for_handle(handle) else {
                        return Ok(u32::MAX as u64);
                    };
                    let Some(previous_suspend_count) = self.scheduler.resume_thread(handle) else {
                        return Ok(u32::MAX as u64);
                    };
                    if previous_suspend_count != 0 && self.pending_thread_attach.remove(&tid) {
                        self.dispatch_thread_notification(tid, DLL_THREAD_ATTACH)?;
                        self.started_threads.insert(tid);
                    }
                    if let Some(thread) = self.scheduler.thread_snapshot(tid) {
                        self.log_thread_event(
                            "THREAD_RESUME",
                            tid,
                            handle,
                            thread.start_address,
                            thread.parameter,
                            "ready",
                        )?;
                        if previous_suspend_count != 0 {
                            self.log_thread_entry_dump_if_dynamic(
                                "THREAD_RESUME_DUMP",
                                "THREAD_RESUME",
                                tid,
                                handle,
                                thread.start_address,
                                thread.parameter,
                                "ready",
                            )?;
                        }
                    }
                    Ok(previous_suspend_count as u64)
                }
                ("kernel32.dll", "SetHandleCount") => Ok(arg(args, 0)),
                ("kernel32.dll", "SetLastError") => {
                    self.set_last_error(arg(args, 0) as u32);
                    Ok(0)
                }
                ("kernel32.dll", "SetPriorityClass") => {
                    if self.process_identity_for_handle(arg(args, 0)).is_none()
                        && !self.is_current_process_handle(arg(args, 0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "SetProcessWorkingSetSize") => {
                    if self.process_identity_for_handle(arg(args, 0)).is_none()
                        && !self.is_current_process_handle(arg(args, 0))
                    {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    } else {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "InitializeProcThreadAttributeList") => {
                    const PROC_THREAD_ATTRIBUTE_LIST_SIZE: u64 = 0x30;
                    if arg(args, 3) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 3), &PROC_THREAD_ATTRIBUTE_LIST_SIZE.to_le_bytes())?;
                    }
                    if arg(args, 0) == 0 {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        self.modules.memory_mut().write(
                            arg(args, 0),
                            &vec![0u8; PROC_THREAD_ATTRIBUTE_LIST_SIZE as usize],
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "UpdateProcThreadAttribute") => Ok(1),
                ("kernel32.dll", "DeleteProcThreadAttributeList") => Ok(0),
                ("kernel32.dll", "SetFilePointer") => {
                    let handle = arg(args, 0) as u32;
                    let low = arg(args, 1) as u32 as u64;
                    let high_ptr = arg(args, 2);
                    let method = arg(args, 3);
                    let high = if high_ptr != 0 {
                        self.read_u32(high_ptr)? as u64
                    } else {
                        0
                    };
                    let offset = (high << 32) | low;
                    if let Some(position) = self.set_device_file_pointer(handle, offset, method) {
                        return Ok((position & 0xFFFF_FFFF) as u64);
                    }
                    let Some(state) = self.file_handles.get_mut(&handle) else {
                        return Ok(u32::MAX as u64);
                    };
                    let position = seek_file(&mut state.file, offset, method)?;
                    Ok((position & 0xFFFF_FFFF) as u64)
                }
                ("kernel32.dll", "SetFilePointerEx") => {
                    let handle = arg(args, 0) as u32;
                    let (distance, new_position_ptr, method) = if self.arch.is_x86() {
                        let low = arg(args, 1) as u32 as u64;
                        let high = arg(args, 2) as u32 as u64;
                        ((high << 32) | low, arg(args, 3), arg(args, 4))
                    } else {
                        (arg(args, 1), arg(args, 2), arg(args, 3))
                    };
                    if let Some(position) = self.set_device_file_pointer(handle, distance, method) {
                        if new_position_ptr != 0 {
                            self.modules
                                .memory_mut()
                                .write(new_position_ptr, &position.to_le_bytes())?;
                        }
                        return Ok(1);
                    }
                    let Some(state) = self.file_handles.get_mut(&handle) else {
                        return Ok(0);
                    };
                    let position = seek_file(&mut state.file, distance, method)?;
                    if new_position_ptr != 0 {
                        self.modules
                            .memory_mut()
                            .write(new_position_ptr, &position.to_le_bytes())?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "SetEndOfFile") => self.set_end_of_file(arg(args, 0) as u32),
                ("kernel32.dll", "SetErrorMode") => Ok(0),
                ("kernel32.dll", "SetEnvironmentVariableA") => {
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    let value = if arg(args, 1) == 0 {
                        None
                    } else {
                        Some(self.read_c_string_from_memory(arg(args, 1))?)
                    };
                    self.set_runtime_environment_variable(&name, value.clone())?;
                    let mut fields = Map::new();
                    fields.insert("name".to_string(), json!(name));
                    fields.insert("value".to_string(), json!(value));
                    self.log_runtime_event("ENV_SET", fields)?;
                    Ok(1)
                }
                ("kernel32.dll", "SetEnvironmentVariableW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    let value = if arg(args, 1) == 0 {
                        None
                    } else {
                        Some(self.read_wide_string_from_memory(arg(args, 1))?)
                    };
                    self.set_runtime_environment_variable(&name, value.clone())?;
                    let mut fields = Map::new();
                    fields.insert("name".to_string(), json!(name));
                    fields.insert("value".to_string(), json!(value));
                    self.log_runtime_event("ENV_SET", fields)?;
                    Ok(1)
                }
                ("kernel32.dll", "SetFileTime") => {
                    if self.file_handles.contains_key(&(arg(args, 0) as u32)) {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "SetWaitableTimer") => {
                    Ok(self.scheduler.set_event(arg(args, 0) as u32).is_some() as u64)
                }
                ("kernel32.dll", "SetUnhandledExceptionFilter") => {
                    let previous = self.top_level_exception_filter;
                    self.top_level_exception_filter = arg(args, 0);
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(previous)
                }
                ("kernel32.dll", "SystemTimeToFileTime") => {
                    if arg(args, 1) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 1), &self.time.current().filetime.to_le_bytes())?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "TerminateProcess") => {
                    let process = arg(args, 0);
                    if self.is_current_process_handle(process) || process == 0 {
                        self.exit_code = Some(arg(args, 1) as u32);
                        self.process_exit_requested = true;
                        self.force_native_return = true;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "TryEnterCriticalSection") => Ok(1),
                ("kernel32.dll", "RtlCaptureContext") => self.rtl_capture_context(arg(args, 0)),
                ("kernel32.dll", "RtlRestoreContext") => self.rtl_restore_context(arg(args, 0)),
                ("kernel32.dll", "RtlLookupFunctionEntry") => {
                    self.rtl_lookup_function_entry(arg(args, 0), arg(args, 1))
                }
                ("kernel32.dll", "RtlPcToFileHeader") => {
                    self.rtl_pc_to_file_header(arg(args, 0), arg(args, 1))
                }
                ("kernel32.dll", "RtlUnwind") => {
                    self.rtl_unwind(arg(args, 0), arg(args, 1), arg(args, 3))
                }
                ("kernel32.dll", "RtlUnwindEx") => {
                    self.rtl_unwind_ex(arg(args, 0), arg(args, 1), arg(args, 3))
                }
                ("kernel32.dll", "RtlVirtualUnwind") => self.rtl_virtual_unwind(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                ("kernel32.dll", "GetThreadContext") => {
                    if arg(args, 1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else if self.write_thread_context(arg(args, 0) as u32, arg(args, 1))? {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "SetThreadContext") => {
                    if arg(args, 1) == 0 {
                        self.set_last_error(ERROR_INVALID_PARAMETER as u32);
                        Ok(0)
                    } else if self.read_thread_context(arg(args, 0) as u32, arg(args, 1))? {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        Ok(0)
                    }
                }
                ("kernel32.dll", "TlsAlloc") => {
                    let slot = self
                        .tls
                        .alloc_for_thread(self.current_tls_thread_id())
                        .unwrap_or(usize::MAX);
                    if slot == usize::MAX {
                        return Ok(u32::MAX as u64);
                    }
                    let mirrored = self.process_env.allocate_tls_slot()?;
                    if mirrored != slot {
                        return Err(VmError::RuntimeInvariant("tls slot allocator drifted"));
                    }
                    self.sync_native_support_state()?;
                    Ok(slot as u64)
                }
                ("kernel32.dll", "TlsFree") => {
                    if !self.tls.free(arg(args, 0) as usize) {
                        return Ok(0);
                    }
                    let _ = self.process_env.free_tls_slot(arg(args, 0) as usize)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                ("kernel32.dll", "TlsGetValue") => Ok(self
                    .tls
                    .get_value_for_thread(self.current_tls_thread_id(), arg(args, 0) as usize)),
                ("kernel32.dll", "TlsSetValue") => {
                    let slot = arg(args, 0) as usize;
                    let value = arg(args, 1);
                    if !self
                        .tls
                        .set_value_for_thread(self.current_tls_thread_id(), slot, value)
                    {
                        return Ok(0);
                    }
                    self.process_env.set_tls_value(slot, value)?;
                    self.sync_native_support_state()?;
                    Ok(1)
                }
                ("kernel32.dll", "UnmapViewOfFile") => self.unmap_view_of_file(arg(args, 0)),
                ("kernel32.dll", "UnhandledExceptionFilter") => Ok(0),
                ("kernel32.dll", "WaitForMultipleObjectsEx") => {
                    let count = (arg(args, 0) as usize).min(64);
                    let handles = self.read_wait_handles(count, arg(args, 1))?;
                    self.wait_for_objects(
                        &handles,
                        arg(args, 2) != 0,
                        arg(args, 3) as u32,
                        arg(args, 4) != 0,
                    )
                }
                ("kernel32.dll", "WaitForMultipleObjects") => {
                    let count = (arg(args, 0) as usize).min(64);
                    let handles = self.read_wait_handles(count, arg(args, 1))?;
                    self.wait_for_objects(&handles, arg(args, 2) != 0, arg(args, 3) as u32, false)
                }
                ("kernel32.dll", "WaitForSingleObject") => {
                    self.wait_for_objects(&[arg(args, 0) as u32], false, arg(args, 1) as u32, false)
                }
                ("kernel32.dll", "WaitForDebugEvent") => Ok(0),
                ("kernel32.dll", "ContinueDebugEvent") => Ok(1),
                ("kernel32.dll", "VirtualAlloc") => self.allocate_virtual_region(
                    self.current_process_space_key(),
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3) as u32,
                    "VirtualAlloc",
                    false,
                ),
                ("kernel32.dll", "VirtualAllocEx") => {
                    if !self.is_known_process_target(arg(args, 0)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let address = self.allocate_virtual_region(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as u32,
                        arg(args, 4) as u32,
                        "VirtualAllocEx",
                        true,
                    )?;
                    if address != 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                    }
                    Ok(address)
                }
                ("kernel32.dll", "VirtualFree") => self.free_virtual_region(
                    self.current_process_space_key(),
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    "VirtualFree",
                ),
                ("kernel32.dll", "VirtualFreeEx") => {
                    if !self.is_known_process_target(arg(args, 0)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    self.free_virtual_region(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3),
                        "VirtualFreeEx",
                    )
                }
                ("kernel32.dll", "VirtualProtectEx") => self.virtual_protect(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    "VirtualProtectEx",
                ),
                ("kernel32.dll", "ReadProcessMemory") => self.read_process_memory(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    arg(args, 4),
                ),
                ("kernel32.dll", "WriteProcessMemory") => self.write_process_memory(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    arg(args, 4),
                ),
                ("kernel32.dll", "WriteConsoleA") => {
                    let handle = arg(args, 0);
                    let buffer = arg(args, 1);
                    let count = arg(args, 2) as usize;
                    let written_ptr = arg(args, 3);
                    let text =
                        String::from_utf8_lossy(&self.read_bytes_from_memory(buffer, count)?)
                            .into_owned();
                    self.emit_console_text("WriteConsoleA", handle, &text)?;
                    if written_ptr != 0 {
                        self.write_u32(written_ptr, count as u32)?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "WideCharToMultiByte") => {
                    let text = self.read_wide_input_string(arg(args, 2), arg(args, 3))?;
                    let mut encoded = self.encode_code_page_string(arg(args, 0), &text);
                    encoded.push(0);
                    let required = encoded.len();
                    if arg(args, 4) == 0 || arg(args, 5) == 0 {
                        Ok(required as u64)
                    } else {
                        self.write_raw_bytes_to_memory(
                            arg(args, 4),
                            arg(args, 5) as usize,
                            &encoded,
                        )
                    }
                }
                ("kernel32.dll", "WriteConsoleW") => {
                    let handle = arg(args, 0);
                    let buffer = arg(args, 1);
                    let count = arg(args, 2) as usize;
                    let written_ptr = arg(args, 3);
                    let text = self.read_wide_counted_string_from_memory(buffer, count)?;
                    self.emit_console_text("WriteConsoleW", handle, &text)?;
                    if written_ptr != 0 {
                        self.write_u32(written_ptr, count as u32)?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "WriteFile") => {
                    let handle = arg(args, 0) as u32;
                    let data = self.read_bytes_from_memory(arg(args, 1), arg(args, 2) as usize)?;
                    let written = if is_std_handle(handle as u64) {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        self.emit_console_text("WriteFile", handle as u64, &text)?;
                        data.len()
                    } else if let Some(written) = self.write_device_handle(handle, &data)? {
                        written
                    } else if let Some(state) = self.file_handles.get_mut(&handle) {
                        let path = state.path.clone();
                        let written = state.file.write(&data).unwrap_or(0);
                        self.log_file_write_event(handle, &path, &data[..written])?;
                        written
                    } else {
                        0
                    };
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), written as u32)?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "FindResourceExW") => {
                    self.set_last_error(1813);
                    Ok(0)
                }
                ("kernel32.dll", "FreeLibraryAndExitThread") => {
                    let module_handle = arg(args, 0);
                    if self.main_module.as_ref().map(|module| module.base) != Some(module_handle) {
                        if let Some(module) = self.modules.get_by_base(module_handle).cloned() {
                            let _ = self.run_dynamic_library_detach(&module);
                            if self.modules.unload_module(module_handle) {
                                self.unregister_process_virtual_allocation(
                                    self.current_process_space_key(),
                                    module_handle,
                                );
                            }
                        }
                    }
                    self.force_native_return = true;
                    Ok(arg(args, 1))
                }
                ("kernel32.dll", "GetFileAttributesW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
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
                ("kernel32.dll", "GetFileTime") => {
                    if !self.file_handles.contains_key(&(arg(args, 0) as u32)) {
                        self.set_last_error(ERROR_INVALID_HANDLE as u32);
                        return Ok(0);
                    }
                    let now = self.time.current().filetime;
                    for pointer in [arg(args, 1), arg(args, 2), arg(args, 3)] {
                        if pointer != 0 {
                            self.modules
                                .memory_mut()
                                .write(pointer, &now.to_le_bytes())?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetProfileIntW") => Ok(arg(args, 2)),
                ("kernel32.dll", "GetSystemDefaultUILanguage") => {
                    Ok(self.system_default_ui_language())
                }
                ("kernel32.dll", "GetUserDefaultUILanguage") => Ok(self.user_default_ui_language()),
                ("kernel32.dll", "GetThreadLocale") => Ok(self.thread_locale()),
                ("kernel32.dll", "GetThreadPreferredUILanguages") => {
                    let flags = arg(args, 0) as u32;
                    let buffer_len_ptr = arg(args, 3);
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
                    if arg(args, 1) != 0 {
                        self.write_u32(arg(args, 1), 1)?;
                    }

                    let capacity = self.read_u32(buffer_len_ptr).unwrap_or(0) as usize;
                    self.write_u32(buffer_len_ptr, required as u32)?;
                    if arg(args, 2) == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    } else if capacity < required {
                        self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                        Ok(0)
                    } else {
                        let written =
                            self.write_wide_string_to_memory(arg(args, 2), capacity, language)?;
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2) + written * 2 + 2, &[0, 0])?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(1)
                    }
                }
                ("kernel32.dll", "GetTempPathW") => {
                    let mut path = self.temporary_directory_path().replace('/', "\\");
                    if !path.ends_with('\\') {
                        path.push('\\');
                    }
                    let path_len = path.encode_utf16().count();
                    let required = path_len + 1;
                    if arg(args, 1) == 0 || arg(args, 0) == 0 {
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 1),
                            arg(args, 0) as usize,
                            &path,
                        )?;
                        self.set_last_error(ERROR_SUCCESS as u32);
                        Ok(path_len as u64)
                    }
                }
                ("kernel32.dll", "GetTempFileNameW") => {
                    let display_directory = if arg(args, 0) != 0 {
                        self.read_wide_string_from_memory(arg(args, 0))?
                    } else {
                        self.temporary_directory_path()
                    };
                    let prefix = if arg(args, 1) != 0 {
                        self.read_wide_string_from_memory(arg(args, 1))?
                    } else {
                        "TMP".to_string()
                    };
                    let unique = if arg(args, 2) != 0 {
                        arg(args, 2) as u32
                    } else {
                        (self.time.current().tick_ms & 0xFFFF) as u32
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
                    if arg(args, 3) != 0 {
                        let _ =
                            self.write_wide_string_to_memory(arg(args, 3), 260, &display_target)?;
                    }
                    self.log_file_event("FILE_OPEN", 0, &display_target, Some(0))?;
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(unique as u64)
                }
                ("kernel32.dll", "GetTimeZoneInformation") => {
                    if arg(args, 0) != 0 {
                        self.modules.memory_mut().write(arg(args, 0), &[0u8; 172])?;
                    }
                    Ok(TIME_ZONE_ID_UNKNOWN)
                }
                ("kernel32.dll", "GetVolumeInformationA") => {
                    let volume = self.volume_profile().clone();
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.write_c_string_to_memory(
                            arg(args, 1),
                            arg(args, 2) as usize,
                            &volume.volume_name,
                        )?;
                    }
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), volume.serial)?;
                    }
                    if arg(args, 4) != 0 {
                        self.write_u32(arg(args, 4), volume.max_component_length)?;
                    }
                    if arg(args, 5) != 0 {
                        self.write_u32(arg(args, 5), volume.flags)?;
                    }
                    if arg(args, 6) != 0 && arg(args, 7) != 0 {
                        let _ = self.write_c_string_to_memory(
                            arg(args, 6),
                            arg(args, 7) as usize,
                            &volume.fs_name,
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetVolumeInformationW") => {
                    let volume = self.volume_profile().clone();
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 1),
                            arg(args, 2) as usize,
                            &volume.volume_name,
                        )?;
                    }
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), volume.serial)?;
                    }
                    if arg(args, 4) != 0 {
                        self.write_u32(arg(args, 4), volume.max_component_length)?;
                    }
                    if arg(args, 5) != 0 {
                        self.write_u32(arg(args, 5), volume.flags)?;
                    }
                    if arg(args, 6) != 0 && arg(args, 7) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 6),
                            arg(args, 7) as usize,
                            &volume.fs_name,
                        )?;
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "GetCurrentDirectoryW") => {
                    let path = self.current_directory_display_text();
                    let required = path.encode_utf16().count() + 1;
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        Ok(required as u64)
                    } else {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 1),
                            arg(args, 0) as usize,
                            &path,
                        )?;
                        Ok(path.encode_utf16().count() as u64)
                    }
                }
                ("kernel32.dll", "SetCurrentDirectoryW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
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
                            self.current_directory = std::path::PathBuf::from(&display_path);
                            self.current_directory_host = target;
                            self.process_env.set_current_directory(&display_path)?;
                            self.sync_native_support_state()?;
                            self.log_file_event("FILE_CHDIR", 0, &display_path, None)?;
                            self.set_last_error(ERROR_SUCCESS as u32);
                        }
                        Ok(result)
                    }
                }
                ("kernel32.dll", "GetFullPathNameA") => {
                    let path = self.read_c_string_from_memory(arg(args, 0))?;
                    let output = self.resolve_runtime_display_path(&path);
                    let required = output.len() as u64;
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.write_c_string_to_memory(
                            arg(args, 2),
                            arg(args, 1) as usize,
                            &output,
                        )?;
                        if arg(args, 3) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| index as u64 + 1)
                                .unwrap_or(0);
                            self.write_pointer_value(arg(args, 3), arg(args, 2) + offset)?;
                        }
                    }
                    Ok(required)
                }
                ("kernel32.dll", "GetFullPathNameW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    let output = self.resolve_runtime_display_path(&path);
                    let required = output.encode_utf16().count() as u64;
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 2),
                            arg(args, 1) as usize,
                            &output,
                        )?;
                        if arg(args, 3) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| output[..index + 1].encode_utf16().count() as u64 * 2)
                                .unwrap_or(0);
                            self.write_pointer_value(arg(args, 3), arg(args, 2) + offset)?;
                        }
                    }
                    Ok(required)
                }
                ("kernel32.dll", "GlobalAddAtomW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    Ok(self.allocate_global_atom(&name) as u64)
                }
                ("kernel32.dll", "GlobalFindAtomW") => {
                    let name = self.read_wide_string_from_memory(arg(args, 0))?;
                    Ok(self.find_global_atom(&name) as u64)
                }
                ("kernel32.dll", "GlobalGetAtomNameW") => {
                    let Some(name) = self.global_atoms.get(&(arg(args, 0) as u16)).cloned() else {
                        return Ok(0);
                    };
                    self.write_wide_string_to_memory(arg(args, 1), arg(args, 2) as usize, &name)
                }
                ("kernel32.dll", "GlobalDeleteAtom") => Ok(
                    if self.global_atoms.remove(&(arg(args, 0) as u16)).is_some() {
                        0
                    } else {
                        arg(args, 0)
                    },
                ),
                ("kernel32.dll", "GlobalAlloc") => {
                    let size = arg(args, 1).max(1);
                    let address = self
                        .heaps
                        .alloc(self.modules.memory_mut(), self.heaps.process_heap(), size)
                        .unwrap_or(0);
                    if address != 0 {
                        if arg(args, 0) & LMEM_ZEROINIT != 0 {
                            self.fill_memory_pattern(address, size, 0)?;
                        }
                        self.log_heap_event(
                            "HEAP_ALLOC",
                            self.heaps.process_heap(),
                            address,
                            size,
                            "GlobalAlloc",
                        )?;
                    }
                    Ok(address)
                }
                ("kernel32.dll", "GlobalFree") => Ok(
                    if self.heaps.free(self.heaps.process_heap(), arg(args, 0)) {
                        let _ = self.log_heap_event(
                            "HEAP_FREE",
                            self.heaps.process_heap(),
                            arg(args, 0),
                            0,
                            "GlobalFree",
                        );
                        0
                    } else {
                        arg(args, 0)
                    },
                ),
                ("kernel32.dll", "GlobalLock") | ("kernel32.dll", "GlobalHandle") => {
                    Ok(arg(args, 0))
                }
                ("kernel32.dll", "GlobalUnlock") => Ok(0),
                ("kernel32.dll", "GlobalSize") => {
                    Ok(self.heaps.size(self.heaps.process_heap(), arg(args, 0)))
                }
                ("kernel32.dll", "GlobalFlags") => Ok(0),
                ("kernel32.dll", "GlobalReAlloc") | ("kernel32.dll", "LocalReAlloc") => {
                    let old_address = arg(args, 0);
                    let new_size = arg(args, 1).max(1);
                    let old_size = self.heaps.size(self.heaps.process_heap(), old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let Some(new_address) = self.heaps.alloc(
                        self.modules.memory_mut(),
                        self.heaps.process_heap(),
                        new_size,
                    ) else {
                        return Ok(0);
                    };
                    let bytes = self
                        .modules
                        .memory()
                        .read(old_address, old_size.min(new_size) as usize)?;
                    self.modules.memory_mut().write(new_address, &bytes)?;
                    if arg(args, 2) & LMEM_ZEROINIT != 0 && new_size > old_size {
                        self.fill_memory_pattern(
                            new_address + old_size,
                            new_size.saturating_sub(old_size),
                            0,
                        )?;
                    }
                    self.heaps.free(self.heaps.process_heap(), old_address);
                    self.log_heap_event(
                        "HEAP_REALLOC",
                        self.heaps.process_heap(),
                        new_address,
                        new_size,
                        definition.function,
                    )?;
                    Ok(new_address)
                }
                ("kernel32.dll", "HeapQueryInformation") => {
                    if arg(args, 2) != 0 && arg(args, 3) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2), &vec![0u8; arg(args, 3) as usize])?;
                    }
                    if arg(args, 4) != 0 {
                        self.write_u32(arg(args, 4), 0)?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "LoadResource")
                | ("kernel32.dll", "LockResource")
                | ("kernel32.dll", "SizeofResource") => Ok(0),
                ("kernel32.dll", "LockFile") | ("kernel32.dll", "UnlockFile") => Ok(1),
                ("kernel32.dll", "lstrcmpA") => {
                    let left = self.read_c_string_from_memory(arg(args, 0))?;
                    let right = self.read_c_string_from_memory(arg(args, 1))?;
                    Ok(match left.cmp(&right) {
                        std::cmp::Ordering::Less => -1i32 as u32 as u64,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    })
                }
                ("kernel32.dll", "lstrcmpW") => {
                    let left = self.read_wide_string_from_memory(arg(args, 0))?;
                    let right = self.read_wide_string_from_memory(arg(args, 1))?;
                    Ok(match left.cmp(&right) {
                        std::cmp::Ordering::Less => -1i32 as u32 as u64,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    })
                }
                ("kernel32.dll", "QueryPerformanceFrequency") => {
                    if arg(args, 0) != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 0), &10_000_000u64.to_le_bytes())?;
                    }
                    Ok(1)
                }
                ("kernel32.dll", "SearchPathW") => {
                    let directory = if arg(args, 0) != 0 {
                        self.read_wide_string_from_memory(arg(args, 0))?
                    } else {
                        self.current_directory_display_text()
                    };
                    let mut file_name = self.read_wide_string_from_memory(arg(args, 1))?;
                    let extension = self.read_wide_string_from_memory(arg(args, 2))?;
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
                    if arg(args, 4) != 0 && arg(args, 3) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 4),
                            arg(args, 3) as usize,
                            &output,
                        )?;
                        if arg(args, 5) != 0 {
                            let offset = output
                                .rfind(|ch| ch == '/' || ch == '\\')
                                .map(|index| output[..index + 1].encode_utf16().count() as u64 * 2)
                                .unwrap_or(0);
                            self.write_pointer_value(arg(args, 5), arg(args, 4) + offset)?;
                        }
                    }
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(required)
                }
                ("kernel32.dll", "SetFileAttributesW") => {
                    let path = self.read_wide_string_from_memory(arg(args, 0))?;
                    let Some(target) =
                        self.prepare_runtime_read_target(&path, "SetFileAttributesW")?
                    else {
                        return Ok(0);
                    };
                    Ok(target.exists() as u64)
                }
                ("kernel32.dll", "SetThreadPriority") => Ok(1),
                ("kernel32.dll", "SystemTimeToTzSpecificLocalTime") => {
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let bytes = self.read_bytes_from_memory(arg(args, 1), 16)?;
                        self.modules.memory_mut().write(arg(args, 2), &bytes)?;
                        Ok(1)
                    } else {
                        Ok(0)
                    }
                }
                ("kernel32.dll", "FileTimeToLocalFileTime") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        Ok(0)
                    } else {
                        let bytes = self.read_bytes_from_memory(arg(args, 0), 8)?;
                        self.modules.memory_mut().write(arg(args, 1), &bytes)?;
                        Ok(1)
                    }
                }
                ("kernel32.dll", "FileTimeToSystemTime") => {
                    if arg(args, 0) == 0 || arg(args, 1) == 0 {
                        Ok(0)
                    } else {
                        let filetime = u64::from_le_bytes(
                            self.read_bytes_from_memory(arg(args, 0), 8)?
                                .try_into()
                                .unwrap(),
                        );
                        self.write_systemtime_struct(
                            arg(args, 1),
                            Self::system_time_components_from_filetime(filetime),
                        )?;
                        Ok(1)
                    }
                }
                ("kernel32.dll", "FormatMessageA") => {
                    let text = if arg(args, 2) == 0 {
                        "The operation completed successfully.".to_string()
                    } else {
                        format!("Sandbox message {}", arg(args, 2))
                    };
                    let required = text.len() + 1;
                    if arg(args, 0) & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
                        let buffer =
                            self.alloc_process_heap_block(required as u64, "FormatMessageA")?;
                        let _ = self.write_c_string_to_memory(buffer, required, &text)?;
                        self.write_pointer_value(arg(args, 4), buffer)?;
                        Ok((required - 1) as u64)
                    } else if arg(args, 4) != 0 && arg(args, 5) != 0 {
                        let _ = self.write_c_string_to_memory(
                            arg(args, 4),
                            arg(args, 5) as usize,
                            &text,
                        )?;
                        Ok((required - 1) as u64)
                    } else {
                        Ok(0)
                    }
                }
                ("kernel32.dll", "FormatMessageW") => {
                    let text = if arg(args, 2) == 0 {
                        "The operation completed successfully.".to_string()
                    } else {
                        format!("Sandbox message {}", arg(args, 2))
                    };
                    let required = text.encode_utf16().count() + 1;
                    if arg(args, 0) & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
                        let buffer =
                            self.alloc_process_heap_block((required * 2) as u64, "FormatMessageW")?;
                        let _ = self.write_wide_string_to_memory(buffer, required, &text)?;
                        self.write_pointer_value(arg(args, 4), buffer)?;
                        Ok((required - 1) as u64)
                    } else if arg(args, 4) != 0 && arg(args, 5) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 4),
                            arg(args, 5) as usize,
                            &text,
                        )?;
                        Ok((required - 1) as u64)
                    } else {
                        Ok(0)
                    }
                }
                ("kernel32.dll", "MulDiv") => {
                    if arg(args, 2) == 0 {
                        Ok(-1i32 as u32 as u64)
                    } else {
                        Ok(
                            ((arg(args, 0) as i64 * arg(args, 1) as i64) / arg(args, 2) as i64)
                                as i32 as u32 as u64,
                        )
                    }
                }
                ("kernel32.dll", "GetPrivateProfileStringW") => {
                    let default = self.read_wide_string_from_memory(arg(args, 2))?;
                    let written = self.write_wide_string_to_memory(
                        arg(args, 3),
                        arg(args, 4) as usize,
                        &default,
                    )?;
                    Ok(written)
                }
                ("kernel32.dll", "GetPrivateProfileIntW") => Ok(arg(args, 2)),
                ("kernel32.dll", "WritePrivateProfileStringW") => Ok(1),
                ("kernel32.dll", "VerLanguageNameW") => {
                    let language_name = "English (United States)";
                    let required = language_name.encode_utf16().count() + 1;
                    if arg(args, 1) != 0 && arg(args, 2) != 0 {
                        let _ = self.write_wide_string_to_memory(
                            arg(args, 1),
                            arg(args, 2) as usize,
                            language_name,
                        )?;
                    }
                    Ok(required as u64)
                }
                ("kernel32.dll", "VerSetConditionMask") => {
                    let (current_mask, type_mask, condition) = if self.arch.is_x86() {
                        (
                            arg(args, 0) | (arg(args, 1) << 32),
                            arg(args, 2),
                            arg(args, 3),
                        )
                    } else {
                        (arg(args, 0), arg(args, 1), arg(args, 2))
                    };
                    let bit_shift = (type_mask.trailing_zeros().min(20) * 3) as u64;
                    Ok(current_mask | ((condition & 0x7) << bit_shift))
                }
                ("kernel32.dll", "VerifyVersionInfoW") => Ok(1),
                ("kernel32.dll", "AddVectoredExceptionHandler") => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(self.allocate_object_handle() as u64)
                }
                ("kernel32.dll", "RemoveVectoredExceptionHandler") => {
                    self.set_last_error(ERROR_SUCCESS as u32);
                    Ok(1)
                }
                ("kernel32.dll", "WaitForSingleObjectEx") => self.wait_for_objects(
                    &[arg(args, 0) as u32],
                    false,
                    arg(args, 1) as u32,
                    arg(args, 2) != 0,
                ),
                ("kernel32.dll", "VirtualProtect") => self.virtual_protect(
                    self.current_process_space_key(),
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as u32,
                    arg(args, 3),
                    "VirtualProtect",
                ),
                ("kernel32.dll", "VirtualQuery") => {
                    if arg(args, 1) == 0 {
                        return Ok(0);
                    }
                    let info = self.query_memory_basic_information(arg(args, 0));
                    Ok(self.write_memory_basic_information(
                        arg(args, 1),
                        arg(args, 2) as usize,
                        info,
                    )? as u64)
                }
                ("kernel32.dll", "VirtualQueryEx") => {
                    if arg(args, 2) == 0 || !self.is_known_process_target(arg(args, 0)) {
                        return Ok(0);
                    }
                    let Some(info) =
                        self.query_memory_basic_information_for_process(arg(args, 0), arg(args, 1))
                    else {
                        return Ok(0);
                    };
                    Ok(self.write_memory_basic_information(
                        arg(args, 2),
                        arg(args, 3) as usize,
                        info,
                    )? as u64)
                }
                ("kernel32.dll", _) => {
                    self.log_unsupported_runtime_stub(
                        definition,
                        stub_address,
                        "missing runtime implementation",
                    )?;
                    Err(VmError::NativeExecution {
                        op: "dispatch",
                        detail: format!(
                            "missing runtime implementation for {}!{}",
                            definition.module, definition.function
                        ),
                    })
                }
                _ => unreachable!("kernel32 dispatch precheck should only route kernel32 calls"),
            }
        })())
    }
}

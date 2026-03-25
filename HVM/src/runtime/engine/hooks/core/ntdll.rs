use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_ntdll_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("ntdll.dll", "NtOpenProcess") | ("ntdll.dll", "ZwOpenProcess") => true,
            ("ntdll.dll", "NtAllocateVirtualMemory") | ("ntdll.dll", "ZwAllocateVirtualMemory") => {
                true
            }
            ("ntdll.dll", "NtFreeVirtualMemory") | ("ntdll.dll", "ZwFreeVirtualMemory") => true,
            ("ntdll.dll", "NtProtectVirtualMemory") | ("ntdll.dll", "ZwProtectVirtualMemory") => {
                true
            }
            ("ntdll.dll", "NtCreateThreadEx") | ("ntdll.dll", "ZwCreateThreadEx") => true,
            ("ntdll.dll", "RtlGetVersion") => true,
            ("ntdll.dll", "RtlCreateUserThread") => true,
            ("ntdll.dll", "NtQueryInformationProcess")
            | ("ntdll.dll", "ZwQueryInformationProcess") => true,
            ("ntdll.dll", "NtQuerySystemInformation")
            | ("ntdll.dll", "ZwQuerySystemInformation") => true,
            ("ntdll.dll", "NtQueryVirtualMemory") | ("ntdll.dll", "ZwQueryVirtualMemory") => true,
            ("ntdll.dll", "NtReadVirtualMemory") | ("ntdll.dll", "ZwReadVirtualMemory") => true,
            ("ntdll.dll", "ZwSetInformationKey") => true,
            ("ntdll.dll", "NtQueueApcThread") | ("ntdll.dll", "ZwQueueApcThread") => true,
            ("ntdll.dll", "NtGetContextThread") | ("ntdll.dll", "ZwGetContextThread") => true,
            ("ntdll.dll", "NtContinue") | ("ntdll.dll", "ZwContinue") => true,
            ("ntdll.dll", "NtSetContextThread") | ("ntdll.dll", "ZwSetContextThread") => true,
            ("ntdll.dll", "RtlAllocateHeap") => true,
            ("ntdll.dll", "RtlCaptureContext") => true,
            ("ntdll.dll", "RtlFillMemory") => true,
            ("ntdll.dll", "RtlFreeHeap") => true,
            ("ntdll.dll", "NtClose") => true,
            ("ntdll.dll", "RtlLookupFunctionEntry") => true,
            ("ntdll.dll", "RtlPcToFileHeader") => true,
            ("ntdll.dll", "RtlRestoreContext") => true,
            ("ntdll.dll", "RtlUnwind") => true,
            ("ntdll.dll", "RtlUnwindEx") => true,
            ("ntdll.dll", "RtlVirtualUnwind") => true,
            ("ntdll.dll", "RtlZeroMemory") => true,
            ("ntdll.dll", "NtCreateSection") | ("ntdll.dll", "ZwCreateSection") => true,
            ("ntdll.dll", "NtDuplicateObject") => true,
            ("ntdll.dll", "NtMapViewOfSection") | ("ntdll.dll", "ZwMapViewOfSection") => true,
            ("ntdll.dll", "NtRemoveProcessDebug") | ("ntdll.dll", "DbgUiSetThreadDebugObject") => {
                true
            }
            ("ntdll.dll", "NtUnmapViewOfSection") | ("ntdll.dll", "ZwUnmapViewOfSection") => true,
            ("ntdll.dll", "NtWriteVirtualMemory") | ("ntdll.dll", "ZwWriteVirtualMemory") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("ntdll.dll", "NtOpenProcess") | ("ntdll.dll", "ZwOpenProcess") => {
                    self.nt_open_process(arg(args, 0), arg(args, 3))
                }
                ("ntdll.dll", "NtAllocateVirtualMemory")
                | ("ntdll.dll", "ZwAllocateVirtualMemory") => self.nt_allocate_virtual_memory(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 3),
                    arg(args, 4) as u32,
                    arg(args, 5) as u32,
                    "NtAllocateVirtualMemory",
                ),
                ("ntdll.dll", "NtFreeVirtualMemory") | ("ntdll.dll", "ZwFreeVirtualMemory") => self
                    .nt_free_virtual_memory(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3),
                        "NtFreeVirtualMemory",
                    ),
                ("ntdll.dll", "NtProtectVirtualMemory")
                | ("ntdll.dll", "ZwProtectVirtualMemory") => self.nt_protect_virtual_memory(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as u32,
                    arg(args, 4),
                    "NtProtectVirtualMemory",
                ),
                ("ntdll.dll", "NtCreateThreadEx") | ("ntdll.dll", "ZwCreateThreadEx") => {
                    let process_handle = arg(args, 3);
                    let handle = if self.is_current_process_handle(process_handle) {
                        self.create_runtime_thread(
                            arg(args, 4),
                            arg(args, 5),
                            if arg(args, 6) & 0x1 != 0 { 0x4 } else { 0 },
                            0,
                        )?
                    } else {
                        if !self.is_known_process_target(process_handle) {
                            return Ok(STATUS_INVALID_HANDLE as u64);
                        }
                        let Some(handle) = self.create_remote_shellcode_thread(
                            process_handle,
                            arg(args, 4),
                            arg(args, 5),
                            arg(args, 6) & 0x1 != 0,
                            0,
                            "NtCreateThreadEx",
                        )?
                        else {
                            return Ok(STATUS_INVALID_PARAMETER as u64);
                        };
                        handle
                    };
                    if arg(args, 0) != 0 {
                        self.write_pointer_value(arg(args, 0), handle)?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                ("ntdll.dll", "RtlGetVersion") => {
                    Ok(if self.write_version_info(arg(args, 0), true)? {
                        STATUS_SUCCESS as u64
                    } else {
                        STATUS_INVALID_PARAMETER as u64
                    })
                }
                ("ntdll.dll", "RtlCreateUserThread") => {
                    let process_handle = arg(args, 0);
                    let suspended = arg(args, 2) != 0;
                    let handle = if self.is_current_process_handle(process_handle) {
                        self.create_runtime_thread(
                            arg(args, 6),
                            arg(args, 7),
                            if suspended { 0x4 } else { 0 },
                            0,
                        )?
                    } else {
                        if !self.is_known_process_target(process_handle) {
                            return Ok(STATUS_INVALID_HANDLE as u64);
                        }
                        let Some(handle) = self.create_remote_shellcode_thread(
                            process_handle,
                            arg(args, 6),
                            arg(args, 7),
                            suspended,
                            0,
                            "RtlCreateUserThread",
                        )?
                        else {
                            return Ok(STATUS_INVALID_PARAMETER as u64);
                        };
                        handle
                    };
                    if arg(args, 8) != 0 {
                        self.write_pointer_value(arg(args, 8), handle)?;
                    }
                    if arg(args, 9) != 0 {
                        let process_id = self
                            .process_identity_for_handle(process_handle)
                            .map(|process| process.pid as u64)
                            .unwrap_or(self.current_process_id() as u64);
                        let thread_id = self
                            .scheduler
                            .thread_tid_for_handle(handle as u32)
                            .unwrap_or(0) as u64;
                        self.write_pointer_value(arg(args, 9), process_id)?;
                        self.write_pointer_value(
                            arg(args, 9) + self.arch.pointer_size as u64,
                            thread_id,
                        )?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                ("ntdll.dll", "NtQueryInformationProcess")
                | ("ntdll.dll", "ZwQueryInformationProcess") => self.nt_query_information_process(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3) as usize,
                    arg(args, 4),
                ),
                ("ntdll.dll", "NtQuerySystemInformation")
                | ("ntdll.dll", "ZwQuerySystemInformation") => self.nt_query_system_information(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2) as usize,
                    arg(args, 3),
                ),
                ("ntdll.dll", "NtQueryVirtualMemory") | ("ntdll.dll", "ZwQueryVirtualMemory") => {
                    self.nt_query_virtual_memory(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3),
                        arg(args, 4) as usize,
                        arg(args, 5),
                    )
                }
                ("ntdll.dll", "NtReadVirtualMemory") | ("ntdll.dll", "ZwReadVirtualMemory") => self
                    .nt_read_virtual_memory(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                    ),
                ("ntdll.dll", "ZwSetInformationKey") => Ok(STATUS_SUCCESS as u64),
                ("ntdll.dll", "NtQueueApcThread") | ("ntdll.dll", "ZwQueueApcThread") => {
                    let status = if self
                        .scheduler
                        .queue_user_apc(arg(args, 0) as u32, arg(args, 1), arg(args, 2))
                        .is_some()
                    {
                        STATUS_SUCCESS
                    } else {
                        STATUS_INVALID_HANDLE
                    };
                    Ok(status as u64)
                }
                ("ntdll.dll", "NtGetContextThread") | ("ntdll.dll", "ZwGetContextThread") => {
                    if arg(args, 1) == 0 {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    } else if self.write_thread_context(arg(args, 0) as u32, arg(args, 1))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_HANDLE as u64)
                    }
                }
                ("ntdll.dll", "NtContinue") | ("ntdll.dll", "ZwContinue") => {
                    if self.queue_current_context_restore(arg(args, 0))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    }
                }
                ("ntdll.dll", "NtSetContextThread") | ("ntdll.dll", "ZwSetContextThread") => {
                    if arg(args, 1) == 0 {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    } else if self.read_thread_context(arg(args, 0) as u32, arg(args, 1))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_HANDLE as u64)
                    }
                }
                ("ntdll.dll", "RtlAllocateHeap") => Ok(self
                    .heaps
                    .alloc(
                        self.modules.memory_mut(),
                        arg(args, 0) as u32,
                        arg(args, 2).max(1),
                    )
                    .unwrap_or(0)),
                ("ntdll.dll", "RtlCaptureContext") => self.rtl_capture_context(arg(args, 0)),
                ("ntdll.dll", "RtlFillMemory") => {
                    self.fill_memory_pattern(arg(args, 0), arg(args, 1), arg(args, 2) as u8)?;
                    Ok(0)
                }
                ("ntdll.dll", "RtlFreeHeap") => {
                    Ok(self.heaps.free(arg(args, 0) as u32, arg(args, 2)) as u64)
                }
                ("ntdll.dll", "NtClose") => Ok(if self.close_object_handle(arg(args, 0) as u32) {
                    STATUS_SUCCESS as u64
                } else {
                    STATUS_INVALID_HANDLE as u64
                }),
                ("ntdll.dll", "RtlLookupFunctionEntry") => {
                    self.rtl_lookup_function_entry(arg(args, 0), arg(args, 1))
                }
                ("ntdll.dll", "RtlPcToFileHeader") => {
                    self.rtl_pc_to_file_header(arg(args, 0), arg(args, 1))
                }
                ("ntdll.dll", "RtlRestoreContext") => self.rtl_restore_context(arg(args, 0)),
                ("ntdll.dll", "RtlUnwind") => {
                    self.rtl_unwind(arg(args, 0), arg(args, 1), arg(args, 3))
                }
                ("ntdll.dll", "RtlUnwindEx") => {
                    self.rtl_unwind_ex(arg(args, 0), arg(args, 1), arg(args, 3))
                }
                ("ntdll.dll", "RtlVirtualUnwind") => self.rtl_virtual_unwind(
                    arg(args, 0),
                    arg(args, 1),
                    arg(args, 2),
                    arg(args, 3),
                    arg(args, 4),
                    arg(args, 5),
                    arg(args, 6),
                ),
                ("ntdll.dll", "RtlZeroMemory") => {
                    self.fill_memory_pattern(arg(args, 0), arg(args, 1), 0)?;
                    Ok(0)
                }
                ("ntdll.dll", "NtCreateSection") | ("ntdll.dll", "ZwCreateSection") => self
                    .nt_create_section(
                        arg(args, 0),
                        arg(args, 2),
                        arg(args, 3),
                        arg(args, 4) as u32,
                        arg(args, 5) as u32,
                        arg(args, 6),
                    ),
                ("ntdll.dll", "NtDuplicateObject") => Ok(STATUS_SUCCESS as u64),
                ("ntdll.dll", "NtMapViewOfSection") | ("ntdll.dll", "ZwMapViewOfSection") => self
                    .nt_map_view_of_section(
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 5),
                        arg(args, 6),
                        arg(args, 9) as u32,
                    ),
                ("ntdll.dll", "NtRemoveProcessDebug")
                | ("ntdll.dll", "DbgUiSetThreadDebugObject") => Ok(STATUS_SUCCESS as u64),
                ("ntdll.dll", "NtUnmapViewOfSection") | ("ntdll.dll", "ZwUnmapViewOfSection") => {
                    self.nt_unmap_view_of_section(arg(args, 0), arg(args, 1))
                }
                ("ntdll.dll", "NtWriteVirtualMemory") | ("ntdll.dll", "ZwWriteVirtualMemory") => {
                    self.nt_write_virtual_memory(
                        arg(args, 0),
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                    )
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}

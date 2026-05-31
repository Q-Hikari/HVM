use super::*;

impl VirtualExecutionEngine {
    /// Nt*/Zw* syscalls + Ldr* + Ki* dispatch — first third of match arms.
    pub(in crate::runtime::engine) fn dispatch_ntdll_syscalls(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        // Validation guard: check that the function belongs to this group.
        if !matches!(
            function,
            "KiUserExceptionDispatcher"
                | "KiRaiseUserExceptionDispatcher"
                | "KiUserApcDispatcher"
                | "KiUserCallbackDispatcher"
                | "LdrFindEntryForAddress"
                | "LdrGetProcedureAddress"
                | "LdrLoadDll"
                | "NtOpenProcess"
                | "ZwOpenProcess"
                | "NtAllocateVirtualMemory"
                | "ZwAllocateVirtualMemory"
                | "NtFreeVirtualMemory"
                | "ZwFreeVirtualMemory"
                | "NtProtectVirtualMemory"
                | "ZwProtectVirtualMemory"
                | "NtCreateThreadEx"
                | "ZwCreateThreadEx"
                | "NtGetTickCount"
                | "RtlEncodePointer"
                | "RtlDecodePointer"
                | "RtlEncodeSystemPointer"
                | "RtlDecodeSystemPointer"
                | "RtlGetVersion"
                | "RtlCreateUserThread"
                | "NtQueryInformationProcess"
                | "ZwQueryInformationProcess"
                | "NtQuerySystemInformation"
                | "ZwQuerySystemInformation"
                | "NtQueryVirtualMemory"
                | "ZwQueryVirtualMemory"
                | "NtReadVirtualMemory"
                | "ZwReadVirtualMemory"
                | "ZwSetInformationKey"
                | "NtQueueApcThread"
                | "ZwQueueApcThread"
                | "NtGetContextThread"
                | "ZwGetContextThread"
                | "NtContinue"
                | "ZwContinue"
                | "NtExitProcess"
                | "RtlExitUserProcess"
                | "RtlExitUserThread"
                | "NtSetContextThread"
                | "ZwSetContextThread"
                | "RtlAcquirePebLock"
                | "RtlReleasePebLock"
                | "RtlAddVectoredExceptionHandler"
                | "RtlRemoveVectoredExceptionHandler"
                | "RtlAllocateHeap"
                | "RtlCaptureContext"
                | "RtlCopyMemory"
                | "RtlMoveMemory"
                | "RtlCreateHeap"
                | "RtlCreateUnicodeStringFromAsciiz"
                | "RtlFillMemory"
                | "RtlFreeUnicodeString"
                | "RtlFreeHeap"
                | "RtlReAllocateHeap"
                | "RtlSizeHeap"
                | "NtClose"
                | "RtlInitUnicodeString"
                | "RtlInt64ToUnicodeString"
                | "RtlIntegerToChar"
                | "RtlLookupFunctionEntry"
                | "RtlPcToFileHeader"
                | "RtlRandomEx"
                | "RtlRestoreContext"
                | "RtlUnwind"
                | "RtlUnwindEx"
                | "RtlVirtualUnwind"
                | "RtlZeroMemory"
                | "NtCreateSection"
                | "ZwCreateSection"
                | "NtDuplicateObject"
                | "NtMapViewOfSection"
                | "ZwMapViewOfSection"
                | "NtRemoveProcessDebug"
                | "DbgUiSetThreadDebugObject"
                | "NtTerminateProcess"
                | "ZwTerminateProcess"
                | "NtTerminateThread"
                | "ZwTerminateThread"
                | "NtUnmapViewOfSection"
                | "ZwUnmapViewOfSection"
                | "NtWriteVirtualMemory"
                | "ZwWriteVirtualMemory"
                | "RtlIpv4AddressToStringW"
                | "RtlIpv4AddressToStringA"
                | "LdrEnumerateLoadedModules"
                | "__vm_ldr_enum_continue"
                | "NtCreateEvent"
                | "ZwCreateEvent"
                | "NtOpenEvent"
                | "ZwOpenEvent"
                | "NtSetEvent"
                | "ZwSetEvent"
                | "NtResetEvent"
                | "ZwResetEvent"
                | "NtClearEvent"
                | "ZwClearEvent"
                | "NtPulseEvent"
                | "ZwPulseEvent"
                | "NtCreateMutant"
                | "ZwCreateMutant"
                | "NtOpenMutant"
                | "ZwOpenMutant"
                | "NtReleaseMutant"
                | "ZwReleaseMutant"
                | "NtCreateSemaphore"
                | "ZwCreateSemaphore"
                | "NtReleaseSemaphore"
                | "ZwReleaseSemaphore"
                | "NtCreateTimer"
                | "ZwCreateTimer"
                | "NtSetTimer"
                | "ZwSetTimer"
                | "NtCancelTimer"
                | "ZwCancelTimer"
                | "NtWaitForSingleObject"
                | "ZwWaitForSingleObject"
                | "NtWaitForMultipleObjects"
                | "ZwWaitForMultipleObjects"
                | "NtSignalAndWaitForSingleObject"
                | "ZwSignalAndWaitForSingleObject"
                | "NtDelayExecution"
                | "ZwDelayExecution"
                | "NtSuspendThread"
                | "ZwSuspendThread"
                | "NtResumeThread"
                | "ZwResumeThread"
                | "NtOpenThread"
                | "ZwOpenThread"
                | "NtSetInformationThread"
                | "ZwSetInformationThread"
                | "NtAlertResumeThread"
                | "ZwAlertResumeThread"
                | "NtAlertThread"
                | "ZwAlertThread"
                | "NtTestAlert"
                | "ZwTestAlert"
                | "NtQueryInformationThread"
                | "ZwQueryInformationThread"
                | "NtSetInformationProcess"
                | "ZwSetInformationProcess"
                | "NtOpenProcessToken"
                | "ZwOpenProcessToken"
                | "NtOpenThreadToken"
                | "ZwOpenThreadToken"
                | "NtOpenProcessTokenEx"
                | "ZwOpenProcessTokenEx"
                | "NtOpenThreadTokenEx"
                | "ZwOpenThreadTokenEx"
                | "NtQueryInformationToken"
                | "ZwQueryInformationToken"
                | "NtDuplicateToken"
                | "ZwDuplicateToken"
                | "NtAdjustPrivilegesToken"
                | "ZwAdjustPrivilegesToken"
                | "NtGetNextProcess"
                | "ZwGetNextProcess"
                | "RtlInitializeCriticalSection"
                | "RtlInitializeCriticalSectionAndSpinCount"
                | "RtlDeleteCriticalSection"
                | "RtlEnterCriticalSection"
                | "RtlLeaveCriticalSection"
                | "RtlTryEnterCriticalSection"
                | "RtlSetCriticalSectionSpinCount"
                | "RtlGetCriticalSectionRecursionCount"
                | "RtlIsCriticalSectionLocked"
                | "RtlIsCriticalSectionLockedByThread"
                | "RtlInitAnsiString"
                | "RtlInitString"
                | "RtlAppendUnicodeToString"
                | "RtlAppendUnicodeStringToString"
                | "RtlCompareMemory"
                | "RtlEqualMemory"
                | "RtlCompareUnicodeString"
                | "RtlEqualUnicodeString"
                | "RtlAnsiStringToUnicodeString"
                | "RtlUnicodeStringToAnsiString"
                | "RtlFreeAnsiString"
                | "RtlFreeString"
                | "RtlFreeOemString"
                | "RtlValidateUnicodeString"
                | "RtlHashUnicodeString"
                | "RtlUpperChar"
                | "RtlLowerChar"
                | "RtlAdjustPrivilege"
                | "RtlNtStatusToDosError"
                | "RtlNtStatusToDosErrorNoTeb"
                | "RtlCrc32"
                | "RtlComputeCrc32"
                | "RtlWalkFrameChain"
                | "RtlDoesFileExists_U"
                | "RtlDoesFileExists_UEx"
                | "NtQueryPerformanceCounter"
                | "ZwQueryPerformanceCounter"
                | "RtlDecompressBuffer"
                | "RtlGetCompressionWorkSpaceSize"
                | "RtlCompressBuffer"
                | "NtQueryTimerResolution"
                | "ZwQueryTimerResolution"
                | "NtQueryObject"
                | "ZwQueryObject"
                | "NtAllocateLocallyUniqueId"
                | "ZwAllocateLocallyUniqueId"
                | "NtAllocateUuids"
                | "ZwAllocateUuids"
                | "NtQuerySection"
                | "ZwQuerySection"
                | "NtOpenSection"
                | "ZwOpenSection"
                | "NtExtendSection"
                | "ZwExtendSection"
                | "NtQuerySystemInformationEx"
                | "ZwQuerySystemInformationEx"
                | "NtSetSystemInformation"
                | "ZwSetSystemInformation"
                | "NtTraceEvent"
                | "ZwTraceEvent"
                | "NtTraceControl"
                | "ZwTraceControl"
                | "EtwEventWrite"
                | "NtQueryLicenseValue"
                | "ZwQueryLicenseValue"
                | "LdrGetDllHandle"
                | "LdrGetDllHandleEx"
                | "LdrGetDllHandleByMapping"
                | "LdrGetDllHandleByName"
                | "LdrGetDllPath"
                | "LdrGetDllFullName"
                | "LdrGetProcedureAddressForCaller"
                | "LdrGetProcedureAddressEx"
                | "LdrUnloadDll"
                | "LdrRegisterDllNotification"
                | "LdrUnregisterDllNotification"
                | "LdrLockLoaderLock"
                | "LdrUnlockLoaderLock"
                | "LdrShutdownProcess"
                | "LdrShutdownThread"
                | "LdrInitializeThunk"
                | "DbgUiConnectToDbg"
                | "DbgUiGetThreadDebugObject"
                | "DbgPrint"
                | "DbgPrintEx"
                | "DbgPrintReturnControlC"
                | "DbgPrompt"
                | "DbgQueryDebugFilterState"
                | "DbgSetDebugFilterState"
                | "DbgUiContinue"
                | "DbgUiWaitStateChange"
                | "DbgUiDebugActiveProcess"
                | "DbgUiStopDebugging"
                | "DbgUiIssueRemoteBreakin"
                | "DbgUserBreakPoint"
                | "DbgUiConvertStateChangeStructure"
                | "DbgUiConvertStateChangeStructureEx"
                | "NtDebugActiveProcess"
                | "ZwDebugActiveProcess"
                | "NtDebugContinue"
                | "ZwDebugContinue"
                | "NtWaitForDebugEvent"
                | "ZwWaitForDebugEvent"
                | "NtSetInformationDebugObject"
                | "ZwSetInformationDebugObject"
                | "NtCreateDebugObject"
                | "ZwCreateDebugObject"
                | "NtCreateFile"
                | "ZwCreateFile"
                | "NtOpenFile"
                | "ZwOpenFile"
                | "NtReadFile"
                | "ZwReadFile"
                | "NtWriteFile"
                | "ZwWriteFile"
                | "NtDeleteFile"
                | "ZwDeleteFile"
                | "NtQueryInformationFile"
                | "ZwQueryInformationFile"
                | "NtSetInformationFile"
                | "ZwSetInformationFile"
                | "NtQueryDirectoryFile"
                | "ZwQueryDirectoryFile"
                | "NtQueryDirectoryFileEx"
                | "ZwQueryDirectoryFileEx"
                | "NtQueryAttributesFile"
                | "ZwQueryAttributesFile"
                | "NtQueryFullAttributesFile"
                | "ZwQueryFullAttributesFile"
                | "NtQueryEaFile"
                | "ZwQueryEaFile"
                | "NtSetEaFile"
                | "ZwSetEaFile"
                | "NtDeviceIoControlFile"
                | "ZwDeviceIoControlFile"
                | "NtFsControlFile"
                | "ZwFsControlFile"
                | "NtFlushBuffersFile"
                | "ZwFlushBuffersFile"
                | "NtFlushBuffersFileEx"
                | "ZwFlushBuffersFileEx"
                | "NtNotifyChangeDirectoryFile"
                | "ZwNotifyChangeDirectoryFile"
                | "NtLockFile"
                | "ZwLockFile"
                | "NtUnlockFile"
                | "ZwUnlockFile"
                | "NtQueryVolumeInformationFile"
                | "ZwQueryVolumeInformationFile"
                | "NtSetVolumeInformationFile"
                | "ZwSetVolumeInformationFile"
                | "NtReadFileScatter"
                | "ZwReadFileScatter"
                | "NtWriteFileGather"
                | "ZwWriteFileGather"
                | "NtCancelIoFile"
                | "ZwCancelIoFile"
                | "NtCancelIoFileEx"
                | "ZwCancelIoFileEx"
                | "NtQueryQuotaInformationFile"
                | "ZwQueryQuotaInformationFile"
                | "NtSetQuotaInformationFile"
                | "ZwSetQuotaInformationFile"
                | "NtQueryInformationByName"
                | "ZwQueryInformationByName"
                | "NtCreateNamedPipeFile"
                | "ZwCreateNamedPipeFile"
                | "NtCreateMailslotFile"
                | "ZwCreateMailslotFile"
                | "NtCreateKey"
                | "ZwCreateKey"
                | "NtOpenKey"
                | "ZwOpenKey"
                | "NtOpenKeyEx"
                | "ZwOpenKeyEx"
                | "NtDeleteKey"
                | "ZwDeleteKey"
                | "NtDeleteValueKey"
                | "ZwDeleteValueKey"
                | "NtEnumerateKey"
                | "ZwEnumerateKey"
                | "NtEnumerateValueKey"
                | "ZwEnumerateValueKey"
                | "NtQueryKey"
                | "ZwQueryKey"
                | "NtQueryValueKey"
                | "ZwQueryValueKey"
                | "NtSetValueKey"
                | "ZwSetValueKey"
                | "NtQueryMultipleValueKey"
                | "ZwQueryMultipleValueKey"
                | "NtNotifyChangeKey"
                | "ZwNotifyChangeKey"
                | "NtNotifyChangeMultipleKeys"
                | "ZwNotifyChangeMultipleKeys"
                | "NtFlushKey"
                | "ZwFlushKey"
                | "NtCompactKeys"
                | "ZwCompactKeys"
                | "NtCompressKey"
                | "ZwCompressKey"
                | "NtLoadKey"
                | "ZwLoadKey"
                | "NtLoadKey2"
                | "ZwLoadKey2"
                | "NtLoadKey3"
                | "ZwLoadKey3"
                | "NtLoadKeyEx"
                | "ZwLoadKeyEx"
                | "NtUnloadKey"
                | "ZwUnloadKey"
                | "NtUnloadKey2"
                | "ZwUnloadKey2"
                | "NtUnloadKeyEx"
                | "ZwUnloadKeyEx"
                | "NtSaveKey"
                | "ZwSaveKey"
                | "NtSaveKeyEx"
                | "ZwSaveKeyEx"
                | "NtSaveMergedKeys"
                | "ZwSaveMergedKeys"
                | "NtRestoreKey"
                | "ZwRestoreKey"
                | "NtRenameKey"
                | "ZwRenameKey"
                | "NtReplaceKey"
                | "ZwReplaceKey"
                | "NtQueryOpenSubKeys"
                | "ZwQueryOpenSubKeys"
                | "NtQueryOpenSubKeysEx"
                | "ZwQueryOpenSubKeysEx"
                | "NtCreateKeyTransacted"
                | "ZwCreateKeyTransacted"
                | "NtOpenKeyTransacted"
                | "ZwOpenKeyTransacted"
                | "NtOpenKeyTransactedEx"
                | "ZwOpenKeyTransactedEx"
                | "NtLockRegistryKey"
                | "ZwLockRegistryKey"
                | "NtCreateProcess"
                | "ZwCreateProcess"
                | "NtCreateProcessEx"
                | "ZwCreateProcessEx"
                | "NtCreateUserProcess"
                | "ZwCreateUserProcess"
                | "NtCreateThread"
                | "ZwCreateThread"
                | "NtIsProcessInJob"
                | "ZwIsProcessInJob"
                | "NtGetNextThread"
                | "ZwGetNextThread"
                | "NtImpersonateThread"
                | "ZwImpersonateThread"
                | "NtImpersonateAnonymousToken"
                | "ZwImpersonateAnonymousToken"
                | "NtAllocateVirtualMemoryEx"
                | "ZwAllocateVirtualMemoryEx"
                | "NtFlushVirtualMemory"
                | "ZwFlushVirtualMemory"
                | "NtLockVirtualMemory"
                | "ZwLockVirtualMemory"
                | "NtUnlockVirtualMemory"
                | "ZwUnlockVirtualMemory"
                | "NtGetWriteWatch"
                | "ZwGetWriteWatch"
                | "NtResetWriteWatch"
                | "ZwResetWriteWatch"
                | "NtCreatePagingFile"
                | "ZwCreatePagingFile"
                | "NtMapViewOfSectionEx"
                | "ZwMapViewOfSectionEx"
                | "NtUnmapViewOfSectionEx"
                | "ZwUnmapViewOfSectionEx"
                | "NtAreMappedFilesTheSame"
                | "ZwAreMappedFilesTheSame"
                | "NtOpenKeyedEvent"
                | "ZwOpenKeyedEvent"
                | "NtReleaseKeyedEvent"
                | "ZwReleaseKeyedEvent"
                | "NtWaitForKeyedEvent"
                | "ZwWaitForKeyedEvent"
                | "NtCreateIoCompletion"
                | "ZwCreateIoCompletion"
                | "NtOpenIoCompletion"
                | "ZwOpenIoCompletion"
                | "NtSetIoCompletion"
                | "ZwSetIoCompletion"
                | "NtRemoveIoCompletion"
                | "ZwRemoveIoCompletion"
                | "NtOpenEventPair"
                | "ZwOpenEventPair"
                | "NtCreateEventPair"
                | "ZwCreateEventPair"
                | "NtOpenSemaphore"
                | "ZwOpenSemaphore"
                | "NtOpenTimer"
                | "ZwOpenTimer"
                | "NtQueryTimer"
                | "ZwQueryTimer"
                | "NtSetTimerEx"
                | "ZwSetTimerEx"
                | "NtQueryMutant"
                | "ZwQueryMutant"
                | "NtQuerySemaphore"
                | "ZwQuerySemaphore"
                | "NtQueryEvent"
                | "ZwQueryEvent"
                | "NtOpenJobObject"
                | "ZwOpenJobObject"
                | "NtCreateJobObject"
                | "ZwCreateJobObject"
                | "NtAssignProcessToJobObject"
                | "ZwAssignProcessToJobObject"
                | "NtTerminateJobObject"
                | "ZwTerminateJobObject"
                | "NtQueryInformationJobObject"
                | "ZwQueryInformationJobObject"
                | "NtSetInformationJobObject"
                | "ZwSetInformationJobObject"
                | "NtOpenSymbolicLinkObject"
                | "ZwOpenSymbolicLinkObject"
                | "NtCreateSymbolicLinkObject"
                | "ZwCreateSymbolicLinkObject"
                | "NtQuerySymbolicLinkObject"
                | "ZwQuerySymbolicLinkObject"
                | "NtOpenDirectoryObject"
                | "ZwOpenDirectoryObject"
                | "NtCreateDirectoryObject"
                | "ZwCreateDirectoryObject"
                | "NtCreateDirectoryObjectEx"
                | "ZwCreateDirectoryObjectEx"
                | "NtQueryDirectoryObject"
                | "ZwQueryDirectoryObject"
                | "NtMakeTemporaryObject"
                | "ZwMakeTemporaryObject"
                | "NtMakePermanentObject"
                | "ZwMakePermanentObject"
                | "RtlCreateUnicodeString"
                | "RtlDuplicateUnicodeString"
        ) {
            return None;
        }
        Some((|| -> Result<u64, VmError> {
            match function {
                "KiUserExceptionDispatcher" => Ok(0),
                "LdrFindEntryForAddress" => self.ldr_find_entry_for_address(ctx.raw(0), ctx.raw(1)),
                "LdrGetProcedureAddress" => self.ldr_get_procedure_address(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as u16,
                    ctx.raw(3),
                ),
                "LdrLoadDll" => self.ldr_load_dll(ctx.raw(0), ctx.raw(1), ctx.raw(2), ctx.raw(3)),
                "NtOpenProcess" | "ZwOpenProcess" => self.nt_open_process(ctx.raw(0), ctx.raw(3)),
                "NtAllocateVirtualMemory" | "ZwAllocateVirtualMemory" => self
                    .nt_allocate_virtual_memory(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(3),
                        ctx.raw(4) as u32,
                        ctx.raw(5) as u32,
                        "NtAllocateVirtualMemory",
                    ),
                "NtFreeVirtualMemory" | "ZwFreeVirtualMemory" => self.nt_free_virtual_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    "NtFreeVirtualMemory",
                ),
                "NtProtectVirtualMemory" | "ZwProtectVirtualMemory" => self
                    .nt_protect_virtual_memory(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2),
                        ctx.raw(3) as u32,
                        ctx.raw(4),
                        "NtProtectVirtualMemory",
                    ),
                "NtCreateThreadEx" | "ZwCreateThreadEx" => {
                    let process_handle = ctx.raw(3);
                    let handle = if self.is_current_process_handle(process_handle)
                        || self.is_synthetic_process_handle(process_handle)
                    {
                        // Synthetic processes share the current process
                        // space — create a runtime thread directly.
                        self.create_runtime_thread(
                            ctx.raw(4),
                            ctx.raw(5),
                            if ctx.raw(6) & 0x1 != 0 { 0x4 } else { 0 },
                            0,
                        )?
                    } else {
                        if !self.is_known_process_target(process_handle) {
                            return Ok(STATUS_INVALID_HANDLE as u64);
                        }
                        let Some(handle) = self.create_remote_shellcode_thread(
                            process_handle,
                            ctx.raw(4),
                            ctx.raw(5),
                            ctx.raw(6) & 0x1 != 0,
                            0,
                            "NtCreateThreadEx",
                        )?
                        else {
                            return Ok(STATUS_INVALID_PARAMETER as u64);
                        };
                        handle
                    };
                    if ctx.raw(0) != 0 {
                        self.write_pointer_value(ctx.raw(0), handle)?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtGetTickCount" => Ok(self.dispatch.time.current().tick_ms),
                "RtlEncodePointer"
                | "RtlDecodePointer"
                | "RtlEncodeSystemPointer"
                | "RtlDecodeSystemPointer" => Ok(ctx.raw(0)),
                "RtlGetVersion" => Ok(if self.write_version_info(ctx.raw(0), true)? {
                    STATUS_SUCCESS as u64
                } else {
                    STATUS_INVALID_PARAMETER as u64
                }),
                "RtlCreateUserThread" => {
                    let process_handle = ctx.raw(0);
                    let suspended = ctx.raw(2) != 0;
                    let handle = if self.is_current_process_handle(process_handle) {
                        self.create_runtime_thread(
                            ctx.raw(6),
                            ctx.raw(7),
                            if suspended { 0x4 } else { 0 },
                            0,
                        )?
                    } else {
                        if !self.is_known_process_target(process_handle) {
                            return Ok(STATUS_INVALID_HANDLE as u64);
                        }
                        let Some(handle) = self.create_remote_shellcode_thread(
                            process_handle,
                            ctx.raw(6),
                            ctx.raw(7),
                            suspended,
                            0,
                            "RtlCreateUserThread",
                        )?
                        else {
                            return Ok(STATUS_INVALID_PARAMETER as u64);
                        };
                        handle
                    };
                    if ctx.raw(8) != 0 {
                        self.write_pointer_value(ctx.raw(8), handle)?;
                    }
                    if ctx.raw(9) != 0 {
                        let process_id = self
                            .process_identity_for_handle(process_handle)
                            .map(|process| process.pid as u64)
                            .unwrap_or(self.current_process_id() as u64);
                        let thread_id = self
                            .core
                            .scheduler
                            .thread_tid_for_handle(handle as u32)
                            .unwrap_or(0) as u64;
                        self.write_pointer_value(ctx.raw(9), process_id)?;
                        self.write_pointer_value(
                            ctx.raw(9) + self.core.arch.pointer_size as u64,
                            thread_id,
                        )?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtQueryInformationProcess" | "ZwQueryInformationProcess" => self
                    .nt_query_information_process(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2),
                        ctx.raw(3) as usize,
                        ctx.raw(4),
                    ),
                "NtQuerySystemInformation" | "ZwQuerySystemInformation" => self
                    .nt_query_system_information(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2) as usize,
                        ctx.raw(3),
                    ),
                "NtQueryVirtualMemory" | "ZwQueryVirtualMemory" => self.nt_query_virtual_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as usize,
                    ctx.raw(5),
                ),
                "NtReadVirtualMemory" | "ZwReadVirtualMemory" => self.nt_read_virtual_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    ctx.raw(4),
                ),
                "ZwSetInformationKey" => Ok(STATUS_SUCCESS as u64),
                "NtQueueApcThread" | "ZwQueueApcThread" => {
                    let status = if self
                        .core
                        .scheduler
                        .queue_user_apc(ctx.raw(0) as u32, ctx.raw(1), ctx.raw(2))
                        .is_some()
                    {
                        STATUS_SUCCESS
                    } else {
                        STATUS_INVALID_HANDLE
                    };
                    Ok(status as u64)
                }
                "NtGetContextThread" | "ZwGetContextThread" => {
                    if ctx.raw(1) == 0 {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    } else if self.write_thread_context(ctx.raw(0) as u32, ctx.raw(1))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_HANDLE as u64)
                    }
                }
                "NtContinue" | "ZwContinue" => {
                    if self.queue_current_context_restore(ctx.raw(0))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    }
                }
                "NtExitProcess" | "RtlExitUserProcess" => {
                    Ok(self.request_ntdll_process_exit(ctx.raw(0)))
                }
                "RtlExitUserThread" => Ok(self.request_ntdll_thread_exit(ctx.raw(0))),
                "NtSetContextThread" | "ZwSetContextThread" => {
                    if ctx.raw(1) == 0 {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    } else if self.read_thread_context(ctx.raw(0) as u32, ctx.raw(1))? {
                        Ok(STATUS_SUCCESS as u64)
                    } else {
                        Ok(STATUS_INVALID_HANDLE as u64)
                    }
                }
                "RtlAcquirePebLock" | "RtlReleasePebLock" => {
                    Ok(self.active_unicorn_return_value().unwrap_or(0))
                }
                "RtlAddVectoredExceptionHandler" => {
                    Ok(self.register_vectored_exception_handler(ctx.raw(0) != 0, ctx.raw(1)))
                }
                "RtlRemoveVectoredExceptionHandler" => {
                    Ok(self.remove_vectored_exception_handler(ctx.raw(0) as u32) as u64)
                }
                "RtlAllocateHeap" => {
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!(
                            "[RTLALLOC_DIAG] hook_enter heap=0x{:X} flags=0x{:X} size=0x{:X}",
                            ctx.raw(0),
                            ctx.raw(1),
                            ctx.raw(2)
                        );
                    }
                    let address = self
                        .process_memory
                        .heaps
                        .alloc(
                            self.core.modules.memory_mut(),
                            ctx.raw(0) as u32,
                            ctx.raw(2).max(1),
                        )
                        .unwrap_or(0);
                    if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
                        eprintln!("[RTLALLOC_DIAG] hook_alloc_done address=0x{:X}", address);
                    }
                    Ok(address)
                }
                "RtlCaptureContext" => self.rtl_capture_context(ctx.raw(0)),
                "RtlCopyMemory" | "RtlMoveMemory" => {
                    self.copy_memory_block(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize)?;
                    Ok(0)
                }
                "RtlCreateHeap" => {
                    let heap = self
                        .process_memory
                        .heaps
                        .create_heap(self.core.modules.memory_mut())?;
                    Ok(heap as u64)
                }
                "RtlCreateUnicodeStringFromAsciiz" => {
                    self.rtl_create_unicode_string_from_asciiz(ctx.raw(0), ctx.raw(1))
                }
                "RtlFillMemory" => {
                    self.fill_memory_pattern(ctx.raw(0), ctx.raw(1), ctx.raw(2) as u8)?;
                    Ok(0)
                }
                "RtlFreeUnicodeString" => self.rtl_free_unicode_string(ctx.raw(0)),
                "RtlFreeHeap" => Ok(self
                    .process_memory
                    .heaps
                    .free(ctx.raw(0) as u32, ctx.raw(2))
                    as u64),
                "RtlReAllocateHeap" => {
                    let heap = ctx.raw(0) as u32;
                    let old_address = ctx.raw(2);
                    let new_size = ctx.raw(3).max(1);
                    let old_size = self.process_memory.heaps.size(heap, old_address);
                    if old_size == u32::MAX as u64 {
                        return Ok(0);
                    }
                    let Some(new_address) = self.process_memory.heaps.alloc(
                        self.core.modules.memory_mut(),
                        heap,
                        new_size,
                    ) else {
                        return Ok(0);
                    };
                    let copy_size = old_size.min(new_size) as usize;
                    let bytes = self.core.modules.memory().read(old_address, copy_size)?;
                    self.core.modules.memory_mut().write(new_address, &bytes)?;
                    if ctx.raw(1) & HEAP_ZERO_MEMORY != 0 && new_size > old_size {
                        self.fill_memory_pattern(
                            new_address + old_size,
                            new_size.saturating_sub(old_size),
                            0,
                        )?;
                    }
                    self.process_memory.heaps.free(heap, old_address);
                    self.log_heap_event("HEAP_REALLOC", heap, new_address, new_size, function)?;
                    Ok(new_address)
                }
                "RtlSizeHeap" => Ok(self
                    .process_memory
                    .heaps
                    .size(ctx.raw(0) as u32, ctx.raw(2))),
                "NtClose" => Ok(if self.close_object_handle(ctx.raw(0) as u32) {
                    STATUS_SUCCESS as u64
                } else {
                    STATUS_INVALID_HANDLE as u64
                }),
                "RtlInitUnicodeString" => self.rtl_init_unicode_string(ctx.raw(0), ctx.raw(1)),
                "RtlInt64ToUnicodeString" => {
                    self.rtl_int64_to_unicode_string(ctx.raw(0), ctx.raw(1) as u32, ctx.raw(2))
                }
                "RtlIntegerToChar" => self.rtl_integer_to_char(
                    ctx.raw(0) as u32,
                    ctx.raw(1) as u32,
                    ctx.raw(2) as i32,
                    ctx.raw(3),
                ),
                "RtlLookupFunctionEntry" => self.rtl_lookup_function_entry(ctx.raw(0), ctx.raw(1)),
                "RtlPcToFileHeader" => self.rtl_pc_to_file_header(ctx.raw(0), ctx.raw(1)),
                "RtlRandomEx" => self.rtl_random_ex(ctx.raw(0)),
                "RtlRestoreContext" => self.rtl_restore_context(ctx.raw(0)),
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
                "RtlZeroMemory" => {
                    self.fill_memory_pattern(ctx.raw(0), ctx.raw(1), 0)?;
                    Ok(0)
                }
                "NtCreateSection" | "ZwCreateSection" => self.nt_create_section(
                    ctx.raw(0),
                    ctx.raw(2),
                    ctx.raw(3),
                    ctx.raw(4) as u32,
                    ctx.raw(5) as u32,
                    ctx.raw(6),
                ),
                "NtDuplicateObject" => Ok(STATUS_SUCCESS as u64),
                "NtMapViewOfSection" | "ZwMapViewOfSection" => self.nt_map_view_of_section(
                    ctx.raw(0) as u32,
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(5),
                    ctx.raw(6),
                    ctx.raw(9) as u32,
                ),
                "NtRemoveProcessDebug" | "DbgUiSetThreadDebugObject" => Ok(STATUS_SUCCESS as u64),
                "NtTerminateProcess" | "ZwTerminateProcess" => {
                    self.nt_terminate_process(ctx.raw(0), ctx.raw(1))
                }
                "NtTerminateThread" | "ZwTerminateThread" => {
                    self.nt_terminate_thread(ctx.raw(0), ctx.raw(1))
                }
                "NtUnmapViewOfSection" | "ZwUnmapViewOfSection" => {
                    self.nt_unmap_view_of_section(ctx.raw(0), ctx.raw(1))
                }
                "NtWriteVirtualMemory" | "ZwWriteVirtualMemory" => self.nt_write_virtual_memory(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2),
                    ctx.raw(3) as usize,
                    ctx.raw(4),
                ),
                "RtlIpv4AddressToStringW" | "RtlIpv4AddressToStringA" => {
                    // Args: (const IN_ADDR *addr, wchar_t/char *buf)
                    // IN_ADDR is a 4-byte struct (the IPv4 address in network byte order)
                    let addr_ptr = ctx.raw(0);
                    let buf_ptr = ctx.raw(1);
                    if let Ok(addr_bytes) = self.core.modules.memory().read(addr_ptr, 4) {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]
                        );
                        if function.ends_with('W') {
                            let wide: Vec<u8> = ip
                                .encode_utf16()
                                .flat_map(|c| c.to_le_bytes())
                                .chain(std::iter::once(0u8).chain(std::iter::once(0u8)))
                                .collect();
                            let _ = self.core.modules.memory_mut().write(buf_ptr, &wide);
                        } else {
                            let mut ascii = ip.into_bytes();
                            ascii.push(0);
                            let _ = self.core.modules.memory_mut().write(buf_ptr, &ascii);
                        }
                    }
                    // Returns pointer to the null terminator
                    Ok(buf_ptr)
                }
                "LdrEnumerateLoadedModules" => {
                    self.ldr_enumerate_loaded_modules(ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                "__vm_ldr_enum_continue" => self.resume_pending_ldr_enum_callback(),

                // ── Synchronization: events ──────────────────────────────
                "NtCreateEvent" | "ZwCreateEvent" => {
                    let manual_reset = ctx.raw(3) != 0;
                    let initial_state = ctx.raw(4) != 0;
                    if let Some(event) = self
                        .core
                        .scheduler
                        .create_event(manual_reset, initial_state)
                    {
                        if ctx.raw(0) != 0 {
                            self.write_pointer_value(ctx.raw(0), event.handle as u64)?;
                        }
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtOpenEvent" | "ZwOpenEvent" => Ok(STATUS_SUCCESS as u64),
                "NtSetEvent" | "ZwSetEvent" => {
                    let _ = self.core.scheduler.set_event(ctx.raw(0) as u32);
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtResetEvent" | "ZwResetEvent" | "NtClearEvent" | "ZwClearEvent" => {
                    let _ = self.core.scheduler.reset_event(ctx.raw(0) as u32);
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtPulseEvent" | "ZwPulseEvent" => {
                    let _ = self.core.scheduler.set_event(ctx.raw(0) as u32);
                    let _ = self.core.scheduler.reset_event(ctx.raw(0) as u32);
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Synchronization: mutexes ─────────────────────────────
                "NtCreateMutant" | "ZwCreateMutant" => {
                    let initial_owner = ctx.raw(2) != 0;
                    let handle = self.create_mutex_handle("", initial_owner);
                    if ctx.raw(0) != 0 {
                        self.write_pointer_value(ctx.raw(0), handle)?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtOpenMutant" | "ZwOpenMutant" => Ok(STATUS_SUCCESS as u64),
                "NtReleaseMutant" | "ZwReleaseMutant" => {
                    Ok(if self.release_mutex_handle(ctx.raw(0) as u32) {
                        STATUS_SUCCESS as u64
                    } else {
                        STATUS_INVALID_HANDLE as u64
                    })
                }

                // ── Synchronization: semaphores ──────────────────────────
                "NtCreateSemaphore" | "ZwCreateSemaphore" => {
                    let initial_count = ctx.raw(2) as u32;
                    let maximum_count = ctx.raw(3) as u32;
                    let handle = self.create_semaphore_handle("", initial_count, maximum_count);
                    if handle == 0 {
                        Ok(STATUS_INVALID_PARAMETER as u64)
                    } else {
                        if ctx.raw(0) != 0 {
                            self.write_pointer_value(ctx.raw(0), handle)?;
                        }
                        Ok(STATUS_SUCCESS as u64)
                    }
                }
                "NtReleaseSemaphore" | "ZwReleaseSemaphore" => {
                    let release_count = ctx.raw(1) as u32;
                    match self.release_semaphore_handle(
                        ctx.raw(0) as u32,
                        release_count,
                        ctx.raw(2),
                    ) {
                        Ok(true) => Ok(STATUS_SUCCESS as u64),
                        Ok(false) => Ok(STATUS_INVALID_HANDLE as u64),
                        Err(_) => Ok(STATUS_INVALID_HANDLE as u64),
                    }
                }

                // ── Synchronization: timers ──────────────────────────────
                "NtCreateTimer" | "ZwCreateTimer" => {
                    let obj = self
                        .core
                        .scheduler
                        .register_external_object(0, "timer", false, true);
                    if ctx.raw(0) != 0 {
                        self.write_pointer_value(ctx.raw(0), obj.handle as u64)?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtSetTimer" | "ZwSetTimer" | "NtCancelTimer" | "ZwCancelTimer" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Synchronization: waits ───────────────────────────────
                "NtWaitForSingleObject" | "ZwWaitForSingleObject" => {
                    self.wait_for_objects(&[ctx.raw(0) as u32], false, 0, ctx.raw(1) != 0)
                }
                "NtWaitForMultipleObjects" | "ZwWaitForMultipleObjects" => {
                    let count = ctx.raw(1) as usize;
                    let wait_all = ctx.raw(2) != 0;
                    let handles = self.read_wait_handles(count, ctx.raw(1))?;
                    self.wait_for_objects(&handles, wait_all, 0, ctx.raw(5) != 0)
                }
                "NtSignalAndWaitForSingleObject" | "ZwSignalAndWaitForSingleObject" => self
                    .signal_object_and_wait(
                        ctx.raw(0) as u32,
                        ctx.raw(1) as u32,
                        0,
                        ctx.raw(2) != 0,
                    ),
                "NtDelayExecution" | "ZwDelayExecution" => Ok(STATUS_SUCCESS as u64),

                // ── Thread control ───────────────────────────────────────
                "NtSuspendThread"
                | "ZwSuspendThread"
                | "NtResumeThread"
                | "ZwResumeThread"
                | "NtOpenThread"
                | "ZwOpenThread"
                | "NtSetInformationThread"
                | "ZwSetInformationThread"
                | "NtAlertResumeThread"
                | "ZwAlertResumeThread"
                | "NtAlertThread"
                | "ZwAlertThread"
                | "NtTestAlert"
                | "ZwTestAlert" => Ok(STATUS_SUCCESS as u64),
                "NtQueryInformationThread" | "ZwQueryInformationThread" => {
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Process control ──────────────────────────────────────
                "NtSetInformationProcess"
                | "ZwSetInformationProcess"
                | "NtDuplicateToken"
                | "ZwDuplicateToken"
                | "NtAdjustPrivilegesToken"
                | "ZwAdjustPrivilegesToken"
                | "NtGetNextProcess"
                | "ZwGetNextProcess" => Ok(STATUS_SUCCESS as u64),
                "NtOpenProcessToken"
                | "ZwOpenProcessToken"
                | "NtOpenThreadToken"
                | "ZwOpenThreadToken"
                | "NtOpenProcessTokenEx"
                | "ZwOpenProcessTokenEx"
                | "NtOpenThreadTokenEx"
                | "ZwOpenThreadTokenEx" => {
                    let token_ptr = match function {
                        "NtOpenProcessToken" | "ZwOpenProcessToken" => ctx.raw(2),
                        "NtOpenThreadToken" | "ZwOpenThreadToken" => ctx.raw(3),
                        "NtOpenProcessTokenEx" | "ZwOpenProcessTokenEx" => ctx.raw(3),
                        _ => ctx.raw(4),
                    };
                    if token_ptr == 0 {
                        return Ok(STATUS_INVALID_PARAMETER as u64);
                    }
                    let handle = self.allocate_object_handle();
                    self.handles.token_handles.insert(handle);
                    self.write_pointer_value(token_ptr, handle as u64)?;
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtQueryInformationToken" | "ZwQueryInformationToken" => {
                    let handle = ctx.raw(0) as u32;
                    if !self.handles.token_handles.contains(&handle) {
                        return Ok(STATUS_INVALID_HANDLE as u64);
                    }

                    let info_class = ctx.raw(1) as u32;
                    let buffer = ctx.raw(2);
                    let buffer_size = ctx.raw(3) as usize;
                    let return_length_ptr = ctx.raw(4);
                    let payload = if info_class == 25 {
                        self.token_integrity_information_bytes(buffer)
                    } else {
                        vec![0u8; buffer_size.max(4)]
                    };
                    let needed = payload.len() as u32;

                    if return_length_ptr != 0 {
                        self.write_u32(return_length_ptr, needed)?;
                    }
                    if buffer == 0 || buffer_size < needed as usize {
                        return Ok(STATUS_BUFFER_TOO_SMALL as u64);
                    }

                    self.core.modules.memory_mut().write(buffer, &payload)?;
                    Ok(STATUS_SUCCESS as u64)
                }

                // ── Critical sections ────────────────────────────────────
                "RtlInitializeCriticalSection" | "RtlInitializeCriticalSectionAndSpinCount" => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let size = if self.core.arch.is_x86() { 24u64 } else { 40 };
                    self.fill_memory_pattern(ctx.raw(0), size, 0)?;
                    Ok(0)
                }
                "RtlDeleteCriticalSection" => Ok(0),
                "RtlEnterCriticalSection" => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let offset = if self.core.arch.is_x86() { 4u64 } else { 8 };
                    let count = self.read_u32(ctx.raw(0) + offset)?;
                    self.write_u32(ctx.raw(0) + offset, count.wrapping_add(1))?;
                    Ok(0)
                }
                "RtlLeaveCriticalSection" => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let offset = if self.core.arch.is_x86() { 4u64 } else { 8 };
                    let count = self.read_u32(ctx.raw(0) + offset)?;
                    self.write_u32(ctx.raw(0) + offset, count.wrapping_sub(1))?;
                    Ok(0)
                }
                "RtlTryEnterCriticalSection" => Ok(1),
                "RtlSetCriticalSectionSpinCount" => Ok(0),
                "RtlGetCriticalSectionRecursionCount" => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let offset = if self.core.arch.is_x86() { 4u64 } else { 8 };
                    Ok(self.read_u32(ctx.raw(0) + offset).unwrap_or(0) as u64)
                }
                "RtlIsCriticalSectionLocked" | "RtlIsCriticalSectionLockedByThread" => {
                    if ctx.raw(0) == 0 {
                        return Ok(0);
                    }
                    let offset = if self.core.arch.is_x86() { 4u64 } else { 8 };
                    Ok(if self.read_u32(ctx.raw(0) + offset).unwrap_or(0) > 0 {
                        1u64
                    } else {
                        0
                    })
                }

                // ── String operations ────────────────────────────────────
                "RtlInitAnsiString" | "RtlInitString" => {
                    self.rtl_init_ansi_string(ctx.raw(0), ctx.raw(1))
                }
                "RtlAppendUnicodeToString" => {
                    self.rtl_append_unicode_to_string(ctx.raw(0), ctx.raw(1))
                }
                "RtlAppendUnicodeStringToString" => {
                    self.rtl_append_unicode_string_to_string(ctx.raw(0), ctx.raw(1))
                }
                "RtlCompareMemory" => Ok(self.rtl_compare_memory_impl(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as usize,
                )? as u64),
                "RtlEqualMemory" => {
                    let result =
                        self.rtl_compare_memory_impl(ctx.raw(0), ctx.raw(1), ctx.raw(2) as usize)?;
                    Ok(if result as u64 == ctx.raw(2) { 1u64 } else { 0 })
                }
                "RtlCompareUnicodeString" => {
                    self.rtl_compare_unicode_string_impl(ctx.raw(0), ctx.raw(1), ctx.raw(2) != 0)
                }
                "RtlEqualUnicodeString" => {
                    self.rtl_equal_unicode_string_impl(ctx.raw(0), ctx.raw(1), ctx.raw(2) != 0)
                }
                "RtlAnsiStringToUnicodeString" => {
                    self.rtl_ansi_string_to_unicode_string(ctx.raw(0), ctx.raw(1), ctx.raw(2) != 0)
                }
                "RtlUnicodeStringToAnsiString" => {
                    self.rtl_unicode_string_to_ansi_string(ctx.raw(0), ctx.raw(1), ctx.raw(2) != 0)
                }
                "RtlFreeAnsiString" | "RtlFreeString" | "RtlFreeOemString" => {
                    self.rtl_free_ansi_string_impl(ctx.raw(0))
                }
                "RtlValidateUnicodeString" | "RtlHashUnicodeString" => Ok(STATUS_SUCCESS as u64),

                // ── Character helpers ────────────────────────────────────
                "RtlUpperChar" => {
                    let ch = ctx.raw(0) as u8;
                    Ok(ch.to_ascii_uppercase() as u64)
                }
                "RtlLowerChar" => {
                    let ch = ctx.raw(0) as u8;
                    Ok(ch.to_ascii_lowercase() as u64)
                }

                // ── Misc high-frequency stubs ────────────────────────────
                "RtlAdjustPrivilege" => Ok(STATUS_SUCCESS as u64),
                "RtlNtStatusToDosError"
                | "RtlNtStatusToDosErrorNoTeb"
                | "RtlCrc32"
                | "RtlComputeCrc32"
                | "RtlWalkFrameChain"
                | "RtlDoesFileExists_U"
                | "RtlDoesFileExists_UEx" => Ok(0),
                "NtQueryPerformanceCounter" | "ZwQueryPerformanceCounter" => {
                    if ctx.raw(0) != 0 {
                        self.write_pointer_value(
                            ctx.raw(0),
                            self.dispatch.time.current().tick_ms * 10000,
                        )?;
                    }
                    if ctx.raw(1) != 0 {
                        self.write_pointer_value(ctx.raw(1), 10000000)?;
                    }
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlDecompressBuffer" | "RtlGetCompressionWorkSpaceSize" | "RtlCompressBuffer" => {
                    Ok(STATUS_SUCCESS as u64)
                }
                "NtQueryTimerResolution"
                | "ZwQueryTimerResolution"
                | "NtQueryObject"
                | "ZwQueryObject"
                | "NtAllocateLocallyUniqueId"
                | "ZwAllocateLocallyUniqueId"
                | "NtAllocateUuids"
                | "ZwAllocateUuids"
                | "NtQuerySection"
                | "ZwQuerySection"
                | "NtOpenSection"
                | "ZwOpenSection"
                | "NtExtendSection"
                | "ZwExtendSection"
                | "NtQuerySystemInformationEx"
                | "ZwQuerySystemInformationEx"
                | "NtSetSystemInformation"
                | "ZwSetSystemInformation"
                | "NtTraceEvent"
                | "ZwTraceEvent"
                | "NtTraceControl"
                | "ZwTraceControl"
                | "EtwEventWrite"
                | "NtQueryLicenseValue"
                | "ZwQueryLicenseValue" => Ok(STATUS_SUCCESS as u64),

                // ── Loader / module helpers ───────────────────────────────
                "LdrGetDllHandle"
                | "LdrGetDllHandleEx"
                | "LdrGetDllHandleByMapping"
                | "LdrGetDllHandleByName"
                | "LdrGetDllPath"
                | "LdrGetDllFullName" => Ok(STATUS_SUCCESS as u64),
                "LdrGetProcedureAddressForCaller" | "LdrGetProcedureAddressEx" => self
                    .ldr_get_procedure_address(
                        ctx.raw(0),
                        ctx.raw(1),
                        ctx.raw(2) as u16,
                        ctx.raw(3),
                    ),
                "LdrUnloadDll" => Ok(STATUS_SUCCESS as u64),
                "LdrRegisterDllNotification"
                | "LdrUnregisterDllNotification"
                | "LdrLockLoaderLock"
                | "LdrUnlockLoaderLock"
                | "LdrShutdownProcess"
                | "LdrShutdownThread"
                | "LdrInitializeThunk" => Ok(STATUS_SUCCESS as u64),

                // ── Debug support ────────────────────────────────────────
                "DbgUiConnectToDbg"
                | "DbgUiGetThreadDebugObject"
                | "DbgPrint"
                | "DbgPrintEx"
                | "DbgPrintReturnControlC"
                | "DbgPrompt"
                | "DbgQueryDebugFilterState"
                | "DbgSetDebugFilterState"
                | "DbgUiContinue"
                | "DbgUiWaitStateChange"
                | "DbgUiDebugActiveProcess"
                | "DbgUiStopDebugging"
                | "DbgUiIssueRemoteBreakin"
                | "DbgUserBreakPoint"
                | "DbgUiConvertStateChangeStructure"
                | "DbgUiConvertStateChangeStructureEx"
                | "NtDebugActiveProcess"
                | "ZwDebugActiveProcess"
                | "NtDebugContinue"
                | "ZwDebugContinue"
                | "NtWaitForDebugEvent"
                | "ZwWaitForDebugEvent"
                | "NtSetInformationDebugObject"
                | "ZwSetInformationDebugObject"
                | "NtCreateDebugObject"
                | "ZwCreateDebugObject" => Ok(STATUS_SUCCESS as u64),

                // ── File I/O stubs ───────────────────────────────────────
                "NtCreateFile"
                | "ZwCreateFile"
                | "NtOpenFile"
                | "ZwOpenFile"
                | "NtReadFile"
                | "ZwReadFile"
                | "NtWriteFile"
                | "ZwWriteFile"
                | "NtDeleteFile"
                | "ZwDeleteFile"
                | "NtQueryInformationFile"
                | "ZwQueryInformationFile"
                | "NtSetInformationFile"
                | "ZwSetInformationFile"
                | "NtQueryDirectoryFile"
                | "ZwQueryDirectoryFile"
                | "NtQueryDirectoryFileEx"
                | "ZwQueryDirectoryFileEx"
                | "NtQueryAttributesFile"
                | "ZwQueryAttributesFile"
                | "NtQueryFullAttributesFile"
                | "ZwQueryFullAttributesFile"
                | "NtQueryEaFile"
                | "ZwQueryEaFile"
                | "NtSetEaFile"
                | "ZwSetEaFile"
                | "NtDeviceIoControlFile"
                | "ZwDeviceIoControlFile"
                | "NtFsControlFile"
                | "ZwFsControlFile"
                | "NtFlushBuffersFile"
                | "ZwFlushBuffersFile"
                | "NtFlushBuffersFileEx"
                | "ZwFlushBuffersFileEx"
                | "NtNotifyChangeDirectoryFile"
                | "ZwNotifyChangeDirectoryFile"
                | "NtLockFile"
                | "ZwLockFile"
                | "NtUnlockFile"
                | "ZwUnlockFile"
                | "NtQueryVolumeInformationFile"
                | "ZwQueryVolumeInformationFile"
                | "NtSetVolumeInformationFile"
                | "ZwSetVolumeInformationFile"
                | "NtReadFileScatter"
                | "ZwReadFileScatter"
                | "NtWriteFileGather"
                | "ZwWriteFileGather"
                | "NtCancelIoFile"
                | "ZwCancelIoFile"
                | "NtCancelIoFileEx"
                | "ZwCancelIoFileEx"
                | "NtQueryQuotaInformationFile"
                | "ZwQueryQuotaInformationFile"
                | "NtSetQuotaInformationFile"
                | "ZwSetQuotaInformationFile"
                | "NtQueryInformationByName"
                | "ZwQueryInformationByName"
                | "NtCreateNamedPipeFile"
                | "ZwCreateNamedPipeFile"
                | "NtCreateMailslotFile"
                | "ZwCreateMailslotFile" => Ok(STATUS_SUCCESS as u64),

                // ── Registry stubs ────────────────────────────────────────
                "NtCreateKey"
                | "ZwCreateKey"
                | "NtOpenKey"
                | "ZwOpenKey"
                | "NtOpenKeyEx"
                | "ZwOpenKeyEx"
                | "NtDeleteKey"
                | "ZwDeleteKey"
                | "NtDeleteValueKey"
                | "ZwDeleteValueKey"
                | "NtEnumerateKey"
                | "ZwEnumerateKey"
                | "NtEnumerateValueKey"
                | "ZwEnumerateValueKey"
                | "NtQueryKey"
                | "ZwQueryKey"
                | "NtQueryValueKey"
                | "ZwQueryValueKey"
                | "NtSetValueKey"
                | "ZwSetValueKey"
                | "NtQueryMultipleValueKey"
                | "ZwQueryMultipleValueKey"
                | "NtNotifyChangeKey"
                | "ZwNotifyChangeKey"
                | "NtNotifyChangeMultipleKeys"
                | "ZwNotifyChangeMultipleKeys"
                | "NtFlushKey"
                | "ZwFlushKey"
                | "NtCompactKeys"
                | "ZwCompactKeys"
                | "NtCompressKey"
                | "ZwCompressKey"
                | "NtLoadKey"
                | "ZwLoadKey"
                | "NtLoadKey2"
                | "ZwLoadKey2"
                | "NtLoadKey3"
                | "ZwLoadKey3"
                | "NtLoadKeyEx"
                | "ZwLoadKeyEx"
                | "NtUnloadKey"
                | "ZwUnloadKey"
                | "NtUnloadKey2"
                | "ZwUnloadKey2"
                | "NtUnloadKeyEx"
                | "ZwUnloadKeyEx"
                | "NtSaveKey"
                | "ZwSaveKey"
                | "NtSaveKeyEx"
                | "ZwSaveKeyEx"
                | "NtSaveMergedKeys"
                | "ZwSaveMergedKeys"
                | "NtRestoreKey"
                | "ZwRestoreKey"
                | "NtRenameKey"
                | "ZwRenameKey"
                | "NtReplaceKey"
                | "ZwReplaceKey"
                | "NtQueryOpenSubKeys"
                | "ZwQueryOpenSubKeys"
                | "NtQueryOpenSubKeysEx"
                | "ZwQueryOpenSubKeysEx"
                | "NtCreateKeyTransacted"
                | "ZwCreateKeyTransacted"
                | "NtOpenKeyTransacted"
                | "ZwOpenKeyTransacted"
                | "NtOpenKeyTransactedEx"
                | "ZwOpenKeyTransactedEx"
                | "NtLockRegistryKey"
                | "ZwLockRegistryKey" => Ok(STATUS_SUCCESS as u64),

                // ── Process/thread extras ─────────────────────────────────
                "NtCreateProcess"
                | "ZwCreateProcess"
                | "NtCreateProcessEx"
                | "ZwCreateProcessEx"
                | "NtCreateUserProcess"
                | "ZwCreateUserProcess"
                | "NtCreateThread"
                | "ZwCreateThread"
                | "NtIsProcessInJob"
                | "ZwIsProcessInJob"
                | "NtGetNextThread"
                | "ZwGetNextThread"
                | "NtImpersonateThread"
                | "ZwImpersonateThread"
                | "NtImpersonateAnonymousToken"
                | "ZwImpersonateAnonymousToken" => Ok(STATUS_SUCCESS as u64),

                // ── Memory extras ─────────────────────────────────────────
                "NtAllocateVirtualMemoryEx"
                | "ZwAllocateVirtualMemoryEx"
                | "NtFlushVirtualMemory"
                | "ZwFlushVirtualMemory"
                | "NtLockVirtualMemory"
                | "ZwLockVirtualMemory"
                | "NtUnlockVirtualMemory"
                | "ZwUnlockVirtualMemory"
                | "NtGetWriteWatch"
                | "ZwGetWriteWatch"
                | "NtResetWriteWatch"
                | "ZwResetWriteWatch"
                | "NtCreatePagingFile"
                | "ZwCreatePagingFile"
                | "NtMapViewOfSectionEx"
                | "ZwMapViewOfSectionEx"
                | "NtUnmapViewOfSectionEx"
                | "ZwUnmapViewOfSectionEx"
                | "NtAreMappedFilesTheSame"
                | "ZwAreMappedFilesTheSame" => Ok(STATUS_SUCCESS as u64),

                // ── Object namespace/extras ───────────────────────────────
                "NtOpenKeyedEvent"
                | "ZwOpenKeyedEvent"
                | "NtReleaseKeyedEvent"
                | "ZwReleaseKeyedEvent"
                | "NtWaitForKeyedEvent"
                | "ZwWaitForKeyedEvent"
                | "NtCreateIoCompletion"
                | "ZwCreateIoCompletion"
                | "NtOpenIoCompletion"
                | "ZwOpenIoCompletion"
                | "NtSetIoCompletion"
                | "ZwSetIoCompletion"
                | "NtRemoveIoCompletion"
                | "ZwRemoveIoCompletion"
                | "NtOpenEventPair"
                | "ZwOpenEventPair"
                | "NtCreateEventPair"
                | "ZwCreateEventPair"
                | "NtOpenSemaphore"
                | "ZwOpenSemaphore"
                | "NtOpenTimer"
                | "ZwOpenTimer"
                | "NtQueryTimer"
                | "ZwQueryTimer"
                | "NtSetTimerEx"
                | "ZwSetTimerEx"
                | "NtQueryMutant"
                | "ZwQueryMutant"
                | "NtQuerySemaphore"
                | "ZwQuerySemaphore"
                | "NtQueryEvent"
                | "ZwQueryEvent"
                | "NtOpenJobObject"
                | "ZwOpenJobObject"
                | "NtCreateJobObject"
                | "ZwCreateJobObject"
                | "NtAssignProcessToJobObject"
                | "ZwAssignProcessToJobObject"
                | "NtTerminateJobObject"
                | "ZwTerminateJobObject"
                | "NtQueryInformationJobObject"
                | "ZwQueryInformationJobObject"
                | "NtSetInformationJobObject"
                | "ZwSetInformationJobObject" => Ok(STATUS_SUCCESS as u64),

                // ── Symbolic links / directory objects ────────────────────
                "NtOpenSymbolicLinkObject"
                | "ZwOpenSymbolicLinkObject"
                | "NtCreateSymbolicLinkObject"
                | "ZwCreateSymbolicLinkObject"
                | "NtQuerySymbolicLinkObject"
                | "ZwQuerySymbolicLinkObject"
                | "NtOpenDirectoryObject"
                | "ZwOpenDirectoryObject"
                | "NtCreateDirectoryObject"
                | "ZwCreateDirectoryObject"
                | "NtCreateDirectoryObjectEx"
                | "ZwCreateDirectoryObjectEx"
                | "NtQueryDirectoryObject"
                | "ZwQueryDirectoryObject"
                | "NtMakeTemporaryObject"
                | "ZwMakeTemporaryObject"
                | "NtMakePermanentObject"
                | "ZwMakePermanentObject" => Ok(STATUS_SUCCESS as u64),

                // ── CRT / string / memory extras ──────────────────────────
                "RtlCreateUnicodeString" => {
                    // Same as RtlCreateUnicodeStringFromAsciiz but with unicode source
                    Ok(STATUS_SUCCESS as u64)
                }
                "RtlDuplicateUnicodeString" => Ok(STATUS_SUCCESS as u64),
                _ => unreachable!(),
            }
        })())
    }
}

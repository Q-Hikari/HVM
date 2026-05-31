use std::sync::OnceLock;

use super::HookContext;
use super::*;
use crate::hooks::signature::HookSignature;

/// Pre-built synthetic VS_VERSION_INFO block (256 bytes).
/// Built once on first access, reused thereafter — avoids per-call Vec allocation.
static SYNTHETIC_VERSION_INFO_BLOCK: OnceLock<[u8; 0x100]> = OnceLock::new();

fn synthetic_version_info_block() -> &'static [u8] {
    SYNTHETIC_VERSION_INFO_BLOCK.get_or_init(|| {
        let mut block = [0u8; 0x100];
        // VS_VERSION_INFO header
        block[0..2].copy_from_slice(&92u16.to_le_bytes());
        block[2..4].copy_from_slice(&52u16.to_le_bytes());
        block[4..6].copy_from_slice(&0u16.to_le_bytes());
        // szKey = "VS_VERSION_INFO\0" (16 wchars = 32 bytes)
        for (i, ch) in "VS_VERSION_INFO\0"
            .encode_utf16()
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
        {
            let off = 6 + i * 2;
            block[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        // VS_FIXEDFILEINFO at offset 0x28
        let ffi = &mut block[0x28..0x28 + 52];
        ffi[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes()); // dwSignature
        ffi[4..8].copy_from_slice(&0x00010000u32.to_le_bytes()); // dwStrucVersion
        ffi[8..12].copy_from_slice(&0x000A0000u32.to_le_bytes()); // dwFileVersionMS
        ffi[12..16].copy_from_slice(&0x4A510001u32.to_le_bytes()); // dwFileVersionLS
        ffi[16..20].copy_from_slice(&0x000A0000u32.to_le_bytes()); // dwProductVersionMS
        ffi[20..24].copy_from_slice(&0x4A510001u32.to_le_bytes()); // dwProductVersionLS
        ffi[24..28].copy_from_slice(&0x0000003Fu32.to_le_bytes()); // dwFileFlagsMask
        ffi[28..32].copy_from_slice(&0x00000000u32.to_le_bytes()); // dwFileFlags
        ffi[32..36].copy_from_slice(&0x00040004u32.to_le_bytes()); // dwFileOS
        ffi[36..40].copy_from_slice(&0x00000002u32.to_le_bytes()); // dwFileType
        ffi[40..44].copy_from_slice(&0x00000000u32.to_le_bytes()); // dwFileSubtype
        ffi[44..48].copy_from_slice(&0x00000000u32.to_le_bytes()); // dwFileDateMS
        ffi[48..52].copy_from_slice(&0x00000000u32.to_le_bytes()); // dwFileDateLS
        block
    })
}

impl VirtualExecutionEngine {
    fn can_reuse_kernel32_manual_contract(module: &str, function: &str) -> bool {
        match module {
            "api-ms-win-core-libraryloader" => matches!(
                function,
                "FindResourceA"
                    | "FindResourceExW"
                    | "FindResourceW"
                    | "FreeLibrary"
                    | "FreeLibraryAndExitThread"
                    | "GetModuleFileNameA"
                    | "GetModuleFileNameW"
                    | "GetModuleHandleA"
                    | "GetModuleHandleW"
                    | "GetProcAddress"
                    | "LoadLibraryA"
                    | "LoadLibraryExA"
                    | "LoadLibraryExW"
                    | "LoadLibraryW"
                    | "LoadResource"
                    | "LockResource"
                    | "SizeofResource"
            ),
            "api-ms-win-core-heap" => matches!(
                function,
                "GlobalAlloc"
                    | "GlobalFlags"
                    | "GlobalFree"
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
                    | "HeapUnlock"
                    | "HeapWalk"
                    | "LocalAlloc"
                    | "LocalFree"
                    | "LocalReAlloc"
            ),
            "api-ms-win-core-memory" => matches!(
                function,
                "CreateFileMappingW"
                    | "FlushViewOfFile"
                    | "MapViewOfFile"
                    | "OpenFileMappingW"
                    | "ReadProcessMemory"
                    | "UnmapViewOfFile"
                    | "VirtualAlloc"
                    | "VirtualAllocEx"
                    | "VirtualFree"
                    | "VirtualFreeEx"
                    | "VirtualProtect"
                    | "VirtualProtectEx"
                    | "VirtualQuery"
                    | "VirtualQueryEx"
                    | "WriteProcessMemory"
            ),
            "api-ms-win-core-console" => matches!(
                function,
                "FreeConsole"
                    | "GetConsoleCP"
                    | "GetConsoleMode"
                    | "GetConsoleOutputCP"
                    | "ReadConsoleW"
                    | "SetConsoleCtrlHandler"
                    | "WriteConsoleA"
                    | "WriteConsoleW"
            ),
            "api-ms-win-core-sidebyside" => matches!(
                function,
                "ActivateActCtx"
                    | "CreateActCtxW"
                    | "DeactivateActCtx"
                    | "FindActCtxSectionStringW"
                    | "QueryActCtxW"
            ),
            "api-ms-win-core-atoms" => matches!(
                function,
                "AddAtomW"
                    | "DeleteAtom"
                    | "GlobalAddAtomW"
                    | "GlobalDeleteAtom"
                    | "GlobalFindAtomW"
                    | "GlobalGetAtomNameW"
            ),
            "api-ms-win-core-wow64" => matches!(function, "GetSystemWow64DirectoryW"),
            "api-ms-win-core-fibers" => {
                matches!(
                    function,
                    "FlsAlloc" | "FlsFree" | "FlsGetValue" | "FlsGetValue2" | "FlsSetValue"
                )
            }
            "api-ms-win-core-synch" => {
                matches!(
                    function,
                    "CreateSemaphoreW"
                        | "InitOnceExecuteOnce"
                        | "WaitForMultipleObjects"
                        | "InitializeConditionVariable"
                        | "InitializeCriticalSectionEx"
                )
            }
            "api-ms-win-core-file" => matches!(
                function,
                "CopyFileW" | "GetTempFileNameA" | "GetTempPathA" | "GetVolumeInformationA"
            ),
            "api-ms-win-core-localization" => {
                matches!(function, "GetNumberFormatEx" | "LCMapStringEx")
            }
            "api-ms-win-core-largeinteger" => matches!(function, "MulDiv"),
            _ => false,
        }
    }

    fn map_api_set_psapi_function(function: &str) -> Option<&'static str> {
        match function {
            "K32EmptyWorkingSet" => Some("EmptyWorkingSet"),
            "K32EnumProcessModules" => Some("EnumProcessModules"),
            "K32EnumProcessModulesEx" => Some("EnumProcessModulesEx"),
            "K32GetMappedFileNameA" => Some("GetMappedFileNameA"),
            "K32GetMappedFileNameW" => Some("GetMappedFileNameW"),
            "K32GetModuleBaseNameA" => Some("GetModuleBaseNameA"),
            "K32GetModuleBaseNameW" => Some("GetModuleBaseNameW"),
            "K32GetModuleFileNameExA" => Some("GetModuleFileNameExA"),
            "K32GetModuleFileNameExW" => Some("GetModuleFileNameExW"),
            "K32GetModuleInformation" => Some("GetModuleInformation"),
            "K32GetProcessImageFileNameA" => Some("GetProcessImageFileNameA"),
            "K32GetProcessImageFileNameW" => Some("GetProcessImageFileNameW"),
            "K32GetProcessMemoryInfo" => Some("GetProcessMemoryInfo"),
            "QueryFullProcessImageNameA" => Some("QueryFullProcessImageNameA"),
            "QueryFullProcessImageNameW" => Some("QueryFullProcessImageNameW"),
            _ => None,
        }
    }

    fn dispatch_manual_contract_hook(
        &mut self,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        match signature.module {
            "api-ms-win-core-libraryloader"
            | "api-ms-win-core-heap"
            | "api-ms-win-core-memory"
            | "api-ms-win-core-console"
            | "api-ms-win-core-sidebyside"
            | "api-ms-win-core-atoms"
            | "api-ms-win-core-wow64"
            | "api-ms-win-core-synch"
            | "api-ms-win-core-fibers"
            | "api-ms-win-core-file"
            | "api-ms-win-core-localization"
            | "api-ms-win-core-largeinteger" => {
                Self::can_reuse_kernel32_manual_contract(signature.module, signature.function)
                    .then(|| {
                        self.dispatch_kernel32_hook(
                            "kernel32.dll",
                            signature.function,
                            signature,
                            stub_address,
                            ctx,
                        )
                    })
                    .flatten()
            }
            "api-ms-win-core-processthreads" => {
                self.dispatch_advapi32_hook(signature.function, ctx)
            }
            module
                if module.starts_with("api-ms-win-crt-")
                    || module.starts_with("api-ms-win-core-crt-") =>
            {
                self.dispatch_msvcrt_hook("msvcrt.dll", signature.function, ctx)
            }
            "api-ms-win-core-apiquery" => {
                self.dispatch_ntdll_hook("ntdll.dll", signature.function, ctx)
            }
            "api-ms-win-core-com" => self.dispatch_ole32_hook("ole32.dll", signature.function, ctx),
            "api-ms-win-core-psapi" => match signature.function {
                "QueryFullProcessImageNameA" | "QueryFullProcessImageNameW" => self
                    .dispatch_kernel32_hook(
                        "kernel32.dll",
                        signature.function,
                        signature,
                        stub_address,
                        ctx,
                    ),
                _ => Self::map_api_set_psapi_function(signature.function).and_then(
                    |psapi_function| self.dispatch_psapi_hook("psapi.dll", psapi_function, ctx),
                ),
            },
            "api-ms-win-core-shlwapi-legacy"
            | "api-ms-win-core-shlwapi-obsolete"
            | "api-ms-win-core-string" => {
                self.dispatch_shlwapi_hook("shlwapi.dll", signature.function, ctx)
            }
            "api-ms-win-core-registry"
            | "api-ms-win-security-appcontainer"
            | "api-ms-win-security-audit"
            | "api-ms-win-security-base" => self.dispatch_advapi32_hook(signature.function, ctx),
            _ => None,
        }
    }

    /// Dispatches a known family hook by module name using O(1) match instead of
    /// a linear fallback chain. Each arm delegates directly to the per-family
    /// dispatch function which validates the function name internally.
    fn dispatch_known_family_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        match module_name {
            // --- Core ---
            "ntdll.dll" => self.dispatch_ntdll_hook(module_name, function, ctx),
            "psapi.dll" => self.dispatch_psapi_hook(module_name, function, ctx),
            // kernel32.dll / kernelbase.dll are dispatched first in
            // dispatch_bound_stub_with_definition; they never reach here.
            // --- CRT ---
            "msvcrt.dll" => self.dispatch_msvcrt_hook(module_name, function, ctx),
            "vcruntime140.dll" => self.dispatch_vcruntime140_hook(module_name, function, ctx),
            // --- Security ---
            "advapi32.dll" => self.dispatch_advapi32_hook(function, ctx),
            "crypt32.dll" => self.dispatch_crypt32_hook(module_name, function, ctx),
            "api-ms-win-eventing-controller-l1-1-0.dll"
            | "api-ms-win-eventing-consumer-l1-1-0.dll" => {
                self.dispatch_eventing_hook(module_name, function, ctx)
            }
            "sfc_os.dll" => self.dispatch_sfc_os_hook(module_name, function, ctx),
            // --- COM ---
            "combase.dll" => self.dispatch_combase_hook(module_name, function, ctx),
            "ole32.dll" => self.dispatch_ole32_hook(module_name, function, ctx),
            "oleaut32.dll" => self.dispatch_oleaut32_hook(module_name, function, ctx),
            "rpcrt4.dll" => self.dispatch_rpcrt4_hook(module_name, function, ctx),
            "com_dispatch.dll" => self.dispatch_com_method(function, ctx),
            // --- Network ---
            "mpr.dll" => self.dispatch_mpr_hook(function, ctx),
            "netapi32.dll" => self.dispatch_netapi32_hook(function, ctx),
            "netutils.dll" => self.dispatch_netapi32_hook(function, ctx),
            "ws2_32.dll" => self.dispatch_ws2_32_hook(module_name, function, ctx),
            "winhttp.dll" => self.dispatch_winhttp_hook(module_name, function, ctx),
            "wininet.dll" => self.dispatch_wininet_hook(module_name, function, ctx),
            "mswsock.dll" => self.dispatch_mswsock_hook(module_name, function, ctx),
            "iphlpapi.dll" => self.dispatch_iphlpapi_hook(module_name, function, ctx),
            // --- UI ---
            "user32.dll" => self.dispatch_user32_hook(function, ctx),
            "comctl32.dll" => self.dispatch_comctl32_hook(module_name, function, ctx),
            "mfc100.dll" => self.dispatch_mfc100_hook(module_name, function, ctx),
            "mfc42u.dll" => self.dispatch_mfc42u_hook(module_name, function, ctx),
            // --- Shell / Services ---
            "shell32.dll" => self.dispatch_shell32_hook(module_name, function, ctx),
            "shlwapi.dll" => self.dispatch_shlwapi_hook(module_name, function, ctx),
            "wtsapi32.dll" => self.dispatch_wtsapi32_hook(module_name, function, ctx),
            // --- Device ---
            "setupapi.dll" => self.dispatch_setupapi_hook(module_name, function, ctx),
            "cfgmgr32.dll" => self.dispatch_cfgmgr32_hook(module_name, function, ctx),
            "cabinet.dll" => self.dispatch_cabinet_hook(module_name, function, ctx),
            // --- Graphics ---
            "gdi32.dll" => self.dispatch_gdi32_hook(module_name, function, ctx),
            "dxgi.dll" => self.dispatch_dxgi_hook(module_name, function, ctx),
            "winmm.dll" => self.dispatch_winmm_hook(module_name, function, ctx),
            // --- API sets (less common, but still direct match) ---
            "api-ms-win-appmodel-runtime-l1-1-2.dll" => {
                self.dispatch_appmodel_runtime_hook(module_name, function, ctx)
            }
            // --- Version (migrated to HookContext typed access) ---
            "version.dll" => self.dispatch_version_hook(ctx),
            _ => None,
        }
    }

    pub(super) fn dispatch_bound_stub_with_signature(
        &mut self,
        signature: &HookSignature,
        stub_address: u64,
        return_address: Option<u64>,
        args: &[u64],
    ) -> Result<HookValue, VmError> {
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("hook.dispatch_bound_stub_with_signature");
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some()
            && signature.module == "ntdll.dll"
            && signature.function == "RtlAllocateHeap"
        {
            eprintln!(
                "[RTLALLOC_DIAG] dispatch_enter stub=0x{stub_address:X} return_to=0x{:X} args={:X?}",
                return_address.unwrap_or(0),
                args
            );
        }
        self.dispatch.reset_api_flow_control();
        // Log arguments before activating hook-side guest-fault recovery so
        // diagnostic string probing cannot mutate guest control flow.
        let call_id = self.log_api_call(signature, stub_address, return_address, args)?;
        self.dispatch
            .begin_hook_dispatch(stub_address, return_address);
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some()
            && signature.module == "ntdll.dll"
            && signature.function == "RtlAllocateHeap"
        {
            eprintln!("[RTLALLOC_DIAG] log_api_call_done call_id={call_id}");
        }
        // signature.module is always lowercase; skip to_ascii_lowercase() allocation.
        let module_name = signature.module;
        // Construct typed hook context for family dispatchers that use it.
        let ctx = HookContext::new(signature, args, &self.core.arch);

        // Module-level fast routing: dispatch directly to the correct family
        // based on the module name, avoiding the sequential cascade of
        // kernel32→manual_contract→known_family that wastes time on every call.
        let retval_result: Result<HookValue, VmError> = {
            let raw = if module_name == "kernel32.dll" {
                // Highest-frequency module: go directly to kernel32 dispatcher.
                self.dispatch_kernel32_hook(
                    module_name,
                    signature.function,
                    signature,
                    stub_address,
                    &ctx,
                )
            } else if module_name.starts_with("api-ms-") {
                // API-set contracts (e.g. api-ms-win-core-heap → kernel32 dispatcher).
                // Try the contract mapping first; fall through to family dispatch
                // for unhandled contracts (api-ms-win-core-apiquery → ntdll, etc.).
                self.dispatch_manual_contract_hook(signature, stub_address, &ctx)
                    .or_else(|| {
                        self.dispatch_known_family_hook(module_name, signature.function, &ctx)
                    })
            } else {
                // All other known modules: direct family dispatch.
                self.dispatch_known_family_hook(module_name, signature.function, &ctx)
            };

            match raw {
                Some(retval) => Ok(HookValue::from_raw_with_spec(
                    retval?,
                    signature.ret,
                    &self.core.arch,
                )),
                None => {
                    self.log_unsupported_runtime_stub(
                        signature,
                        stub_address,
                        if self.strict_unknown_api_policy() {
                            "unknown_api_policy=strict"
                        } else {
                            "default stub return 0"
                        },
                    )?;
                    if self.core.config.exit_on_unsupported_hook {
                        self.core.stop_reason = Some(RunStopReason::UnsupportedHook);
                        return Err(VmError::NativeExecution {
                            op: "dispatch",
                            detail: format!(
                                "exit_on_unsupported: no handler for {}!{}",
                                signature.module, signature.function
                            ),
                        });
                    }
                    if self.strict_unknown_api_policy() {
                        Err(VmError::NativeExecution {
                            op: "dispatch",
                            detail: format!(
                                "unknown_api_policy={} rejected unimplemented runtime stub {}!{}",
                                self.core.config.unknown_api_policy,
                                signature.module,
                                signature.function
                            ),
                        })
                    } else {
                        Ok(HookValue::Raw(0))
                    }
                }
            }
        };
        let recovered_guest_exception = self.dispatch.take_recovered_guest_exception_in_hook();
        let hook_return_override = self.dispatch.hook_return_override();
        self.dispatch.end_hook_dispatch();
        if recovered_guest_exception.is_some() {
            self.dispatch.request_resume_at_updated_pc();
            return Ok(HookValue::Raw(0));
        }
        if let Some(override_value) = hook_return_override {
            return Ok(HookValue::Raw(override_value.raw_retval));
        }
        if matches!(retval_result, Err(VmError::HookAbortedForGuestException)) {
            self.dispatch.request_resume_at_updated_pc();
            return Ok(HookValue::Raw(0));
        }
        let retval = retval_result?;
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some()
            && signature.module == "ntdll.dll"
            && signature.function == "RtlAllocateHeap"
        {
            eprintln!(
                "[RTLALLOC_DIAG] dispatch_body_done retval=0x{:X} defer_return={}",
                retval.into_raw(&self.core.arch),
                self.dispatch.api_return_deferred()
            );
        }
        if self.dispatch.api_return_deferred() {
            return Ok(retval);
        }
        self.log_api_return(
            call_id,
            signature,
            stub_address,
            args,
            retval.into_raw(&self.core.arch),
        )?;
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some()
            && signature.module == "ntdll.dll"
            && signature.function == "RtlAllocateHeap"
        {
            eprintln!("[RTLALLOC_DIAG] log_api_return_done");
        }
        Ok(retval)
    }

    /// Dispatches version.dll hooks — file version information queries.
    ///
    /// Dispatches version.dll hooks using typed HookContext parameter access.
    ///
    /// Returns synthetic version information mimicking a typical Windows 10
    /// system DLL so that shellcodes performing OS version checks do not bail
    /// out when the real version resource is unavailable.
    fn dispatch_version_hook(&mut self, ctx: &HookContext<'_>) -> Option<Result<u64, VmError>> {
        match ctx.function() {
            // GetFileVersionInfoSizeExW/A(flags, filename, handle_ptr) → DWORD
            "GetFileVersionInfoSizeExW" | "GetFileVersionInfoSizeExA" => {
                Some(self.version_info_size_ex(ctx))
            }
            // GetFileVersionInfoSizeW/A(filename, handle_ptr) → DWORD
            "GetFileVersionInfoSizeW" | "GetFileVersionInfoSizeA" => {
                Some(self.version_info_size(ctx))
            }
            // GetFileVersionInfoExW/A(flags, filename, handle, size, data) → BOOL
            "GetFileVersionInfoExW" | "GetFileVersionInfoExA" => {
                Some(self.version_info_get_ex(ctx))
            }
            // GetFileVersionInfoW/A(filename, handle, size, data) → BOOL
            "GetFileVersionInfoW" | "GetFileVersionInfoA" => Some(self.version_info_get(ctx)),
            // VerQueryValueW/A(block, subblock, buffer_ptr, buflen_ptr) → BOOL
            "VerQueryValueW" | "VerQueryValueA" => Some(self.version_query_value(ctx)),
            _ => None,
        }
    }

    fn version_info_size_ex(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let handle_ptr: u64 = ctx.get(2)?;
        if handle_ptr != 0 {
            self.write_u32(handle_ptr, 0)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(synthetic_version_info_block().len() as u64)
    }

    fn version_info_size(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let handle_ptr: u64 = ctx.get(1)?;
        if handle_ptr != 0 {
            self.write_u32(handle_ptr, 0)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(synthetic_version_info_block().len() as u64)
    }

    fn version_info_get_ex(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let data_ptr: u64 = ctx.get(4)?;
        let buf_size: usize = ctx.get::<u32>(3)? as usize;
        if data_ptr == 0 || buf_size == 0 {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        let block = synthetic_version_info_block();
        let write_len = block.len().min(buf_size);
        self.core
            .modules
            .memory_mut()
            .write(data_ptr, &block[..write_len])?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn version_info_get(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let data_ptr: u64 = ctx.get(3)?;
        let buf_size: usize = ctx.get::<u32>(2)? as usize;
        if data_ptr == 0 || buf_size == 0 {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        let block = synthetic_version_info_block();
        let write_len = block.len().min(buf_size);
        self.core
            .modules
            .memory_mut()
            .write(data_ptr, &block[..write_len])?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn version_query_value(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let block_ptr: u64 = ctx.get(0)?;
        let buffer_ptr: u64 = ctx.get(2)?;
        let buflen_ptr: u64 = ctx.get(3)?;
        if block_ptr == 0 || buffer_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        // The VS_FIXEDFILEINFO starts at offset 0x28 (40) within the
        // VS_VERSION_INFO block (after the header + key + padding).
        const VS_FIXEDFILEINFO_OFFSET: u64 = 0x28;
        const VS_FIXEDFILEINFO_SIZE: u32 = 52;
        if buflen_ptr != 0 {
            self.write_u32(buflen_ptr, VS_FIXEDFILEINFO_SIZE)?;
        }
        self.write_u32(buffer_ptr, (block_ptr + VS_FIXEDFILEINFO_OFFSET) as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }
}

use super::*;

/// Well-known CLSID for MMC20.Application: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
pub(super) const CLSID_MMC20_APPLICATION: [u8; 16] = [
    0x1A, 0x79, 0xB2, 0x49, // Data1 (LE)
    0xAE, 0xB1, // Data2 (LE)
    0x90, 0x4C, // Data3 (LE)
    0x9B, 0x8E, // Data4[0..2]
    0xE8, 0x60, // Data4[2..4]
    0xBA, 0x07, // Data4[4..6]
    0xF8, 0x89, // Data4[6..8]
];

/// COM automation dispatch flags.
#[allow(dead_code)]
const DISPATCH_METHOD: u16 = 0x1;
const DISPATCH_PROPERTYGET: u16 = 0x2;

/// CO_E_CLASSSTRING — class string is invalid or not registered.
const CO_E_CLASSSTRING_HRESULT: u64 = 0x8004_01F3;

/// Internal COM object class identifiers for our fake objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum ComClassId {
    MmcApplication = 1,
    MmcDocument = 2,
    MmcActiveView = 3,
    ElevatedShellWindows = 4,
    EnumUnknown = 5,
    ElevatedMonikerObject = 6,
}

impl VirtualExecutionEngine {
    pub(super) fn dispatch_com_initialize(&self) -> Result<u64, VmError> {
        Ok(ERROR_SUCCESS)
    }

    pub(super) fn dispatch_com_uninitialize(&self) -> Result<u64, VmError> {
        Ok(0)
    }

    /// IIDFromString — converts a string GUID to binary IID.
    pub(super) fn dispatch_iid_from_string(
        &mut self,
        string_ptr: u64,
        iid_ptr: u64,
    ) -> Result<u64, VmError> {
        if string_ptr == 0 || iid_ptr == 0 {
            return Ok(E_INVALIDARG_HRESULT);
        }
        let guid_str = self
            .read_wide_string_from_memory(string_ptr)
            .unwrap_or_default();
        if let Some(bytes) = parse_guid_string_le(&guid_str) {
            self.core.modules.memory_mut().write(iid_ptr, &bytes)?;
            Ok(ERROR_SUCCESS)
        } else {
            Ok(CO_E_CLASSSTRING_HRESULT)
        }
    }

    /// CoGetObject — creates a COM object from a display name (moniker).
    /// For elevation monikers (`Elevation:Administrator!new:{CLSID}`),
    /// create a fake elevated COM object so the shellcode continues executing.
    pub(super) fn dispatch_com_get_object(
        &mut self,
        name_ptr: u64,
        result_ptr: u64,
    ) -> Result<u64, VmError> {
        let name = if name_ptr != 0 {
            self.read_wide_string_from_memory(name_ptr)
                .unwrap_or_default()
        } else {
            String::new()
        };
        self.log_com_event("CoGetObject", &name, 0)?;

        let name_upper = name.to_ascii_uppercase();
        if name_upper.contains("ELEVATION:") && name_upper.contains("!NEW:") {
            // Elevation moniker — create a fake elevated COM object.
            // Use a non-IDispatch vtable because the shellcode calls vtable
            // methods directly (not through IDispatch::Invoke). The shellcode
            // at vtable slot 9 pushes 6 args, so every slot beyond IUnknown
            // must use a 6-arg stdcall stub to avoid stack corruption.
            let obj_ptr = self.create_elevated_moniker_object()?;
            if result_ptr != 0 {
                self.write_pointer_value(result_ptr, obj_ptr)?;
            }
            // Log the PowerShell command if visible in nearby heap allocations
            self.log_com_event("CoGetObject", &format!("elevated_obj=0x{obj_ptr:X}"), 0)?;
            return Ok(ERROR_SUCCESS);
        }

        // Unknown moniker
        if result_ptr != 0 {
            self.write_pointer_value(result_ptr, 0)?;
        }
        Ok(CO_E_CLASSSTRING_HRESULT)
    }

    pub(super) fn dispatch_com_activation_not_registered(
        &mut self,
        result_ptr: u64,
    ) -> Result<u64, VmError> {
        if result_ptr != 0 {
            self.write_pointer_value(result_ptr, 0)?;
        }
        Ok(REGDB_E_CLASSNOTREG_HRESULT)
    }

    /// Handles CLSIDFromProgID for known COM classes.
    pub(super) fn dispatch_clsid_from_progid(
        &mut self,
        progid_ptr: u64,
        clsid_ptr: u64,
    ) -> Result<u64, VmError> {
        let progid = self
            .read_wide_string_from_memory(progid_ptr)
            .unwrap_or_default();
        let progid_upper = progid.to_ascii_uppercase();
        if progid_upper == "MMC20.APPLICATION" {
            if clsid_ptr != 0 {
                self.core
                    .modules
                    .memory_mut()
                    .write(clsid_ptr, &CLSID_MMC20_APPLICATION)?;
            }
            return Ok(ERROR_SUCCESS);
        }
        // Unknown ProgID
        Ok(REGDB_E_CLASSNOTREG_HRESULT)
    }

    /// Handles CoCreateInstance for known COM CLSIDs.
    pub(super) fn dispatch_com_create_instance(
        &mut self,
        clsid_ptr: u64,
        _outer_unknown: u64,
        _clsctx: u64,
        _riid_ptr: u64,
        result_ptr: u64,
    ) -> Result<u64, VmError> {
        if clsid_ptr == 0 {
            return Ok(E_INVALIDARG_HRESULT);
        }
        let clsid = self.read_bytes_from_memory(clsid_ptr, 16)?;
        if clsid.as_slice() == CLSID_MMC20_APPLICATION {
            let obj_ptr = self.create_com_object(ComClassId::MmcApplication)?;
            if result_ptr != 0 {
                self.write_pointer_value(result_ptr, obj_ptr)?;
            }
            self.log_com_event("CoCreateInstance", "MMC20.Application", obj_ptr)?;
            return Ok(ERROR_SUCCESS);
        }
        // Unknown CLSID — fall back to not registered
        if result_ptr != 0 {
            self.write_pointer_value(result_ptr, 0)?;
        }
        Ok(REGDB_E_CLASSNOTREG_HRESULT)
    }

    /// Allocates a fake COM object with a vtable in virtual memory.
    /// The vtable has 32 entries to cover IUnknown + IDispatch + many
    /// interface-specific methods so that vtable calls don't read garbage.
    /// Each vtable slot uses a dedicated stdcall stub with the correct arg count
    /// to avoid stack corruption.
    fn create_com_object(&mut self, class: ComClassId) -> Result<u64, VmError> {
        let ptr_size = self.core.arch.pointer_size as u64;
        let object_size = ptr_size * 3;
        let obj_addr = self.alloc_process_heap_block(object_size, "COM_Object")?;

        let vtable_entries = 32usize;
        let vtable_size = ptr_size * vtable_entries as u64;
        let vtable_addr = self.alloc_process_heap_block(vtable_size, "COM_VTable")?;

        // Bind IDispatch stubs (vtable slots 0-6)
        let hook_qi = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "QueryInterface");
        let hook_addref = self.core.hooks.bind_stub("com_dispatch.dll", "AddRef");
        let hook_release = self.core.hooks.bind_stub("com_dispatch.dll", "Release");
        let hook_gtic = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "GetTypeInfoCount");
        let hook_gti = self.core.hooks.bind_stub("com_dispatch.dll", "GetTypeInfo");
        let hook_gion = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "GetIDsOfNames");
        let hook_invoke = self.core.hooks.bind_stub("com_dispatch.dll", "Invoke");

        let idispatch_hooks = [
            hook_qi,
            hook_addref,
            hook_release,
            hook_gtic,
            hook_gti,
            hook_gion,
            hook_invoke,
        ];

        // Bind interface-specific stubs for slots 7+.
        // IShellWindows: slot 7=get_Count(2), 8=Item(3), 9=_NewEnum(2)
        let sw_count = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "ShellWindows_get_Count");
        let sw_item = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "ShellWindows_Item");
        let sw_newenum = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "ShellWindows__NewEnum");
        // Generic fallback for unknown methods (2 args)
        let extra2 = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "ComMethodExtra2");

        // Slots 7,8,9 = IShellWindows methods; 10+ = generic 2-arg fallback
        let extra_hooks = [
            sw_count, sw_item, sw_newenum, extra2, extra2, extra2, extra2, extra2, extra2, extra2,
            extra2, extra2, extra2, extra2, extra2, extra2, extra2, extra2, extra2, extra2, extra2,
            extra2, extra2, extra2, extra2,
        ];

        // Write all vtable entries
        for i in 0..vtable_entries {
            let hook_addr = if i < idispatch_hooks.len() {
                idispatch_hooks[i]
            } else {
                let extra_idx = i - idispatch_hooks.len();
                extra_hooks[extra_idx.min(extra_hooks.len() - 1)]
            };
            let entry_addr = vtable_addr + ptr_size * i as u64;
            self.write_pointer_value(entry_addr, hook_addr)?;
        }

        // Write object: [vtable_ptr][class_id][0]
        self.write_pointer_value(obj_addr, vtable_addr)?;
        self.write_u32(obj_addr + ptr_size, class as u32)?;
        self.write_u32(obj_addr + ptr_size * 2, 0)?;

        Ok(obj_addr)
    }

    /// Creates a fake IEnumUnknown COM object with the correct vtable layout.
    /// IEnumUnknown vtable: QI(3), AddRef(1), Release(1), Next(4), Skip(2), Reset(1), Clone(2)
    fn create_enum_unknown(&mut self) -> Result<u64, VmError> {
        let ptr_size = self.core.arch.pointer_size as u64;
        let object_size = ptr_size * 3;
        let obj_addr = self.alloc_process_heap_block(object_size, "COM_EnumUnknown")?;

        // IEnumUnknown has 7 vtable entries
        let vtable_entries = 7usize;
        let vtable_size = ptr_size * vtable_entries as u64;
        let vtable_addr = self.alloc_process_heap_block(vtable_size, "COM_EnumVTable")?;

        let hook_qi = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "QueryInterface");
        let hook_addref = self.core.hooks.bind_stub("com_dispatch.dll", "AddRef");
        let hook_release = self.core.hooks.bind_stub("com_dispatch.dll", "Release");
        let hook_next = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "IEnumUnknown_Next");
        let hook_skip = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "IEnumUnknown_Skip");
        let hook_reset = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "IEnumUnknown_Reset");
        let hook_clone = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "IEnumUnknown_Clone");

        let hooks = [
            hook_qi,
            hook_addref,
            hook_release,
            hook_next,
            hook_skip,
            hook_reset,
            hook_clone,
        ];
        for i in 0..vtable_entries {
            let entry_addr = vtable_addr + ptr_size * i as u64;
            self.write_pointer_value(entry_addr, hooks[i])?;
        }

        // Write object: [vtable_ptr][class_id=EnumUnknown][enumerated_count=0]
        self.write_pointer_value(obj_addr, vtable_addr)?;
        self.write_u32(obj_addr + ptr_size, ComClassId::EnumUnknown as u32)?;
        self.write_u32(obj_addr + ptr_size * 2, 0)?; // enumerated count

        Ok(obj_addr)
    }

    /// Creates a COM object for the Elevation moniker result with a
    /// non-IDispatch vtable. The shellcode calls vtable methods directly
    /// (e.g. slot 9 with 6 args), so every slot beyond IUnknown uses a
    /// 6-arg stdcall stub to avoid stack corruption.
    fn create_elevated_moniker_object(&mut self) -> Result<u64, VmError> {
        let ptr_size = self.core.arch.pointer_size as u64;
        let object_size = ptr_size * 3;
        let obj_addr = self.alloc_process_heap_block(object_size, "COM_ElevatedMoniker")?;

        let vtable_entries = 32usize;
        let vtable_size = ptr_size * vtable_entries as u64;
        let vtable_addr = self.alloc_process_heap_block(vtable_size, "COM_ElevatedVTable")?;

        // IUnknown slots 0-2
        let hook_qi = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "QueryInterface");
        let hook_addref = self.core.hooks.bind_stub("com_dispatch.dll", "AddRef");
        let hook_release = self.core.hooks.bind_stub("com_dispatch.dll", "Release");
        // All remaining slots use 6-arg stub (matches shellcode's calling pattern)
        let hook_extra6 = self
            .core
            .hooks
            .bind_stub("com_dispatch.dll", "ComMethodExtra6");

        let iunknown_hooks = [hook_qi, hook_addref, hook_release];

        for i in 0..vtable_entries {
            let hook_addr = if i < iunknown_hooks.len() {
                iunknown_hooks[i]
            } else {
                hook_extra6
            };
            let entry_addr = vtable_addr + ptr_size * i as u64;
            self.write_pointer_value(entry_addr, hook_addr)?;
        }

        // Write object: [vtable_ptr][class_id=ElevatedMonikerObject][0]
        self.write_pointer_value(obj_addr, vtable_addr)?;
        self.write_u32(
            obj_addr + ptr_size,
            ComClassId::ElevatedMonikerObject as u32,
        )?;
        self.write_u32(obj_addr + ptr_size * 2, 0)?;

        Ok(obj_addr)
    }

    /// Dispatches a COM vtable method call.
    pub(in crate::runtime::engine) fn dispatch_com_method(
        &mut self,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        match function {
            "QueryInterface" => Some(self.com_query_interface(ctx)),
            "AddRef" => Some(Ok(2)),
            "Release" => Some(Ok(1)),
            "GetTypeInfoCount" => Some(self.com_get_type_info_count(ctx)),
            "GetTypeInfo" => Some(Ok(0x8000_4001)), // TYPE_E_CANTLOADLIBRARY
            "GetIDsOfNames" => Some(self.com_get_ids_of_names(ctx)),
            "Invoke" => Some(self.com_invoke(ctx)),
            "ShellWindows_get_Count" => {
                // IShellWindows::get_Count(this, long *pCount) → write count=1
                let this = ctx.raw(0);
                let p_count = ctx.raw(1);
                let _ = self.log_com_event("ShellWindows::get_Count", "vtable_call", this);
                if p_count != 0 {
                    let _ = self.write_u32(p_count, 1);
                }
                Some(Ok(ERROR_SUCCESS))
            }
            "ShellWindows_Item" => {
                // IShellWindows::Item(this, VARIANT index, IDispatch **ppDisp)
                let this = ctx.raw(0);
                let pp_disp = ctx.raw(2);
                let _ = self.log_com_event("ShellWindows::Item", "vtable_call", this);
                if pp_disp != 0 {
                    if let Ok(obj_ptr) = self.create_com_object(ComClassId::ElevatedShellWindows) {
                        let _ = self.write_pointer_value(pp_disp, obj_ptr);
                    }
                }
                Some(Ok(ERROR_SUCCESS))
            }
            "ShellWindows__NewEnum" => {
                // IShellWindows::_NewEnum(this, IUnknown **ppunkEnum)
                // Return a proper IEnumUnknown COM object.
                let this = ctx.raw(0);
                let pp_enum = ctx.raw(1);
                let _ = self.log_com_event("ShellWindows::_NewEnum", "vtable_call", this);
                if pp_enum != 0 {
                    if let Ok(obj_ptr) = self.create_enum_unknown() {
                        let _ = self.write_pointer_value(pp_enum, obj_ptr);
                    }
                }
                Some(Ok(ERROR_SUCCESS))
            }
            "IEnumUnknown_Next" => {
                // IEnumUnknown::Next(this, celt, rgelt, pceltFetched)
                // Return one fake shell window on first call, then S_FALSE.
                let this = ctx.raw(0);
                let celt = ctx.raw(1) as u32;
                let rgelt = ctx.raw(2);
                let pcelt_fetched = ctx.raw(3);
                let _ = self.log_com_event("IEnumUnknown::Next", &format!("celt={celt}"), this);
                let ptr_size = self.core.arch.pointer_size as u64;
                // Read how many we've already enumerated (stored at this+2*ptr_size)
                let enumerated = self.read_u32(this + ptr_size * 2).unwrap_or(0);
                if enumerated == 0 && celt >= 1 && rgelt != 0 {
                    // Return one fake shell browser window
                    if let Ok(obj_ptr) = self.create_com_object(ComClassId::ElevatedShellWindows) {
                        let _ = self.write_pointer_value(rgelt, obj_ptr);
                    }
                    // Update enumerated count
                    let _ = self.write_u32(this + ptr_size * 2, 1);
                    if pcelt_fetched != 0 {
                        let _ = self.write_u32(pcelt_fetched, 1);
                    }
                    Some(Ok(ERROR_SUCCESS)) // S_OK
                } else {
                    // No more elements
                    if pcelt_fetched != 0 {
                        let _ = self.write_u32(pcelt_fetched, 0);
                    }
                    Some(Ok(1)) // S_FALSE
                }
            }
            "IEnumUnknown_Skip" => {
                // IEnumUnknown::Skip — just succeed
                Some(Ok(ERROR_SUCCESS))
            }
            "IEnumUnknown_Reset" => {
                // IEnumUnknown::Reset(this) — reset enumeration
                let this = ctx.raw(0);
                let ptr_size = self.core.arch.pointer_size as u64;
                let _ = self.write_u32(this + ptr_size * 2, 0);
                Some(Ok(ERROR_SUCCESS))
            }
            "IEnumUnknown_Clone" => {
                // IEnumUnknown::Clone(this, IEnumUnknown **ppenum)
                let pp_enum = ctx.raw(1);
                if pp_enum != 0 {
                    if let Ok(obj_ptr) = self.create_enum_unknown() {
                        let _ = self.write_pointer_value(pp_enum, obj_ptr);
                    }
                }
                Some(Ok(ERROR_SUCCESS))
            }
            "ComMethodExtra6" => {
                // Elevated COM object vtable method called with 6 args.
                // The shellcode calls vtable[9] on the CoGetObject elevation
                // moniker result with (this, program, args, 0, 0, 0).
                let this = ctx.raw(0);
                let ptr_size = self.core.arch.pointer_size as u64;
                let class_id = self.read_u32(this + ptr_size).unwrap_or(0);
                let class = ComClassId::try_from(class_id).unwrap_or(ComClassId::MmcApplication);

                // Read arg1 (program name) and arg2 (command line) as strings
                let program = if ctx.argc() > 1 && ctx.raw(1) != 0 {
                    self.read_wide_string_from_memory(ctx.raw(1))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let params = if ctx.argc() > 2 && ctx.raw(2) != 0 {
                    self.read_wide_string_from_memory(ctx.raw(2))
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                if class == ComClassId::ElevatedMonikerObject && !program.is_empty() {
                    // This is the shellcode's execute call via the elevated COM object
                    let _ = self.log_com_event(
                        "ElevatedCom_Execute",
                        &format!("program={program} params_len={}", params.len()),
                        this,
                    );

                    // Record as a shell execution for structured output
                    let mut fields = serde_json::Map::new();
                    fields.insert(
                        "command".to_string(),
                        serde_json::Value::String(program.clone()),
                    );
                    if !params.is_empty() {
                        // Truncate for log readability but keep full content
                        let display_params = if params.len() > self.core.config.api_log_string_limit
                        {
                            format!(
                                "{}...[truncated, total {} chars]",
                                &params[..self.core.config.api_log_string_limit],
                                params.len()
                            )
                        } else {
                            params.clone()
                        };
                        fields.insert(
                            "parameters".to_string(),
                            serde_json::Value::String(display_params),
                        );
                    }
                    let _ = self.log_runtime_event("COM_SHELL_EXECUTE", fields);

                    self.record_process_operation(
                        "shell_execute",
                        Some(&program),
                        Some(&params),
                        None,
                    );
                } else if class == ComClassId::ElevatedShellWindows {
                    // Try last arg first, then second-to-last
                    for &out_arg in [ctx.raw(ctx.argc().saturating_sub(1)), ctx.raw(1)].iter() {
                        if out_arg != 0 {
                            if let Ok(obj_ptr) =
                                self.create_com_object(ComClassId::ElevatedShellWindows)
                            {
                                let _ = self.write_pointer_value(out_arg, obj_ptr);
                            }
                            break;
                        }
                    }
                } else {
                    let _ = self.log_com_event(function, "vtable_fallback", this);
                }
                Some(Ok(ERROR_SUCCESS))
            }
            "ComMethodExtra2" | "ComMethodExtra3" => {
                // Generic catch-all for unknown vtable methods beyond IShellWindows.
                // For elevated objects, write a fake COM object to the last arg
                // (typically the output interface pointer).
                let this = ctx.raw(0);
                let _ = self.log_com_event(function, "vtable_fallback", this);
                let ptr_size = self.core.arch.pointer_size as u64;
                let class_id = self.read_u32(this + ptr_size).unwrap_or(0);
                let class = ComClassId::try_from(class_id).unwrap_or(ComClassId::MmcApplication);
                if class == ComClassId::ElevatedShellWindows {
                    // Try last arg first, then second-to-last
                    for &out_arg in [ctx.raw(ctx.argc().saturating_sub(1)), ctx.raw(1)].iter() {
                        if out_arg != 0 {
                            if let Ok(obj_ptr) =
                                self.create_com_object(ComClassId::ElevatedShellWindows)
                            {
                                let _ = self.write_pointer_value(out_arg, obj_ptr);
                            }
                            break;
                        }
                    }
                }
                Some(Ok(ERROR_SUCCESS))
            }
            _ => None,
        }
    }

    fn com_query_interface(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        let this = ctx.raw(0);
        //ppv = ctx.raw(2);
        // For QueryInterface, just return the same pointer
        if ctx.argc() > 2 && ctx.raw(2) != 0 {
            self.write_pointer_value(ctx.raw(2), this)?;
        }
        Ok(ERROR_SUCCESS)
    }

    fn com_get_type_info_count(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        if ctx.argc() > 1 && ctx.raw(1) != 0 {
            self.write_u32(ctx.raw(1), 0)?;
        }
        Ok(ERROR_SUCCESS)
    }

    fn com_get_ids_of_names(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        // args: this, riid, rgszNames, cNames, lcid, rgDispId
        let rgsz_names = ctx.raw(2);
        let c_names = ctx.raw(3) as usize;
        let rg_dispid = ctx.raw(5);

        if rgsz_names == 0 || c_names == 0 || rg_dispid == 0 {
            return Ok(ERROR_SUCCESS);
        }

        let ptr_size = self.core.arch.pointer_size as u64;
        for i in 0..c_names {
            let name_ptr = if self.core.arch.is_x86() {
                self.read_u32(rgsz_names + ptr_size * i as u64)? as u64
            } else {
                self.read_pointer_value(rgsz_names + ptr_size * i as u64)?
            };
            let name = self
                .read_wide_string_from_memory(name_ptr)
                .unwrap_or_default();
            let dispid = self.resolve_dispid(&name);
            self.write_u32(rg_dispid + 4 * i as u64, dispid)?;
        }
        Ok(ERROR_SUCCESS)
    }

    /// Resolves a COM property/method name to a DISPID for our fake objects.
    fn resolve_dispid(&self, name: &str) -> u32 {
        match name.to_ascii_uppercase().as_str() {
            // MMC20.Application methods
            "DOCUMENT" => 100,
            "ACTIVEVIEW" => 101,
            "EXECUTESHELLCOMMAND" => 102,
            "EXECUTECOMMAND" => 103,
            "CLOSE" => 104,
            // ShellWindows / elevated COM methods
            "ITEM" => 200,
            "COUNT" => 201,
            "_NEWENUM" => 202,
            // ShellBrowserWindow / IWebBrowser2 methods
            "NAVIGATE" => 204,
            "QUIT" => 205,
            "FULLNAME" => 206,
            "NAME" => 207,
            "HWND" => 208,
            "VISIBLE" => 209,
            "SHELLFRAMEVIEW" => 210,
            "SHELLBROWSER" => 211,
            "APPLICATION" => 212,
            "PARENT" => 213,
            "LOCATIONURL" => 214,
            "LOCATIONNAME" => 215,
            _ => 0, // DISPID_UNKNOWN
        }
    }

    fn com_invoke(&mut self, ctx: &HookContext<'_>) -> Result<u64, VmError> {
        // args: this, dispidMember, riid, lcid, wFlags, pdispparams, pvarResult, pexcepinfo, puArgErr
        let this = ctx.raw(0);
        let dispid = ctx.raw(1) as u32;
        let w_flags = if ctx.argc() > 4 { ctx.raw(4) as u16 } else { 0 };
        let p_disp_params = ctx.raw(5);
        let p_var_result = ctx.raw(6);

        // Read class_id from the COM object
        let ptr_size = self.core.arch.pointer_size as u64;
        let class_id = self.read_u32(this + ptr_size)?;
        let class = ComClassId::try_from(class_id).unwrap_or(ComClassId::MmcApplication);

        match dispid {
            100 => {
                // "Document" property — return a new MmcDocument COM object
                if w_flags & DISPATCH_PROPERTYGET != 0 && p_var_result != 0 {
                    let doc_ptr = self.create_com_object(ComClassId::MmcDocument)?;
                    self.write_variant_pointer(p_var_result, doc_ptr)?;
                }
                Ok(ERROR_SUCCESS)
            }
            101 => {
                // "ActiveView" property — return a new MmcActiveView COM object
                if w_flags & DISPATCH_PROPERTYGET != 0 && p_var_result != 0 {
                    let view_ptr = self.create_com_object(ComClassId::MmcActiveView)?;
                    self.write_variant_pointer(p_var_result, view_ptr)?;
                }
                Ok(ERROR_SUCCESS)
            }
            102 | 103 => {
                // ExecuteShellCommand / ExecuteCommand
                self.handle_execute_shell_command(class, p_disp_params)?;
                Ok(ERROR_SUCCESS)
            }
            200 => {
                // ShellWindows::Item(index) — return a fake shell browser window
                if p_var_result != 0 {
                    let window_ptr = self.create_com_object(ComClassId::ElevatedShellWindows)?;
                    self.write_variant_pointer(p_var_result, window_ptr)?;
                }
                Ok(ERROR_SUCCESS)
            }
            201 => {
                // ShellWindows::Count — return 1
                if p_var_result != 0 {
                    let vt_i4: u16 = 3;
                    self.write_u16(p_var_result, vt_i4)?;
                    self.write_u32(p_var_result + 8, 1)?;
                }
                Ok(ERROR_SUCCESS)
            }
            202 => {
                // _NewEnum — not implemented, return error
                Ok(0x8000_4001) // E_NOTIMPL
            }
            203 | 204 | 205 | 206 | 207 | 208 | 209 | 210 | 211 | 212 | 213 | 214 | 215 => {
                // ShellBrowserWindow properties — return another fake object or empty
                if w_flags & DISPATCH_PROPERTYGET != 0 && p_var_result != 0 {
                    let obj_ptr = self.create_com_object(ComClassId::ElevatedShellWindows)?;
                    self.write_variant_pointer(p_var_result, obj_ptr)?;
                }
                Ok(ERROR_SUCCESS)
            }
            _ => {
                // Unknown DISPID
                self.log_com_event("IDispatch::Invoke", &format!("DISPID={dispid}"), this)?;
                Ok(0x8002_00AF) // DISP_E_MEMBERNOTFOUND
            }
        }
    }

    /// Handles the ExecuteShellCommand method — the key malicious behavior.
    fn handle_execute_shell_command(
        &mut self,
        _class: ComClassId,
        p_disp_params: u64,
    ) -> Result<(), VmError> {
        let (command, directory, parameters, _window_state) =
            self.read_execute_shell_command_args(p_disp_params)?;

        self.log_com_event(
            "MMC20.ExecuteShellCommand",
            &format!("cmd={command} dir={directory} params={parameters}"),
            0,
        )?;

        // Record as a process operation for the analysis output
        let mut fields = serde_json::Map::new();
        fields.insert(
            "command".to_string(),
            serde_json::Value::String(command.clone()),
        );
        if !directory.is_empty() {
            fields.insert(
                "directory".to_string(),
                serde_json::Value::String(directory),
            );
        }
        if !parameters.is_empty() {
            fields.insert(
                "parameters".to_string(),
                serde_json::Value::String(parameters.clone()),
            );
        }
        self.log_runtime_event("COM_SHELL_EXECUTE", fields)?;

        // Record in file operations for structured output
        self.record_process_operation("shell_execute", Some(&command), Some(&parameters), None);
        Ok(())
    }

    /// Reads the 4 arguments from a DISPPARAMS structure for ExecuteShellCommand.
    fn read_execute_shell_command_args(
        &mut self,
        p_disp_params: u64,
    ) -> Result<(String, String, String, u64), VmError> {
        if p_disp_params == 0 {
            return Ok((String::new(), String::new(), String::new(), 0));
        }

        let ptr_size = self.core.arch.pointer_size as u64;

        // DISPPARAMS layout:
        //   +0: rgvarg (pointer to array of VARIANTARG)
        //   +ptr: rgdispidNamedArgs
        //   +2*ptr: cArgs
        //   +3*ptr: cNamedArgs
        let rg_varg = if self.core.arch.is_x86() {
            self.read_u32(p_disp_params)? as u64
        } else {
            self.read_pointer_value(p_disp_params)?
        };
        let c_args = if self.core.arch.is_x86() {
            self.read_u32(p_disp_params + ptr_size * 2)? as u64
        } else {
            self.read_pointer_value(p_disp_params + ptr_size * 2)?
        };

        if rg_varg == 0 || c_args == 0 {
            return Ok((String::new(), String::new(), String::new(), 0));
        }

        // VARIANTARG layout (x86: 16 bytes, x64: 24 bytes)
        // +0: vt (u16)
        // +2: wReserved1 (u16)
        // +4: wReserved2 (u16)
        // +6: wReserved3 (u16)
        // +8: data (variant_data: pointer for VT_BSTR)
        let variant_size = if self.core.arch.is_x86() {
            16u64
        } else {
            24u64
        };
        let vt_bstr: u16 = 8;
        let vt_i4: u16 = 3;

        // Arguments are in reverse order in DISPPARAMS
        // ExecuteShellCommand(command, directory, parameters, windowState)
        let mut strings = Vec::new();
        let mut last_int = 0u64;
        for i in 0..c_args.min(4) {
            let variant_addr = rg_varg + variant_size * i;
            let vt = self.read_u16(variant_addr)?;
            let data_offset = if self.core.arch.is_x86() { 8u64 } else { 8u64 };
            if vt == vt_bstr {
                let bstr_ptr = if self.core.arch.is_x86() {
                    self.read_u32(variant_addr + data_offset)? as u64
                } else {
                    self.read_pointer_value(variant_addr + data_offset)?
                };
                let s = self.read_bstr_as_string(bstr_ptr)?;
                strings.push(s);
            } else if vt == vt_i4 {
                let val = self.read_u32(variant_addr + data_offset)? as u64;
                last_int = val;
                strings.push(format!("{val}"));
            } else {
                strings.push(String::new());
            }
        }
        // Reverse because DISPPARAMS stores args in reverse
        strings.reverse();

        let command = strings.get(0).cloned().unwrap_or_default();
        let directory = strings.get(1).cloned().unwrap_or_default();
        let parameters = strings.get(2).cloned().unwrap_or_default();

        Ok((command, directory, parameters, last_int))
    }

    /// Reads a BSTR and returns it as a String.
    fn read_bstr_as_string(&self, bstr_ptr: u64) -> Result<String, VmError> {
        if bstr_ptr == 0 {
            return Ok(String::new());
        }
        // BSTR layout: 4-byte length prefix, then UTF-16 data, then null terminator
        // The pointer points to the data, length is at pointer - 4
        let byte_len = self.read_u32(bstr_ptr - 4)? as usize;
        let char_len = byte_len / 2;
        let bytes = self.read_bytes_from_memory(bstr_ptr, byte_len)?;
        let mut result = String::new();
        for i in 0..char_len {
            let word = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            if word == 0 {
                break;
            }
            if let Some(c) = char::from_u32(word as u32) {
                result.push(c);
            }
        }
        Ok(result)
    }

    /// Writes a VT_DISPATCH VARIANT containing a COM object pointer.
    fn write_variant_pointer(&mut self, variant_addr: u64, ptr: u64) -> Result<(), VmError> {
        let vt_dispatch: u16 = 9;
        self.write_u16(variant_addr, vt_dispatch)?;
        // padding
        self.write_u16(variant_addr + 2, 0)?;
        self.write_u16(variant_addr + 4, 0)?;
        self.write_u16(variant_addr + 6, 0)?;
        // data at offset 8
        self.write_pointer_value(variant_addr + 8, ptr)?;
        Ok(())
    }

    fn log_com_event(&mut self, method: &str, detail: &str, this: u64) -> Result<(), VmError> {
        let mut fields = serde_json::Map::new();
        fields.insert(
            "method".to_string(),
            serde_json::Value::String(method.to_string()),
        );
        fields.insert(
            "detail".to_string(),
            serde_json::Value::String(detail.to_string()),
        );
        if this != 0 {
            fields.insert("this".to_string(), serde_json::json!(this));
        }
        self.log_runtime_event("COM_CALL", fields)
    }

    pub(super) fn dispatch_com_create_guid(&mut self, buffer: u64) -> Result<u64, VmError> {
        if buffer == 0 {
            Ok(E_INVALIDARG_HRESULT)
        } else {
            let guid = self.next_guid_bytes_le(4);
            self.core.modules.memory_mut().write(buffer, &guid)?;
            Ok(ERROR_SUCCESS)
        }
    }

    pub(super) fn dispatch_com_task_mem_realloc(
        &mut self,
        old_address: u64,
        new_size: u64,
    ) -> Result<u64, VmError> {
        if old_address == 0 {
            return self.alloc_process_heap_block(new_size.max(1), "CoTaskMemRealloc");
        }
        if new_size == 0 {
            let _ = self
                .process_memory
                .heaps
                .free(self.process_memory.heaps.process_heap(), old_address);
            return Ok(0);
        }
        let old_size = self
            .process_memory
            .heaps
            .size(self.process_memory.heaps.process_heap(), old_address);
        if old_size == u32::MAX as u64 {
            return Ok(0);
        }
        let new_address = self.alloc_process_heap_block(new_size, "CoTaskMemRealloc")?;
        let bytes = self.read_bytes_from_memory(old_address, old_size.min(new_size) as usize)?;
        self.core.modules.memory_mut().write(new_address, &bytes)?;
        let _ = self
            .process_memory
            .heaps
            .free(self.process_memory.heaps.process_heap(), old_address);
        Ok(new_address)
    }
}

impl TryFrom<u32> for ComClassId {
    type Error = ();
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ComClassId::MmcApplication),
            2 => Ok(ComClassId::MmcDocument),
            3 => Ok(ComClassId::MmcActiveView),
            4 => Ok(ComClassId::ElevatedShellWindows),
            5 => Ok(ComClassId::EnumUnknown),
            6 => Ok(ComClassId::ElevatedMonikerObject),
            _ => Err(()),
        }
    }
}

/// Parses a GUID string like `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` into
/// 16 bytes in the Windows GUID memory layout (little-endian for first three groups).
fn parse_guid_string_le(guid: &str) -> Option<[u8; 16]> {
    let trimmed = guid.trim().trim_matches(|ch| ch == '{' || ch == '}');
    let parts = trimmed.split('-').collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    let time_low = u32::from_str_radix(parts[0], 16).ok()?;
    let time_mid = u16::from_str_radix(parts[1], 16).ok()?;
    let time_hi = u16::from_str_radix(parts[2], 16).ok()?;
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
    bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
    bytes[6..8].copy_from_slice(&time_hi.to_le_bytes());
    bytes[8] = u8::from_str_radix(&parts[3][0..2], 16).ok()?;
    bytes[9] = u8::from_str_radix(&parts[3][2..4], 16).ok()?;
    for index in 0..6 {
        let start = index * 2;
        bytes[10 + index] = u8::from_str_radix(&parts[4][start..start + 2], 16).ok()?;
    }
    Some(bytes)
}

use super::*;

const MFC_OBJECT_POINTER_OFFSET: u64 = 0x30;
const MFC_CURRENT_POINTER_OFFSET: u64 = 0x38;
const MFC_END_POINTER_OFFSET: u64 = 0x40;
const MFC_OBJECT_HEADER_SIZE: u64 = 0x100;
const MFC_VTABLE_SIZE: u64 = 0xB0;
const MFC_MIN_SPARE_BYTES: u64 = 0x40;
const MFC_MIN_CAPACITY: u64 = 0x200;
const MFC_X64_LDR_DLL_BASE_OFFSET: u64 = 0x30;
const MFC_NATIVE_RESOLVER_HELPER_RVA: u64 = 0x1E6E;
const MFC_NATIVE_RESOLVER_STATE_OFFSET: u64 = 0x80;
const MFC_SMALL_STATE_PRIMARY_OFFSET: u64 = 0x00;
const MFC_SMALL_STATE_CURSOR_OFFSET: u64 = 0x08;
const MFC_SMALL_STATE_AUX_OFFSET: u64 = 0x10;
const MFC_SMALL_STATE_SIZE: u64 = 0x20;
const MFC_SERIALIZED_OBJECT_COPY_OFFSET: u64 = 0x08;
const MFC_SERIALIZED_OBJECT_COPY_SIZE: usize = 0x78;
const MFC_DEBUG_CHAIN_RVA_CABINET_DESCRIPTOR_READY: u64 = 0x26E8D;
const MFC_OBJECT_METHOD_40: &str = "__vm_mfc42u_object_method_40";
const MFC_OBJECT_METHOD_80: &str = "__vm_mfc42u_object_method_80";
const MFC_OBJECT_METHOD_A8: &str = "__vm_mfc42u_object_method_a8";
const MFC_ORDINAL_3997_CALLBACK: &str = "__vm_mfc42u_ordinal_3997_callback";

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn maybe_recover_mfc42u_cabinet_module_base(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<(), VmError> {
        if !self.core.arch.is_x64() || address == 0 {
            return Ok(());
        }
        let Some(module_base) = self
            .entry_module()
            .or_else(|| self.main_module())
            .map(|module| module.base)
        else {
            return Ok(());
        };
        if address.saturating_sub(module_base) != MFC_DEBUG_CHAIN_RVA_CABINET_DESCRIPTOR_READY {
            return Ok(());
        }

        let current_rax = unsafe { api.reg_read_raw(uc, UC_X86_REG_RAX) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(rax)",
                detail,
            }
        })?;
        if current_rax != 0 {
            return Ok(());
        }

        let loader_entry_slot =
            unsafe { api.reg_read_raw(uc, UC_X86_REG_RDX) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_read(rdx)",
                    detail,
                }
            })?;
        if loader_entry_slot == 0 {
            return Ok(());
        }

        let loader_entry = self.read_pointer_value(loader_entry_slot)?;
        if loader_entry == 0 {
            return Ok(());
        }
        let module_base = self.read_pointer_value(loader_entry + MFC_X64_LDR_DLL_BASE_OFFSET)?;
        if module_base == 0
            || !self
                .core
                .modules
                .get_by_base(module_base)
                .map(|module| module.name.eq_ignore_ascii_case("cabinet.dll"))
                .unwrap_or(false)
        {
            return Ok(());
        }

        unsafe { api.reg_write_raw(uc, UC_X86_REG_RAX, module_base) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(rax)",
                detail,
            }
        })?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn maybe_recover_mfc42u_native_resolver_argument(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<(), VmError> {
        if !self.core.arch.is_x64() || address == 0 {
            return Ok(());
        }
        let helper_address = self
            .entry_module()
            .or_else(|| self.main_module())
            .map(|module| module.base + MFC_NATIVE_RESOLVER_HELPER_RVA);
        if helper_address != Some(address) {
            return Ok(());
        }

        let current_r8 = unsafe { api.reg_read_raw(uc, UC_X86_REG_R8) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(r8)",
                detail,
            }
        })?;
        if current_r8 != 0 {
            return Ok(());
        }

        let object = unsafe { api.reg_read_raw(uc, UC_X86_REG_RCX) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(rcx)",
                detail,
            }
        })?;
        if !self.is_mfc42u_native_resolver_state(object)? {
            return Ok(());
        }

        let recovered = self.read_pointer_value(object + MFC_NATIVE_RESOLVER_STATE_OFFSET)?;
        if recovered == 0 {
            return Ok(());
        }
        unsafe { api.reg_write_raw(uc, UC_X86_REG_R8, recovered) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(r8)",
                detail,
            }
        })?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn dispatch_mfc42u_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("mfc42u.dll", "ordinal_620")
            | ("mfc42u.dll", "ordinal_622")
            | ("mfc42u.dll", "ordinal_624")
            | ("mfc42u.dll", "ordinal_625")
            | ("mfc42u.dll", "ordinal_626")
            | ("mfc42u.dll", "ordinal_799")
            | ("mfc42u.dll", "ordinal_966")
            | ("mfc42u.dll", "ordinal_1040")
            | ("mfc42u.dll", "ordinal_1122")
            | ("mfc42u.dll", "ordinal_1126")
            | ("mfc42u.dll", "ordinal_1284")
            | ("mfc42u.dll", "ordinal_1287")
            | ("mfc42u.dll", "ordinal_1559")
            | ("mfc42u.dll", "ordinal_1838")
            | ("mfc42u.dll", "ordinal_2827")
            | ("mfc42u.dll", "ordinal_3647")
            | ("mfc42u.dll", "ordinal_3997")
            | ("mfc42u.dll", "ordinal_4375")
            | ("mfc42u.dll", "ordinal_6331")
            | ("mfc42u.dll", "ordinal_6772")
            | ("mfc42u.dll", "ordinal_6415")
            | ("mfc42u.dll", "ordinal_6416")
            | ("mfc42u.dll", "__vm_mfc42u_ordinal_3997_callback")
            | ("mfc42u.dll", "__vm_mfc42u_object_method_40")
            | ("mfc42u.dll", "__vm_mfc42u_object_method_80")
            | ("mfc42u.dll", "__vm_mfc42u_object_method_a8") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "ordinal_620" => self.mfc42u_attach_or_copy_small_state(ctx.raw(0), ctx.raw(1)),
                "ordinal_622" => {
                    self.mfc42u_prepare_small_state_and_report_status(ctx.raw(0), ctx.raw(1))
                }
                "ordinal_624" => self.mfc42u_read_small_state_char(ctx.raw(0), ctx.raw(1)),
                "ordinal_625" => self.mfc42u_seed_small_state(ctx.raw(0), ctx.raw(1), ctx.raw(2)),
                "ordinal_626" => self.mfc42u_construct_small_state(ctx.raw(0)),
                "ordinal_799" => self.mfc42u_return_this(ctx.raw(0)),
                "ordinal_966" => self.mfc42u_return_this(ctx.raw(0)),
                "ordinal_1040" => self.mfc42u_destruct_small_state(ctx.raw(0)),
                "ordinal_1122" => self.mfc42u_attach_small_state(ctx.raw(0), ctx.raw(1)),
                "ordinal_1126" => self.mfc42u_attach_small_state(ctx.raw(0), ctx.raw(1)),
                "ordinal_1284" => self.mfc42u_attach_small_state(ctx.raw(0), ctx.raw(1)),
                "ordinal_1287" => self.mfc42u_attach_small_state(ctx.raw(0), ctx.raw(1)),
                "ordinal_1559" => Ok(0),
                "ordinal_1838" => self.mfc42u_return_this(ctx.raw(0)),
                "ordinal_2827" => self.mfc42u_ensure_object_buffer(ctx.raw(0)),
                "ordinal_3647" => Ok(ctx.raw(0)),
                "ordinal_3997" => self.mfc42u_resolve_ordinal_3997(ctx.raw(0), ctx.raw(1)),
                "ordinal_4375" => {
                    self.mfc42u_attach_native_resolver_payload(ctx.raw(0), ctx.raw(1))
                }
                "ordinal_6331" => self.mfc42u_return_this(ctx.raw(0)),
                "ordinal_6772" => self.mfc42u_return_this(ctx.raw(0)),
                "ordinal_6415" => Ok(0),
                "ordinal_6416" => Ok(0),
                "__vm_mfc42u_ordinal_3997_callback" => Ok(0),
                "__vm_mfc42u_object_method_40" => {
                    self.mfc42u_dispatch_object_method_40(ctx.raw(0), ctx.raw(1))
                }
                "__vm_mfc42u_object_method_80" => {
                    self.mfc42u_dispatch_object_method_80(ctx.raw(0), ctx.raw(1), ctx.raw(2))
                }
                "__vm_mfc42u_object_method_a8" => Ok(0),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }

    fn ensure_mfc42u_ordinal_3997_callback_stub(&mut self) -> u64 {
        self.core
            .hooks
            .binding_address("mfc42u.dll", MFC_ORDINAL_3997_CALLBACK)
            .unwrap_or_else(|| self.bind_hook_for_test("mfc42u.dll", MFC_ORDINAL_3997_CALLBACK))
    }

    fn mfc42u_write_x64_rcx(&mut self, value: u64) -> Result<(), VmError> {
        if !self.core.arch.is_x64() || !unicorn_context_active() {
            return Ok(());
        }
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        unsafe { api.reg_write_raw(uc, UC_X86_REG_RCX, value) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(rcx)",
                detail,
            }
        })?;
        Ok(())
    }

    fn mfc42u_return_this(&mut self, value: u64) -> Result<u64, VmError> {
        self.mfc42u_write_x64_rcx(value)?;
        Ok(value)
    }

    fn mfc42u_clear_small_state(&mut self, address: u64) -> Result<(), VmError> {
        if address != 0 {
            self.core
                .modules
                .memory_mut()
                .write(address, &vec![0u8; MFC_SMALL_STATE_SIZE as usize])?;
        }
        Ok(())
    }

    fn mfc42u_store_small_state(
        &mut self,
        address: u64,
        value: u64,
        aux: u64,
    ) -> Result<(), VmError> {
        if address == 0 {
            return Ok(());
        }
        self.mfc42u_clear_small_state(address)?;
        self.write_pointer_value(address + MFC_SMALL_STATE_PRIMARY_OFFSET, value)?;
        self.write_pointer_value(address + MFC_SMALL_STATE_CURSOR_OFFSET, value)?;
        self.write_pointer_value(address + MFC_SMALL_STATE_AUX_OFFSET, aux)?;
        Ok(())
    }

    fn mfc42u_construct_small_state(&mut self, address: u64) -> Result<u64, VmError> {
        self.mfc42u_clear_small_state(address)?;
        Ok(address)
    }

    fn mfc42u_destruct_small_state(&mut self, address: u64) -> Result<u64, VmError> {
        self.mfc42u_clear_small_state(address)?;
        Ok(0)
    }

    fn mfc42u_attach_small_state(&mut self, address: u64, value: u64) -> Result<u64, VmError> {
        self.mfc42u_store_small_state(address, value, 0)?;
        Ok(0)
    }

    fn mfc42u_prepare_small_state_and_report_status(
        &mut self,
        address: u64,
        value: u64,
    ) -> Result<u64, VmError> {
        self.mfc42u_store_small_state(address, value, 0x8000)?;
        Ok(0x8000)
    }

    fn mfc42u_seed_small_state(
        &mut self,
        address: u64,
        value: u64,
        aux: u64,
    ) -> Result<u64, VmError> {
        self.mfc42u_store_small_state(address, value, aux)?;
        Ok(value)
    }

    fn mfc42u_attach_or_copy_small_state(
        &mut self,
        address: u64,
        value: u64,
    ) -> Result<u64, VmError> {
        if address != 0
            && value != 0
            && self
                .core
                .modules
                .memory()
                .is_range_mapped(address + MFC_SERIALIZED_OBJECT_COPY_OFFSET, 0x10)
            && self
                .core
                .modules
                .memory()
                .is_range_mapped(value + MFC_SERIALIZED_OBJECT_COPY_OFFSET, 0x10)
        {
            let bytes = self.read_bytes_from_memory(
                address + MFC_SERIALIZED_OBJECT_COPY_OFFSET,
                MFC_SERIALIZED_OBJECT_COPY_SIZE,
            )?;
            self.core
                .modules
                .memory_mut()
                .write(value + MFC_SERIALIZED_OBJECT_COPY_OFFSET, &bytes)?;
            self.write_pointer_value(value + MFC_SMALL_STATE_PRIMARY_OFFSET, address)?;
            return Ok(address);
        }

        self.mfc42u_store_small_state(address, value, 0)?;
        Ok(address)
    }

    fn mfc42u_write_small_state_char_result(&mut self, value: u8) -> Result<(), VmError> {
        self.mfc42u_write_x64_rcx(u64::from(value))
    }

    fn mfc42u_read_small_state_char(&mut self, address: u64, mirror: u64) -> Result<u64, VmError> {
        let mut cursor = 0u64;
        if address != 0 {
            cursor = self.read_pointer_value(address + MFC_SMALL_STATE_CURSOR_OFFSET)?;
            if cursor == 0 {
                cursor = self.read_pointer_value(address + MFC_SMALL_STATE_PRIMARY_OFFSET)?;
            }
        }
        if cursor == 0 || !self.core.modules.memory().is_range_mapped(cursor, 1) {
            self.mfc42u_write_small_state_char_result(0)?;
            return Ok(0);
        }

        let value = self.read_u8(cursor)?;
        if value != 0 && address != 0 {
            self.write_pointer_value(address + MFC_SMALL_STATE_CURSOR_OFFSET, cursor + 1)?;
        }
        if mirror != 0 && self.core.modules.memory().is_range_mapped(mirror, 8) {
            self.write_pointer_value(mirror, cursor + u64::from(value != 0))?;
        }
        self.mfc42u_write_small_state_char_result(value)?;
        Ok(u64::from(value))
    }

    fn mfc42u_resolve_ordinal_3997(
        &mut self,
        callback_state: u64,
        status_state: u64,
    ) -> Result<u64, VmError> {
        let callback = self.ensure_mfc42u_ordinal_3997_callback_stub();
        // Write only the callback function pointer (first pointer-sized slot).
        // Do NOT zero the full 0x20-byte buffer — the sample passes a stack
        // address that overlaps with saved nonvolatile registers (rsi, rbx,
        // return address) of an outer frame.  Zeroing the buffer destroys
        // those values and causes a null return-address crash in the shared
        // epilogue.
        if callback_state != 0
            && self
                .core
                .modules
                .memory()
                .is_range_mapped(callback_state, self.core.arch.pointer_size as u64)
        {
            self.write_pointer_value(callback_state, callback)?;
        }
        // Same caution for status_state: do not zero the full buffer because
        // the caller may pass a stack address that overlaps with live data.
        if status_state != 0
            && self
                .core
                .modules
                .memory()
                .is_range_mapped(status_state, self.core.arch.pointer_size as u64)
        {
            self.write_pointer_value(status_state, 0)?;
        }
        Ok(callback)
    }

    fn mfc42u_attach_native_resolver_payload(
        &mut self,
        object: u64,
        value: u64,
    ) -> Result<u64, VmError> {
        if object != 0
            && self.core.modules.memory().is_range_mapped(
                object + MFC_NATIVE_RESOLVER_STATE_OFFSET,
                self.core.arch.pointer_size as u64,
            )
        {
            self.write_pointer_value(object + MFC_NATIVE_RESOLVER_STATE_OFFSET, value)?;
        }
        Ok(0)
    }

    fn mfc42u_ensure_object_buffer(&mut self, owner: u64) -> Result<u64, VmError> {
        if owner == 0 {
            return Ok(0);
        }

        let object = self.read_pointer_value(owner + MFC_OBJECT_POINTER_OFFSET)?;
        let mut current = self.read_pointer_value(owner + MFC_CURRENT_POINTER_OFFSET)?;
        let mut end = self.read_pointer_value(owner + MFC_END_POINTER_OFFSET)?;
        let mut used = 0u64;
        let mut vtable = 0u64;

        if object != 0 {
            vtable = self.read_pointer_value(object)?;
            let data_start = object + MFC_OBJECT_HEADER_SIZE;
            if current >= data_start && end >= current {
                used = current.saturating_sub(data_start);
                if end.saturating_sub(current) >= MFC_MIN_SPARE_BYTES {
                    return Ok(owner);
                }
            } else {
                current = 0;
                end = 0;
            }
        }

        if vtable == 0 {
            vtable = self.mfc42u_allocate_object_vtable()?;
        }

        let mut capacity = end
            .saturating_sub(object.saturating_add(MFC_OBJECT_HEADER_SIZE))
            .max(MFC_MIN_CAPACITY);
        capacity = capacity.max(used.saturating_add(MFC_MIN_SPARE_BYTES));
        if capacity < used.saturating_add(MFC_MIN_SPARE_BYTES) {
            capacity = used.saturating_add(MFC_MIN_SPARE_BYTES);
        }
        if capacity < MFC_MIN_CAPACITY {
            capacity = MFC_MIN_CAPACITY;
        }
        if object != 0 {
            capacity = capacity.saturating_mul(2);
        }

        let block = self
            .alloc_process_heap_block(MFC_OBJECT_HEADER_SIZE + capacity, "mfc42u:object_buffer")?;
        self.write_pointer_value(block, vtable)?;

        if object != 0 && used != 0 && current != 0 {
            let data_start = object + MFC_OBJECT_HEADER_SIZE;
            let bytes = self.read_bytes_from_memory(data_start, used as usize)?;
            self.core
                .modules
                .memory_mut()
                .write(block + MFC_OBJECT_HEADER_SIZE, &bytes)?;
        }

        self.write_pointer_value(owner + MFC_OBJECT_POINTER_OFFSET, block)?;
        self.write_pointer_value(
            owner + MFC_CURRENT_POINTER_OFFSET,
            block + MFC_OBJECT_HEADER_SIZE + used,
        )?;
        self.write_pointer_value(
            owner + MFC_END_POINTER_OFFSET,
            block + MFC_OBJECT_HEADER_SIZE + capacity,
        )?;
        Ok(owner)
    }

    fn mfc42u_allocate_object_vtable(&mut self) -> Result<u64, VmError> {
        let vtable = self.alloc_process_heap_block(MFC_VTABLE_SIZE, "mfc42u:vtable")?;
        let module_base = self
            .core
            .modules
            .get_loaded("mfc42u.dll")
            .map(|module| module.base)
            .ok_or(VmError::RuntimeInvariant(
                "mfc42u.dll not loaded for synthetic object vtable",
            ))?;
        let method_40 = self.core.modules.resolve_export(
            module_base,
            &self.core.config,
            &mut self.core.hooks,
            Some(MFC_OBJECT_METHOD_40),
            None,
        );
        let method_80 = self.core.modules.resolve_export(
            module_base,
            &self.core.config,
            &mut self.core.hooks,
            Some(MFC_OBJECT_METHOD_80),
            None,
        );
        let method_a8 = self.core.modules.resolve_export(
            module_base,
            &self.core.config,
            &mut self.core.hooks,
            Some(MFC_OBJECT_METHOD_A8),
            None,
        );
        self.write_pointer_value(vtable + 0x40, method_40)?;
        self.write_pointer_value(vtable + 0x80, method_80)?;
        self.write_pointer_value(vtable + 0xA8, method_a8)?;
        Ok(vtable)
    }

    fn mfc42u_dispatch_object_method_40(
        &mut self,
        object: u64,
        _state: u64,
    ) -> Result<u64, VmError> {
        let module_base = self
            .entry_module()
            .or_else(|| self.main_module())
            .map(|module| module.base)
            .ok_or(VmError::RuntimeInvariant(
                "execution module missing for mfc42u object dispatch",
            ))?;
        if self.core.arch.is_x64() && unicorn_context_active() {
            let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
            let api = unsafe { &*api_ptr };
            unsafe { api.reg_write_raw(uc, UC_X86_REG_R8, module_base) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_write(r8)",
                    detail,
                }
            })?;
        }
        Ok(if object != 0 { module_base } else { 0 })
    }

    fn mfc42u_dispatch_object_method_80(
        &mut self,
        object: u64,
        value: u64,
        _len: u64,
    ) -> Result<u64, VmError> {
        if object != 0 {
            self.write_pointer_value(object + 8, value)?;
        }
        Ok(object)
    }

    fn is_mfc42u_native_resolver_state(&mut self, object: u64) -> Result<bool, VmError> {
        if object == 0 {
            return Ok(false);
        }
        let Some(load_dll) = self.core.hooks.binding_address("ntdll.dll", "LdrLoadDll") else {
            return Ok(false);
        };
        let Some(create_unicode) = self
            .core
            .hooks
            .binding_address("ntdll.dll", "RtlCreateUnicodeStringFromAsciiz")
        else {
            return Ok(false);
        };
        let Some(find_entry) = self
            .core
            .hooks
            .binding_address("ntdll.dll", "LdrFindEntryForAddress")
        else {
            return Ok(false);
        };

        Ok(self.read_pointer_value(object)? == load_dll
            && self.read_pointer_value(object + 0x8)? == create_unicode
            && self.read_pointer_value(object + 0x10)? == find_entry)
    }
}

use super::*;

impl VirtualExecutionEngine {
    pub(super) fn dispatch_x64_seh_fault_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_rsp = registers.rsp;
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let scratch_end = fault_rsp & !0x0Fu64;
        let scratch_start = match scratch_end.checked_sub(X64_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x40) => value,
            _ => return Ok(false),
        };
        let exception_record = align_up_u64(scratch_start + 0x40, 0x10);
        let context_record = align_up_u64(
            exception_record + X64_EXCEPTION_RECORD_SIZE as u64 + 0x20,
            0x10,
        );
        let dispatcher_context =
            align_up_u64(context_record + X64_CONTEXT_SIZE as u64 + 0x20, 0x10);
        let scratch_size = usize::try_from(
            dispatcher_context
                .saturating_add(X64_DISPATCHER_CONTEXT_SIZE as u64)
                .saturating_sub(scratch_start),
        )
        .map_err(|_| VmError::RuntimeInvariant("x64 SEH scratch frame too large"))?;
        self.core
            .modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x64_exception_record(exception_record, fault)?;
        self.write_x64_context_record(context_record, &registers)?;
        self.log_x64_seh_dispatch(fault, exception_record, context_record)?;
        let exception_code = self.read_u32(exception_record)?;

        let mut working = registers;
        let mut visited = BTreeSet::new();
        for _ in 0..64usize {
            let control_pc = working.rip;
            let current_rsp = working.rsp;
            if current_rsp == 0 {
                return Ok(false);
            }
            if control_pc == self.core.native_return_sentinel {
                if self.exception.top_level_exception_filter != 0
                    && !self.exception.dispatching_top_level_exception_filter
                {
                    self.exception.pending_x64_top_level_filter_seed = Some(working);
                    return Ok(false);
                }
                let mut terminated = working;
                terminated.rip = self.core.native_return_sentinel;
                terminated.rax = u64::from(exception_code);
                self.log_x64_seh_unhandled(exception_code, control_pc, current_rsp)?;
                self.restore_unicorn_thread_registers(api, uc, &terminated)?;
                return Ok(true);
            }
            if !visited.insert((control_pc, current_rsp)) {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: format!(
                        "x64 SEH unwind cycle at pc=0x{control_pc:X} rsp=0x{current_rsp:X}"
                    ),
                });
            }

            let unwind = if control_pc == 0 {
                self.x64_virtual_unwind_null_pc_context(&working)?
            } else {
                self.x64_virtual_unwind_context(control_pc, &working, X64_UNW_FLAG_EHANDLER)?
            };
            let Some(unwind) = unwind else {
                return Ok(false);
            };
            self.write_x64_dispatcher_context(
                dispatcher_context,
                control_pc,
                unwind.image_base,
                unwind.function_entry_address,
                unwind.establisher_frame,
                context_record,
                unwind.handler_address.unwrap_or(0),
                unwind.handler_data_address.unwrap_or(0),
            )?;
            self.log_x64_seh_frame(
                control_pc,
                unwind.function_entry_address,
                unwind.unwind_info_address,
                unwind.establisher_frame,
                unwind.handler_address,
                unwind.handler_data_address,
                unwind.flags,
                unwind.leaf,
                unwind.caller_context.rip,
                unwind.caller_context.rsp,
            )?;

            // Log suspicious nonvolatile restores after each unwind step.
            // Small non-zero values in saved registers often indicate stack corruption.
            let caller_rbx = unwind.caller_context.rbx;
            if caller_rbx != 0 && caller_rbx < 0x1000 {
                let control_pc_val = working.rip;
                self.log_x64_seh_unwind_suspicious(
                    control_pc_val,
                    unwind.establisher_frame,
                    "rbx",
                    caller_rbx,
                    &unwind.caller_context,
                )?;
            }

            if let Some(handler) = unwind.handler_address {
                let handler_rflags = if working.rflags != 0 {
                    working.rflags
                } else {
                    0x202
                };
                let disposition = if let Some(disposition) = self.dispatch_x64_bound_handler(
                    handler,
                    exception_record,
                    unwind.establisher_frame,
                    context_record,
                    dispatcher_context,
                    &working,
                    scratch_end,
                    handler_rflags,
                )? {
                    disposition
                } else {
                    self.restore_unicorn_thread_registers(api, uc, &working)?;
                    self.call_x64_native_with_unicorn_context(
                        handler,
                        &[
                            exception_record,
                            unwind.establisher_frame,
                            context_record,
                            dispatcher_context,
                        ],
                        scratch_end,
                        handler_rflags,
                        NativeCallRunMode::Standalone,
                        false,
                    )? as u32
                };
                self.log_seh_handler(unwind.function_entry_address, handler, disposition)?;
                match disposition {
                    EXCEPTION_CONTINUE_EXECUTION => {
                        let restored = deserialize_register_context(
                            self.core.modules.memory(),
                            self.core.arch,
                            context_record,
                        )?;
                        self.log_seh_resume(context_record, &restored)?;
                        self.restore_unicorn_thread_registers(api, uc, &restored)?;
                        return Ok(true);
                    }
                    EXCEPTION_CONTINUE_SEARCH => {
                        working = unwind.caller_context;
                        continue;
                    }
                    _ => {
                        return Err(VmError::NativeExecution {
                            op: "seh",
                            detail: format!(
                                "unsupported x64 SEH disposition {disposition} from handler 0x{handler:X}"
                            ),
                        });
                    }
                }
            }

            working = unwind.caller_context;
        }

        Err(VmError::NativeExecution {
            op: "seh",
            detail: "x64 SEH unwind exceeded 64 frames".to_string(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_x64_bound_handler(
        &mut self,
        handler: u64,
        exception_record: u64,
        establisher_frame: u64,
        context_record: u64,
        dispatcher_context: u64,
        frame_context: &RegisterFile,
        handler_stack_top: u64,
        handler_rflags: u64,
    ) -> Result<Option<u32>, VmError> {
        let Some(bound) = self.resolve_bound_exception_handler(handler)? else {
            return Ok(None);
        };
        if bound.0 == "msvcrt.dll" && bound.1 == "__c_specific_handler" {
            return self
                .dispatch_x64_c_specific_handler(
                    exception_record,
                    establisher_frame,
                    context_record,
                    dispatcher_context,
                    frame_context,
                    handler_stack_top,
                    handler_rflags,
                )
                .map(Some);
        }
        if bound.0 == "msvcrt.dll" && bound.1 == "__cxxframehandler3" {
            return Ok(Some(EXCEPTION_CONTINUE_SEARCH));
        }
        Ok(None)
    }

    pub(super) fn resolve_bound_exception_handler(
        &self,
        address: u64,
    ) -> Result<Option<(String, String)>, VmError> {
        if let Some(bound) = self.core.hooks.bound_lookup(address) {
            return Ok(Some((bound.module.to_string(), bound.function.to_string())));
        }
        let Ok(bytes) = self.read_bytes_from_memory(address, 6) else {
            return Ok(None);
        };
        if bytes.len() != 6 || bytes[0] != 0xFF || bytes[1] != 0x25 {
            return Ok(None);
        }
        let displacement = i32::from_le_bytes(bytes[2..6].try_into().unwrap()) as i64;
        let slot = address
            .checked_add(6)
            .and_then(|next| next.checked_add_signed(displacement))
            .ok_or(VmError::NativeExecution {
                op: "seh",
                detail: format!("x64 import thunk overflow while resolving 0x{address:X}"),
            })?;
        let target = self.read_pointer_value(slot)?;
        Ok(self
            .core
            .hooks
            .bound_lookup(target)
            .map(|bound| (bound.module.to_string(), bound.function.to_string())))
    }

    pub(super) fn dispatch_x64_c_specific_handler(
        &mut self,
        exception_record: u64,
        establisher_frame: u64,
        context_record: u64,
        dispatcher_context: u64,
        frame_context: &RegisterFile,
        handler_stack_top: u64,
        handler_rflags: u64,
    ) -> Result<u32, VmError> {
        let exception_flags = self.read_u32(exception_record + 0x04)?;
        // Unwind / termination handling is still conservative. Search-phase filters are what the
        // current samples rely on.
        if exception_flags != 0 {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }
        let image_base = self.read_pointer_value(dispatcher_context + 0x08)?;
        let control_pc = self.read_pointer_value(dispatcher_context + 0x00)?;
        let handler_data = self.read_pointer_value(dispatcher_context + 0x38)?;
        if image_base == 0 || handler_data == 0 || control_pc < image_base {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }
        let control_rva = u32::try_from(control_pc.saturating_sub(image_base)).map_err(|_| {
            VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "x64 __C_specific_handler control pc 0x{control_pc:X} out of range"
                ),
            }
        })?;
        let scope_records = self.read_x64_scope_records(handler_data)?;
        if scope_records.is_empty() {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }

        let exception_pointers = align_up_u64(
            dispatcher_context + X64_DISPATCHER_CONTEXT_SIZE as u64 + 0x10,
            0x10,
        );
        self.core
            .modules
            .memory_mut()
            .write(exception_pointers, &vec![0u8; X64_EXCEPTION_POINTERS_SIZE])?;
        self.write_pointer_value(exception_pointers + 0x00, exception_record)?;
        self.write_pointer_value(exception_pointers + 0x08, context_record)?;

        for record in scope_records {
            if control_rva < record.begin_rva || control_rva >= record.end_rva {
                continue;
            }
            if record.jump_target == 0 {
                continue;
            }
            let filter = image_base + record.handler_rva as u64;
            let filter_result = self.call_x64_native_with_unicorn_context(
                filter,
                &[exception_pointers, establisher_frame],
                handler_stack_top,
                handler_rflags,
                NativeCallRunMode::Standalone,
                false,
            )? as u32;
            let filter_result_signed = filter_result as i32;
            if filter_result_signed < 0 {
                return Ok(EXCEPTION_CONTINUE_EXECUTION);
            }
            if filter_result_signed == 0 {
                continue;
            }

            let mut resume_context = *frame_context;
            resume_context.rip = image_base + record.jump_target as u64;
            resume_context.rsp = establisher_frame;
            self.write_x64_context_record(context_record, &resume_context)?;
            return Ok(EXCEPTION_CONTINUE_EXECUTION);
        }

        Ok(EXCEPTION_CONTINUE_SEARCH)
    }

    pub(super) fn read_x64_scope_records(
        &self,
        handler_data: u64,
    ) -> Result<Vec<X64ScopeRecord>, VmError> {
        let count = self.read_u32(handler_data)? as usize;
        if count == 0 || count > 64 {
            return Ok(Vec::new());
        }
        let mut records = Vec::with_capacity(count);
        let mut cursor = handler_data + 4;
        for _ in 0..count {
            records.push(X64ScopeRecord {
                begin_rva: self.read_u32(cursor)?,
                end_rva: self.read_u32(cursor + 4)?,
                handler_rva: self.read_u32(cursor + 8)?,
                jump_target: self.read_u32(cursor + 12)?,
            });
            cursor += 16;
        }
        Ok(records)
    }

    pub(in crate::runtime::engine) fn lookup_x64_runtime_function_entry(
        &self,
        control_pc: u64,
    ) -> Result<Option<X64RuntimeFunctionLookup>, VmError> {
        let Some(module) = self.core.modules.get_by_address(control_pc) else {
            return Ok(None);
        };
        let Some(function) = self.lookup_x64_runtime_function_in_module(module, control_pc)? else {
            return Ok(None);
        };
        Ok(Some(X64RuntimeFunctionLookup {
            image_base: module.base,
            function_entry_address: function.entry_address,
        }))
    }

    pub(in crate::runtime::engine) fn rtl_virtual_unwind(
        &mut self,
        handler_type: u64,
        image_base: u64,
        control_pc: u64,
        function_entry: u64,
        context_record: u64,
        handler_data_out: u64,
        establisher_frame_out: u64,
    ) -> Result<u64, VmError> {
        if !self.core.arch.is_x64() || context_record == 0 {
            if handler_data_out != 0 {
                self.write_pointer_value(handler_data_out, 0)?;
            }
            if establisher_frame_out != 0 {
                self.write_pointer_value(establisher_frame_out, 0)?;
            }
            return Ok(0);
        }

        let registers = deserialize_register_context(
            self.core.modules.memory(),
            self.core.arch,
            context_record,
        )?;
        let control_pc = if control_pc != 0 {
            control_pc
        } else {
            registers.rip
        };
        let unwind = self.x64_virtual_unwind_context_with_module_hint(
            control_pc,
            image_base,
            function_entry,
            &registers,
            handler_type as u8,
        )?;
        let Some(unwind) = unwind else {
            if handler_data_out != 0 {
                self.write_pointer_value(handler_data_out, 0)?;
            }
            if establisher_frame_out != 0 {
                self.write_pointer_value(establisher_frame_out, 0)?;
            }
            return Ok(0);
        };

        self.write_x64_context_record(context_record, &unwind.caller_context)?;
        if handler_data_out != 0 {
            self.write_pointer_value(handler_data_out, unwind.handler_data_address.unwrap_or(0))?;
        }
        if establisher_frame_out != 0 {
            self.write_pointer_value(establisher_frame_out, unwind.establisher_frame)?;
        }
        Ok(unwind.handler_address.unwrap_or(0))
    }

    pub(super) fn lookup_x64_runtime_function_in_module(
        &self,
        module: &ModuleRecord,
        control_pc: u64,
    ) -> Result<Option<X64RuntimeFunction>, VmError> {
        let Some((table_base, table_size)) = self.x64_exception_directory(module)? else {
            return Ok(None);
        };
        if control_pc < module.base || control_pc >= module.base.saturating_add(module.size) {
            return Ok(None);
        }
        let control_rva = u32::try_from(control_pc.saturating_sub(module.base)).map_err(|_| {
            VmError::NativeExecution {
                op: "seh",
                detail: format!("control pc 0x{control_pc:X} is outside x64 RVA space"),
            }
        })?;
        let entry_count = usize::try_from(table_size / 12).unwrap_or(0);
        let mut low = 0usize;
        let mut high = entry_count;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry_address = table_base + mid as u64 * 12;
            let begin_rva = self.read_u32(entry_address)?;
            let end_rva = self.read_u32(entry_address + 4)?;
            if control_rva < begin_rva {
                high = mid;
            } else if control_rva >= end_rva {
                low = mid + 1;
            } else {
                let unwind_rva = self.read_u32(entry_address + 8)?;
                return Ok(Some(X64RuntimeFunction {
                    entry_address,
                    begin_rva,
                    end_rva,
                    unwind_rva,
                }));
            }
        }
        Ok(None)
    }

    pub(super) fn x64_exception_directory(
        &self,
        module: &ModuleRecord,
    ) -> Result<Option<(u64, u32)>, VmError> {
        if module.synthetic || module.base == 0 {
            return Ok(None);
        }
        let e_lfanew = self.read_u32(module.base + 0x3C)? as u64;
        let optional_header = module.base + e_lfanew + 4 + 20;
        let magic = self.read_u16(optional_header)?;
        if magic != 0x20B {
            return Ok(None);
        }
        let number_of_rva_and_sizes = self.read_u32(optional_header + 0x6C)?;
        if number_of_rva_and_sizes <= 3 {
            return Ok(None);
        }
        let directory = optional_header + 0x70 + 3 * 8;
        let rva = self.read_u32(directory)?;
        let size = self.read_u32(directory + 4)?;
        if rva == 0 || size < 12 {
            return Ok(None);
        }
        Ok(Some((module.base + rva as u64, size)))
    }

    pub(super) fn x64_virtual_unwind_context(
        &self,
        control_pc: u64,
        registers: &RegisterFile,
        handler_mask: u8,
    ) -> Result<Option<X64VirtualUnwindResult>, VmError> {
        self.x64_virtual_unwind_context_with_module_hint(control_pc, 0, 0, registers, handler_mask)
    }

    pub(super) fn x64_virtual_unwind_null_pc_context(
        &self,
        registers: &RegisterFile,
    ) -> Result<Option<X64VirtualUnwindResult>, VmError> {
        let rsp = registers.rsp;
        if rsp == 0 {
            return Ok(None);
        }
        let Some(region) = self.core.modules.memory().find_region(rsp, 1) else {
            return Ok(None);
        };

        let scan_end = region.end().min(
            rsp.saturating_add(X64_NULL_PC_CONTINUATION_SCAN_WINDOW)
                .saturating_add(8),
        );
        let mut first_executable_slot = None;
        let mut slot = rsp;
        while slot < scan_end {
            let candidate = self.read_pointer_value(slot)?;
            if candidate == self.core.native_return_sentinel
                || self.lookup_x64_runtime_function_entry(candidate)?.is_some()
            {
                return Ok(Some(
                    self.x64_leaf_unwind_result(registers, rsp, slot, candidate),
                ));
            }
            if first_executable_slot.is_none() && self.x64_is_executable_continuation(candidate) {
                first_executable_slot = Some((slot, candidate));
            }
            slot = slot.saturating_add(8);
        }

        Ok(first_executable_slot
            .map(|(slot, candidate)| self.x64_leaf_unwind_result(registers, rsp, slot, candidate)))
    }

    pub(super) fn x64_virtual_unwind_context_with_module_hint(
        &self,
        control_pc: u64,
        image_base_hint: u64,
        function_entry_hint: u64,
        registers: &RegisterFile,
        handler_mask: u8,
    ) -> Result<Option<X64VirtualUnwindResult>, VmError> {
        let hinted_module = if image_base_hint != 0 {
            self.core.modules.get_by_base(image_base_hint)
        } else {
            None
        };
        let module = hinted_module.or_else(|| self.core.modules.get_by_address(control_pc));
        if let Some(module) = module {
            let function = if function_entry_hint != 0 {
                Some(self.read_x64_runtime_function(function_entry_hint)?)
            } else {
                self.lookup_x64_runtime_function_in_module(module, control_pc)?
            };
            if let Some(function) = function {
                let unwind = self.parse_x64_unwind_info(module, &function, 0)?;
                let control_offset =
                    control_pc.saturating_sub(module.base + function.begin_rva as u64) as u32;
                let in_prolog = u64::from(control_offset) < u64::from(unwind.prolog_size);
                let establisher_frame =
                    self.x64_establisher_frame(registers, &unwind, in_prolog, control_offset);
                let mut caller_context = *registers;
                let mut rsp = registers.rsp;
                for code in &unwind.operations {
                    if in_prolog && u64::from(code.code_offset) > u64::from(control_offset) {
                        continue;
                    }
                    self.apply_x64_unwind_code(
                        &mut caller_context,
                        &mut rsp,
                        establisher_frame,
                        code,
                    )?;
                }
                let return_address = self.read_pointer_value(rsp)?;
                caller_context.rsp = rsp.saturating_add(8);
                caller_context.rip = return_address;
                return Ok(Some(X64VirtualUnwindResult {
                    image_base: module.base,
                    function_entry_address: function.entry_address,
                    unwind_info_address: unwind.unwind_info_address,
                    establisher_frame,
                    handler_address: if unwind.flags & handler_mask != 0 {
                        unwind.handler_address
                    } else {
                        None
                    },
                    handler_data_address: if unwind.flags & handler_mask != 0 {
                        unwind.handler_data_address
                    } else {
                        None
                    },
                    flags: unwind.flags,
                    leaf: false,
                    caller_context,
                }));
            }
        }

        let rsp = registers.rsp;
        if rsp == 0 || !self.core.modules.memory().is_range_mapped(rsp, 8) {
            return Ok(None);
        }
        let return_address = self.read_pointer_value(rsp)?;
        Ok(Some(self.x64_leaf_unwind_result(
            registers,
            rsp,
            rsp,
            return_address,
        )))
    }

    pub(super) fn x64_is_executable_continuation(&self, address: u64) -> bool {
        address != 0
            && self
                .core
                .modules
                .memory()
                .find_region(address, 1)
                .map(|region| region.perms & PROT_EXEC != 0)
                .unwrap_or(false)
    }

    pub(super) fn x64_leaf_unwind_result(
        &self,
        registers: &RegisterFile,
        establisher_frame: u64,
        return_slot: u64,
        return_address: u64,
    ) -> X64VirtualUnwindResult {
        let mut caller_context = *registers;
        caller_context.rsp = return_slot.saturating_add(8);
        caller_context.rip = return_address;
        X64VirtualUnwindResult {
            image_base: self
                .core
                .modules
                .get_by_address(return_address)
                .map(|record| record.base)
                .unwrap_or(0),
            function_entry_address: 0,
            unwind_info_address: 0,
            establisher_frame,
            handler_address: None,
            handler_data_address: None,
            flags: 0,
            leaf: true,
            caller_context,
        }
    }

    pub(super) fn read_x64_runtime_function(
        &self,
        address: u64,
    ) -> Result<X64RuntimeFunction, VmError> {
        Ok(X64RuntimeFunction {
            entry_address: address,
            begin_rva: self.read_u32(address)?,
            end_rva: self.read_u32(address + 4)?,
            unwind_rva: self.read_u32(address + 8)?,
        })
    }

    pub(super) fn parse_x64_unwind_info(
        &self,
        module: &ModuleRecord,
        function: &X64RuntimeFunction,
        depth: usize,
    ) -> Result<X64UnwindInfo, VmError> {
        if depth > 4 {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "x64 chained UNWIND_INFO recursion exceeded limit for 0x{:X}",
                    function.entry_address
                ),
            });
        }

        let unwind_info_address = module.base + function.unwind_rva as u64;
        let version_and_flags = self.read_u8(unwind_info_address)?;
        let version = version_and_flags & 0x07;
        let flags = version_and_flags >> 3;
        if version != 1 && version != 2 {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "unsupported x64 UNWIND_INFO version {version} at 0x{unwind_info_address:X}"
                ),
            });
        }
        let prolog_size = self.read_u8(unwind_info_address + 1)?;
        let count_of_codes = self.read_u8(unwind_info_address + 2)? as usize;
        let frame = self.read_u8(unwind_info_address + 3)?;
        let frame_register = frame & 0x0F;
        let frame_offset = frame >> 4;
        let mut cursor = unwind_info_address + 4;
        let mut slot = 0usize;
        let mut operations = Vec::new();
        while slot < count_of_codes {
            let code_offset = self.read_u8(cursor)?;
            let unwind = self.read_u8(cursor + 1)?;
            let op = unwind & 0x0F;
            let op_info = unwind >> 4;
            cursor += 2;
            slot += 1;
            let operation = match op {
                X64_UWOP_PUSH_NONVOL => X64UnwindOperation::PushNonVol { register: op_info },
                X64_UWOP_ALLOC_LARGE => {
                    let size = if op_info == 0 {
                        let scaled = self.read_u16(cursor)? as u32;
                        cursor += 2;
                        slot += 1;
                        scaled.saturating_mul(8)
                    } else if op_info == 1 {
                        let low = self.read_u16(cursor)? as u32;
                        let high = self.read_u16(cursor + 2)? as u32;
                        cursor += 4;
                        slot += 2;
                        low | (high << 16)
                    } else {
                        return Err(VmError::NativeExecution {
                            op: "seh",
                            detail: format!(
                                "unsupported x64 UWOP_ALLOC_LARGE info {op_info} at 0x{unwind_info_address:X}"
                            ),
                        });
                    };
                    X64UnwindOperation::AllocLarge { size }
                }
                X64_UWOP_ALLOC_SMALL => X64UnwindOperation::AllocSmall {
                    size: u32::from(op_info).saturating_mul(8).saturating_add(8),
                },
                X64_UWOP_SET_FPREG => X64UnwindOperation::SetFpReg,
                X64_UWOP_SAVE_NONVOL => {
                    let scaled = self.read_u16(cursor)? as u32;
                    cursor += 2;
                    slot += 1;
                    X64UnwindOperation::SaveNonVol {
                        register: op_info,
                        offset: scaled.saturating_mul(8),
                    }
                }
                X64_UWOP_SAVE_NONVOL_FAR => {
                    let low = self.read_u16(cursor)? as u32;
                    let high = self.read_u16(cursor + 2)? as u32;
                    cursor += 4;
                    slot += 2;
                    X64UnwindOperation::SaveNonVolFar {
                        register: op_info,
                        offset: low | (high << 16),
                    }
                }
                X64_UWOP_SAVE_XMM128 => {
                    let scaled = self.read_u16(cursor)? as u32;
                    cursor += 2;
                    slot += 1;
                    X64UnwindOperation::SaveXmm128 {
                        register: op_info,
                        offset: scaled.saturating_mul(16),
                    }
                }
                X64_UWOP_SAVE_XMM128_FAR => {
                    let low = self.read_u16(cursor)? as u32;
                    let high = self.read_u16(cursor + 2)? as u32;
                    cursor += 4;
                    slot += 2;
                    X64UnwindOperation::SaveXmm128Far {
                        register: op_info,
                        offset: low | (high << 16),
                    }
                }
                X64_UWOP_PUSH_MACHFRAME => X64UnwindOperation::PushMachFrame {
                    with_error_code: op_info != 0,
                },
                _ => {
                    // Unknown unwind code (e.g. version 2 extensions).  Skip it;
                    // the unwind codes we do understand are sufficient for most
                    // real-world frames.
                    X64UnwindOperation::Unknown
                }
            };
            operations.push(X64UnwindCode {
                code_offset,
                operation,
            });
        }

        let trailer = unwind_info_address + 4 + (count_of_codes.next_multiple_of(2) as u64 * 2);
        let mut handler_address = None;
        let mut handler_data_address = None;
        if flags & X64_UNW_FLAG_CHAININFO != 0 {
            let chained = self.read_x64_runtime_function(trailer)?;
            let chained_info = self.parse_x64_unwind_info(module, &chained, depth + 1)?;
            operations.extend(chained_info.operations);
            handler_address = chained_info.handler_address;
            handler_data_address = chained_info.handler_data_address;
        } else if flags & (X64_UNW_FLAG_EHANDLER | X64_UNW_FLAG_UHANDLER) != 0 {
            let handler_rva = self.read_u32(trailer)?;
            handler_address = Some(module.base + handler_rva as u64);
            handler_data_address = Some(trailer + 4);
        }

        Ok(X64UnwindInfo {
            flags,
            prolog_size,
            frame_register,
            frame_offset,
            unwind_info_address,
            handler_address,
            handler_data_address,
            operations,
        })
    }

    pub(super) fn x64_establisher_frame(
        &self,
        registers: &RegisterFile,
        unwind: &X64UnwindInfo,
        in_prolog: bool,
        control_offset: u32,
    ) -> u64 {
        let current_rsp = registers.rsp;
        if unwind.frame_register == 0 {
            return current_rsp;
        }
        let frame_reg_active = !in_prolog
            || unwind.operations.iter().any(|code| {
                matches!(code.operation, X64UnwindOperation::SetFpReg)
                    && u64::from(code.code_offset) <= u64::from(control_offset)
            });
        if !frame_reg_active {
            return current_rsp;
        }
        let Some(name) = x64_register_name(unwind.frame_register) else {
            return current_rsp;
        };
        let frame_reg_value = registers.get(name);
        let effective = if frame_reg_value != 0 {
            frame_reg_value
        } else {
            current_rsp
        };
        effective.saturating_sub(u64::from(unwind.frame_offset) * 16)
    }

    pub(super) fn apply_x64_unwind_code(
        &self,
        registers: &mut RegisterFile,
        rsp: &mut u64,
        establisher_frame: u64,
        code: &X64UnwindCode,
    ) -> Result<(), VmError> {
        match &code.operation {
            X64UnwindOperation::PushNonVol { register } => {
                let value = self.read_pointer_value(*rsp)?;
                self.write_x64_unwind_register(registers, *register, value)?;
                *rsp = rsp.saturating_add(8);
            }
            X64UnwindOperation::AllocLarge { size } | X64UnwindOperation::AllocSmall { size } => {
                *rsp = rsp.saturating_add(u64::from(*size));
            }
            X64UnwindOperation::SetFpReg => {
                *rsp = establisher_frame;
            }
            X64UnwindOperation::SaveNonVol { register, offset }
            | X64UnwindOperation::SaveNonVolFar { register, offset } => {
                let value = self.read_pointer_value(establisher_frame + u64::from(*offset))?;
                self.write_x64_unwind_register(registers, *register, value)?;
            }
            X64UnwindOperation::SaveXmm128 { .. } | X64UnwindOperation::SaveXmm128Far { .. } => {
                // Current fidelity work only needs caller RIP/RSP and preserved integer registers.
            }
            X64UnwindOperation::PushMachFrame { .. } => {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: "x64 UWOP_PUSH_MACHFRAME is not implemented".to_string(),
                });
            }
            X64UnwindOperation::Unknown => {
                // No-op: skip unknown/unsupported unwind codes.
            }
        }
        Ok(())
    }

    pub(super) fn write_x64_unwind_register(
        &self,
        registers: &mut RegisterFile,
        register: u8,
        value: u64,
    ) -> Result<(), VmError> {
        let Some(name) = x64_register_name(register) else {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!("unsupported x64 register index {register} in unwind info"),
            });
        };
        registers.set(name, value);
        Ok(())
    }

    pub(super) fn encode_x64_push_nonvolatile(register: u8) -> Option<&'static [u8]> {
        match register {
            3 => Some(&[0x53]),
            5 => Some(&[0x55]),
            6 => Some(&[0x56]),
            7 => Some(&[0x57]),
            12 => Some(&[0x41, 0x54]),
            13 => Some(&[0x41, 0x55]),
            14 => Some(&[0x41, 0x56]),
            15 => Some(&[0x41, 0x57]),
            _ => None,
        }
    }

    pub(super) fn write_x86_exception_record(
        &mut self,
        address: u64,
        fault: UnicornFault,
    ) -> Result<(), VmError> {
        let exception_code = fault.exception_code.unwrap_or(STATUS_ACCESS_VIOLATION);
        self.write_u32(address + 0x04, 0)?;
        self.write_u32(address + 0x08, 0)?;
        self.write_u32(address, exception_code)?;
        self.write_u32(address + 0x0C, fault.pc as u32)?;
        let parameter_count = if fault.exception_code.is_some() {
            fault.exception_information_count
        } else {
            2
        };
        self.write_u32(address + 0x10, parameter_count)?;
        if parameter_count >= 1 {
            let first = if fault.exception_code.is_some() {
                fault.exception_information[0] as u32
            } else {
                self.exception_access_code(fault.access) as u32
            };
            self.write_u32(address + 0x14, first)?;
        }
        if parameter_count >= 2 {
            let second = if fault.exception_code.is_some() {
                fault.exception_information[1] as u32
            } else {
                fault.address as u32
            };
            self.write_u32(address + 0x18, second)?;
        }
        Ok(())
    }

    pub(super) fn write_x64_exception_record(
        &mut self,
        address: u64,
        fault: UnicornFault,
    ) -> Result<(), VmError> {
        let exception_code = fault.exception_code.unwrap_or(STATUS_ACCESS_VIOLATION);
        let parameter_count = if fault.exception_code.is_some() {
            fault.exception_information_count
        } else {
            2
        };
        self.write_u32(address, exception_code)?;
        self.write_u32(address + 0x04, 0)?;
        self.write_pointer_value(address + 0x08, 0)?;
        self.write_pointer_value(address + 0x10, fault.pc)?;
        self.write_u32(address + 0x18, parameter_count)?;
        self.write_u32(address + 0x1C, 0)?;
        if parameter_count >= 1 {
            let first = if fault.exception_code.is_some() {
                fault.exception_information[0]
            } else {
                self.exception_access_code(fault.access)
            };
            self.write_pointer_value(address + 0x20, first)?;
        }
        if parameter_count >= 2 {
            let second = if fault.exception_code.is_some() {
                fault.exception_information[1]
            } else {
                fault.address
            };
            self.write_pointer_value(address + 0x28, second)?;
        }
        Ok(())
    }

    pub(super) fn write_x86_context_record(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
        registers: &RegisterFile,
    ) -> Result<(), VmError> {
        self.write_u32(address, X86_CONTEXT_FULL)?;
        serialize_register_context(
            self.core.modules.memory_mut(),
            self.core.arch,
            address,
            registers,
        )?;
        for (offset, regid, op) in [
            (X86_CONTEXT_SEG_GS_OFFSET, UC_X86_REG_GS, "uc_reg_read(gs)"),
            (X86_CONTEXT_SEG_FS_OFFSET, UC_X86_REG_FS, "uc_reg_read(fs)"),
            (X86_CONTEXT_SEG_ES_OFFSET, UC_X86_REG_ES, "uc_reg_read(es)"),
            (X86_CONTEXT_SEG_DS_OFFSET, UC_X86_REG_DS, "uc_reg_read(ds)"),
            (X86_CONTEXT_SEG_CS_OFFSET, UC_X86_REG_CS, "uc_reg_read(cs)"),
            (X86_CONTEXT_SEG_SS_OFFSET, UC_X86_REG_SS, "uc_reg_read(ss)"),
        ] {
            let value = unsafe { api.reg_read_raw(uc, regid) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
            self.write_u32(address + offset, value as u32)?;
        }
        Ok(())
    }

    pub(super) fn write_x64_context_record(
        &mut self,
        address: u64,
        registers: &RegisterFile,
    ) -> Result<(), VmError> {
        self.core
            .modules
            .memory_mut()
            .write(address, &vec![0u8; X64_CONTEXT_SIZE])?;
        self.write_u32(address + X64_CONTEXT_FLAGS_OFFSET, X64_CONTEXT_FULL)?;
        serialize_register_context(
            self.core.modules.memory_mut(),
            self.core.arch,
            address,
            registers,
        )?;
        Ok(())
    }

    pub(super) fn write_x64_dispatcher_context(
        &mut self,
        address: u64,
        control_pc: u64,
        image_base: u64,
        function_entry: u64,
        establisher_frame: u64,
        context_record: u64,
        language_handler: u64,
        handler_data: u64,
    ) -> Result<(), VmError> {
        self.core
            .modules
            .memory_mut()
            .write(address, &vec![0u8; X64_DISPATCHER_CONTEXT_SIZE])?;
        self.write_pointer_value(address + 0x00, control_pc)?;
        self.write_pointer_value(address + 0x08, image_base)?;
        self.write_pointer_value(address + 0x10, function_entry)?;
        self.write_pointer_value(address + 0x18, establisher_frame)?;
        self.write_pointer_value(address + 0x20, 0)?;
        self.write_pointer_value(address + 0x28, context_record)?;
        self.write_pointer_value(address + 0x30, language_handler)?;
        self.write_pointer_value(address + 0x38, handler_data)?;
        self.write_pointer_value(address + 0x40, 0)?;
        self.write_u32(address + 0x48, 0)?;
        self.write_u32(address + 0x4C, 0)?;
        Ok(())
    }

    pub(super) fn exception_access_code(&self, access: UnicornFaultAccess) -> u64 {
        match access {
            UnicornFaultAccess::Read => 0,
            UnicornFaultAccess::Write => 1,
            UnicornFaultAccess::Execute => 8,
        }
    }

    pub(in crate::runtime::engine) fn restore_unicorn_x86_segments_from_context(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<(), VmError> {
        for (offset, regid, op) in [
            (X86_CONTEXT_SEG_GS_OFFSET, UC_X86_REG_GS, "uc_reg_write(gs)"),
            (X86_CONTEXT_SEG_FS_OFFSET, UC_X86_REG_FS, "uc_reg_write(fs)"),
            (X86_CONTEXT_SEG_ES_OFFSET, UC_X86_REG_ES, "uc_reg_write(es)"),
            (X86_CONTEXT_SEG_DS_OFFSET, UC_X86_REG_DS, "uc_reg_write(ds)"),
            (X86_CONTEXT_SEG_CS_OFFSET, UC_X86_REG_CS, "uc_reg_write(cs)"),
            (X86_CONTEXT_SEG_SS_OFFSET, UC_X86_REG_SS, "uc_reg_write(ss)"),
        ] {
            let value = self.read_u32(address + offset)? as u64;
            if value == 0 {
                continue;
            }
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        Ok(())
    }
}

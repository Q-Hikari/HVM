use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn register_vectored_exception_handler(
        &mut self,
        first: bool,
        handler: u64,
    ) -> u64 {
        if handler == 0 {
            return 0;
        }
        let handle = self.allocate_object_handle();
        let record = VectoredExceptionHandler { handle, handler };
        if first {
            self.exception.vectored_exception_handlers.insert(0, record);
        } else {
            self.exception.vectored_exception_handlers.push(record);
        }
        handle as u64
    }

    pub(in crate::runtime::engine) fn remove_vectored_exception_handler(
        &mut self,
        handle: u32,
    ) -> bool {
        let before = self.exception.vectored_exception_handlers.len();
        self.exception
            .vectored_exception_handlers
            .retain(|entry| entry.handle != handle);
        before != self.exception.vectored_exception_handlers.len()
    }

    pub(in crate::runtime::engine) fn emit_startup_resume_chain(&mut self) -> Result<(), VmError> {
        let Some(signature) = self
            .core
            .hooks
            .signature("ntdll.dll", "NtContinue")
            .cloned()
        else {
            return Ok(());
        };
        let stub_address =
            if let Some(stub) = self.core.hooks.binding_address("ntdll.dll", "NtContinue") {
                stub
            } else if let Some(module_base) = self
                .core
                .modules
                .get_loaded("ntdll.dll")
                .map(|module| module.base)
            {
                let resolved = self.core.modules.resolve_export(
                    module_base,
                    &self.core.config,
                    &mut self.core.hooks,
                    Some("NtContinue"),
                    None,
                );
                if resolved != 0 {
                    resolved
                } else {
                    self.bind_hook_for_test("ntdll.dll", "NtContinue")
                }
            } else {
                self.bind_hook_for_test("ntdll.dll", "NtContinue")
            };
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(());
        };
        let stack_pointer = if self.core.arch.is_x86() {
            let esp = thread.registers.esp;
            if esp != 0 {
                esp
            } else {
                thread.stack_top
            }
        } else {
            let rsp = thread.registers.rsp;
            if rsp != 0 {
                rsp
            } else {
                thread.stack_top
            }
        };
        let context_size = if self.core.arch.is_x86() {
            STARTUP_CONTEXT_RECORD_SIZE_X86
        } else {
            STARTUP_CONTEXT_RECORD_SIZE_X64
        };
        let Some(context_address) = stack_pointer
            .checked_sub(context_size + 0x80)
            .filter(|address| *address >= thread.stack_limit.saturating_add(0x40))
        else {
            return Ok(());
        };
        self.core
            .modules
            .memory_mut()
            .write(context_address, &vec![0u8; context_size as usize])?;

        for stage in 0..STARTUP_NTCONTINUE_RESUME_COUNT {
            let _ = self.capture_current_context(context_address)?;
            let _ = self.dispatch_bound_stub_with_signature(
                &signature,
                stub_address,
                None,
                &[context_address, 0],
            )?;
            self.commit_startup_context_restore(stage as u64 + 1)?;
        }
        Ok(())
    }

    pub(super) fn commit_startup_context_restore(&mut self, stage: u64) -> Result<(), VmError> {
        let Some(restore) = self.exception.pending_context_restore.take() else {
            self.dispatch.reset_api_flow_control();
            return Ok(());
        };
        self.dispatch.reset_api_flow_control();
        let pc = if self.core.arch.is_x86() {
            restore.registers.eip
        } else {
            restore.registers.rip
        };
        let mut fields = Map::new();
        fields.insert("stage".to_string(), json!(stage));
        fields.insert("context_record".to_string(), json!(restore.context_address));
        fields.insert("pc".to_string(), json!(pc));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("STARTUP_RESUME", fields)
    }

    pub(in crate::runtime::engine) fn rtl_unwind_x86(
        &mut self,
        target_frame: u64,
        target_ip: u64,
        return_value: u64,
        stack_arg_count: usize,
    ) -> Result<u64, VmError> {
        if !self.core.arch.is_x86() {
            return Ok(0);
        }

        let mut registers = if unicorn_context_active() {
            let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
            let api = unsafe { &*api_ptr };
            self.capture_unicorn_thread_registers(api, uc)?
        } else {
            self.current_thread_snapshot()
                .map(|thread| thread.registers)
                .unwrap_or_default()
        };

        let current_esp = registers.esp;
        if current_esp == 0 {
            return Ok(0);
        }

        let resume_ip = if target_ip != 0 {
            target_ip
        } else {
            self.read_u32(current_esp)? as u64
        };
        let resume_esp =
            current_esp.saturating_add(4 + u64::try_from(stack_arg_count).unwrap_or(0) * 4);

        registers.eax = return_value;
        registers.eip = resume_ip;
        registers.esp = resume_esp;

        let stack_limit = self
            .current_thread_snapshot()
            .map(|thread| thread.stack_limit)
            .unwrap_or(0);
        let Some(context_address) = current_esp
            .checked_sub(X86_CONTEXT_SIZE as u64 + 0x40)
            .filter(|address| *address >= stack_limit.saturating_add(0x20))
        else {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!("x86 RtlUnwind scratch frame underflow at esp=0x{current_esp:X}"),
            });
        };
        self.core
            .modules
            .memory_mut()
            .write(context_address, &vec![0u8; X86_CONTEXT_SIZE])?;

        if unicorn_context_active() {
            let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
            let api = unsafe { &*api_ptr };
            self.write_x86_context_record(api, uc, context_address, &registers)?;
        } else {
            self.write_u32(context_address, X86_CONTEXT_FULL)?;
            serialize_register_context(
                self.core.modules.memory_mut(),
                self.core.arch,
                context_address,
                &registers,
            )?;
        }

        if target_frame != 0 {
            let exception_list_ptr = self.core.process_env.current_teb()
                + self.core.process_env.offsets().teb_exception_list as u64;
            let mut registration = self.read_pointer_value(exception_list_ptr)?;
            let mut next_after_target = None;
            while registration != 0 && registration != X86_EXCEPTION_CHAIN_END {
                let next = self.read_pointer_value(registration)?;
                if registration == target_frame {
                    next_after_target = Some(next);
                    break;
                }
                registration = next;
            }
            if let Some(next) = next_after_target {
                // After RtlUnwind enters the target __except/__finally, the target
                // registration frame and all frames above it must be removed from the
                // exception chain to avoid re-triggering faults in an infinite loop.
                self.write_pointer_value(exception_list_ptr, next)?;
            }
        }
        self.exception.pending_x86_seh_unwind = Some(PendingX86SehUnwind {
            context_address,
            registers,
        });
        self.dispatch.force_native_return = true;
        Ok(0)
    }

    pub(in crate::runtime::engine) fn handle_pending_unicorn_fault(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        self.exception.pending_x64_top_level_filter_seed = None;
        if self.maybe_complete_x64_shared_epilogue_synthetic_return(api, uc, fault)? {
            return Ok(true);
        }
        if fault.exception_code.is_none()
            && fault.access != UnicornFaultAccess::Execute
            && self.expand_current_thread_stack_for_native_access(fault.address, fault.size)?
        {
            return Ok(true);
        }
        let original_registers = self.capture_unicorn_thread_registers(api, uc)?;
        let handled = if self.core.arch.is_x86() {
            self.dispatch_x86_vectored_exception_handlers_with_unicorn(api, uc, fault)?
        } else if self.core.arch.is_x64() {
            self.dispatch_x64_vectored_exception_handlers_with_unicorn(api, uc, fault)?
        } else {
            false
        };
        if handled {
            return Ok(true);
        }
        let handled = if self.core.arch.is_x86() {
            self.dispatch_x86_seh_fault_with_unicorn(api, uc, fault)?
        } else if self.core.arch.is_x64() {
            self.dispatch_x64_seh_fault_with_unicorn(api, uc, fault)?
        } else {
            false
        };
        if handled {
            return Ok(true);
        }
        let handled = if self.core.arch.is_x86() {
            self.dispatch_x86_top_level_exception_filter_with_unicorn(api, uc, fault)
        } else if self.core.arch.is_x64() {
            self.dispatch_x64_top_level_exception_filter_with_unicorn(api, uc, fault)
        } else {
            Ok(false)
        }?;
        if handled {
            return Ok(true);
        }
        if self.core.process_exit_requested {
            let mut terminated = original_registers;
            let exit_code = u64::from(self.core.exit_code.unwrap_or(0));
            if self.core.arch.is_x86() {
                terminated.eip = self.core.native_return_sentinel;
                terminated.eax = exit_code;
            } else {
                terminated.rip = self.core.native_return_sentinel;
                terminated.rax = exit_code;
            }
            self.restore_unicorn_thread_registers(api, uc, &terminated)?;
            return Ok(true);
        }
        self.restore_unicorn_thread_registers(api, uc, &original_registers)?;
        Ok(false)
    }

    pub(super) fn dispatch_x86_vectored_exception_handlers_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let handlers = self.exception.vectored_exception_handlers.clone();
        if handlers.is_empty() {
            return Ok(false);
        }
        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_esp = registers.esp;
        let fault_eflags = if registers.eflags != 0 {
            registers.eflags
        } else {
            0x202
        } as u32;
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let dispatcher_esp = match fault_esp.checked_sub(X86_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x20) => value,
            _ => return Ok(false),
        };
        let exception_record = dispatcher_esp + 0x40;
        let context_record =
            (exception_record + X86_EXCEPTION_RECORD_SIZE as u64 + 0x0F) & !0x0Fu64;
        let exception_pointers =
            align_up_u64(context_record + X86_CONTEXT_SIZE as u64 + 0x10, 0x10);
        let scratch_start = dispatcher_esp.saturating_sub(0x20);
        let scratch_end = exception_pointers + self.core.arch.pointer_size as u64 * 2;
        let scratch_size =
            usize::try_from(scratch_end.saturating_sub(scratch_start)).map_err(|_| {
                VmError::RuntimeInvariant("x86 vectored handler scratch frame too large")
            })?;
        self.core
            .modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x86_exception_record(exception_record, fault)?;
        self.write_x86_context_record(api, uc, context_record, &registers)?;
        self.write_pointer_value(exception_pointers, exception_record)?;
        self.write_pointer_value(
            exception_pointers + self.core.arch.pointer_size as u64,
            context_record,
        )?;

        for handler in handlers {
            let disposition = self.call_x86_native_with_unicorn_context(
                handler.handler,
                &[exception_pointers],
                fault_esp,
                fault_eflags,
                NativeCallRunMode::Standalone,
            )? as u32;
            if disposition != EXCEPTION_CONTINUE_EXECUTION {
                continue;
            }

            let restored = deserialize_register_context(
                self.core.modules.memory(),
                self.core.arch,
                context_record,
            )?;
            self.log_seh_resume(context_record, &restored)?;
            self.restore_unicorn_thread_registers(api, uc, &restored)?;
            self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn dispatch_x64_vectored_exception_handlers_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let handlers = self.exception.vectored_exception_handlers.clone();
        if handlers.is_empty() {
            return Ok(false);
        }
        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_rsp = registers.rsp;
        let fault_rflags = if registers.rflags != 0 {
            registers.rflags
        } else {
            0x202
        };
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
        let exception_pointers =
            align_up_u64(context_record + X64_CONTEXT_SIZE as u64 + 0x20, 0x10);
        let scratch_size = usize::try_from(
            exception_pointers
                .saturating_add(X64_EXCEPTION_POINTERS_SIZE as u64)
                .saturating_sub(scratch_start),
        )
        .map_err(|_| VmError::RuntimeInvariant("x64 vectored handler scratch frame too large"))?;
        self.core
            .modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x64_exception_record(exception_record, fault)?;
        self.write_x64_context_record(context_record, &registers)?;
        self.write_pointer_value(exception_pointers + 0x00, exception_record)?;
        self.write_pointer_value(exception_pointers + 0x08, context_record)?;

        for handler in handlers {
            let disposition = self.call_x64_native_with_unicorn_context(
                handler.handler,
                &[exception_pointers],
                scratch_end,
                fault_rflags,
                NativeCallRunMode::Standalone,
                true,
            )? as u32;
            if disposition != EXCEPTION_CONTINUE_EXECUTION {
                continue;
            }

            let restored = deserialize_register_context(
                self.core.modules.memory(),
                self.core.arch,
                context_record,
            )?;
            self.log_seh_resume(context_record, &restored)?;
            self.restore_unicorn_thread_registers(api, uc, &restored)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn maybe_complete_x64_shared_epilogue_synthetic_return(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        if !self.core.arch.is_x64()
            || fault.exception_code.is_some()
            || fault.access != UnicornFaultAccess::Execute
            || fault.pc != 0
            || fault.address != 0
        {
            return Ok(false);
        }

        // A genuine NULL_CALL (e.g. malware calling through a NULL function
        // pointer returned by GetProcAddress) also produces pc=0 / address=0.
        // Only handle this fault when a synthetic call is actually in progress;
        // otherwise let it fall through to the unhandled-fault path so the
        // thread terminates cleanly instead of spinning in an infinite
        // log-and-retry loop.
        if self.trace.active_x64_synthetic_call.is_none() {
            return Ok(false);
        }

        // Some x64 callbacks tail-jump into shared epilogues that restore more
        // nonvolatile registers than our synthetic call frame originally reserved.
        // In that case the sentinel return address can be popped into a preserved
        // register and the final `ret` faults at RIP=0. Treat that signature as a
        // completed synthetic return and resume at the sentinel directly.
        const X64_SHARED_EPILOGUE_RETURN_SLACK: u64 = 0x40;
        let mut sentinel_was_popped = false;
        for (regid, op) in [
            (UC_X86_REG_RBX, "uc_reg_read(rbx)"),
            (UC_X86_REG_RBP, "uc_reg_read(rbp)"),
            (UC_X86_REG_RSI, "uc_reg_read(rsi)"),
            (UC_X86_REG_RDI, "uc_reg_read(rdi)"),
            (UC_X86_REG_R12, "uc_reg_read(r12)"),
            (UC_X86_REG_R13, "uc_reg_read(r13)"),
            (UC_X86_REG_R14, "uc_reg_read(r14)"),
            (UC_X86_REG_R15, "uc_reg_read(r15)"),
        ] {
            let value = unsafe { api.reg_read_raw(uc, regid) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
            if value == self.core.native_return_sentinel {
                sentinel_was_popped = true;
                break;
            }
        }
        if !sentinel_was_popped {
            let rsp = unsafe { api.reg_read_raw(uc, UC_X86_REG_RSP) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_read(rsp)",
                    detail,
                }
            })?;
            let Some(call) = self.trace.active_x64_synthetic_call else {
                return Ok(false);
            };
            let within_shared_epilogue_return = rsp >= call.caller_rsp
                && rsp
                    <= call
                        .caller_rsp
                        .saturating_add(X64_SHARED_EPILOGUE_RETURN_SLACK);
            if !within_shared_epilogue_return || rsp < 8 {
                return Ok(false);
            }
            let popped_return = self.read_pointer_value(rsp - 8).unwrap_or(u64::MAX);
            if popped_return != 0 {
                return Ok(false);
            }
        }

        unsafe { api.reg_write_raw(uc, UC_X86_REG_RIP, self.core.native_return_sentinel) }
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_write(rip)",
                detail,
            })?;
        Ok(true)
    }

    pub(in crate::runtime::engine) fn unhandled_unicorn_fault_error(
        &self,
        fault: UnicornFault,
    ) -> VmError {
        let detail = if let Some(exception_code) = fault.exception_code {
            format!(
                "unhandled CPU exception {} at pc=0x{:X}",
                Self::format_exception_code_for_log(exception_code),
                fault.pc
            )
        } else {
            format!(
                "unhandled native {} fault at pc=0x{:X} address=0x{:X} size=0x{:X}",
                fault.access.as_str(),
                fault.pc,
                fault.address,
                fault.size
            )
        };
        VmError::NativeExecution {
            op: "fault",
            detail,
        }
    }

    pub(super) fn dispatch_x86_top_level_exception_filter_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let filter = self.exception.top_level_exception_filter;
        if filter == 0 || self.exception.dispatching_top_level_exception_filter {
            return Ok(false);
        }
        self.exception.dispatching_top_level_exception_filter = true;
        let dispatch_result = (|| {
            let registers = self.capture_unicorn_thread_registers(api, uc)?;
            let fault_esp = registers.esp;
            let fault_eflags = if registers.eflags != 0 {
                registers.eflags
            } else {
                0x202
            } as u32;
            let Some(thread) = self.current_thread_snapshot() else {
                return Ok(false);
            };
            let dispatcher_esp = match fault_esp.checked_sub(X86_EXCEPTION_DISPATCH_STACK) {
                Some(value) if value >= thread.stack_limit.saturating_add(0x20) => value,
                _ => return Ok(false),
            };
            let exception_record = dispatcher_esp + 0x40;
            let context_record =
                (exception_record + X86_EXCEPTION_RECORD_SIZE as u64 + 0x0F) & !0x0Fu64;
            let exception_pointers =
                align_up_u64(context_record + X86_CONTEXT_SIZE as u64 + 0x10, 0x10);
            let scratch_start = dispatcher_esp.saturating_sub(0x20);
            let scratch_end = exception_pointers + self.core.arch.pointer_size as u64 * 2;
            let scratch_size =
                usize::try_from(scratch_end.saturating_sub(scratch_start)).map_err(|_| {
                    VmError::RuntimeInvariant("x86 top-level filter scratch frame too large")
                })?;
            self.core
                .modules
                .memory_mut()
                .write(scratch_start, &vec![0u8; scratch_size])?;

            self.write_x86_exception_record(exception_record, fault)?;
            self.write_x86_context_record(api, uc, context_record, &registers)?;
            self.write_pointer_value(exception_pointers, exception_record)?;
            self.write_pointer_value(
                exception_pointers + self.core.arch.pointer_size as u64,
                context_record,
            )?;

            let filter_result = self.call_x86_native_with_unicorn_context(
                filter,
                &[exception_pointers],
                fault_esp,
                fault_eflags,
                NativeCallRunMode::Standalone,
            )? as i32;
            if filter_result != EXCEPTION_CONTINUE_EXECUTION_FILTER {
                return Ok(false);
            }

            let restored = deserialize_register_context(
                self.core.modules.memory(),
                self.core.arch,
                context_record,
            )?;
            self.log_seh_resume(context_record, &restored)?;
            self.restore_unicorn_thread_registers(api, uc, &restored)?;
            self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
            Ok(true)
        })();
        self.exception.dispatching_top_level_exception_filter = false;
        dispatch_result
    }

    pub(super) fn dispatch_x64_top_level_exception_filter_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let filter = self.exception.top_level_exception_filter;
        if filter == 0 || self.exception.dispatching_top_level_exception_filter {
            return Ok(false);
        }
        self.exception.dispatching_top_level_exception_filter = true;
        let dispatch_result = (|| {
            let registers = self.capture_unicorn_thread_registers(api, uc)?;
            // The top-level exception filter runs in the faulting thread's context.
            // Do NOT seed nonvolatile registers from the SEH unwind chain — the
            // unwind restores callee-saved values from each frame's prologue save
            // area, which can produce values the filter's handler code does not
            // expect (e.g. rbx restored to a stale "1" instead of a valid object
            // pointer).  On real Windows the kernel calls the filter with the
            // original faulting registers, so we do the same here.
            //
            // We still consume the seed so it does not leak into a later dispatch.
            let _ = self.exception.pending_x64_top_level_filter_seed.take();
            let fault_rsp = registers.rsp;
            let fault_rflags = if registers.rflags != 0 {
                registers.rflags
            } else {
                0x202
            };
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
            let exception_pointers =
                align_up_u64(context_record + X64_CONTEXT_SIZE as u64 + 0x20, 0x10);
            let scratch_size = usize::try_from(
                exception_pointers
                    .saturating_add(X64_EXCEPTION_POINTERS_SIZE as u64)
                    .saturating_sub(scratch_start),
            )
            .map_err(|_| {
                VmError::RuntimeInvariant("x64 top-level filter scratch frame too large")
            })?;
            self.core
                .modules
                .memory_mut()
                .write(scratch_start, &vec![0u8; scratch_size])?;

            self.write_x64_exception_record(exception_record, fault)?;
            self.write_x64_context_record(context_record, &registers)?;
            self.write_pointer_value(exception_pointers + 0x00, exception_record)?;
            self.write_pointer_value(exception_pointers + 0x08, context_record)?;

            let filter_target = self.prepare_x64_top_level_exception_filter_target(filter)?;
            let filter_result = self.call_x64_native_with_unicorn_context(
                filter_target,
                &[exception_pointers, X64_TOP_LEVEL_EXCEPTION_FILTER_REASON],
                scratch_end,
                fault_rflags,
                NativeCallRunMode::Standalone,
                true,
            )? as i32;
            if filter_result != EXCEPTION_CONTINUE_EXECUTION_FILTER {
                return Ok(false);
            }

            let restored = deserialize_register_context(
                self.core.modules.memory(),
                self.core.arch,
                context_record,
            )?;
            self.log_seh_resume(context_record, &restored)?;
            self.restore_unicorn_thread_registers(api, uc, &restored)?;
            Ok(true)
        })();
        self.exception.dispatching_top_level_exception_filter = false;
        dispatch_result
    }

    pub(super) fn prepare_x64_top_level_exception_filter_target(
        &mut self,
        filter: u64,
    ) -> Result<u64, VmError> {
        if filter == 0 {
            return Ok(0);
        }
        if let Some(&thunk) = self
            .exception
            .x64_top_level_exception_filter_thunks
            .get(&filter)
        {
            return Ok(thunk);
        }

        let Some(module) = self.core.modules.get_by_address(filter).cloned() else {
            return Ok(filter);
        };
        let Some(function) = self.lookup_x64_runtime_function_in_module(&module, filter)? else {
            return Ok(filter);
        };
        let function_start = module.base + function.begin_rva as u64;
        if function_start == filter {
            return Ok(filter);
        }

        let unwind = self.parse_x64_unwind_info(&module, &function, 0)?;
        let control_offset = filter
            .checked_sub(function_start)
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or_else(|| VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "x64 top-level filter 0x{filter:X} is outside function entry 0x{function_start:X}"
                ),
            })?;
        let in_prolog = u64::from(control_offset) < u64::from(unwind.prolog_size);
        let executed_pushes = unwind
            .operations
            .iter()
            .filter(|code| !in_prolog || u64::from(code.code_offset) <= u64::from(control_offset))
            .map(|code| match code.operation {
                X64UnwindOperation::PushNonVol { register } => Some(register),
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let Some(executed_pushes) = executed_pushes else {
            return Ok(filter);
        };
        if executed_pushes.is_empty() {
            return Ok(filter);
        }

        let thunk = self
            .core
            .modules
            .memory_mut()
            .reserve(PAGE_SIZE, None, "native:seh_filter_thunk", false)
            .map_err(VmError::from)?;
        let mut bytes = Vec::with_capacity(executed_pushes.len() * 2 + 12);
        for register in executed_pushes.into_iter().rev() {
            let Some(push) = Self::encode_x64_push_nonvolatile(register) else {
                return Ok(filter);
            };
            bytes.extend_from_slice(push);
        }
        bytes.extend_from_slice(&[0x48, 0xB8]);
        bytes.extend_from_slice(&filter.to_le_bytes());
        bytes.extend_from_slice(&[0xFF, 0xE0]);
        self.core.modules.memory_mut().write(thunk, &bytes)?;
        self.exception
            .x64_top_level_exception_filter_thunks
            .insert(filter, thunk);
        Ok(thunk)
    }

    pub(super) fn dispatch_x86_seh_fault_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let exception_list_ptr = self.core.process_env.current_teb()
            + self.core.process_env.offsets().teb_exception_list as u64;
        let mut registration = self.read_pointer_value(exception_list_ptr)?;
        self.log_seh_dispatch(fault, registration)?;
        if registration == 0 || registration == X86_EXCEPTION_CHAIN_END {
            return Ok(false);
        }

        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_esp = registers.esp;
        let fault_eflags = if registers.eflags != 0 {
            registers.eflags
        } else {
            0x202
        } as u32;
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let dispatcher_esp = match fault_esp.checked_sub(X86_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x20) => value,
            _ => return Ok(false),
        };
        let exception_record = dispatcher_esp + 0x40;
        let context_record =
            (exception_record + X86_EXCEPTION_RECORD_SIZE as u64 + 0x0F) & !0x0Fu64;
        let scratch_start = dispatcher_esp.saturating_sub(0x20);
        let scratch_end = context_record + X86_CONTEXT_SIZE as u64;
        let scratch_size = usize::try_from(scratch_end.saturating_sub(scratch_start))
            .map_err(|_| VmError::RuntimeInvariant("x86 SEH scratch frame too large"))?;
        self.core
            .modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x86_exception_record(exception_record, fault)?;
        self.write_x86_context_record(api, uc, context_record, &registers)?;
        let fault_context = self
            .core
            .modules
            .memory()
            .read(context_record, X86_CONTEXT_SIZE)?;

        let mut visited = BTreeSet::new();
        loop {
            if registration == 0 || registration == X86_EXCEPTION_CHAIN_END {
                return Ok(false);
            }
            if !visited.insert(registration) {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: format!("x86 SEH registration cycle at 0x{registration:X}"),
                });
            }
            if !self.core.modules.memory().is_range_mapped(registration, 8) {
                return Ok(false);
            }

            let next = self.read_pointer_value(registration)?;
            let handler = self.read_pointer_value(registration + 4)?;
            if handler == 0 {
                registration = next;
                continue;
            }

            let disposition = self.call_x86_native_with_unicorn_context(
                handler,
                &[exception_record, registration, context_record, 0],
                fault_esp,
                fault_eflags,
                NativeCallRunMode::Standalone,
            )? as u32;
            self.log_seh_handler(registration, handler, disposition)?;
            if let Some(unwind) = self.exception.pending_x86_seh_unwind.take() {
                let Some(tid) = self
                    .core
                    .scheduler
                    .current_tid()
                    .or(self.core.main_thread_tid)
                else {
                    return Err(VmError::RuntimeInvariant(
                        "x86 SEH unwind restore missing current thread",
                    ));
                };
                self.core
                    .scheduler
                    .set_thread_registers(tid, unwind.registers.clone())
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to stage x86 SEH unwind registers",
                    ))?;
                self.log_seh_resume(unwind.context_address, &unwind.registers)?;
                self.restore_unicorn_thread_registers(api, uc, &unwind.registers)?;
                self.restore_unicorn_x86_segments_from_context(api, uc, unwind.context_address)?;
                return Ok(true);
            }
            match disposition {
                EXCEPTION_CONTINUE_EXECUTION => {
                    let restored = deserialize_register_context(
                        self.core.modules.memory(),
                        self.core.arch,
                        context_record,
                    )?;
                    self.log_seh_resume(context_record, &restored)?;
                    self.restore_unicorn_thread_registers(api, uc, &restored)?;
                    self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
                    return Ok(true);
                }
                EXCEPTION_CONTINUE_SEARCH => {
                    self.core
                        .modules
                        .memory_mut()
                        .write(context_record, &fault_context)?;
                    self.restore_unicorn_thread_registers(api, uc, &registers)?;
                    self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
                    registration = next;
                }
                _ => {
                    return Err(VmError::NativeExecution {
                        op: "seh",
                        detail: format!(
                            "unsupported x86 SEH disposition {disposition} from handler 0x{handler:X}"
                        ),
                    });
                }
            }
        }
    }
}

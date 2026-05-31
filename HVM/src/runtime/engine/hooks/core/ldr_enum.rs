use crate::hooks::types::LogicalAbi;
use crate::runtime::engine::abi::{post_return_stack_pointer, select_adapter};

use super::*;

impl VirtualExecutionEngine {
    fn ensure_ldr_enum_continue_stub(&mut self) -> u64 {
        self.core
            .hooks
            .binding_address("ntdll.dll", "__vm_ldr_enum_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("ntdll.dll", "__vm_ldr_enum_continue"))
    }

    /// Collects the LDR_DATA_TABLE_ENTRY base addresses for all loaded modules.
    fn ldr_collect_module_entries(&self) -> Vec<u64> {
        self.core
            .process_env
            .loader_module_bases()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|base| {
                self.core
                    .process_env
                    .loader_entry_for_module_base(base)
                    .ok()
                    .flatten()
            })
            .collect()
    }

    /// Allocates a small region for the BOOLEAN Stop variable used by the callback.
    fn allocate_stop_var(&mut self) -> u64 {
        // Allocate on a heap for simplicity. 1 byte is enough.
        self.process_memory
            .heaps
            .alloc(
                self.core.modules.memory_mut(),
                self.process_memory.heaps.process_heap(),
                4,
            )
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn ldr_enumerate_loaded_modules(
        &mut self,
        _reserved_flags: u64,
        callback: u64,
        context: u64,
    ) -> Result<u64, VmError> {
        if callback == 0 {
            return Ok(STATUS_SUCCESS as u64);
        }
        let module_entries = self.ldr_collect_module_entries();
        if module_entries.is_empty() {
            return Ok(STATUS_SUCCESS as u64);
        }

        if unicorn_context_active() && !self.core.hooks.is_bound_address(callback) {
            let first_entry = module_entries.first().copied().unwrap_or(0);
            let stop_var = self.allocate_stop_var();
            if stop_var == 0 {
                return Ok(STATUS_SUCCESS as u64);
            }
            self.schedule_active_ldr_enum_callback(
                callback,
                first_entry,
                context,
                stop_var,
                1,
                module_entries,
                false,
            )?;
            return Ok(0);
        }

        // Synchronous path: bound stub or no Unicorn context
        for entry_base in &module_entries {
            let stop_var = self.allocate_stop_var();
            if stop_var == 0 {
                break;
            }
            let _ = self.core.modules.memory_mut().write(stop_var, &[0]);
            if self.core.hooks.is_bound_address(callback) {
                self.dispatch_bound_stub(callback, &[*entry_base as u64, context, stop_var])?;
            } else {
                self.call_native_with_entry_frame(
                    callback,
                    &[*entry_base as u64, context, stop_var],
                )?;
            }
            let stop = self
                .core
                .modules
                .memory()
                .read(stop_var, 1)
                .map(|b| b[0])
                .unwrap_or(0);
            if stop != 0 {
                break;
            }
        }
        Ok(STATUS_SUCCESS as u64)
    }

    fn save_callee_saved_registers(
        api: &UnicornApi,
        uc: *mut UcEngine,
        is_x64: bool,
    ) -> Result<CalleeSavedRegisters, VmError> {
        if is_x64 {
            Ok(CalleeSavedRegisters {
                rbx: unsafe { api.reg_read_raw(uc, UC_X86_REG_RBX) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(rbx)",
                        detail,
                    }
                })?,
                rsi: unsafe { api.reg_read_raw(uc, UC_X86_REG_RSI) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(rsi)",
                        detail,
                    }
                })?,
                rdi: unsafe { api.reg_read_raw(uc, UC_X86_REG_RDI) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(rdi)",
                        detail,
                    }
                })?,
                rbp: unsafe { api.reg_read_raw(uc, UC_X86_REG_RBP) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(rbp)",
                        detail,
                    }
                })?,
                r12: unsafe { api.reg_read_raw(uc, UC_X86_REG_R12) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(r12)",
                        detail,
                    }
                })?,
                r13: unsafe { api.reg_read_raw(uc, UC_X86_REG_R13) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(r13)",
                        detail,
                    }
                })?,
                r14: unsafe { api.reg_read_raw(uc, UC_X86_REG_R14) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(r14)",
                        detail,
                    }
                })?,
                r15: unsafe { api.reg_read_raw(uc, UC_X86_REG_R15) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(r15)",
                        detail,
                    }
                })?,
            })
        } else {
            Ok(CalleeSavedRegisters {
                rbx: unsafe { api.reg_read_raw(uc, UC_X86_REG_EBX) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(ebx)",
                        detail,
                    }
                })?,
                rsi: unsafe { api.reg_read_raw(uc, UC_X86_REG_ESI) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(esi)",
                        detail,
                    }
                })?,
                rdi: unsafe { api.reg_read_raw(uc, UC_X86_REG_EDI) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(edi)",
                        detail,
                    }
                })?,
                rbp: unsafe { api.reg_read_raw(uc, UC_X86_REG_EBP) }.map_err(|detail| {
                    VmError::NativeExecution {
                        op: "uc_reg_read(ebp)",
                        detail,
                    }
                })?,
                ..Default::default()
            })
        }
    }

    fn restore_callee_saved_registers(
        api: &UnicornApi,
        uc: *mut UcEngine,
        is_x64: bool,
        saved: &CalleeSavedRegisters,
    ) -> Result<(), VmError> {
        if is_x64 {
            for (regid, value, op) in [
                (UC_X86_REG_RBX, saved.rbx, "uc_reg_write(rbx)"),
                (UC_X86_REG_RSI, saved.rsi, "uc_reg_write(rsi)"),
                (UC_X86_REG_RDI, saved.rdi, "uc_reg_write(rdi)"),
                (UC_X86_REG_RBP, saved.rbp, "uc_reg_write(rbp)"),
                (UC_X86_REG_R12, saved.r12, "uc_reg_write(r12)"),
                (UC_X86_REG_R13, saved.r13, "uc_reg_write(r13)"),
                (UC_X86_REG_R14, saved.r14, "uc_reg_write(r14)"),
                (UC_X86_REG_R15, saved.r15, "uc_reg_write(r15)"),
            ] {
                unsafe { api.reg_write_raw(uc, regid, value) }
                    .map_err(|detail| VmError::NativeExecution { op, detail })?;
            }
        } else {
            for (regid, value, op) in [
                (UC_X86_REG_EBX, saved.rbx, "uc_reg_write(ebx)"),
                (UC_X86_REG_ESI, saved.rsi, "uc_reg_write(esi)"),
                (UC_X86_REG_EDI, saved.rdi, "uc_reg_write(edi)"),
                (UC_X86_REG_EBP, saved.rbp, "uc_reg_write(ebp)"),
            ] {
                unsafe { api.reg_write_raw(uc, regid, value) }
                    .map_err(|detail| VmError::NativeExecution { op, detail })?;
            }
        }
        Ok(())
    }

    fn schedule_active_ldr_enum_callback(
        &mut self,
        callback: u64,
        module_entry: u64,
        context: u64,
        stop_var: u64,
        next_index: usize,
        module_entries: Vec<u64>,
        reuse_top_state: bool,
    ) -> Result<(), VmError> {
        let continuation = self.ensure_ldr_enum_continue_stub();
        // Use ensure_unicorn_session instead of active_unicorn_api_and_handle
        // because this may be called from the protected-fetch path where the
        // thread-local ACTIVE_UNICORN_CONTEXT has been cleared.
        let (api_ptr, uc) = self.ensure_unicorn_session()?;
        let api = unsafe { &*api_ptr };
        let is_x64 = self.core.arch.is_x64();
        let (entry_rsp, resume_rsp, return_address, callee_saved) = if reuse_top_state {
            let state = self
                .dispatch
                .pending_ldr_enum_callbacks
                .last()
                .cloned()
                .ok_or(VmError::RuntimeInvariant(
                    "ldr enum continuation state missing during reuse",
                ))?;
            (
                state.entry_rsp,
                state.resume_rsp,
                state.return_address,
                state.callee_saved,
            )
        } else {
            let sp_reg = if is_x64 {
                UC_X86_REG_RSP
            } else {
                UC_X86_REG_ESP
            };
            let entry_rsp = unsafe { api.reg_read_raw(uc, sp_reg) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_read(sp)",
                    detail,
                }
            })?;
            let ptr_size = self.core.arch.pointer_size as u64;
            let return_address = unsafe { api.mem_read_raw(uc, entry_rsp, ptr_size as usize) }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_mem_read(stack)",
                    detail,
                })
                .map(|bytes| {
                    if is_x64 {
                        u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
                    } else {
                        u32::from_le_bytes(bytes[..ptr_size as usize].try_into().unwrap_or([0; 4]))
                            as u64
                    }
                })?;
            let resume_rsp =
                post_return_stack_pointer(&self.core.arch, LogicalAbi::WinApi, 3, entry_rsp);
            let callee_saved = Self::save_callee_saved_registers(api, uc, is_x64)?;
            (entry_rsp, resume_rsp, return_address, callee_saved)
        };

        let args = [module_entry, context, stop_var];
        let adapter = select_adapter(&self.core.arch, &LogicalAbi::Callback);
        let _prepared = {
            let mut reg_read = |regid: i32| unsafe { api.reg_read_raw(uc, regid).map_err(|s| s) };
            let mut reg_write = |regid: i32, value: u64| unsafe {
                api.reg_write_raw(uc, regid, value).map_err(|s| s)
            };
            let mut mem_write = |addr: u64, data: &[u8]| unsafe {
                api.mem_write_raw(uc, addr, data).map_err(|s| s)
            };
            adapter.prepare_callback_frame(
                &self.core.arch,
                callback,
                continuation,
                &args,
                entry_rsp,
                &mut reg_read,
                &mut reg_write,
                &mut mem_write,
            )?
        };

        // Zero the stop variable before calling the callback
        let _ = self.core.modules.memory_mut().write(stop_var, &[0]);

        let pending = PendingLdrEnumCallback {
            entry_rsp,
            resume_rsp,
            return_address,
            callback,
            context,
            next_index,
            stop_var,
            module_entries,
            callee_saved,
        };
        if reuse_top_state {
            if let Some(active) = self.dispatch.pending_ldr_enum_callbacks.last_mut() {
                *active = pending;
            } else {
                self.dispatch.pending_ldr_enum_callbacks.push(pending);
            }
        } else {
            self.dispatch.pending_ldr_enum_callbacks.push(pending);
        }
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    fn complete_active_ldr_enum_callback(
        &mut self,
        state: &PendingLdrEnumCallback,
        retval: u64,
    ) -> Result<(), VmError> {
        let (api_ptr, uc) = self.ensure_unicorn_session()?;
        let api = unsafe { &*api_ptr };
        let is_x64 = self.core.arch.is_x64();
        let adapter = select_adapter(&self.core.arch, &LogicalAbi::Callback);
        {
            let mut reg_write = |regid: i32, value: u64| unsafe {
                api.reg_write_raw(uc, regid, value).map_err(|s| s)
            };
            adapter.write_return_value(&self.core.arch, retval, &mut reg_write)?;
        }
        let (sp_reg, pc_reg) = if is_x64 {
            (UC_X86_REG_RSP, UC_X86_REG_RIP)
        } else {
            (UC_X86_REG_ESP, UC_X86_REG_EIP)
        };
        unsafe { api.reg_write_raw(uc, sp_reg, state.resume_rsp) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(sp)",
                detail,
            }
        })?;
        unsafe { api.reg_write_raw(uc, pc_reg, state.return_address) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(pc)",
                detail,
            }
        })?;
        // Restore callee-saved registers.
        Self::restore_callee_saved_registers(api, uc, is_x64, &state.callee_saved)?;
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    pub(in crate::runtime::engine) fn resume_pending_ldr_enum_callback(
        &mut self,
    ) -> Result<u64, VmError> {
        // Use has Unicorn session check instead of unicorn_context_active().
        // The continuation stub may be dispatched through the protected-fetch
        // path (handle_pending_protected_fetch) which runs after emu_start_raw
        // returns and clears ACTIVE_UNICORN_CONTEXT.  The Unicorn session is
        // still valid in that case, and we must still restore registers.
        let has_session = self.unicorn_state.unicorn.is_some();

        loop {
            let Some(state) = self.dispatch.pending_ldr_enum_callbacks.last().cloned() else {
                return Ok(0);
            };

            // Check the BOOLEAN Stop variable set by the callback
            let stop = self
                .core
                .modules
                .memory()
                .read(state.stop_var, 1)
                .map(|b| b[0])
                .unwrap_or(0);
            if stop != 0 {
                let _ = self.dispatch.pending_ldr_enum_callbacks.pop();
                if has_session {
                    self.complete_active_ldr_enum_callback(&state, STATUS_SUCCESS as u64)?;
                }
                return Ok(STATUS_SUCCESS as u64);
            }

            // Enumeration complete — all modules visited
            if state.next_index >= state.module_entries.len() {
                let _ = self.dispatch.pending_ldr_enum_callbacks.pop();
                if has_session {
                    self.complete_active_ldr_enum_callback(&state, STATUS_SUCCESS as u64)?;
                }
                return Ok(STATUS_SUCCESS as u64);
            }

            let module_entry = state.module_entries[state.next_index];
            let next_index = state.next_index.saturating_add(1);

            // Bound stub — dispatch synchronously
            if self.core.hooks.is_bound_address(state.callback) {
                if let Some(active) = self.dispatch.pending_ldr_enum_callbacks.last_mut() {
                    active.next_index = next_index;
                }
                let _ = self.core.modules.memory_mut().write(state.stop_var, &[0]);
                self.dispatch_bound_stub(
                    state.callback,
                    &[module_entry, state.context, state.stop_var],
                )?;
                continue;
            }

            // Native Unicorn callback — schedule next iteration
            if has_session {
                self.schedule_active_ldr_enum_callback(
                    state.callback,
                    module_entry,
                    state.context,
                    state.stop_var,
                    next_index,
                    state.module_entries.clone(),
                    true,
                )?;
                return Ok(0);
            }

            // No Unicorn context — call native synchronously
            if let Some(active) = self.dispatch.pending_ldr_enum_callbacks.last_mut() {
                active.next_index = next_index;
            }
            let _ = self.core.modules.memory_mut().write(state.stop_var, &[0]);
            self.call_native_with_entry_frame(
                state.callback,
                &[module_entry, state.context, state.stop_var],
            )?;
        }
    }
}

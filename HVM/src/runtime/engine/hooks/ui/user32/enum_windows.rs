use crate::hooks::types::LogicalAbi;
use crate::runtime::engine::abi::{post_return_stack_pointer, select_adapter};

use super::*;

impl VirtualExecutionEngine {
    fn save_user32_enumwindows_callee_saved_registers(
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

    fn restore_user32_enumwindows_callee_saved_registers(
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

    fn ensure_user32_enumwindows_continue_stub(&mut self) -> u64 {
        self.core
            .hooks
            .binding_address("user32.dll", "__vm_enumwindows_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("user32.dll", "__vm_enumwindows_continue"))
    }

    fn user32_collect_enum_windows_targets(&mut self) -> Vec<u32> {
        let mut handles: Vec<u32> = self
            .ui
            .user32_state
            .windows
            .values()
            .filter(|record| record.parent == 0)
            .map(|record| record.handle)
            .collect();
        if handles.is_empty() {
            handles.push(self.user32_window_handle("active"));
        }
        handles.sort_unstable();
        handles.dedup();
        handles
    }

    fn user32_invoke_enumwindows_callback(
        &mut self,
        callback: u64,
        hwnd: u64,
        l_param: u64,
    ) -> Result<u64, VmError> {
        if self.core.hooks.is_bound_address(callback) {
            self.dispatch_bound_stub(callback, &[hwnd, l_param])
        } else {
            self.call_native_with_entry_frame(callback, &[hwnd, l_param])
        }
    }

    fn user32_enum_windows_sync(
        &mut self,
        callback: u64,
        l_param: u64,
        window_handles: &[u32],
    ) -> Result<u64, VmError> {
        for hwnd in window_handles {
            if self.user32_invoke_enumwindows_callback(callback, *hwnd as u64, l_param)? == 0 {
                return Ok(0);
            }
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn schedule_active_user32_enumwindows_callback(
        &mut self,
        callback: u64,
        hwnd: u64,
        l_param: u64,
        next_index: usize,
        window_handles: Vec<u32>,
        reuse_top_state: bool,
    ) -> Result<(), VmError> {
        let continuation = self.ensure_user32_enumwindows_continue_stub();
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let is_x64 = self.core.arch.is_x64();
        let (entry_rsp, resume_rsp, return_address, callee_saved) = if reuse_top_state {
            let state = self
                .ui
                .pending_user32_enumwindows_callbacks
                .last()
                .cloned()
                .ok_or(VmError::RuntimeInvariant(
                    "user32 enumwindows continuation state missing during reuse",
                ))?;
            (
                state.entry_rsp,
                state.resume_rsp,
                state.return_address,
                state.callee_saved,
            )
        } else {
            let entry_rsp = if is_x64 {
                unsafe { api.reg_read_raw(uc, UC_X86_REG_RSP) }
            } else {
                unsafe { api.reg_read_raw(uc, UC_X86_REG_ESP) }
            }
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_read(sp)",
                detail,
            })?;
            let ptr_size = self.core.arch.pointer_size as u64;
            let ra_bytes = unsafe { api.mem_read_raw(uc, entry_rsp, ptr_size as usize) }.map_err(
                |detail| VmError::NativeExecution {
                    op: "uc_mem_read(stack)",
                    detail,
                },
            )?;
            let return_address = if is_x64 {
                u64::from_le_bytes(ra_bytes.try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(ra_bytes[..4].try_into().unwrap_or([0; 4])) as u64
            };
            let resume_rsp =
                post_return_stack_pointer(&self.core.arch, LogicalAbi::WinApi, 2, entry_rsp);
            let callee_saved =
                Self::save_user32_enumwindows_callee_saved_registers(api, uc, is_x64)?;
            (entry_rsp, resume_rsp, return_address, callee_saved)
        };

        let args = [hwnd, l_param];
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

        let pending = PendingUser32EnumWindowsCallback {
            entry_rsp,
            resume_rsp,
            return_address,
            callback,
            l_param,
            next_index,
            window_handles,
            callee_saved,
        };
        if reuse_top_state {
            if let Some(active) = self.ui.pending_user32_enumwindows_callbacks.last_mut() {
                *active = pending;
            } else {
                self.ui.pending_user32_enumwindows_callbacks.push(pending);
            }
        } else {
            self.ui.pending_user32_enumwindows_callbacks.push(pending);
        }
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    fn complete_active_user32_enumwindows_callback(
        &mut self,
        state: &PendingUser32EnumWindowsCallback,
        retval: u64,
    ) -> Result<(), VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let is_x64 = self.core.arch.is_x64();
        let adapter = select_adapter(&self.core.arch, &LogicalAbi::Callback);
        {
            let mut reg_write = |regid: i32, value: u64| unsafe {
                api.reg_write_raw(uc, regid, value).map_err(|s| s)
            };
            adapter.write_return_value(&self.core.arch, retval, &mut reg_write)?;
        }
        let (sp_reg, pc_reg) = if self.core.arch.is_x64() {
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
        Self::restore_user32_enumwindows_callee_saved_registers(
            api,
            uc,
            is_x64,
            &state.callee_saved,
        )?;
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    pub(super) fn resume_pending_user32_enumwindows_callback(&mut self) -> Result<u64, VmError> {
        let active_inline = unicorn_context_active();
        let mut callback_result = if active_inline {
            self.active_unicorn_return_value()?
        } else {
            0
        };
        loop {
            let Some(state) = self.ui.pending_user32_enumwindows_callbacks.last().cloned() else {
                return Ok(callback_result);
            };
            if callback_result == 0 {
                let _ = self.ui.pending_user32_enumwindows_callbacks.pop();
                if active_inline {
                    self.complete_active_user32_enumwindows_callback(&state, 0)?;
                }
                return Ok(0);
            }
            if state.next_index >= state.window_handles.len() {
                let _ = self.ui.pending_user32_enumwindows_callbacks.pop();
                self.set_last_error(ERROR_SUCCESS as u32);
                if active_inline {
                    self.complete_active_user32_enumwindows_callback(&state, 1)?;
                }
                return Ok(1);
            }

            let hwnd = state.window_handles[state.next_index] as u64;
            let next_index = state.next_index.saturating_add(1);
            if self.core.hooks.is_bound_address(state.callback) {
                if let Some(active) = self.ui.pending_user32_enumwindows_callbacks.last_mut() {
                    active.next_index = next_index;
                }
                callback_result =
                    self.dispatch_bound_stub(state.callback, &[hwnd, state.l_param])?;
                continue;
            }
            if active_inline {
                self.schedule_active_user32_enumwindows_callback(
                    state.callback,
                    hwnd,
                    state.l_param,
                    next_index,
                    state.window_handles.clone(),
                    true,
                )?;
                return Ok(0);
            }
            if let Some(active) = self.ui.pending_user32_enumwindows_callbacks.last_mut() {
                active.next_index = next_index;
            }
            callback_result =
                self.call_native_with_entry_frame(state.callback, &[hwnd, state.l_param])?;
        }
    }

    pub(super) fn user32_enum_windows(
        &mut self,
        callback: u64,
        l_param: u64,
    ) -> Result<u64, VmError> {
        if callback == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let window_handles = self.user32_collect_enum_windows_targets();
        if unicorn_context_active() && !self.core.hooks.is_bound_address(callback) {
            let hwnd = window_handles.first().copied().unwrap_or(0) as u64;
            self.schedule_active_user32_enumwindows_callback(
                callback,
                hwnd,
                l_param,
                1,
                window_handles,
                false,
            )?;
            return Ok(0);
        }
        self.user32_enum_windows_sync(callback, l_param, &window_handles)
    }
}

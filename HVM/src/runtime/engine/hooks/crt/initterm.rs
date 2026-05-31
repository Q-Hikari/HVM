use crate::hooks::types::LogicalAbi;
use crate::runtime::engine::abi::{post_return_stack_pointer, select_adapter};

use super::*;

impl VirtualExecutionEngine {
    fn ensure_msvcrt_initterm_continue_stub(&mut self) -> u64 {
        self.core
            .hooks
            .binding_address("msvcrt.dll", "__vm_initterm_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("msvcrt.dll", "__vm_initterm_continue"))
    }

    fn schedule_active_msvcrt_initterm_callback(
        &mut self,
        function: u64,
        next_cursor: u64,
        last: u64,
        stop_on_nonzero: bool,
        reuse_top_state: bool,
    ) -> Result<(), VmError> {
        let continuation = self.ensure_msvcrt_initterm_continue_stub();
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        let (entry_rsp, resume_rsp, return_address) = if reuse_top_state {
            let state = self.crt.pending_msvcrt_initterm.last().copied().ok_or(
                VmError::RuntimeInvariant("msvcrt continuation state missing during reuse"),
            )?;
            (state.entry_rsp, state.resume_rsp, state.return_address)
        } else {
            let sp_reg = if self.core.arch.is_x64() {
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
                    if self.core.arch.is_x64() {
                        u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
                    } else {
                        u32::from_le_bytes(bytes[..ptr_size as usize].try_into().unwrap_or([0; 4]))
                            as u64
                    }
                })?;
            let resume_rsp =
                post_return_stack_pointer(&self.core.arch, LogicalAbi::Cdecl, 2, entry_rsp);
            (entry_rsp, resume_rsp, return_address)
        };

        let args: [u64; 0] = [];
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
                function,
                continuation,
                &args,
                entry_rsp,
                &mut reg_read,
                &mut reg_write,
                &mut mem_write,
            )?
        };

        let pending = PendingMsvcrtInitterm {
            entry_rsp,
            resume_rsp,
            return_address,
            next_cursor,
            last,
            stop_on_nonzero,
        };
        if reuse_top_state {
            if let Some(active) = self.crt.pending_msvcrt_initterm.last_mut() {
                *active = pending;
            } else {
                self.crt.pending_msvcrt_initterm.push(pending);
            }
        } else {
            self.crt.pending_msvcrt_initterm.push(pending);
        }
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    fn complete_active_msvcrt_initterm(
        &mut self,
        state: PendingMsvcrtInitterm,
        retval: u64,
    ) -> Result<(), VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
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
        self.dispatch.request_resume_at_updated_pc();
        Ok(())
    }

    pub(super) fn resume_pending_msvcrt_initterm(&mut self) -> Result<u64, VmError> {
        let active_inline = unicorn_context_active();
        let callback_result = if active_inline {
            self.active_unicorn_return_value()?
        } else {
            0
        };
        loop {
            let Some(state) = self.crt.pending_msvcrt_initterm.last().copied() else {
                return Ok(callback_result);
            };
            if state.stop_on_nonzero && callback_result != 0 {
                self.crt.pending_msvcrt_initterm.pop();
                if active_inline {
                    self.complete_active_msvcrt_initterm(state, callback_result)?;
                }
                return Ok(callback_result);
            }

            let step = self.core.arch.pointer_size as u64;
            let mut cursor = state.next_cursor;
            while cursor < state.last {
                let function = self.read_pointer_value(cursor)?;
                if function != 0 && function != u64::MAX {
                    if let Some(active) = self.crt.pending_msvcrt_initterm.last_mut() {
                        active.next_cursor = cursor.saturating_add(step);
                    }
                    let result = if self.core.hooks.is_bound_address(function) {
                        self.dispatch_bound_stub(function, &[])?
                    } else if active_inline {
                        self.schedule_active_msvcrt_initterm_callback(
                            function,
                            cursor.saturating_add(step),
                            state.last,
                            state.stop_on_nonzero,
                            true,
                        )?;
                        return Ok(0);
                    } else {
                        self.call_native_with_entry_frame(function, &[])?
                    };
                    if state.stop_on_nonzero && result != 0 {
                        self.crt.pending_msvcrt_initterm.pop();
                        if active_inline {
                            self.complete_active_msvcrt_initterm(state, result)?;
                        }
                        return Ok(result);
                    }
                }
                cursor = cursor.saturating_add(step);
                if let Some(active) = self.crt.pending_msvcrt_initterm.last_mut() {
                    active.next_cursor = cursor;
                }
            }
            self.crt.pending_msvcrt_initterm.pop();
            if active_inline {
                self.complete_active_msvcrt_initterm(state, 0)?;
            }
            return Ok(0);
        }
    }

    pub(super) fn run_msvcrt_initterm_range(
        &mut self,
        first: u64,
        last: u64,
        stop_on_nonzero: bool,
    ) -> Result<u64, VmError> {
        if first == 0 || last == 0 || first >= last {
            return Ok(0);
        }
        let step = self.core.arch.pointer_size as u64;
        let mut cursor = first;
        while cursor < last {
            let function = self.read_pointer_value(cursor)?;
            if function != 0 && function != u64::MAX {
                let result = if self.core.hooks.is_bound_address(function) {
                    self.dispatch_bound_stub(function, &[])?
                } else if unicorn_context_active() {
                    self.schedule_active_msvcrt_initterm_callback(
                        function,
                        cursor.saturating_add(step),
                        last,
                        stop_on_nonzero,
                        false,
                    )?;
                    return Ok(0);
                } else {
                    self.call_native_with_entry_frame(function, &[])?
                };
                if stop_on_nonzero && result != 0 {
                    return Ok(result);
                }
            }
            cursor = cursor.saturating_add(step);
        }
        Ok(0)
    }
}

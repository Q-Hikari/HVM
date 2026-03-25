use super::*;

impl VirtualExecutionEngine {
    fn ensure_msvcrt_initterm_continue_stub(&mut self) -> u64 {
        self.hooks
            .binding_address("msvcrt.dll", "__vm_initterm_continue")
            .unwrap_or_else(|| self.bind_hook_for_test("msvcrt.dll", "__vm_initterm_continue"))
    }

    fn schedule_active_x64_msvcrt_initterm_callback(
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
        let (entry_rsp, resume_rsp, return_address) =
            if reuse_top_state {
                let state = self.pending_msvcrt_initterm.last().copied().ok_or(
                    VmError::RuntimeInvariant("msvcrt continuation state missing during reuse"),
                )?;
                (state.entry_rsp, state.resume_rsp, state.return_address)
            } else {
                let entry_rsp =
                    unsafe { api.reg_read_raw(uc, UC_X86_REG_RSP) }.map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(rsp)",
                            detail,
                        }
                    })?;
                let return_address = unsafe { api.mem_read_raw(uc, entry_rsp, 8) }
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_mem_read(stack)",
                        detail,
                    })
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))?;
                let resume_rsp = entry_rsp.checked_add(8).ok_or(VmError::RuntimeInvariant(
                    "msvcrt continuation stack overflow",
                ))?;
                (entry_rsp, resume_rsp, return_address)
            };
        let call_rsp = entry_rsp
            .checked_sub(0x28)
            .ok_or(VmError::RuntimeInvariant(
                "msvcrt continuation stack underflow",
            ))?;
        let mut frame = [0u8; 0x28];
        frame[..8].copy_from_slice(&continuation.to_le_bytes());
        self.modules.memory_mut().write(call_rsp, &frame)?;
        unsafe { api.mem_write_raw(uc, call_rsp, &frame) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_mem_write(msvcrt_continuation)",
                detail,
            }
        })?;
        for (regid, value, op) in [
            (UC_X86_REG_RIP, function, "uc_reg_write(rip)"),
            (UC_X86_REG_RSP, call_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RCX, 0, "uc_reg_write(rcx)"),
            (UC_X86_REG_RDX, 0, "uc_reg_write(rdx)"),
            (UC_X86_REG_R8, 0, "uc_reg_write(r8)"),
            (UC_X86_REG_R9, 0, "uc_reg_write(r9)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        let pending = PendingMsvcrtInitterm {
            entry_rsp,
            resume_rsp,
            return_address,
            next_cursor,
            last,
            stop_on_nonzero,
        };
        if reuse_top_state {
            if let Some(active) = self.pending_msvcrt_initterm.last_mut() {
                *active = pending;
            } else {
                self.pending_msvcrt_initterm.push(pending);
            }
        } else {
            self.pending_msvcrt_initterm.push(pending);
        }
        self.defer_api_return = true;
        Ok(())
    }

    fn complete_active_x64_msvcrt_initterm(
        &mut self,
        state: PendingMsvcrtInitterm,
        retval: u64,
    ) -> Result<(), VmError> {
        let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
        let api = unsafe { &*api_ptr };
        for (regid, value, op) in [
            (UC_X86_REG_RAX, retval, "uc_reg_write(rax)"),
            (UC_X86_REG_RSP, state.resume_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RIP, state.return_address, "uc_reg_write(rip)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        self.defer_api_return = true;
        Ok(())
    }

    pub(super) fn resume_pending_msvcrt_initterm(&mut self) -> Result<u64, VmError> {
        let active_x64 = self.arch.is_x64() && unicorn_context_active();
        let callback_result = if active_x64 {
            self.active_unicorn_return_value()?
        } else {
            0
        };
        loop {
            let Some(state) = self.pending_msvcrt_initterm.last().copied() else {
                return Ok(callback_result);
            };
            if state.stop_on_nonzero && callback_result != 0 {
                self.pending_msvcrt_initterm.pop();
                if active_x64 {
                    self.complete_active_x64_msvcrt_initterm(state, callback_result)?;
                }
                return Ok(callback_result);
            }

            let step = self.arch.pointer_size as u64;
            let mut cursor = state.next_cursor;
            while cursor < state.last {
                let function = self.read_pointer_value(cursor)?;
                if function != 0 && function != u64::MAX {
                    if let Some(active) = self.pending_msvcrt_initterm.last_mut() {
                        active.next_cursor = cursor.saturating_add(step);
                    }
                    let result = if self.hooks.is_bound_address(function) {
                        self.dispatch_bound_stub(function, &[])?
                    } else if active_x64 {
                        self.schedule_active_x64_msvcrt_initterm_callback(
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
                        self.pending_msvcrt_initterm.pop();
                        if active_x64 {
                            self.complete_active_x64_msvcrt_initterm(state, result)?;
                        }
                        return Ok(result);
                    }
                }
                cursor = cursor.saturating_add(step);
                if let Some(active) = self.pending_msvcrt_initterm.last_mut() {
                    active.next_cursor = cursor;
                }
            }
            self.pending_msvcrt_initterm.pop();
            if active_x64 {
                self.complete_active_x64_msvcrt_initterm(state, 0)?;
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
        let step = self.arch.pointer_size as u64;
        let mut cursor = first;
        while cursor < last {
            let function = self.read_pointer_value(cursor)?;
            if function != 0 && function != u64::MAX {
                let result = if self.hooks.is_bound_address(function) {
                    self.dispatch_bound_stub(function, &[])?
                } else if self.arch.is_x64() && unicorn_context_active() {
                    self.schedule_active_x64_msvcrt_initterm_callback(
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

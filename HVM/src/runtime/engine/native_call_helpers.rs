use super::*;

impl VirtualExecutionEngine {
    /// Builds the raw frame bytes for a native x86 call.
    ///
    /// Constructs the stack frame containing the return address followed by
    /// all arguments as 32-bit values. Returns `(frame_bytes, new_esp)` where
    /// `new_esp` is the adjusted stack pointer after pushing the frame.
    pub(super) fn build_x86_native_frame(
        &self,
        return_address: u64,
        args: &[u64],
        current_esp: u64,
    ) -> Result<(Vec<u8>, u64), VmError> {
        let mut frame = Vec::with_capacity((args.len() + 1) * 4);
        frame.extend_from_slice(&(return_address as u32).to_le_bytes());
        for value in args {
            frame.extend_from_slice(&(*value as u32).to_le_bytes());
        }
        let new_esp = current_esp
            .checked_sub(frame.len() as u64)
            .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
        Ok((frame, new_esp))
    }

    /// Builds the raw frame bytes for a native x64 call.
    ///
    /// Constructs the stack frame with the return address at offset 0,
    /// 32 bytes of shadow space, and any stack arguments beyond the first 4
    /// register-passed arguments. Returns `(frame_bytes, new_rsp)` where
    /// `new_rsp` is the adjusted stack pointer after allocating the frame.
    pub(super) fn build_x64_native_frame(
        &self,
        return_address: u64,
        args: &[u64],
        current_rsp: u64,
    ) -> Result<(Vec<u8>, u64), VmError> {
        let stack_arg_count = args.len().saturating_sub(4);
        let frame_size = 0x28 + stack_arg_count * 8;
        let new_rsp = current_rsp
            .checked_sub(frame_size as u64)
            .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
        let mut frame = vec![0u8; frame_size];
        frame[0..8].copy_from_slice(&return_address.to_le_bytes());
        for (index, value) in args.iter().skip(4).enumerate() {
            let offset = 0x28 + index * 8;
            frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok((frame, new_rsp))
    }

    pub(super) fn call_native_with_entry_frame(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        if self.core.hooks.is_bound_address(address) {
            return self.dispatch_bound_stub(address, args);
        }
        if self.core.arch.is_x64() {
            if self.unicorn_state.unicorn.is_some() && !unicorn_context_active() {
                self.call_x64_native_with_entry_frame_unicorn(address, args)
            } else {
                Err(VmError::NativeExecution {
                    op: "run",
                    detail: "x64 execution requires a native Unicorn backend".to_string(),
                })
            }
        } else if self.unicorn_state.unicorn.is_some() && !unicorn_context_active() {
            self.call_x86_native_with_entry_frame_unicorn(address, args)
        } else {
            self.call_x86_native_with_entry_frame_interpreter(address, args)
        }
    }

    fn native_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        let main_tid = self
            .core
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .core
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        let saved_esp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            let esp = thread.registers.esp;
            if esp == 0 {
                return Err(VmError::RuntimeInvariant("main thread ESP missing"));
            }
            esp
        };
        let saved_eflags = if thread.registers.eflags != 0 {
            thread.registers.eflags
        } else {
            0x202
        } as u32;
        Ok((saved_esp, saved_eflags))
    }

    fn native_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        let main_tid = self
            .core
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .core
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        let saved_rsp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            let rsp = thread.registers.rsp;
            if rsp == 0 {
                return Err(VmError::RuntimeInvariant("main thread RSP missing"));
            }
            rsp
        };
        let saved_rflags = if thread.registers.rflags != 0 {
            thread.registers.rflags
        } else {
            0x202
        };
        Ok((saved_rsp, saved_rflags))
    }

    pub(super) fn standalone_native_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        // Use the live Unicorn stack cursor for standalone native calls.
        self.native_x86_call_context()
    }

    pub(super) fn thread_entry_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        let tid = self
            .core
            .scheduler
            .current_tid()
            .or(self.core.main_thread_tid)
            .ok_or(VmError::RuntimeInvariant("current thread not initialized"))?;
        let thread = self
            .core
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("current thread snapshot missing"))?;
        let saved_esp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            let esp = thread.registers.esp;
            if esp == 0 {
                return Err(VmError::RuntimeInvariant("current thread ESP missing"));
            }
            esp
        };
        let saved_eflags = if thread.registers.eflags != 0 {
            thread.registers.eflags
        } else {
            0x202
        } as u32;
        Ok((saved_esp, saved_eflags))
    }

    pub(super) fn standalone_native_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        self.native_x64_call_context()
    }

    pub(super) fn thread_entry_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        let tid = self
            .core
            .scheduler
            .current_tid()
            .or(self.core.main_thread_tid)
            .ok_or(VmError::RuntimeInvariant("current thread not initialized"))?;
        let thread = self
            .core
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("current thread snapshot missing"))?;
        let saved_rsp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            let rsp = thread.registers.rsp;
            if rsp == 0 {
                return Err(VmError::RuntimeInvariant("current thread RSP missing"));
            }
            rsp
        };
        let saved_rflags = if thread.registers.rflags != 0 {
            thread.registers.rflags
        } else {
            0x202
        };
        Ok((saved_rsp, saved_rflags))
    }

    pub(super) fn blocked_entry_frame_return_value(
        &self,
        entry_tid: Option<u32>,
        fallback: u64,
        deferred_api_return: bool,
    ) -> u64 {
        if deferred_api_return
            || entry_tid
                .and_then(|tid| self.core.scheduler.thread_state(tid))
                .is_some_and(|state| matches!(state, "waiting" | "sleeping"))
        {
            crate::runtime::scheduler::WAIT_TIMEOUT as u64
        } else {
            fallback
        }
    }

    pub(super) fn sync_native_support_state(&mut self) -> Result<(), VmError> {
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("runtime.sync_native_support_state");
        if self.core.process_env.is_dirty() {
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("runtime.sync_current_thread_from_memory");
                self.core
                    .process_env
                    .sync_current_thread_from_memory(self.core.modules.memory())
                    .map_err(VmError::from)?;
            }
            {
                let _profile = self
                    .core
                    .runtime_profiler
                    .start_scope("runtime.materialize_process_environment");
                self.core
                    .process_env
                    .materialize_into(self.core.modules.memory_mut())
                    .map_err(VmError::from)?;
            }
        }
        {
            let _profile = self
                .core
                .runtime_profiler
                .start_scope("runtime.sync_native_thread_binding");
            self.sync_native_thread_binding()
        }
    }

    fn sync_native_thread_binding(&mut self) -> Result<(), VmError> {
        if self.core.arch.is_x64() {
            if let (Some(unicorn), Some(handle)) = (
                self.unicorn_state.unicorn.as_deref(),
                self.unicorn_state.unicorn_handle,
            ) {
                unsafe {
                    unicorn.reg_write_raw(
                        handle,
                        UC_X86_REG_GS_BASE,
                        self.core.process_env.current_teb(),
                    )
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(gs_base)",
                    detail,
                })?;
            }
        }
        Ok(())
    }

    pub(super) fn call_x86_native_interpreter_context(
        &mut self,
        address: u64,
        args: &[u64],
        saved_esp: u64,
        saved_eflags: u32,
        _run_mode: NativeCallRunMode,
    ) -> Result<u64, VmError> {
        self.dispatch.force_native_return = false;
        let preserve_blocked_api_frame = self.dispatch.preserve_blocked_api_frame;
        self.dispatch.preserve_blocked_api_frame =
            matches!(_run_mode, NativeCallRunMode::Standalone);
        let entry_tid = self.core.scheduler.current_tid();
        let result = (|| {
            if matches!(_run_mode, NativeCallRunMode::EntryFrame) {
                if let Some(tid) = self.core.scheduler.current_tid() {
                    let _ = self.core.scheduler.mark_thread_running(tid);
                }
            }
            let (frame, new_esp) =
                self.build_x86_native_frame(self.core.native_return_sentinel, args, saved_esp)?;
            self.core.modules.memory_mut().write(new_esp, &frame)?;
            let mut state = X86State::new(address as u32, new_esp as u32, saved_eflags);
            let instruction_budget = self.core.config.max_instructions.max(1);
            let time_slice = self.core.scheduler.time_slice_instructions().max(1);
            let mut steps_in_slice: u64 = 0;

            for _ in 0..instruction_budget {
                // Preemptive yield: every time_slice steps, check if other
                // threads are ready and switch if so.
                steps_in_slice = steps_in_slice.saturating_add(1);
                if steps_in_slice >= time_slice
                    && !self.dispatch.thread_yield_requested()
                    && self.core.scheduler.has_ready_threads()
                {
                    steps_in_slice = 0;
                    if let Some(tid) = self.core.scheduler.current_tid() {
                        let registers = RegisterFile {
                            eax: state.eax as u64,
                            ebx: state.ebx as u64,
                            ecx: state.ecx as u64,
                            edx: state.edx as u64,
                            esi: state.esi as u64,
                            edi: state.edi as u64,
                            ebp: state.ebp as u64,
                            esp: state.esp as u64,
                            eip: state.eip as u64,
                            eflags: state._eflags as u64,
                            ..RegisterFile::new()
                        };
                        let _ = self.core.scheduler.set_thread_registers(tid, registers);
                        let _ = self.core.scheduler.mark_thread_ready(tid);
                        if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                            let next_regs = self
                                .core
                                .scheduler
                                .thread_registers(next_tid)
                                .unwrap_or(RegisterFile::new());
                            let _ = self
                                .core
                                .scheduler
                                .switch_to(next_tid, &mut self.core.process_env);
                            state = X86State {
                                eax: next_regs.eax as u32,
                                ecx: next_regs.ecx as u32,
                                edx: next_regs.edx as u32,
                                ebx: next_regs.ebx as u32,
                                esp: next_regs.esp as u32,
                                ebp: next_regs.ebp as u32,
                                esi: next_regs.esi as u32,
                                edi: next_regs.edi as u32,
                                eip: next_regs.eip as u32,
                                _eflags: if next_regs.eflags != 0 {
                                    next_regs.eflags
                                } else {
                                    0x202
                                } as u32,
                            };
                            continue;
                        }
                    }
                }
                if state.eip as u64 == self.core.native_return_sentinel {
                    if matches!(_run_mode, NativeCallRunMode::EntryFrame)
                        && self.core.scheduler.current_tid() != entry_tid
                    {
                        let return_value = state.eax as u64;
                        let _ = self.terminate_current_thread(return_value as u32);
                        self.handle_requested_thread_yield();
                        if let Some(tid) = entry_tid {
                            if matches!(
                                self.core.scheduler.thread_state(tid),
                                Some("ready" | "running")
                            ) {
                                let _ = self.core.scheduler.mark_thread_running(tid);
                                continue;
                            }
                        }
                        if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                            let next_thread =
                                self.core.scheduler.thread_snapshot(next_tid).ok_or(
                                    VmError::RuntimeInvariant("next thread snapshot missing"),
                                )?;
                            let _ = self
                                .core
                                .scheduler
                                .switch_to(next_tid, &mut self.core.process_env);
                            state = X86State {
                                eax: next_thread.registers.eax as u32,
                                ecx: next_thread.registers.ecx as u32,
                                edx: next_thread.registers.edx as u32,
                                ebx: next_thread.registers.ebx as u32,
                                esp: next_thread.registers.esp as u32,
                                ebp: next_thread.registers.ebp as u32,
                                esi: next_thread.registers.esi as u32,
                                edi: next_thread.registers.edi as u32,
                                eip: next_thread.registers.eip as u32,
                                _eflags: next_thread.registers.eflags as u32,
                            };
                            continue;
                        }
                        return Ok(self.blocked_entry_frame_return_value(
                            entry_tid,
                            self.entry_frame_x86_fallback_ret(entry_tid, return_value),
                            self.dispatch.api_return_deferred(),
                        ));
                    }
                    return Ok(state.eax as u64);
                }
                self.record_instruction_retired();
                self.step_x86_interpreter(&mut state)?;
                let current_thread_state = self
                    .core
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.core.scheduler.thread_state(tid));
                let yielded_blocking_thread = current_thread_state != Some("running");
                if self.dispatch.thread_yield_requested() || yielded_blocking_thread {
                    let deferred_api_return = self.dispatch.api_return_deferred();
                    let _ = self.log_native_yield_event("x86_interpreter", yielded_blocking_thread);
                    if self.dispatch.thread_yield_requested() {
                        self.dispatch.reset_api_flow_control();
                    }
                    if yielded_blocking_thread {
                        if let Some(tid) = self.core.scheduler.current_tid() {
                            let registers = RegisterFile {
                                eax: state.eax as u64,
                                ebx: state.ebx as u64,
                                ecx: state.ecx as u64,
                                edx: state.edx as u64,
                                esi: state.esi as u64,
                                edi: state.edi as u64,
                                ebp: state.ebp as u64,
                                esp: state.esp as u64,
                                eip: state.eip as u64,
                                eflags: state._eflags as u64,
                                ..RegisterFile::new()
                            };
                            self.core
                                .scheduler
                                .set_thread_registers(tid, registers)
                                .ok_or(VmError::RuntimeInvariant(
                                    "failed to persist entry-frame yield registers",
                                ))?;
                        }
                        match _run_mode {
                            NativeCallRunMode::Standalone => {
                                self.handle_requested_thread_yield();
                                if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                                    let next_thread =
                                        self.core.scheduler.thread_snapshot(next_tid).ok_or(
                                            VmError::RuntimeInvariant(
                                                "next thread snapshot missing",
                                            ),
                                        )?;
                                    let _ = self
                                        .core
                                        .scheduler
                                        .switch_to(next_tid, &mut self.core.process_env);
                                    state = X86State {
                                        eax: next_thread.registers.eax as u32,
                                        ecx: next_thread.registers.ecx as u32,
                                        edx: next_thread.registers.edx as u32,
                                        ebx: next_thread.registers.ebx as u32,
                                        esp: next_thread.registers.esp as u32,
                                        ebp: next_thread.registers.ebp as u32,
                                        esi: next_thread.registers.esi as u32,
                                        edi: next_thread.registers.edi as u32,
                                        eip: next_thread.registers.eip as u32,
                                        _eflags: next_thread.registers.eflags as u32,
                                    };
                                    continue;
                                }
                                continue;
                            }
                            NativeCallRunMode::EntryFrame => {
                                self.handle_requested_thread_yield();
                                if let Some(tid) = entry_tid {
                                    if matches!(
                                        self.core.scheduler.thread_state(tid),
                                        Some("ready" | "running")
                                    ) {
                                        let _ = self.core.scheduler.mark_thread_running(tid);
                                        continue;
                                    }
                                }
                                return Ok(self.blocked_entry_frame_return_value(
                                    entry_tid,
                                    self.entry_frame_x86_fallback_ret(entry_tid, state.eax as u64),
                                    deferred_api_return,
                                ));
                            }
                        }
                    }
                    self.handle_requested_thread_yield();
                } else {
                    // Non-blocking yield: the thread requested a yield but its
                    // scheduler state is still "running".  Save registers and
                    // switch to a ready thread so busy-waiting callers (e.g.
                    // WaitForSingleObject on an always-signaled handle) do not
                    // starve other threads.
                    if let Some(tid) = self.core.scheduler.current_tid() {
                        let registers = RegisterFile {
                            eax: state.eax as u64,
                            ebx: state.ebx as u64,
                            ecx: state.ecx as u64,
                            edx: state.edx as u64,
                            esi: state.esi as u64,
                            edi: state.edi as u64,
                            ebp: state.ebp as u64,
                            esp: state.esp as u64,
                            eip: state.eip as u64,
                            eflags: state._eflags as u64,
                            ..RegisterFile::new()
                        };
                        let _ = self.core.scheduler.set_thread_registers(tid, registers);
                        if self.core.scheduler.has_ready_threads() {
                            let _ = self.core.scheduler.mark_thread_ready(tid);
                            if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                                let next_regs = self
                                    .core
                                    .scheduler
                                    .thread_registers(next_tid)
                                    .unwrap_or(RegisterFile::new());
                                let _ = self
                                    .core
                                    .scheduler
                                    .switch_to(next_tid, &mut self.core.process_env);
                                state = X86State {
                                    eax: next_regs.eax as u32,
                                    ecx: next_regs.ecx as u32,
                                    edx: next_regs.edx as u32,
                                    ebx: next_regs.ebx as u32,
                                    esp: next_regs.esp as u32,
                                    ebp: next_regs.ebp as u32,
                                    esi: next_regs.esi as u32,
                                    edi: next_regs.edi as u32,
                                    eip: next_regs.eip as u32,
                                    _eflags: if next_regs.eflags != 0 {
                                        next_regs.eflags
                                    } else {
                                        0x202
                                    } as u32,
                                };
                                self.dispatch.reset_api_flow_control();
                                continue;
                            }
                        }
                    }
                    self.handle_requested_thread_yield();
                }
            }

            Err(VmError::NativeExecution {
                op: "run",
                detail: format!("instruction budget exhausted at 0x{:X}", state.eip as u64),
            })
        })();
        self.dispatch.preserve_blocked_api_frame = preserve_blocked_api_frame;
        result
    }

    pub(super) fn entry_frame_x86_fallback_ret(
        &self,
        entry_tid: Option<u32>,
        fallback: u64,
    ) -> u64 {
        entry_tid
            .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
            .map(|thread| thread.registers.eax)
            .unwrap_or(fallback)
    }

    pub(super) fn call_x86_native_interpreter(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_esp, saved_eflags) = self.standalone_native_x86_call_context()?;
        self.call_x86_native_interpreter_context(
            address,
            args,
            saved_esp,
            saved_eflags,
            NativeCallRunMode::Standalone,
        )
    }

    pub(super) fn call_x86_native_with_entry_frame_interpreter(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_esp, saved_eflags) = self.thread_entry_x86_call_context()?;
        self.call_x86_native_interpreter_context(
            address,
            args,
            saved_esp,
            saved_eflags,
            NativeCallRunMode::EntryFrame,
        )
    }
}

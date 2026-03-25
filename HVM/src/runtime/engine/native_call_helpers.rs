use super::*;

impl VirtualExecutionEngine {
    pub(super) fn call_native_with_entry_frame(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        if self.hooks.is_bound_address(address) {
            return self.dispatch_bound_stub(address, args);
        }
        if self.arch.is_x64() {
            if self.unicorn.is_some() && !unicorn_context_active() {
                self.call_x64_native_with_entry_frame_unicorn(address, args)
            } else {
                Err(VmError::NativeExecution {
                    op: "run",
                    detail: "x64 execution requires a native Unicorn backend".to_string(),
                })
            }
        } else if self.unicorn.is_some() && !unicorn_context_active() {
            self.call_x86_native_with_entry_frame_unicorn(address, args)
        } else {
            self.call_x86_native_with_entry_frame_interpreter(address, args)
        }
    }

    fn native_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        let main_tid = self
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        let saved_esp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            thread
                .registers
                .get("esp")
                .copied()
                .ok_or(VmError::RuntimeInvariant("main thread ESP missing"))?
        };
        let saved_eflags = thread.registers.get("eflags").copied().unwrap_or(0x202) as u32;
        Ok((saved_esp, saved_eflags))
    }

    fn native_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        let main_tid = self
            .main_thread_tid
            .ok_or(VmError::RuntimeInvariant("main thread not initialized"))?;
        let thread = self
            .scheduler
            .thread_snapshot(main_tid)
            .ok_or(VmError::RuntimeInvariant("main thread snapshot missing"))?;
        let saved_rsp = if thread.stack_top != 0 {
            thread.stack_top
        } else {
            thread
                .registers
                .get("rsp")
                .copied()
                .ok_or(VmError::RuntimeInvariant("main thread RSP missing"))?
        };
        let saved_rflags = thread.registers.get("rflags").copied().unwrap_or(0x202);
        Ok((saved_rsp, saved_rflags))
    }

    pub(super) fn standalone_native_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        // Python's standalone call_native uses the live Unicorn stack cursor, which starts at
        // stack_top rather than the scheduler entry frame at stack_top - 8.
        self.native_x86_call_context()
    }

    pub(super) fn thread_entry_x86_call_context(&self) -> Result<(u64, u32), VmError> {
        self.native_x86_call_context()
    }

    pub(super) fn standalone_native_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        self.native_x64_call_context()
    }

    pub(super) fn thread_entry_x64_call_context(&self) -> Result<(u64, u64), VmError> {
        self.native_x64_call_context()
    }

    pub(super) fn sync_native_support_state(&mut self) -> Result<(), VmError> {
        let _profile = self
            .runtime_profiler
            .start_scope("runtime.sync_native_support_state");
        if self.process_env.is_dirty() {
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("runtime.sync_current_thread_from_memory");
                self.process_env
                    .sync_current_thread_from_memory(self.modules.memory())
                    .map_err(VmError::from)?;
            }
            {
                let _profile = self
                    .runtime_profiler
                    .start_scope("runtime.materialize_process_environment");
                self.process_env
                    .materialize_into(self.modules.memory_mut())
                    .map_err(VmError::from)?;
            }
        }
        {
            let _profile = self
                .runtime_profiler
                .start_scope("runtime.sync_native_thread_binding");
            self.sync_native_thread_binding()
        }
    }

    fn sync_native_thread_binding(&mut self) -> Result<(), VmError> {
        if self.arch.is_x64() {
            if let (Some(unicorn), Some(handle)) = (self.unicorn.as_deref(), self.unicorn_handle) {
                unsafe {
                    unicorn.reg_write_raw(
                        handle,
                        UC_X86_REG_GS_BASE,
                        self.process_env.current_teb(),
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
        run_mode: NativeCallRunMode,
    ) -> Result<u64, VmError> {
        self.force_native_return = false;

        let mut frame = Vec::with_capacity((args.len() + 1) * 4);
        frame.extend_from_slice(&(self.native_return_sentinel as u32).to_le_bytes());
        for value in args {
            frame.extend_from_slice(&(*value as u32).to_le_bytes());
        }
        let new_esp = saved_esp
            .checked_sub(frame.len() as u64)
            .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
        self.modules.memory_mut().write(new_esp, &frame)?;
        let mut state = X86State::new(address as u32, new_esp as u32, saved_eflags);
        let instruction_budget = self.config.max_instructions.max(1);

        for _ in 0..instruction_budget {
            if state.eip as u64 == self.native_return_sentinel {
                return Ok(state.eax as u64);
            }
            self.record_instruction_retired();
            self.step_x86_interpreter(&mut state)?;
            if self.thread_yield_requested {
                self.handle_requested_thread_yield();
                let yielded_entry_frame = matches!(run_mode, NativeCallRunMode::EntryFrame)
                    && self
                        .scheduler
                        .current_tid()
                        .and_then(|tid| self.scheduler.thread_state(tid))
                        != Some("running");
                self.thread_yield_requested = false;
                self.defer_api_return = false;
                if yielded_entry_frame {
                    return Ok(state.eax as u64);
                }
            }
        }

        Err(VmError::NativeExecution {
            op: "run",
            detail: format!("instruction budget exhausted at 0x{:X}", state.eip as u64),
        })
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

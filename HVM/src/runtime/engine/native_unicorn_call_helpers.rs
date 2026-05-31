use super::*;

impl VirtualExecutionEngine {
    #[allow(dead_code)]
    pub(super) fn call_x86_native_with_unicorn_context(
        &mut self,
        address: u64,
        args: &[u64],
        saved_esp: u64,
        saved_eflags: u32,
        run_mode: NativeCallRunMode,
    ) -> Result<u64, VmError> {
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("unicorn.call_x86_native_with_unicorn_context");
        self.dispatch.force_native_return = false;
        let preserve_blocked_api_frame = self.dispatch.preserve_blocked_api_frame;
        self.dispatch.preserve_blocked_api_frame =
            matches!(run_mode, NativeCallRunMode::Standalone);
        let entry_tid = self.core.scheduler.current_tid();
        let result = (|| {
            if matches!(run_mode, NativeCallRunMode::EntryFrame) {
                if let Some(tid) = self.core.scheduler.current_tid() {
                    let _ = self.core.scheduler.mark_thread_running(tid);
                }
            }
            let (frame, new_esp) =
                self.build_x86_native_frame(self.core.native_return_sentinel, args, saved_esp)?;
            self.core.modules.memory_mut().write(new_esp, &frame)?;
            self.sync_native_support_state()?;
            let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
            let unicorn = unsafe { &*unicorn_ptr };
            let bound = unsafe { unicorn.bind(uc) };
            bound.reg_write(UC_X86_REG_EIP, address).map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_write(eip)",
                    detail,
                }
            })?;
            bound.reg_write(UC_X86_REG_ESP, new_esp).map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_write(esp)",
                    detail,
                }
            })?;
            bound
                .reg_write(UC_X86_REG_EFLAGS, saved_eflags as u64)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(eflags)",
                    detail,
                })?;

            let mut instruction_budget =
                usize::try_from(self.core.config.max_instructions.max(1)).unwrap_or(usize::MAX);
            let mut run_context = UnicornRunContext {
                engine: self as *mut Self,
                api: unicorn_ptr,
                uc,
                callback_error: None,
                pending_fault: None,
                pending_protected_fetch: None,
                pending_writes: Vec::new(),
                pending_write_bytes: 0,
                suppress_mem_write_hook: false,
                last_native_block: None,
                recent_blocks: VecDeque::new(),
                logged_ldr_module_snapshot: false,
                recent_sensitive_reads: VecDeque::new(),
                recent_branch_trace: VecDeque::new(),
                branch_trace_until_instruction: 0,
                last_sensitive_chain_key: None,
            };
            let mut start_address = address;
            loop {
                {
                    let _profile = self
                        .core
                        .runtime_profiler
                        .start_scope("unicorn.poll_blocked_threads");
                    self.core
                        .scheduler
                        .poll_blocked_threads(self.dispatch.time.current().tick_ms);
                }
                let before = self.core.instruction_count;
                run_context.callback_error = None;
                run_context.pending_fault = None;
                run_context.pending_protected_fetch = None;
                run_context.last_native_block = None;
                // Flush stale TB cache before starting to prevent UC_HOOK_BLOCK
                // "wrongly cached" / block-chaining from skipping hooks (see uc_priv.h:518).
                {
                    let _ = bound.ctl_flush_tb();
                }
                let ts: usize = self
                    .core
                    .scheduler
                    .time_slice_instructions()
                    .try_into()
                    .unwrap_or(usize::MAX);
                let emu_count = instruction_budget.min(ts).max(1);
                let emu_result = {
                    let _profile = self.core.runtime_profiler.start_scope("unicorn.emu_start");
                    ACTIVE_UNICORN_CONTEXT.with(|slot| {
                        let previous =
                            slot.replace((&mut run_context as *mut UnicornRunContext).cast());
                        if !previous.is_null() {
                            slot.set(previous);
                            return Err(VmError::NativeExecution {
                                op: "uc_emu_start",
                                detail: "reentrant Unicorn execution is not supported".to_string(),
                            });
                        }
                        let result = bound.emu_start(
                            start_address,
                            self.core.native_return_sentinel,
                            0,
                            emu_count,
                        );
                        slot.set(previous);
                        result.map_err(|detail| VmError::NativeExecution {
                            op: "uc_emu_start",
                            detail,
                        })
                    })
                };
                flush_unicorn_pending_writes(&mut run_context, uc)?;
                let hook_consumed =
                    usize::try_from(self.core.instruction_count.saturating_sub(before))
                        .unwrap_or(0);
                let is_clean_return = run_context.callback_error.is_none()
                    && run_context.pending_fault.is_none()
                    && run_context.pending_protected_fetch.is_none();
                let consumed = if is_clean_return {
                    let c = hook_consumed.max(emu_count);
                    if c > hook_consumed {
                        self.core.emu_floor_instructions += (c - hook_consumed) as u64;
                    }
                    c
                } else {
                    hook_consumed.max(1)
                };
                instruction_budget = instruction_budget.saturating_sub(consumed);
                if let Some(error) = run_context.callback_error.take() {
                    let pc = bound.reg_read(UC_X86_REG_EIP).unwrap_or(0);
                    self.log_emu_stop("hook", pc, &error.to_string())?;
                    return Err(error);
                }
                if let Some(action) = run_context.pending_protected_fetch.take() {
                    self.handle_pending_protected_fetch(unicorn, uc, action)?;
                    let current_thread_state = self
                        .core
                        .scheduler
                        .current_tid()
                        .and_then(|tid| self.core.scheduler.thread_state(tid));
                    let yielded_blocking = current_thread_state != Some("running");
                    if self.dispatch.thread_yield_requested() || yielded_blocking {
                        let deferred_api_return = self.dispatch.api_return_deferred();
                        let _ = self.log_native_yield_event("x86_unicorn_pf", yielded_blocking);
                        if self.dispatch.thread_yield_requested() {
                            self.dispatch.reset_api_flow_control();
                        }
                        if yielded_blocking {
                            // Save + handle blocking yield (same as outer yield code)
                            if let Some(tid) = self.core.scheduler.current_tid() {
                                let registers =
                                    self.capture_unicorn_thread_registers(unicorn, uc)?;
                                self.core
                                    .scheduler
                                    .set_thread_registers(tid, registers)
                                    .ok_or(VmError::RuntimeInvariant(
                                        "failed to persist entry-frame yield registers",
                                    ))?;
                            }
                            match run_mode {
                                NativeCallRunMode::Standalone => {
                                    let current_tid = self.core.scheduler.current_tid();
                                    self.handle_requested_thread_yield();
                                    if current_tid == self.core.scheduler.current_tid()
                                        && matches!(
                                            current_tid.and_then(|tid| self
                                                .core
                                                .scheduler
                                                .thread_state(tid)),
                                            Some("ready" | "running")
                                        )
                                    {
                                        let tid = current_tid.unwrap();
                                        let _ = self.core.scheduler.mark_thread_running(tid);
                                        start_address = Self::next_thread_or_pc(unicorn, uc)?;
                                        continue;
                                    }
                                    if let Some(next_pc) =
                                        self.switch_to_ready_x86_unicorn_thread(unicorn, uc)?
                                    {
                                        start_address = next_pc;
                                        continue;
                                    }
                                    start_address = Self::next_thread_or_pc(unicorn, uc)?;
                                    continue;
                                }
                                NativeCallRunMode::EntryFrame => {
                                    self.handle_requested_thread_yield();
                                    if let Some(entry_pc) = self
                                        .try_resume_entry_frame_x86_unicorn(
                                            unicorn, uc, entry_tid,
                                        )?
                                    {
                                        start_address = entry_pc;
                                        continue;
                                    }
                                    if let Some(next_pc) =
                                        self.switch_to_ready_x86_unicorn_thread(unicorn, uc)?
                                    {
                                        start_address = next_pc;
                                        continue;
                                    }
                                    let blocked_ret = self.blocked_entry_frame_return_value(
                                        entry_tid,
                                        self.entry_frame_x86_fallback_ret(
                                            entry_tid,
                                            bound.reg_read(UC_X86_REG_EAX).map_err(|detail| {
                                                VmError::NativeExecution {
                                                    op: "uc_reg_read(eax)",
                                                    detail,
                                                }
                                            })?,
                                        ),
                                        deferred_api_return,
                                    );
                                    return Ok(blocked_ret);
                                }
                            }
                        }
                        if let Some(next_pc) =
                            self.handle_x86_unicorn_nonblocking_yield(unicorn, uc)?
                        {
                            start_address = next_pc;
                            continue;
                        }
                    }
                    start_address = Self::next_thread_or_pc(unicorn, uc)?;
                    continue;
                }
                if let Some(fault) = run_context.pending_fault.take() {
                    if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                        start_address = bound.reg_read(UC_X86_REG_EIP).map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(eip)",
                                detail,
                            }
                        })?;
                        continue;
                    }
                    let emu_result = Err(self.unhandled_unicorn_fault_error(fault));
                    match emu_result {
                        Ok(()) => {}
                        Err(VmError::NativeExecution { op, detail }) => {
                            let pc = bound.reg_read(UC_X86_REG_EIP).unwrap_or(fault.pc);
                            let sp = bound.reg_read(UC_X86_REG_ESP).unwrap_or(0);
                            let eax = bound.reg_read(UC_X86_REG_EAX).unwrap_or(0);
                            let ebx = bound.reg_read(UC_X86_REG_EBX).unwrap_or(0);
                            let ecx = bound.reg_read(UC_X86_REG_ECX).unwrap_or(0);
                            let edx = bound.reg_read(UC_X86_REG_EDX).unwrap_or(0);
                            let ebp = bound.reg_read(UC_X86_REG_EBP).unwrap_or(0);
                            let esi = bound.reg_read(UC_X86_REG_ESI).unwrap_or(0);
                            let edi = bound.reg_read(UC_X86_REG_EDI).unwrap_or(0);
                            let stack_arg = |offset| {
                                bound
                                    .mem_read(ebp + offset, 4)
                                    .ok()
                                    .map(|bytes| {
                                        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
                                    })
                                    .unwrap_or(0)
                            };
                            let ret = stack_arg(4);
                            let arg0 = stack_arg(8);
                            let arg1 = stack_arg(12);
                            let arg2 = stack_arg(16);
                            let message = format!(
                            "{detail}; pc=0x{pc:X}; sp=0x{sp:X}; eax=0x{eax:X}; ebx=0x{ebx:X}; ecx=0x{ecx:X}; edx=0x{edx:X}; ebp=0x{ebp:X}; esi=0x{esi:X}; edi=0x{edi:X}; ret=0x{ret:X}; arg0=0x{arg0:X}; arg1=0x{arg1:X}; arg2=0x{arg2:X}"
                        );
                            self.log_emu_stop("native", pc, &message)?;
                            return Err(VmError::NativeExecution {
                                op,
                                detail: message,
                            });
                        }
                        Err(error) => return Err(error),
                    }
                }
                match emu_result {
                    Ok(()) => {}
                    Err(VmError::NativeExecution { op, detail }) => {
                        let pc = bound.reg_read(UC_X86_REG_EIP).unwrap_or(0);
                        let sp = bound.reg_read(UC_X86_REG_ESP).unwrap_or(0);
                        let eax = bound.reg_read(UC_X86_REG_EAX).unwrap_or(0);
                        let ebx = bound.reg_read(UC_X86_REG_EBX).unwrap_or(0);
                        let ecx = bound.reg_read(UC_X86_REG_ECX).unwrap_or(0);
                        let edx = bound.reg_read(UC_X86_REG_EDX).unwrap_or(0);
                        let ebp = bound.reg_read(UC_X86_REG_EBP).unwrap_or(0);
                        let esi = bound.reg_read(UC_X86_REG_ESI).unwrap_or(0);
                        let edi = bound.reg_read(UC_X86_REG_EDI).unwrap_or(0);
                        let stack_arg = |offset| {
                            bound
                                .mem_read(ebp + offset, 4)
                                .ok()
                                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as u64)
                                .unwrap_or(0)
                        };
                        let ret = stack_arg(4);
                        let arg0 = stack_arg(8);
                        let arg1 = stack_arg(12);
                        let arg2 = stack_arg(16);
                        let message = format!(
                        "{detail}; pc=0x{pc:X}; sp=0x{sp:X}; eax=0x{eax:X}; ebx=0x{ebx:X}; ecx=0x{ecx:X}; edx=0x{edx:X}; ebp=0x{ebp:X}; esi=0x{esi:X}; edi=0x{edi:X}; ret=0x{ret:X}; arg0=0x{arg0:X}; arg1=0x{arg1:X}; arg2=0x{arg2:X}"
                    );
                        self.log_emu_stop("native", pc, &message)?;
                        return Err(VmError::NativeExecution {
                            op,
                            detail: message,
                        });
                    }
                    Err(error) => return Err(error),
                }
                if self.dispatch.should_restart_from_updated_pc() {
                    start_address = bound.reg_read(UC_X86_REG_EIP).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(eip)",
                            detail,
                        }
                    })?;
                    self.dispatch.reset_api_flow_control();
                    continue;
                }
                let current_thread_state = self
                    .core
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.core.scheduler.thread_state(tid));
                let yielded_blocking_thread = current_thread_state != Some("running");
                if self.dispatch.thread_yield_requested() || yielded_blocking_thread {
                    let deferred_api_return = self.dispatch.api_return_deferred();
                    let _ = self.log_native_yield_event("x86_unicorn", yielded_blocking_thread);
                    if self.dispatch.thread_yield_requested() {
                        self.dispatch.reset_api_flow_control();
                    }
                    if yielded_blocking_thread {
                        if let Some(tid) = self.core.scheduler.current_tid() {
                            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                            self.core
                                .scheduler
                                .set_thread_registers(tid, registers)
                                .ok_or(VmError::RuntimeInvariant(
                                    "failed to persist entry-frame yield registers",
                                ))?;
                        }
                        match run_mode {
                            NativeCallRunMode::Standalone => {
                                let current_tid = self.core.scheduler.current_tid();
                                self.handle_requested_thread_yield();
                                if current_tid == self.core.scheduler.current_tid()
                                    && matches!(
                                        current_tid
                                            .and_then(|tid| self.core.scheduler.thread_state(tid)),
                                        Some("ready" | "running")
                                    )
                                {
                                    let tid = current_tid.unwrap();
                                    let _ = self.core.scheduler.mark_thread_running(tid);
                                    start_address = Self::next_thread_or_pc(unicorn, uc)?;
                                    continue;
                                }
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
                                    self.sync_native_support_state()?;
                                    self.restore_unicorn_thread_registers(
                                        unicorn,
                                        uc,
                                        &next_thread.registers,
                                    )?;
                                    start_address = next_thread.registers.eip;
                                    continue;
                                }
                                start_address =
                                    bound.reg_read(UC_X86_REG_EIP).map_err(|detail| {
                                        VmError::NativeExecution {
                                            op: "uc_reg_read(eip)",
                                            detail,
                                        }
                                    })?;
                                continue;
                            }
                            NativeCallRunMode::EntryFrame => {
                                self.handle_requested_thread_yield();
                                if let Some(entry_pc) =
                                    self.try_resume_entry_frame_x86_unicorn(unicorn, uc, entry_tid)?
                                {
                                    start_address = entry_pc;
                                    continue;
                                }
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
                                    self.sync_native_support_state()?;
                                    self.restore_unicorn_thread_registers(
                                        unicorn,
                                        uc,
                                        &next_thread.registers,
                                    )?;
                                    start_address = next_thread.registers.eip;
                                    continue;
                                }
                                let blocked_ret = self.blocked_entry_frame_return_value(
                                    entry_tid,
                                    self.entry_frame_x86_fallback_ret(
                                        entry_tid,
                                        bound.reg_read(UC_X86_REG_EAX).map_err(|detail| {
                                            VmError::NativeExecution {
                                                op: "uc_reg_read(eax)",
                                                detail,
                                            }
                                        })?,
                                    ),
                                    deferred_api_return,
                                );
                                return Ok(blocked_ret);
                            }
                        }
                    }
                    self.handle_requested_thread_yield();
                } else {
                    if let Some(next_pc) = self.handle_x86_unicorn_nonblocking_yield(unicorn, uc)? {
                        start_address = next_pc;
                        continue;
                    }
                }
                let exit_pc =
                    bound
                        .reg_read(UC_X86_REG_EIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(eip)",
                            detail,
                        })?;
                if exit_pc != self.core.native_return_sentinel {
                    start_address = exit_pc;
                    continue;
                }
                if matches!(run_mode, NativeCallRunMode::EntryFrame)
                    && self.core.scheduler.current_tid() != entry_tid
                {
                    let return_value = bound.reg_read(UC_X86_REG_EAX).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(eax)",
                            detail,
                        }
                    })?;
                    let _ = self.terminate_current_thread(return_value as u32);
                    self.handle_requested_thread_yield();
                    if let Some(entry_pc) =
                        self.try_resume_entry_frame_x86_unicorn(unicorn, uc, entry_tid)?
                    {
                        start_address = entry_pc;
                        continue;
                    }
                    if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                        let next_thread = self
                            .core
                            .scheduler
                            .thread_snapshot(next_tid)
                            .ok_or(VmError::RuntimeInvariant("next thread snapshot missing"))?;
                        let _ = self
                            .core
                            .scheduler
                            .switch_to(next_tid, &mut self.core.process_env);
                        self.sync_native_support_state()?;
                        self.restore_unicorn_thread_registers(unicorn, uc, &next_thread.registers)?;
                        start_address = next_thread.registers.eip;
                        continue;
                    }
                    let blocked_ret = self.blocked_entry_frame_return_value(
                        entry_tid,
                        self.entry_frame_x86_fallback_ret(entry_tid, return_value),
                        self.dispatch.api_return_deferred(),
                    );
                    return Ok(blocked_ret);
                }
                break;
            }
            let exit_pc = bound.reg_read(UC_X86_REG_EIP).unwrap_or(0);
            if instruction_budget == 0 && exit_pc != self.core.native_return_sentinel {
                let detail = format!("instruction budget exhausted at 0x{exit_pc:X}");
                match run_mode {
                    NativeCallRunMode::Standalone => {
                        self.log_emu_stop("native", exit_pc, &detail)?;
                        return Err(VmError::NativeExecution { op: "run", detail });
                    }
                    NativeCallRunMode::EntryFrame => {
                        self.core.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
                        self.log_instruction_budget_exhausted("native_entry", exit_pc)?;
                        if let Some(main_tid) = self.core.main_thread_tid {
                            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                            self.core
                                .scheduler
                                .set_thread_registers(main_tid, registers)
                                .ok_or(VmError::RuntimeInvariant(
                                    "failed to persist main thread registers after budget stop",
                                ))?;
                        }
                    }
                }
            }
            bound
                .reg_read(UC_X86_REG_EAX)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_read(eax)",
                    detail,
                })
        })();
        self.dispatch.preserve_blocked_api_frame = preserve_blocked_api_frame;
        result
    }

    #[allow(dead_code)]
    pub(super) fn call_x86_native_with_unicorn(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_esp, saved_eflags) = self.standalone_native_x86_call_context()?;
        self.call_x86_native_with_unicorn_context(
            address,
            args,
            saved_esp,
            saved_eflags,
            NativeCallRunMode::Standalone,
        )
    }

    #[allow(dead_code)]
    pub(super) fn call_x86_native_with_entry_frame_unicorn(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_esp, saved_eflags) = self.thread_entry_x86_call_context()?;
        self.call_x86_native_with_unicorn_context(
            address,
            args,
            saved_esp,
            saved_eflags,
            NativeCallRunMode::EntryFrame,
        )
    }

    pub(super) fn call_x64_native_with_unicorn_context(
        &mut self,
        address: u64,
        args: &[u64],
        saved_rsp: u64,
        saved_rflags: u64,
        run_mode: NativeCallRunMode,
        preserve_unused_arg_registers: bool,
    ) -> Result<u64, VmError> {
        let _profile = self
            .core
            .runtime_profiler
            .start_scope("unicorn.call_x64_native_with_unicorn_context");
        self.dispatch.force_native_return = false;
        let preserve_blocked_api_frame = self.dispatch.preserve_blocked_api_frame;
        self.dispatch.preserve_blocked_api_frame =
            matches!(run_mode, NativeCallRunMode::Standalone);
        let entry_tid = self.core.scheduler.current_tid();
        let previous_synthetic_call =
            self.trace
                .active_x64_synthetic_call
                .replace(ActiveX64SyntheticCall {
                    caller_rsp: saved_rsp,
                });
        let result = (|| -> Result<u64, VmError> {
            if matches!(run_mode, NativeCallRunMode::EntryFrame) {
                if let Some(tid) = self.core.scheduler.current_tid() {
                    let _ = self.core.scheduler.mark_thread_running(tid);
                }
            }
            let (frame, new_rsp) =
                self.build_x64_native_frame(self.core.native_return_sentinel, args, saved_rsp)?;
            self.core.modules.memory_mut().write(new_rsp, &frame)?;
            self.sync_native_support_state()?;
            let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
            let unicorn = unsafe { &*unicorn_ptr };
            let bound = unsafe { unicorn.bind(uc) };
            for (regid, value, op) in [
                (UC_X86_REG_RIP, address, "uc_reg_write(rip)"),
                (UC_X86_REG_RSP, new_rsp, "uc_reg_write(rsp)"),
                (UC_X86_REG_RFLAGS, saved_rflags, "uc_reg_write(rflags)"),
            ] {
                bound
                    .reg_write(regid, value)
                    .map_err(|detail| VmError::NativeExecution { op, detail })?;
            }
            for (index, (regid, op)) in [
                (UC_X86_REG_RCX, "uc_reg_write(rcx)"),
                (UC_X86_REG_RDX, "uc_reg_write(rdx)"),
                (UC_X86_REG_R8, "uc_reg_write(r8)"),
                (UC_X86_REG_R9, "uc_reg_write(r9)"),
            ]
            .into_iter()
            .enumerate()
            {
                if preserve_unused_arg_registers && index >= args.len() {
                    continue;
                }
                bound
                    .reg_write(regid, args.arg(index))
                    .map_err(|detail| VmError::NativeExecution { op, detail })?;
            }

            let mut instruction_budget =
                usize::try_from(self.core.config.max_instructions.max(1)).unwrap_or(usize::MAX);
            let mut run_context = UnicornRunContext {
                engine: self as *mut Self,
                api: unicorn_ptr,
                uc,
                callback_error: None,
                pending_fault: None,
                pending_protected_fetch: None,
                pending_writes: Vec::new(),
                pending_write_bytes: 0,
                suppress_mem_write_hook: false,
                last_native_block: None,
                recent_blocks: VecDeque::new(),
                logged_ldr_module_snapshot: false,
                recent_sensitive_reads: VecDeque::new(),
                recent_branch_trace: VecDeque::new(),
                branch_trace_until_instruction: 0,
                last_sensitive_chain_key: None,
            };
            let mut start_address = address;
            loop {
                {
                    let _profile = self
                        .core
                        .runtime_profiler
                        .start_scope("unicorn.poll_blocked_threads");
                    self.core
                        .scheduler
                        .poll_blocked_threads(self.dispatch.time.current().tick_ms);
                }
                let before = self.core.instruction_count;
                run_context.callback_error = None;
                run_context.pending_fault = None;
                run_context.pending_protected_fetch = None;
                run_context.last_native_block = None;
                // Flush stale TB cache before starting to prevent UC_HOOK_BLOCK
                // "wrongly cached" / block-chaining from skipping hooks (see uc_priv.h:518).
                {
                    let _ = bound.ctl_flush_tb();
                }
                let ts: usize = self
                    .core
                    .scheduler
                    .time_slice_instructions()
                    .try_into()
                    .unwrap_or(usize::MAX);
                let emu_count = instruction_budget.min(ts).max(1);
                let emu_result = {
                    let _profile = self.core.runtime_profiler.start_scope("unicorn.emu_start");
                    ACTIVE_UNICORN_CONTEXT.with(|slot| {
                        let previous =
                            slot.replace((&mut run_context as *mut UnicornRunContext).cast());
                        if !previous.is_null() {
                            slot.set(previous);
                            return Err(VmError::NativeExecution {
                                op: "uc_emu_start",
                                detail: "reentrant Unicorn execution is not supported".to_string(),
                            });
                        }
                        let result = bound.emu_start(
                            start_address,
                            self.core.native_return_sentinel,
                            0,
                            emu_count,
                        );
                        slot.set(previous);
                        result.map_err(|detail| VmError::NativeExecution {
                            op: "uc_emu_start",
                            detail,
                        })
                    })
                };
                flush_unicorn_pending_writes(&mut run_context, uc)?;
                let hook_consumed =
                    usize::try_from(self.core.instruction_count.saturating_sub(before))
                        .unwrap_or(0);
                let is_clean_return = run_context.callback_error.is_none()
                    && run_context.pending_fault.is_none()
                    && run_context.pending_protected_fetch.is_none();
                let consumed = if is_clean_return {
                    let c = hook_consumed.max(emu_count);
                    if c > hook_consumed {
                        self.core.emu_floor_instructions += (c - hook_consumed) as u64;
                    }
                    c
                } else {
                    hook_consumed.max(1)
                };
                instruction_budget = instruction_budget.saturating_sub(consumed);
                if let Some(error) = run_context.callback_error.take() {
                    let pc = bound.reg_read(UC_X86_REG_RIP).unwrap_or(0);
                    self.log_emu_stop("hook", pc, &error.to_string())?;
                    return Err(error);
                }
                if let Some(action) = run_context.pending_protected_fetch.take() {
                    self.handle_pending_protected_fetch(unicorn, uc, action)?;
                    let current_thread_state = self
                        .core
                        .scheduler
                        .current_tid()
                        .and_then(|tid| self.core.scheduler.thread_state(tid));
                    let yielded_blocking_thread = current_thread_state != Some("running");
                    if self.dispatch.thread_yield_requested() || yielded_blocking_thread {
                        let deferred_api_return = self.dispatch.api_return_deferred();
                        let _ =
                            self.log_native_yield_event("x64_unicorn_pf", yielded_blocking_thread);
                        if self.dispatch.thread_yield_requested() {
                            self.dispatch.reset_api_flow_control();
                        }
                        if yielded_blocking_thread {
                            if let Some(tid) = self.core.scheduler.current_tid() {
                                let registers =
                                    self.capture_unicorn_thread_registers(unicorn, uc)?;
                                self.core
                                    .scheduler
                                    .set_thread_registers(tid, registers)
                                    .ok_or(VmError::RuntimeInvariant(
                                        "failed to persist entry-frame yield registers",
                                    ))?;
                            }
                            match run_mode {
                                NativeCallRunMode::Standalone => {
                                    let current_tid = self.core.scheduler.current_tid();
                                    self.handle_requested_thread_yield();
                                    if current_tid == self.core.scheduler.current_tid()
                                        && matches!(
                                            current_tid.and_then(|tid| self
                                                .core
                                                .scheduler
                                                .thread_state(tid)),
                                            Some("ready" | "running")
                                        )
                                    {
                                        let tid = current_tid.unwrap();
                                        let _ = self.core.scheduler.mark_thread_running(tid);
                                        start_address = Self::next_thread_or_pc64(unicorn, uc)?;
                                        continue;
                                    }
                                    if let Some(next_pc) =
                                        self.switch_to_ready_x64_unicorn_thread(unicorn, uc)?
                                    {
                                        start_address = next_pc;
                                        continue;
                                    }
                                    start_address = Self::next_thread_or_pc64(unicorn, uc)?;
                                    continue;
                                }
                                NativeCallRunMode::EntryFrame => {
                                    self.handle_requested_thread_yield();
                                    if let Some(entry_pc) = self
                                        .try_resume_entry_frame_x64_unicorn(
                                            unicorn, uc, entry_tid,
                                        )?
                                    {
                                        start_address = entry_pc;
                                        continue;
                                    }
                                    if let Some(next_pc) =
                                        self.switch_to_ready_x64_unicorn_thread(unicorn, uc)?
                                    {
                                        start_address = next_pc;
                                        continue;
                                    }
                                    let blocked_ret = self.blocked_entry_frame_return_value(
                                        entry_tid,
                                        self.entry_frame_x64_fallback_ret(
                                            entry_tid,
                                            bound.reg_read(UC_X86_REG_RAX).map_err(|detail| {
                                                VmError::NativeExecution {
                                                    op: "uc_reg_read(rax)",
                                                    detail,
                                                }
                                            })?,
                                        ),
                                        deferred_api_return,
                                    );
                                    return Ok(blocked_ret);
                                }
                            }
                        }
                        if let Some(next_pc) =
                            self.handle_x64_unicorn_nonblocking_yield(unicorn, uc)?
                        {
                            start_address = next_pc;
                            continue;
                        }
                    }
                    start_address = Self::next_thread_or_pc64(unicorn, uc)?;
                    continue;
                }
                if let Some(fault) = run_context.pending_fault.take() {
                    if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                        start_address = bound.reg_read(UC_X86_REG_RIP).map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(rip)",
                                detail,
                            }
                        })?;
                        continue;
                    }
                    let emu_result = Err(self.unhandled_unicorn_fault_error(fault));
                    match emu_result {
                        Ok(()) => {}
                        Err(VmError::NativeExecution { op, detail }) => {
                            let pc = bound.reg_read(UC_X86_REG_RIP).unwrap_or(fault.pc);
                            let sp = bound.reg_read(UC_X86_REG_RSP).unwrap_or(0);
                            let rax = bound.reg_read(UC_X86_REG_RAX).unwrap_or(0);
                            let rcx = bound.reg_read(UC_X86_REG_RCX).unwrap_or(0);
                            let rdx = bound.reg_read(UC_X86_REG_RDX).unwrap_or(0);
                            let r8 = bound.reg_read(UC_X86_REG_R8).unwrap_or(0);
                            let r9 = bound.reg_read(UC_X86_REG_R9).unwrap_or(0);
                            let message = format!(
                                "{detail}; pc=0x{pc:X}; sp=0x{sp:X}; rax=0x{rax:X}; rcx=0x{rcx:X}; rdx=0x{rdx:X}; r8=0x{r8:X}; r9=0x{r9:X}"
                            );
                            self.log_emu_stop("native", pc, &message)?;
                            return Err(VmError::NativeExecution {
                                op,
                                detail: message,
                            });
                        }
                        Err(error) => return Err(error),
                    }
                }
                match emu_result {
                    Ok(()) => {}
                    Err(VmError::NativeExecution { op, detail }) => {
                        let pc = bound.reg_read(UC_X86_REG_RIP).unwrap_or(0);
                        let sp = bound.reg_read(UC_X86_REG_RSP).unwrap_or(0);
                        let rax = bound.reg_read(UC_X86_REG_RAX).unwrap_or(0);
                        let rcx = bound.reg_read(UC_X86_REG_RCX).unwrap_or(0);
                        let rdx = bound.reg_read(UC_X86_REG_RDX).unwrap_or(0);
                        let r8 = bound.reg_read(UC_X86_REG_R8).unwrap_or(0);
                        let r9 = bound.reg_read(UC_X86_REG_R9).unwrap_or(0);
                        let message = format!(
                            "{detail}; pc=0x{pc:X}; sp=0x{sp:X}; rax=0x{rax:X}; rcx=0x{rcx:X}; rdx=0x{rdx:X}; r8=0x{r8:X}; r9=0x{r9:X}"
                        );
                        self.log_emu_stop("native", pc, &message)?;
                        return Err(VmError::NativeExecution {
                            op,
                            detail: message,
                        });
                    }
                    Err(error) => return Err(error),
                }
                if self.dispatch.should_restart_from_updated_pc() {
                    start_address = bound.reg_read(UC_X86_REG_RIP).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(rip)",
                            detail,
                        }
                    })?;
                    self.dispatch.reset_api_flow_control();
                    continue;
                }
                let current_thread_state = self
                    .core
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.core.scheduler.thread_state(tid));
                let yielded_blocking_thread = current_thread_state != Some("running");
                if self.dispatch.thread_yield_requested() || yielded_blocking_thread {
                    let deferred_api_return = self.dispatch.api_return_deferred();
                    let _ = self.log_native_yield_event("x64_unicorn", yielded_blocking_thread);
                    if self.dispatch.thread_yield_requested() {
                        self.dispatch.reset_api_flow_control();
                    }
                    if yielded_blocking_thread {
                        if let Some(tid) = self.core.scheduler.current_tid() {
                            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                            self.core
                                .scheduler
                                .set_thread_registers(tid, registers)
                                .ok_or(VmError::RuntimeInvariant(
                                    "failed to persist entry-frame yield registers",
                                ))?;
                        }
                        match run_mode {
                            NativeCallRunMode::Standalone => {
                                let current_tid = self.core.scheduler.current_tid();
                                self.handle_requested_thread_yield();
                                if current_tid == self.core.scheduler.current_tid()
                                    && matches!(
                                        current_tid
                                            .and_then(|tid| self.core.scheduler.thread_state(tid)),
                                        Some("ready" | "running")
                                    )
                                {
                                    let tid = current_tid.unwrap();
                                    let _ = self.core.scheduler.mark_thread_running(tid);
                                    start_address = Self::next_thread_or_pc64(unicorn, uc)?;
                                    continue;
                                }
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
                                    self.sync_native_support_state()?;
                                    self.restore_unicorn_thread_registers(
                                        unicorn,
                                        uc,
                                        &next_thread.registers,
                                    )?;
                                    start_address = next_thread.registers.rip;
                                    continue;
                                }
                                start_address =
                                    bound.reg_read(UC_X86_REG_RIP).map_err(|detail| {
                                        VmError::NativeExecution {
                                            op: "uc_reg_read(rip)",
                                            detail,
                                        }
                                    })?;
                                continue;
                            }
                            NativeCallRunMode::EntryFrame => {
                                self.handle_requested_thread_yield();
                                if let Some(entry_pc) =
                                    self.try_resume_entry_frame_x64_unicorn(unicorn, uc, entry_tid)?
                                {
                                    start_address = entry_pc;
                                    continue;
                                }
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
                                    self.sync_native_support_state()?;
                                    self.restore_unicorn_thread_registers(
                                        unicorn,
                                        uc,
                                        &next_thread.registers,
                                    )?;
                                    start_address = next_thread.registers.rip;
                                    continue;
                                }
                                let blocked_ret = self.blocked_entry_frame_return_value(
                                    entry_tid,
                                    self.entry_frame_x64_fallback_ret(
                                        entry_tid,
                                        bound.reg_read(UC_X86_REG_RAX).map_err(|detail| {
                                            VmError::NativeExecution {
                                                op: "uc_reg_read(rax)",
                                                detail,
                                            }
                                        })?,
                                    ),
                                    deferred_api_return,
                                );
                                return Ok(blocked_ret);
                            }
                        }
                    }
                    self.handle_requested_thread_yield();
                } else {
                    if let Some(next_pc) = self.handle_x64_unicorn_nonblocking_yield(unicorn, uc)? {
                        start_address = next_pc;
                        continue;
                    }
                    if instruction_budget == 0 {
                        let exit_pc = Self::next_thread_or_pc64(unicorn, uc)?;
                        let detail = format!("instruction budget exhausted at 0x{exit_pc:X}");
                        self.log_emu_stop("native", exit_pc, &detail)?;
                        match run_mode {
                            NativeCallRunMode::Standalone => {
                                return Err(VmError::NativeExecution { op: "run", detail });
                            }
                            NativeCallRunMode::EntryFrame => {
                                self.core.stop_reason =
                                    Some(RunStopReason::InstructionBudgetExhausted);
                                self.log_instruction_budget_exhausted("native_entry", exit_pc)?;
                                if let Some(main_tid) = self.core.main_thread_tid {
                                    let registers =
                                        self.capture_unicorn_thread_registers(unicorn, uc)?;
                                    self.core
                                        .scheduler
                                        .set_thread_registers(main_tid, registers)
                                        .ok_or(VmError::RuntimeInvariant(
                                            "failed to persist main thread registers after budget stop",
                                        ))?;
                                }
                                break;
                            }
                        }
                    }
                }
                let exit_pc =
                    bound
                        .reg_read(UC_X86_REG_RIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(rip)",
                            detail,
                        })?;
                if exit_pc != self.core.native_return_sentinel {
                    start_address = exit_pc;
                    continue;
                }
                if matches!(run_mode, NativeCallRunMode::EntryFrame)
                    && self.core.scheduler.current_tid() != entry_tid
                {
                    let return_value = bound.reg_read(UC_X86_REG_RAX).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(rax)",
                            detail,
                        }
                    })?;
                    let _ = self.terminate_current_thread(return_value as u32);
                    self.handle_requested_thread_yield();
                    if let Some(entry_pc) =
                        self.try_resume_entry_frame_x64_unicorn(unicorn, uc, entry_tid)?
                    {
                        start_address = entry_pc;
                        continue;
                    }
                    if let Some(next_tid) = self.core.scheduler.next_ready_tid() {
                        let next_thread = self
                            .core
                            .scheduler
                            .thread_snapshot(next_tid)
                            .ok_or(VmError::RuntimeInvariant("next thread snapshot missing"))?;
                        let _ = self
                            .core
                            .scheduler
                            .switch_to(next_tid, &mut self.core.process_env);
                        self.sync_native_support_state()?;
                        self.restore_unicorn_thread_registers(unicorn, uc, &next_thread.registers)?;
                        start_address = next_thread.registers.rip;
                        continue;
                    }
                    let blocked_ret = self.blocked_entry_frame_return_value(
                        entry_tid,
                        self.entry_frame_x64_fallback_ret(entry_tid, return_value),
                        self.dispatch.api_return_deferred(),
                    );
                    return Ok(blocked_ret);
                }
                break;
            }
            let exit_pc = bound.reg_read(UC_X86_REG_RIP).unwrap_or(0);
            if instruction_budget == 0 && exit_pc != self.core.native_return_sentinel {
                let detail = format!("instruction budget exhausted at 0x{exit_pc:X}");
                match run_mode {
                    NativeCallRunMode::Standalone => {
                        self.log_emu_stop("native", exit_pc, &detail)?;
                        return Err(VmError::NativeExecution { op: "run", detail });
                    }
                    NativeCallRunMode::EntryFrame => {
                        self.core.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
                        self.log_instruction_budget_exhausted("native_entry", exit_pc)?;
                        if let Some(main_tid) = self.core.main_thread_tid {
                            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                            self.core
                                .scheduler
                                .set_thread_registers(main_tid, registers)
                                .ok_or(VmError::RuntimeInvariant(
                                    "failed to persist main thread registers after budget stop",
                                ))?;
                        }
                    }
                }
            }
            bound
                .reg_read(UC_X86_REG_RAX)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_read(rax)",
                    detail,
                })
        })();
        self.trace.active_x64_synthetic_call = previous_synthetic_call;
        self.dispatch.preserve_blocked_api_frame = preserve_blocked_api_frame;
        result
    }

    fn try_resume_entry_frame_x86_unicorn(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
        entry_tid: Option<u32>,
    ) -> Result<Option<u64>, VmError> {
        let Some(tid) = entry_tid else {
            return Ok(None);
        };
        if !matches!(
            self.core.scheduler.thread_state(tid),
            Some("ready" | "running")
        ) {
            return Ok(None);
        }
        let thread = self
            .core
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("entry thread snapshot missing"))?;
        let _ = self.core.scheduler.mark_thread_running(tid);
        let _ = self
            .core
            .scheduler
            .switch_to(tid, &mut self.core.process_env);
        self.sync_native_support_state()?;
        self.restore_unicorn_thread_registers(unicorn, uc, &thread.registers)?;
        Ok(Some(thread.registers.eip))
    }

    fn try_resume_entry_frame_x64_unicorn(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
        entry_tid: Option<u32>,
    ) -> Result<Option<u64>, VmError> {
        let Some(tid) = entry_tid else {
            return Ok(None);
        };
        if !matches!(
            self.core.scheduler.thread_state(tid),
            Some("ready" | "running")
        ) {
            return Ok(None);
        }
        let thread = self
            .core
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("entry thread snapshot missing"))?;
        let _ = self.core.scheduler.mark_thread_running(tid);
        let _ = self
            .core
            .scheduler
            .switch_to(tid, &mut self.core.process_env);
        self.sync_native_support_state()?;
        self.restore_unicorn_thread_registers(unicorn, uc, &thread.registers)?;
        Ok(Some(thread.registers.rip))
    }

    fn entry_frame_x64_fallback_ret(&self, entry_tid: Option<u32>, fallback: u64) -> u64 {
        entry_tid
            .and_then(|tid| self.core.scheduler.thread_snapshot(tid))
            .map(|thread| thread.registers.rax)
            .unwrap_or(fallback)
    }

    fn switch_to_ready_x86_unicorn_thread(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<Option<u64>, VmError> {
        let Some(next_tid) = self.core.scheduler.next_ready_tid() else {
            return Ok(None);
        };
        let next_thread = self
            .core
            .scheduler
            .thread_snapshot(next_tid)
            .ok_or(VmError::RuntimeInvariant("next thread snapshot missing"))?;
        let _ = self
            .core
            .scheduler
            .switch_to(next_tid, &mut self.core.process_env);
        self.sync_native_support_state()?;
        self.restore_unicorn_thread_registers(unicorn, uc, &next_thread.registers)?;
        Ok(Some(next_thread.registers.eip))
    }

    fn switch_to_ready_x64_unicorn_thread(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<Option<u64>, VmError> {
        let Some(next_tid) = self.core.scheduler.next_ready_tid() else {
            return Ok(None);
        };
        let next_thread = self
            .core
            .scheduler
            .thread_snapshot(next_tid)
            .ok_or(VmError::RuntimeInvariant("next thread snapshot missing"))?;
        let _ = self
            .core
            .scheduler
            .switch_to(next_tid, &mut self.core.process_env);
        self.sync_native_support_state()?;
        self.restore_unicorn_thread_registers(unicorn, uc, &next_thread.registers)?;
        Ok(Some(next_thread.registers.rip))
    }

    fn handle_x86_unicorn_nonblocking_yield(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<Option<u64>, VmError> {
        if let Some(tid) = self.core.scheduler.current_tid() {
            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
            self.core
                .scheduler
                .set_thread_registers(tid, registers)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to persist yield registers",
                ))?;
            if self.core.scheduler.has_ready_threads() {
                let _ = self.core.scheduler.mark_thread_ready(tid);
                if let Some(next_pc) = self.switch_to_ready_x86_unicorn_thread(unicorn, uc)? {
                    self.dispatch.reset_api_flow_control();
                    return Ok(Some(next_pc));
                }
            }
        }
        self.handle_requested_thread_yield();
        Ok(None)
    }

    fn handle_x64_unicorn_nonblocking_yield(
        &mut self,
        unicorn: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<Option<u64>, VmError> {
        if let Some(tid) = self.core.scheduler.current_tid() {
            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
            self.core
                .scheduler
                .set_thread_registers(tid, registers)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to persist yield registers",
                ))?;
            if self.core.scheduler.has_ready_threads() {
                let _ = self.core.scheduler.mark_thread_ready(tid);
                if let Some(next_pc) = self.switch_to_ready_x64_unicorn_thread(unicorn, uc)? {
                    self.dispatch.reset_api_flow_control();
                    return Ok(Some(next_pc));
                }
            }
        }
        self.handle_requested_thread_yield();
        Ok(None)
    }

    fn next_thread_or_pc(unicorn: &UnicornApi, uc: *mut UcEngine) -> Result<u64, VmError> {
        let bound = unsafe { unicorn.bind(uc) };
        bound
            .reg_read(UC_X86_REG_EIP)
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_read(eip)",
                detail,
            })
    }

    fn next_thread_or_pc64(unicorn: &UnicornApi, uc: *mut UcEngine) -> Result<u64, VmError> {
        let bound = unsafe { unicorn.bind(uc) };
        bound
            .reg_read(UC_X86_REG_RIP)
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_read(rip)",
                detail,
            })
    }

    pub(super) fn call_x64_native_with_unicorn(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_rsp, saved_rflags) = self.standalone_native_x64_call_context()?;
        self.call_x64_native_with_unicorn_context(
            address,
            args,
            saved_rsp,
            saved_rflags,
            NativeCallRunMode::Standalone,
            false,
        )
    }

    pub(super) fn call_x64_native_with_entry_frame_unicorn(
        &mut self,
        address: u64,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let (saved_rsp, saved_rflags) = self.thread_entry_x64_call_context()?;
        self.call_x64_native_with_unicorn_context(
            address,
            args,
            saved_rsp,
            saved_rflags,
            NativeCallRunMode::EntryFrame,
            false,
        )
    }
}

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
            .runtime_profiler
            .start_scope("unicorn.call_x86_native_with_unicorn_context");
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
        self.sync_native_support_state()?;
        let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
        let unicorn = unsafe { &*unicorn_ptr };
        unsafe { unicorn.reg_write_raw(uc, UC_X86_REG_EIP, address) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(eip)",
                detail,
            }
        })?;
        unsafe { unicorn.reg_write_raw(uc, UC_X86_REG_ESP, new_esp) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(esp)",
                detail,
            }
        })?;
        unsafe { unicorn.reg_write_raw(uc, UC_X86_REG_EFLAGS, saved_eflags as u64) }.map_err(
            |detail| VmError::NativeExecution {
                op: "uc_reg_write(eflags)",
                detail,
            },
        )?;

        let mut instruction_budget =
            usize::try_from(self.config.max_instructions.max(1)).unwrap_or(usize::MAX);
        let mut run_context = UnicornRunContext {
            engine: self as *mut Self,
            api: unicorn_ptr,
            uc,
            callback_error: None,
            pending_fault: None,
            pending_writes: Vec::new(),
            suppress_mem_write_hook: false,
            last_native_block: None,
            recent_blocks: VecDeque::new(),
        };
        let mut start_address = address;
        loop {
            let before = self.instruction_count;
            run_context.callback_error = None;
            run_context.pending_fault = None;
            let emu_result = {
                let _profile = self.runtime_profiler.start_scope("unicorn.emu_start");
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
                    let result = unsafe {
                        unicorn.emu_start_raw(
                            uc,
                            start_address,
                            self.native_return_sentinel,
                            0,
                            instruction_budget.max(1),
                        )
                    };
                    slot.set(previous);
                    result.map_err(|detail| VmError::NativeExecution {
                        op: "uc_emu_start",
                        detail,
                    })
                })
            };
            flush_unicorn_pending_writes(&mut run_context, uc)?;
            let consumed =
                usize::try_from(self.instruction_count.saturating_sub(before)).unwrap_or(0);
            instruction_budget = instruction_budget.saturating_sub(consumed.max(1));
            if let Some(error) = run_context.callback_error.take() {
                let pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.unwrap_or(0);
                self.log_emu_stop("hook", pc, &error.to_string())?;
                return Err(error);
            }
            if let Some(fault) = run_context.pending_fault.take() {
                if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                    start_address =
                        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(eip)",
                                detail,
                            }
                        })?;
                    continue;
                }
            }
            match emu_result {
                Ok(()) => {}
                Err(VmError::NativeExecution { op, detail }) => {
                    let pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.unwrap_or(0);
                    let sp = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_ESP) }.unwrap_or(0);
                    let eax = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EAX) }.unwrap_or(0);
                    let ebx = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EBX) }.unwrap_or(0);
                    let ecx = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_ECX) }.unwrap_or(0);
                    let edx = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EDX) }.unwrap_or(0);
                    let ebp = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EBP) }.unwrap_or(0);
                    let esi = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_ESI) }.unwrap_or(0);
                    let edi = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EDI) }.unwrap_or(0);
                    let stack_arg = |offset| {
                        unsafe { unicorn.mem_read_raw(uc, ebp + offset, 4) }
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
                    break;
                }
                start_address =
                    unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(eip)",
                            detail,
                        }
                    })?;
                continue;
            }
            break;
        }
        let exit_pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.unwrap_or(0);
        if instruction_budget == 0 && exit_pc != self.native_return_sentinel {
            let detail = format!("instruction budget exhausted at 0x{exit_pc:X}");
            match run_mode {
                NativeCallRunMode::Standalone => {
                    self.log_emu_stop("native", exit_pc, &detail)?;
                    return Err(VmError::NativeExecution { op: "run", detail });
                }
                NativeCallRunMode::EntryFrame => {
                    self.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
                    self.log_instruction_budget_exhausted("native_entry", exit_pc)?;
                    if let Some(main_tid) = self.main_thread_tid {
                        let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                        self.scheduler
                            .set_thread_registers(main_tid, registers)
                            .ok_or(VmError::RuntimeInvariant(
                                "failed to persist main thread registers after budget stop",
                            ))?;
                    }
                }
            }
        }
        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EAX) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(eax)",
                detail,
            }
        })
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
    ) -> Result<u64, VmError> {
        let _profile = self
            .runtime_profiler
            .start_scope("unicorn.call_x64_native_with_unicorn_context");
        self.force_native_return = false;

        let stack_arg_count = args.len().saturating_sub(4);
        let frame_size = 0x28 + stack_arg_count * 8;
        let new_rsp = saved_rsp
            .checked_sub(frame_size as u64)
            .ok_or(VmError::RuntimeInvariant("native call stack underflow"))?;
        let mut frame = vec![0u8; frame_size];
        frame[0..8].copy_from_slice(&self.native_return_sentinel.to_le_bytes());
        for (index, value) in args.iter().skip(4).enumerate() {
            let offset = 0x28 + index * 8;
            frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        self.modules.memory_mut().write(new_rsp, &frame)?;
        self.sync_native_support_state()?;
        let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
        let unicorn = unsafe { &*unicorn_ptr };
        for (regid, value, op) in [
            (UC_X86_REG_RIP, address, "uc_reg_write(rip)"),
            (UC_X86_REG_RSP, new_rsp, "uc_reg_write(rsp)"),
            (UC_X86_REG_RFLAGS, saved_rflags, "uc_reg_write(rflags)"),
            (UC_X86_REG_RCX, arg(args, 0), "uc_reg_write(rcx)"),
            (UC_X86_REG_RDX, arg(args, 1), "uc_reg_write(rdx)"),
            (UC_X86_REG_R8, arg(args, 2), "uc_reg_write(r8)"),
            (UC_X86_REG_R9, arg(args, 3), "uc_reg_write(r9)"),
        ] {
            unsafe { unicorn.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }

        let mut instruction_budget =
            usize::try_from(self.config.max_instructions.max(1)).unwrap_or(usize::MAX);
        let mut run_context = UnicornRunContext {
            engine: self as *mut Self,
            api: unicorn_ptr,
            uc,
            callback_error: None,
            pending_fault: None,
            pending_writes: Vec::new(),
            suppress_mem_write_hook: false,
            last_native_block: None,
            recent_blocks: VecDeque::new(),
        };
        let mut start_address = address;
        loop {
            let before = self.instruction_count;
            run_context.callback_error = None;
            run_context.pending_fault = None;
            let emu_result = {
                let _profile = self.runtime_profiler.start_scope("unicorn.emu_start");
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
                    let result = unsafe {
                        unicorn.emu_start_raw(
                            uc,
                            start_address,
                            self.native_return_sentinel,
                            0,
                            instruction_budget.max(1),
                        )
                    };
                    slot.set(previous);
                    result.map_err(|detail| VmError::NativeExecution {
                        op: "uc_emu_start",
                        detail,
                    })
                })
            };
            flush_unicorn_pending_writes(&mut run_context, uc)?;
            let consumed =
                usize::try_from(self.instruction_count.saturating_sub(before)).unwrap_or(0);
            instruction_budget = instruction_budget.saturating_sub(consumed.max(1));
            if let Some(error) = run_context.callback_error.take() {
                let pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.unwrap_or(0);
                self.log_emu_stop("hook", pc, &error.to_string())?;
                return Err(error);
            }
            if let Some(fault) = run_context.pending_fault.take() {
                if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                    start_address =
                        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(rip)",
                                detail,
                            }
                        })?;
                    continue;
                }
            }
            match emu_result {
                Ok(()) => {}
                Err(VmError::NativeExecution { op, detail }) => {
                    let pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.unwrap_or(0);
                    let sp = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RSP) }.unwrap_or(0);
                    let rax = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RAX) }.unwrap_or(0);
                    let rcx = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RCX) }.unwrap_or(0);
                    let rdx = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RDX) }.unwrap_or(0);
                    let r8 = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_R8) }.unwrap_or(0);
                    let r9 = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_R9) }.unwrap_or(0);
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
                    break;
                }
                start_address =
                    unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_reg_read(rip)",
                            detail,
                        }
                    })?;
                continue;
            }
            break;
        }
        let exit_pc = unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.unwrap_or(0);
        if instruction_budget == 0 && exit_pc != self.native_return_sentinel {
            let detail = format!("instruction budget exhausted at 0x{exit_pc:X}");
            match run_mode {
                NativeCallRunMode::Standalone => {
                    self.log_emu_stop("native", exit_pc, &detail)?;
                    return Err(VmError::NativeExecution { op: "run", detail });
                }
                NativeCallRunMode::EntryFrame => {
                    self.stop_reason = Some(RunStopReason::InstructionBudgetExhausted);
                    self.log_instruction_budget_exhausted("native_entry", exit_pc)?;
                    if let Some(main_tid) = self.main_thread_tid {
                        let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                        self.scheduler
                            .set_thread_registers(main_tid, registers)
                            .ok_or(VmError::RuntimeInvariant(
                                "failed to persist main thread registers after budget stop",
                            ))?;
                    }
                }
            }
        }
        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RAX) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_read(rax)",
                detail,
            }
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
        )
    }
}

use super::*;

const STATUS_ACCESS_VIOLATION_EXIT: u32 = 0xC000_0005;

const X86_UNICORN_REG_WRITES: [(&str, i32, u64); 10] = [
    ("eax", UC_X86_REG_EAX, 0),
    ("ebx", UC_X86_REG_EBX, 0),
    ("ecx", UC_X86_REG_ECX, 0),
    ("edx", UC_X86_REG_EDX, 0),
    ("esi", UC_X86_REG_ESI, 0),
    ("edi", UC_X86_REG_EDI, 0),
    ("ebp", UC_X86_REG_EBP, 0),
    ("esp", UC_X86_REG_ESP, 0),
    ("eip", UC_X86_REG_EIP, 0),
    ("eflags", UC_X86_REG_EFLAGS, 0x202),
];

const X64_UNICORN_REG_WRITES: [(&str, i32, u64); 18] = [
    ("rax", UC_X86_REG_RAX, 0),
    ("rbx", UC_X86_REG_RBX, 0),
    ("rcx", UC_X86_REG_RCX, 0),
    ("rdx", UC_X86_REG_RDX, 0),
    ("rsi", UC_X86_REG_RSI, 0),
    ("rdi", UC_X86_REG_RDI, 0),
    ("rbp", UC_X86_REG_RBP, 0),
    ("rsp", UC_X86_REG_RSP, 0),
    ("rip", UC_X86_REG_RIP, 0),
    ("r8", UC_X86_REG_R8, 0),
    ("r9", UC_X86_REG_R9, 0),
    ("r10", UC_X86_REG_R10, 0),
    ("r11", UC_X86_REG_R11, 0),
    ("r12", UC_X86_REG_R12, 0),
    ("r13", UC_X86_REG_R13, 0),
    ("r14", UC_X86_REG_R14, 0),
    ("r15", UC_X86_REG_R15, 0),
    ("rflags", UC_X86_REG_RFLAGS, 0x202),
];

const X86_UNICORN_REG_READS: [(&str, i32); 10] = [
    ("eax", UC_X86_REG_EAX),
    ("ebx", UC_X86_REG_EBX),
    ("ecx", UC_X86_REG_ECX),
    ("edx", UC_X86_REG_EDX),
    ("esi", UC_X86_REG_ESI),
    ("edi", UC_X86_REG_EDI),
    ("ebp", UC_X86_REG_EBP),
    ("esp", UC_X86_REG_ESP),
    ("eip", UC_X86_REG_EIP),
    ("eflags", UC_X86_REG_EFLAGS),
];

const X64_UNICORN_REG_READS: [(&str, i32); 18] = [
    ("rax", UC_X86_REG_RAX),
    ("rbx", UC_X86_REG_RBX),
    ("rcx", UC_X86_REG_RCX),
    ("rdx", UC_X86_REG_RDX),
    ("rsi", UC_X86_REG_RSI),
    ("rdi", UC_X86_REG_RDI),
    ("rbp", UC_X86_REG_RBP),
    ("rsp", UC_X86_REG_RSP),
    ("rip", UC_X86_REG_RIP),
    ("r8", UC_X86_REG_R8),
    ("r9", UC_X86_REG_R9),
    ("r10", UC_X86_REG_R10),
    ("r11", UC_X86_REG_R11),
    ("r12", UC_X86_REG_R12),
    ("r13", UC_X86_REG_R13),
    ("r14", UC_X86_REG_R14),
    ("r15", UC_X86_REG_R15),
    ("rflags", UC_X86_REG_RFLAGS),
];

impl VirtualExecutionEngine {
    pub(super) fn ensure_unicorn_session(
        &mut self,
    ) -> Result<(*const UnicornApi, *mut UcEngine), VmError> {
        let unicorn_ptr = self
            .unicorn_state
            .unicorn
            .as_deref()
            .map(std::ptr::from_ref)
            .ok_or(VmError::RuntimeInvariant("unicorn backend unavailable"))?;
        if let Some(handle) = self.unicorn_state.unicorn_handle {
            return Ok((unicorn_ptr, handle));
        }

        let unicorn = unsafe { &*unicorn_ptr };
        let uc = if self.core.arch.is_x86() {
            unicorn.open_x86_raw()
        } else {
            unicorn.open_x64_raw()
        }
        .map_err(|detail| VmError::NativeExecution {
            op: "uc_open",
            detail,
        })?;
        let bound = unsafe { unicorn.bind(uc) };
        let setup_result = (|| -> Result<(), VmError> {
            for region in self.core.modules.memory().regions.values() {
                bound
                    .mem_map(region.base, region.size, unicorn_prot(region.perms))
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_mem_map",
                        detail: format!(
                            "{detail}; base=0x{:X}; size=0x{:X}",
                            region.base, region.size
                        ),
                    })?;
                let data = self
                    .core
                    .modules
                    .memory()
                    .read(region.base, region.size as usize)?;
                if data.iter().any(|byte| *byte != 0) {
                    bound.mem_write(region.base, &data).map_err(|detail| {
                        VmError::NativeExecution {
                            op: "uc_mem_write",
                            detail: format!(
                                "{detail}; base=0x{:X}; size=0x{:X}",
                                region.base, region.size
                            ),
                        }
                    })?;
                }
            }
            if self.core.arch.is_x86() {
                self.configure_unicorn_x86_segments_raw(unicorn, uc)?;
            } else {
                bound
                    .reg_write(UC_X86_REG_GS_BASE, self.core.process_env.current_teb())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_reg_write(gs_base)",
                        detail,
                    })?;
            }
            if !self.unicorn_state.unicorn_intr_hook_installed {
                bound
                    .add_intr_hook(unicorn_intr_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            if !self.unicorn_state.unicorn_block_hook_installed {
                bound
                    .add_block_hook(unicorn_block_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            // UC_HOOK_CODE is disabled — UC_HOOK_BLOCK (above) handles
            // instruction counting, bound-stub dispatch, return-sentinel
            // detection, and MFC42u recoveries in a single callback.
            // Non-executable-module enforcement is handled by the existing
            // UC_HOOK_MEM_FETCH_PROT path.
            if !self.unicorn_state.unicorn_mem_write_hook_installed {
                bound
                    .add_mem_write_hook(unicorn_mem_write_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            if !self.unicorn_state.unicorn_mem_read_hook_installed {
                bound
                    .add_mem_read_hook(unicorn_mem_read_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            if !self.unicorn_state.unicorn_mem_prot_hook_installed {
                bound
                    .add_mem_prot_hook(unicorn_mem_prot_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            if !self.unicorn_state.unicorn_mem_unmapped_hook_installed {
                bound
                    .add_mem_unmapped_hook(unicorn_mem_unmapped_hook, std::ptr::null_mut())
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            for record in self.process_memory.virtual_allocations.values() {
                for segment in &record.segments {
                    if segment.state == MEM_COMMIT && segment.protect & PAGE_GUARD != 0 {
                        bound
                            .mem_protect(segment.base, segment.size, 0)
                            .map_err(|detail| VmError::NativeExecution {
                                op: "uc_mem_protect",
                                detail,
                            })?;
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
            let _ = unsafe { unicorn.close_raw(uc) };
            return Err(error);
        }

        self.core
            .modules
            .memory_mut()
            .attach_native(unicorn_ptr, uc);
        self.unicorn_state.unicorn_handle = Some(uc);
        self.unicorn_state.unicorn_intr_hook_installed = true;
        self.unicorn_state.unicorn_block_hook_installed = true;
        self.unicorn_state.unicorn_code_hook_installed = true;
        self.unicorn_state.unicorn_mem_write_hook_installed = true;
        self.unicorn_state.unicorn_mem_read_hook_installed = true;
        self.unicorn_state.unicorn_mem_prot_hook_installed = true;
        self.unicorn_state.unicorn_mem_unmapped_hook_installed = true;
        Ok((unicorn_ptr, uc))
    }

    pub(super) fn close_unicorn_session(&mut self) {
        self.core.modules.memory_mut().detach_native();
        self.unicorn_state.unicorn_intr_hook_installed = false;
        self.unicorn_state.unicorn_block_hook_installed = false;
        self.unicorn_state.unicorn_code_hook_installed = false;
        self.unicorn_state.unicorn_mem_write_hook_installed = false;
        self.unicorn_state.unicorn_mem_read_hook_installed = false;
        self.unicorn_state.unicorn_mem_prot_hook_installed = false;
        self.unicorn_state.unicorn_mem_unmapped_hook_installed = false;
        let Some(handle) = self.unicorn_state.unicorn_handle.take() else {
            return;
        };
        if let Some(unicorn) = self.unicorn_state.unicorn.as_deref() {
            let _ = unsafe { unicorn.close_raw(handle) };
        }
    }

    pub(super) fn configure_unicorn_x86_segments_raw(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<(), VmError> {
        let unicorn = unsafe { api.bind(uc) };
        let gdtr = X86Mmr {
            selector: 0,
            base: self.core.process_env.layout().gdt_base,
            limit: 31,
            flags: 0,
        };
        unicorn
            .reg_write_mmr(UC_X86_REG_GDTR, &gdtr)
            .map_err(|detail| VmError::NativeExecution {
                op: "uc_reg_write(gdtr)",
                detail,
            })?;
        for (regid, value, op) in [
            (UC_X86_REG_CS, 1 << 3, "uc_reg_write(cs)"),
            (UC_X86_REG_DS, 2 << 3, "uc_reg_write(ds)"),
            (UC_X86_REG_ES, 2 << 3, "uc_reg_write(es)"),
            (UC_X86_REG_SS, 2 << 3, "uc_reg_write(ss)"),
            (UC_X86_REG_GS, 2 << 3, "uc_reg_write(gs)"),
            (UC_X86_REG_FS, 3 << 3, "uc_reg_write(fs)"),
        ] {
            unicorn
                .reg_write(regid, value)
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn restore_unicorn_thread_registers(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        registers: &RegisterFile,
    ) -> Result<(), VmError> {
        let unicorn = unsafe { api.bind(uc) };
        let register_set = if self.core.arch.is_x86() {
            &X86_UNICORN_REG_WRITES[..]
        } else {
            &X64_UNICORN_REG_WRITES[..]
        };
        for &(name, regid, _default) in register_set {
            let value = registers.get(name);
            unicorn
                .reg_write(regid, value)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write",
                    detail: format!("{detail}; register={name}"),
                })?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn capture_unicorn_thread_registers(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<RegisterFile, VmError> {
        let unicorn = unsafe { api.bind(uc) };
        let mut registers = RegisterFile::new();
        let register_set = if self.core.arch.is_x86() {
            &X86_UNICORN_REG_READS[..]
        } else {
            &X64_UNICORN_REG_READS[..]
        };
        for &(name, regid) in register_set {
            let value = unicorn
                .reg_read(regid)
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_read",
                    detail: format!("{detail}; register={name}"),
                })?;
            registers.set(name, value);
        }
        Ok(registers)
    }

    pub(super) fn capture_unicorn_stack_words(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        registers: &RegisterFile,
    ) -> Result<BTreeMap<String, u64>, VmError> {
        let unicorn = unsafe { api.bind(uc) };
        let stack_pointer = if self.core.arch.is_x86() {
            registers.esp
        } else {
            registers.rsp
        };
        if stack_pointer == 0 {
            return Ok(BTreeMap::new());
        };
        let pointer_size = if self.core.arch.is_x86() { 4 } else { 8 };
        let offsets = if self.core.arch.is_x86() {
            vec![0, 4, 0x28, 0x40, 0x60, 0x90, 0xA4]
        } else {
            vec![0, 8, 0x20, 0x28, 0x40]
        };
        let mut words = BTreeMap::new();
        for offset in offsets {
            let address = stack_pointer.saturating_add(offset);
            let Ok(bytes) = unicorn.mem_read(address, pointer_size) else {
                continue;
            };
            let value = if pointer_size == 4 {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
            } else {
                u64::from_le_bytes(bytes[..8].try_into().unwrap())
            };
            words.insert(format!("sp+0x{offset:X}"), value);
        }
        Ok(words)
    }

    fn native_fault_hint(
        &self,
        tid: u32,
        exit_pc: u64,
        snapshots: &VecDeque<NativeBlockSnapshot>,
    ) -> Option<String> {
        if exit_pc != 0 {
            return None;
        }
        let mut parts = vec!["hint=suspect null indirect call/jump".to_string()];
        if let Some(snapshot) = snapshots.back() {
            parts.push(format!(
                "last_block=0x{:X}/0x{:X}",
                snapshot.pc, snapshot.size
            ));
            let last_pc = if self.core.arch.is_x86() {
                let eip = snapshot.registers.eip;
                if eip != 0 {
                    eip
                } else {
                    snapshot.pc
                }
            } else {
                let rip = snapshot.registers.rip;
                if rip != 0 {
                    rip
                } else {
                    snapshot.pc
                }
            };
            parts.push(format!("last_block_pc=0x{last_pc:X}"));
        }
        if let Some(metadata) = self.trace.remote_shellcode_threads.get(&tid) {
            parts.push(format!(
                "remote_source_process=0x{:X}",
                metadata.source_process_handle
            ));
            parts.push(format!(
                "remote_source_start=0x{:X}",
                metadata.source_start_address
            ));
            if let Some(staged_start) = metadata.staged_start_address {
                parts.push(format!("remote_staged_start=0x{staged_start:X}"));
            }
        }
        Some(parts.join("; "))
    }

    #[allow(dead_code)]
    pub(super) fn run_unicorn_thread_slice(
        &mut self,
        tid: u32,
        instruction_budget: u64,
    ) -> Result<(), VmError> {
        let thread = self
            .core
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("thread snapshot missing"))?;
        let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
        let unicorn = unsafe { &*unicorn_ptr };
        let bound = unsafe { unicorn.bind(uc) };
        self.restore_unicorn_thread_registers(unicorn, uc, &thread.registers)?;

        let mut start_address = if self.core.arch.is_x86() {
            let eip = thread.registers.eip;
            if eip != 0 {
                eip
            } else {
                thread.start_address
            }
        } else {
            let rip = thread.registers.rip;
            if rip != 0 {
                rip
            } else {
                thread.start_address
            }
        };
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
            let stack_pointer = if self.core.arch.is_x86() {
                thread.registers.esp
            } else {
                thread.registers.rsp
            };
            eprintln!(
                "[LOAD_STAGE] unicorn_slice:start tid={} start=0x{:X} sp=0x{:X} budget={}",
                tid, start_address, stack_pointer, instruction_budget
            );
        }
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
        let mut remaining_budget = usize::try_from(instruction_budget.max(1)).unwrap_or(usize::MAX);
        let (emu_result, registers) = loop {
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
            let emu_count = remaining_budget.max(1);
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
                usize::try_from(self.core.instruction_count.saturating_sub(before)).unwrap_or(0);
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
            remaining_budget = remaining_budget.saturating_sub(consumed);
            if let Some(error) = run_context.callback_error.take() {
                let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                self.core
                    .scheduler
                    .set_thread_registers(tid, registers)
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to capture thread registers",
                    ))?;
                return Err(error);
            }
            if let Some(action) = run_context.pending_protected_fetch.take() {
                self.handle_pending_protected_fetch(unicorn, uc, action)?;
                start_address = if self.core.arch.is_x86() {
                    bound
                        .reg_read(UC_X86_REG_EIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(eip)",
                            detail,
                        })?
                } else {
                    bound
                        .reg_read(UC_X86_REG_RIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(rip)",
                            detail,
                        })?
                };
                continue;
            }
            let mut unhandled_fault = None;
            if let Some(fault) = run_context.pending_fault.take() {
                if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                    start_address = if self.core.arch.is_x86() {
                        bound.reg_read(UC_X86_REG_EIP).map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(eip)",
                                detail,
                            }
                        })?
                    } else {
                        bound.reg_read(UC_X86_REG_RIP).map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(rip)",
                                detail,
                            }
                        })?
                    };
                    continue;
                }
                unhandled_fault = Some(fault);
            }
            let emu_result = if let Some(fault) = unhandled_fault {
                Err(self.unhandled_unicorn_fault_error(fault))
            } else {
                emu_result
            };
            if emu_result.is_ok() && self.dispatch.should_restart_from_updated_pc() {
                start_address = if self.core.arch.is_x86() {
                    bound
                        .reg_read(UC_X86_REG_EIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(eip)",
                            detail,
                        })?
                } else {
                    bound
                        .reg_read(UC_X86_REG_RIP)
                        .map_err(|detail| VmError::NativeExecution {
                            op: "uc_reg_read(rip)",
                            detail,
                        })?
                };
                self.dispatch.reset_api_flow_control();
                continue;
            }
            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
            break (emu_result, registers);
        };
        let exit_pc = if self.core.arch.is_x86() {
            let eip = registers.eip;
            if eip != 0 {
                eip
            } else {
                start_address
            }
        } else {
            let rip = registers.rip;
            if rip != 0 {
                rip
            } else {
                start_address
            }
        };
        if std::env::var_os("HVM_DEBUG_LOAD_STAGE").is_some() {
            let stack_pointer = if self.core.arch.is_x86() {
                registers.esp
            } else {
                registers.rsp
            };
            eprintln!(
                "[LOAD_STAGE] unicorn_slice:end tid={} exit_pc=0x{:X} sp=0x{:X} emu_ok={}",
                tid,
                exit_pc,
                stack_pointer,
                emu_result.is_ok()
            );
        }
        let return_value = if self.core.arch.is_x86() {
            registers.eax as u32
        } else {
            registers.rax as u32
        };
        let error_context = if self.core.arch.is_x86() {
            (
                registers.esp,
                registers.eax,
                registers.ebx,
                registers.ecx,
                registers.edx,
                registers.ebp,
                registers.esi,
                registers.edi,
            )
        } else {
            (
                registers.rsp,
                registers.rax,
                registers.rcx,
                registers.rdx,
                registers.r8,
                registers.r9,
                0,
                0,
            )
        };

        self.core
            .scheduler
            .set_thread_registers(tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to capture thread registers",
            ))?;

        if exit_pc == self.core.native_return_sentinel {
            let _ = self.terminate_current_thread(return_value);
            if Some(tid) == self.core.main_thread_tid && self.core.exit_code.is_none() {
                self.core.exit_code = Some(return_value);
            }
        } else if self.core.scheduler.thread_state(tid) == Some("running") {
            self.core
                .scheduler
                .mark_thread_ready(tid)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to ready scheduler thread",
                ))?;
        }

        if self.dispatch.thread_yield_requested() {
            self.dispatch.reset_api_flow_control();
        }

        match emu_result {
            Ok(()) => Ok(()),
            Err(VmError::NativeExecution { op, detail }) => {
                let message = if self.core.arch.is_x86() {
                    format!(
                        "{detail}; pc=0x{exit_pc:X}; sp=0x{:X}; eax=0x{:X}; ebx=0x{:X}; ecx=0x{:X}; edx=0x{:X}; ebp=0x{:X}; esi=0x{:X}; edi=0x{:X}",
                        error_context.0,
                        error_context.1,
                        error_context.2,
                        error_context.3,
                        error_context.4,
                        error_context.5,
                        error_context.6,
                        error_context.7,
                    )
                } else {
                    format!(
                        "{detail}; pc=0x{exit_pc:X}; sp=0x{:X}; rax=0x{:X}; rcx=0x{:X}; rdx=0x{:X}; r8=0x{:X}; r9=0x{:X}",
                        error_context.0,
                        error_context.1,
                        error_context.2,
                        error_context.3,
                        error_context.4,
                        error_context.5,
                    )
                };
                let message = if let Some(hint) =
                    self.native_fault_hint(tid, exit_pc, &run_context.recent_blocks)
                {
                    format!("{message}; {hint}")
                } else {
                    message
                };
                self.log_emu_stop("native", exit_pc, &message)?;
                if self.core.scheduler.thread_state(tid) != Some("terminated") {
                    let _ = self.terminate_current_thread(STATUS_ACCESS_VIOLATION_EXIT);
                    if Some(tid) == self.core.main_thread_tid && self.core.exit_code.is_none() {
                        self.core.exit_code = Some(STATUS_ACCESS_VIOLATION_EXIT);
                    }
                }
                if self.core.scheduler.thread_state(tid) == Some("terminated") {
                    Ok(())
                } else {
                    Err(VmError::NativeExecution {
                        op,
                        detail: message,
                    })
                }
            }
            Err(error) => Err(error),
        }
    }
}

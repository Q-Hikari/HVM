use super::*;

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
            .unicorn
            .as_deref()
            .map(std::ptr::from_ref)
            .ok_or(VmError::RuntimeInvariant("unicorn backend unavailable"))?;
        if let Some(handle) = self.unicorn_handle {
            return Ok((unicorn_ptr, handle));
        }

        let unicorn = unsafe { &*unicorn_ptr };
        let uc = if self.arch.is_x86() {
            unicorn.open_x86_raw()
        } else {
            unicorn.open_x64_raw()
        }
        .map_err(|detail| VmError::NativeExecution {
            op: "uc_open",
            detail,
        })?;
        let setup_result = (|| -> Result<(), VmError> {
            for region in &self.modules.memory().regions {
                unsafe {
                    unicorn.mem_map_raw(uc, region.base, region.size, unicorn_prot(region.perms))
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_mem_map",
                    detail: format!(
                        "{detail}; base=0x{:X}; size=0x{:X}",
                        region.base, region.size
                    ),
                })?;
                let data = self
                    .modules
                    .memory()
                    .read(region.base, region.size as usize)?;
                if data.iter().any(|byte| *byte != 0) {
                    unsafe { unicorn.mem_write_raw(uc, region.base, &data) }.map_err(|detail| {
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
            if self.arch.is_x86() {
                self.configure_unicorn_x86_segments_raw(unicorn, uc)?;
            } else {
                unsafe {
                    unicorn.reg_write_raw(uc, UC_X86_REG_GS_BASE, self.process_env.current_teb())
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_reg_write(gs_base)",
                    detail,
                })?;
            }
            if !self.unicorn_block_hook_installed {
                unsafe { unicorn.hook_add_block_raw(uc, unicorn_block_hook, std::ptr::null_mut()) }
                    .map_err(|detail| VmError::NativeExecution {
                        op: "uc_hook_add",
                        detail,
                    })?;
            }
            if !self.unicorn_code_hook_installed {
                unsafe { unicorn.hook_add_code_raw(uc, unicorn_code_hook, std::ptr::null_mut()) }
                    .map_err(|detail| VmError::NativeExecution {
                    op: "uc_hook_add",
                    detail,
                })?;
            }
            if !self.unicorn_mem_write_hook_installed {
                unsafe {
                    unicorn.hook_add_mem_write_raw(uc, unicorn_mem_write_hook, std::ptr::null_mut())
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_hook_add",
                    detail,
                })?;
            }
            if !self.unicorn_mem_prot_hook_installed {
                unsafe {
                    unicorn.hook_add_mem_prot_raw(uc, unicorn_mem_prot_hook, std::ptr::null_mut())
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_hook_add",
                    detail,
                })?;
            }
            if !self.unicorn_mem_unmapped_hook_installed {
                unsafe {
                    unicorn.hook_add_mem_unmapped_raw(
                        uc,
                        unicorn_mem_unmapped_hook,
                        std::ptr::null_mut(),
                    )
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_hook_add",
                    detail,
                })?;
            }
            for record in self.virtual_allocations.values() {
                for segment in &record.segments {
                    if segment.state == MEM_COMMIT && segment.protect & PAGE_GUARD != 0 {
                        unsafe { unicorn.mem_protect_raw(uc, segment.base, segment.size, 0) }
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

        self.modules.memory_mut().attach_native(unicorn_ptr, uc);
        self.unicorn_handle = Some(uc);
        self.unicorn_block_hook_installed = true;
        self.unicorn_code_hook_installed = true;
        self.unicorn_mem_write_hook_installed = true;
        self.unicorn_mem_prot_hook_installed = true;
        self.unicorn_mem_unmapped_hook_installed = true;
        Ok((unicorn_ptr, uc))
    }

    pub(super) fn close_unicorn_session(&mut self) {
        self.modules.memory_mut().detach_native();
        self.unicorn_block_hook_installed = false;
        self.unicorn_code_hook_installed = false;
        self.unicorn_mem_write_hook_installed = false;
        self.unicorn_mem_prot_hook_installed = false;
        self.unicorn_mem_unmapped_hook_installed = false;
        let Some(handle) = self.unicorn_handle.take() else {
            return;
        };
        if let Some(unicorn) = self.unicorn.as_deref() {
            let _ = unsafe { unicorn.close_raw(handle) };
        }
    }

    pub(super) fn configure_unicorn_x86_segments_raw(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<(), VmError> {
        let gdtr = X86Mmr {
            selector: 0,
            base: self.process_env.layout().gdt_base,
            limit: 31,
            flags: 0,
        };
        unsafe { api.reg_write_mmr_raw(uc, UC_X86_REG_GDTR, &gdtr) }.map_err(|detail| {
            VmError::NativeExecution {
                op: "uc_reg_write(gdtr)",
                detail,
            }
        })?;
        for (regid, value, op) in [
            (UC_X86_REG_CS, 1 << 3, "uc_reg_write(cs)"),
            (UC_X86_REG_DS, 2 << 3, "uc_reg_write(ds)"),
            (UC_X86_REG_ES, 2 << 3, "uc_reg_write(es)"),
            (UC_X86_REG_SS, 2 << 3, "uc_reg_write(ss)"),
            (UC_X86_REG_GS, 2 << 3, "uc_reg_write(gs)"),
            (UC_X86_REG_FS, 3 << 3, "uc_reg_write(fs)"),
        ] {
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn restore_unicorn_thread_registers(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        registers: &BTreeMap<String, u64>,
    ) -> Result<(), VmError> {
        let register_set = if self.arch.is_x86() {
            &X86_UNICORN_REG_WRITES[..]
        } else {
            &X64_UNICORN_REG_WRITES[..]
        };
        for &(name, regid, default) in register_set {
            let value = registers.get(name).copied().unwrap_or(default);
            unsafe { api.reg_write_raw(uc, regid, value) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_write",
                    detail: format!("{detail}; register={name}"),
                }
            })?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn capture_unicorn_thread_registers(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
    ) -> Result<BTreeMap<String, u64>, VmError> {
        let mut registers = BTreeMap::new();
        let register_set = if self.arch.is_x86() {
            &X86_UNICORN_REG_READS[..]
        } else {
            &X64_UNICORN_REG_READS[..]
        };
        for &(name, regid) in register_set {
            let value = unsafe { api.reg_read_raw(uc, regid) }.map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_reg_read",
                    detail: format!("{detail}; register={name}"),
                }
            })?;
            registers.insert(name.to_string(), value);
        }
        Ok(registers)
    }

    pub(super) fn capture_unicorn_stack_words(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        registers: &BTreeMap<String, u64>,
    ) -> Result<BTreeMap<String, u64>, VmError> {
        let Some(stack_pointer) = registers
            .get(if self.arch.is_x86() { "esp" } else { "rsp" })
            .copied()
        else {
            return Ok(BTreeMap::new());
        };
        let pointer_size = if self.arch.is_x86() { 4 } else { 8 };
        let offsets = if self.arch.is_x86() {
            vec![0, 4, 0x28, 0x40, 0x60, 0x90, 0xA4]
        } else {
            vec![0, 8, 0x20, 0x28, 0x40]
        };
        let mut words = BTreeMap::new();
        for offset in offsets {
            let address = stack_pointer.saturating_add(offset);
            let Ok(bytes) = (unsafe { api.mem_read_raw(uc, address, pointer_size) }) else {
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

    #[allow(dead_code)]
    pub(super) fn run_unicorn_thread_slice(
        &mut self,
        tid: u32,
        instruction_budget: u64,
    ) -> Result<(), VmError> {
        let thread = self
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant("thread snapshot missing"))?;
        let (unicorn_ptr, uc) = self.ensure_unicorn_session()?;
        let unicorn = unsafe { &*unicorn_ptr };
        self.restore_unicorn_thread_registers(unicorn, uc, &thread.registers)?;

        let mut start_address = if self.arch.is_x86() {
            thread
                .registers
                .get("eip")
                .copied()
                .unwrap_or(thread.start_address)
        } else {
            thread
                .registers
                .get("rip")
                .copied()
                .unwrap_or(thread.start_address)
        };
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
        let mut remaining_budget = usize::try_from(instruction_budget.max(1)).unwrap_or(usize::MAX);
        let (emu_result, registers) = loop {
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
                            remaining_budget.max(1),
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
            remaining_budget = remaining_budget.saturating_sub(consumed.max(1));
            if let Some(error) = run_context.callback_error.take() {
                let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
                self.scheduler.set_thread_registers(tid, registers).ok_or(
                    VmError::RuntimeInvariant("failed to capture thread registers"),
                )?;
                return Err(error);
            }
            if let Some(fault) = run_context.pending_fault.take() {
                if self.handle_pending_unicorn_fault(unicorn, uc, fault)? {
                    start_address = if self.arch.is_x86() {
                        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_EIP) }.map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(eip)",
                                detail,
                            }
                        })?
                    } else {
                        unsafe { unicorn.reg_read_raw(uc, UC_X86_REG_RIP) }.map_err(|detail| {
                            VmError::NativeExecution {
                                op: "uc_reg_read(rip)",
                                detail,
                            }
                        })?
                    };
                    continue;
                }
            }
            let registers = self.capture_unicorn_thread_registers(unicorn, uc)?;
            break (emu_result, registers);
        };
        let exit_pc = if self.arch.is_x86() {
            registers.get("eip").copied().unwrap_or(start_address)
        } else {
            registers.get("rip").copied().unwrap_or(start_address)
        };
        let return_value = if self.arch.is_x86() {
            registers.get("eax").copied().unwrap_or(0) as u32
        } else {
            registers.get("rax").copied().unwrap_or(0) as u32
        };
        let error_context = if self.arch.is_x86() {
            (
                registers.get("esp").copied().unwrap_or(0),
                registers.get("eax").copied().unwrap_or(0),
                registers.get("ebx").copied().unwrap_or(0),
                registers.get("ecx").copied().unwrap_or(0),
                registers.get("edx").copied().unwrap_or(0),
                registers.get("ebp").copied().unwrap_or(0),
                registers.get("esi").copied().unwrap_or(0),
                registers.get("edi").copied().unwrap_or(0),
            )
        } else {
            (
                registers.get("rsp").copied().unwrap_or(0),
                registers.get("rax").copied().unwrap_or(0),
                registers.get("rcx").copied().unwrap_or(0),
                registers.get("rdx").copied().unwrap_or(0),
                registers.get("r8").copied().unwrap_or(0),
                registers.get("r9").copied().unwrap_or(0),
                0,
                0,
            )
        };

        self.scheduler
            .set_thread_registers(tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to capture thread registers",
            ))?;

        if exit_pc == self.native_return_sentinel {
            let _ = self.terminate_current_thread(return_value);
            if Some(tid) == self.main_thread_tid && self.exit_code.is_none() {
                self.exit_code = Some(return_value);
            }
        } else if self.scheduler.thread_state(tid) == Some("running") {
            self.scheduler
                .mark_thread_ready(tid)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to ready scheduler thread",
                ))?;
        }

        if self.thread_yield_requested {
            self.thread_yield_requested = false;
            self.defer_api_return = false;
        }

        match emu_result {
            Ok(()) => Ok(()),
            Err(VmError::NativeExecution { op, detail }) => {
                let message = if self.arch.is_x86() {
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
                self.log_emu_stop("native", exit_pc, &message)?;
                Err(VmError::NativeExecution {
                    op,
                    detail: message,
                })
            }
            Err(error) => Err(error),
        }
    }
}

use super::*;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
const EXCEPTION_CONTINUE_SEARCH: u32 = 1;
const X86_EXCEPTION_CHAIN_END: u64 = u32::MAX as u64;
const X86_EXCEPTION_RECORD_SIZE: usize = 0x50;
const X86_CONTEXT_SIZE: usize = 0x2CC;
const X86_CONTEXT_FULL: u32 = 0x0001_0007;
const X86_CONTEXT_SEG_GS_OFFSET: u64 = 0x8C;
const X86_CONTEXT_SEG_FS_OFFSET: u64 = 0x90;
const X86_CONTEXT_SEG_ES_OFFSET: u64 = 0x94;
const X86_CONTEXT_SEG_DS_OFFSET: u64 = 0x98;
const X86_CONTEXT_SEG_CS_OFFSET: u64 = 0xBC;
const X86_CONTEXT_SEG_SS_OFFSET: u64 = 0xC8;
const X86_EXCEPTION_DISPATCH_STACK: u64 = 0x400;
const X64_EXCEPTION_RECORD_SIZE: usize = 0x98;
const X64_CONTEXT_SIZE: usize = 0x200;
const X64_CONTEXT_FLAGS_OFFSET: u64 = 0x30;
const X64_CONTEXT_FULL: u32 = 0x0010_000B;
const X64_DISPATCHER_CONTEXT_SIZE: usize = 0x50;
const X64_EXCEPTION_POINTERS_SIZE: usize = 0x10;
const X64_EXCEPTION_DISPATCH_STACK: u64 = 0x2000;
const X64_UNW_FLAG_EHANDLER: u8 = 0x1;
const X64_UNW_FLAG_UHANDLER: u8 = 0x2;
const X64_UNW_FLAG_CHAININFO: u8 = 0x4;
const X64_UWOP_PUSH_NONVOL: u8 = 0;
const X64_UWOP_ALLOC_LARGE: u8 = 1;
const X64_UWOP_ALLOC_SMALL: u8 = 2;
const X64_UWOP_SET_FPREG: u8 = 3;
const X64_UWOP_SAVE_NONVOL: u8 = 4;
const X64_UWOP_SAVE_NONVOL_FAR: u8 = 5;
const X64_UWOP_SAVE_XMM128: u8 = 8;
const X64_UWOP_SAVE_XMM128_FAR: u8 = 9;
const X64_UWOP_PUSH_MACHFRAME: u8 = 10;
const STARTUP_CONTEXT_RECORD_SIZE_X86: u64 = 0x200;
const STARTUP_CONTEXT_RECORD_SIZE_X64: u64 = 0x200;
const STARTUP_NTCONTINUE_RESUME_COUNT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X64RuntimeFunction {
    entry_address: u64,
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum X64UnwindOperation {
    PushNonVol { register: u8 },
    AllocLarge { size: u32 },
    AllocSmall { size: u32 },
    SetFpReg,
    SaveNonVol { register: u8, offset: u32 },
    SaveNonVolFar { register: u8, offset: u32 },
    SaveXmm128 { register: u8, offset: u32 },
    SaveXmm128Far { register: u8, offset: u32 },
    PushMachFrame { with_error_code: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64UnwindCode {
    code_offset: u8,
    operation: X64UnwindOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64UnwindInfo {
    flags: u8,
    prolog_size: u8,
    frame_register: u8,
    frame_offset: u8,
    unwind_info_address: u64,
    handler_address: Option<u64>,
    handler_data_address: Option<u64>,
    operations: Vec<X64UnwindCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) struct X64RuntimeFunctionLookup {
    pub(in crate::runtime::engine) image_base: u64,
    pub(in crate::runtime::engine) function_entry_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct X64VirtualUnwindResult {
    image_base: u64,
    function_entry_address: u64,
    unwind_info_address: u64,
    establisher_frame: u64,
    handler_address: Option<u64>,
    handler_data_address: Option<u64>,
    flags: u8,
    leaf: bool,
    caller_context: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct X64ScopeRecord {
    begin_rva: u32,
    end_rva: u32,
    handler_rva: u32,
    jump_target: u32,
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .unwrap_or(value)
}

fn x64_register_name(register: u8) -> Option<&'static str> {
    match register {
        0 => Some("rax"),
        1 => Some("rcx"),
        2 => Some("rdx"),
        3 => Some("rbx"),
        4 => Some("rsp"),
        5 => Some("rbp"),
        6 => Some("rsi"),
        7 => Some("rdi"),
        8 => Some("r8"),
        9 => Some("r9"),
        10 => Some("r10"),
        11 => Some("r11"),
        12 => Some("r12"),
        13 => Some("r13"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn emit_startup_resume_chain(&mut self) -> Result<(), VmError> {
        let Some(definition) = self.hooks.definition("ntdll.dll", "NtContinue").cloned() else {
            return Ok(());
        };
        let stub_address = if let Some(stub) = self.hooks.binding_address("ntdll.dll", "NtContinue")
        {
            stub
        } else if let Some(module_base) = self
            .modules
            .get_loaded("ntdll.dll")
            .map(|module| module.base)
        {
            let resolved = self.modules.resolve_export(
                module_base,
                &self.config,
                &mut self.hooks,
                Some("NtContinue"),
                None,
            );
            if resolved != 0 {
                resolved
            } else {
                self.bind_hook_for_test("ntdll.dll", "NtContinue")
            }
        } else {
            self.bind_hook_for_test("ntdll.dll", "NtContinue")
        };
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(());
        };
        let stack_pointer = thread
            .registers
            .get(if self.arch.is_x86() { "esp" } else { "rsp" })
            .copied()
            .unwrap_or(thread.stack_top);
        let context_size = if self.arch.is_x86() {
            STARTUP_CONTEXT_RECORD_SIZE_X86
        } else {
            STARTUP_CONTEXT_RECORD_SIZE_X64
        };
        let Some(context_address) = stack_pointer
            .checked_sub(context_size + 0x80)
            .filter(|address| *address >= thread.stack_limit.saturating_add(0x40))
        else {
            return Ok(());
        };
        self.modules
            .memory_mut()
            .write(context_address, &vec![0u8; context_size as usize])?;

        for stage in 0..STARTUP_NTCONTINUE_RESUME_COUNT {
            let _ = self.capture_current_context(context_address)?;
            let _ = self.dispatch_bound_stub_with_definition(
                &definition,
                stub_address,
                None,
                &[context_address, 0],
            )?;
            self.commit_startup_context_restore(stage as u64 + 1)?;
        }
        Ok(())
    }

    fn commit_startup_context_restore(&mut self, stage: u64) -> Result<(), VmError> {
        let Some(restore) = self.pending_context_restore.take() else {
            self.defer_api_return = false;
            return Ok(());
        };
        self.defer_api_return = false;
        let pc = if self.arch.is_x86() {
            restore.registers.get("eip").copied().unwrap_or(0)
        } else {
            restore.registers.get("rip").copied().unwrap_or(0)
        };
        let mut fields = Map::new();
        fields.insert("stage".to_string(), json!(stage));
        fields.insert("context_record".to_string(), json!(restore.context_address));
        fields.insert("pc".to_string(), json!(pc));
        self.add_address_ref_fields(&mut fields, "pc", pc);
        self.log_runtime_event("STARTUP_RESUME", fields)
    }

    pub(in crate::runtime::engine) fn rtl_unwind_x86(
        &mut self,
        target_frame: u64,
        target_ip: u64,
        return_value: u64,
        stack_arg_count: usize,
    ) -> Result<u64, VmError> {
        if !self.arch.is_x86() {
            return Ok(0);
        }

        let mut registers = if unicorn_context_active() {
            let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
            let api = unsafe { &*api_ptr };
            self.capture_unicorn_thread_registers(api, uc)?
        } else {
            self.current_thread_snapshot()
                .map(|thread| thread.registers)
                .unwrap_or_default()
        };

        let current_esp = registers.get("esp").copied().unwrap_or(0);
        if current_esp == 0 {
            return Ok(0);
        }

        let resume_ip = if target_ip != 0 {
            target_ip
        } else {
            self.read_u32(current_esp)? as u64
        };
        let resume_esp =
            current_esp.saturating_add(4 + u64::try_from(stack_arg_count).unwrap_or(0) * 4);

        registers.insert("eax".to_string(), return_value);
        registers.insert("eip".to_string(), resume_ip);
        registers.insert("esp".to_string(), resume_esp);

        let stack_limit = self
            .current_thread_snapshot()
            .map(|thread| thread.stack_limit)
            .unwrap_or(0);
        let Some(context_address) = current_esp
            .checked_sub(X86_CONTEXT_SIZE as u64 + 0x40)
            .filter(|address| *address >= stack_limit.saturating_add(0x20))
        else {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!("x86 RtlUnwind scratch frame underflow at esp=0x{current_esp:X}"),
            });
        };
        self.modules
            .memory_mut()
            .write(context_address, &vec![0u8; X86_CONTEXT_SIZE])?;

        if unicorn_context_active() {
            let (api_ptr, uc) = self.active_unicorn_api_and_handle()?;
            let api = unsafe { &*api_ptr };
            self.write_x86_context_record(api, uc, context_address, &registers)?;
        } else {
            self.write_u32(context_address, X86_CONTEXT_FULL)?;
            serialize_register_context(
                self.modules.memory_mut(),
                self.arch,
                context_address,
                &registers,
            )?;
        }

        if target_frame != 0 {
            let exception_list_ptr = self.process_env.current_teb()
                + self.process_env.offsets().teb_exception_list as u64;
            let mut registration = self.read_pointer_value(exception_list_ptr)?;
            let mut next_after_target = None;
            while registration != 0 && registration != X86_EXCEPTION_CHAIN_END {
                let next = self.read_pointer_value(registration)?;
                if registration == target_frame {
                    next_after_target = Some(next);
                    break;
                }
                registration = next;
            }
            if let Some(next) = next_after_target {
                // x86 RtlUnwind 进入目标 __except/__finally 之后，目标注册帧及其之上的帧
                // 已经从异常链中退出，否则同一帧会重复吃到后续 fault，形成死循环。
                self.write_pointer_value(exception_list_ptr, next)?;
            }
        }
        self.pending_x86_seh_unwind = Some(PendingX86SehUnwind {
            context_address,
            registers,
        });
        self.force_native_return = true;
        Ok(0)
    }

    pub(in crate::runtime::engine) fn handle_pending_unicorn_fault(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let original_registers = self.capture_unicorn_thread_registers(api, uc)?;
        let handled = if self.arch.is_x86() {
            self.dispatch_x86_seh_fault_with_unicorn(api, uc, fault)?
        } else if self.arch.is_x64() {
            self.dispatch_x64_seh_fault_with_unicorn(api, uc, fault)?
        } else {
            false
        };
        if handled {
            return Ok(true);
        }
        let handled = if self.arch.is_x86() {
            self.dispatch_x86_top_level_exception_filter_with_unicorn(api, uc, fault)
        } else if self.arch.is_x64() {
            self.dispatch_x64_top_level_exception_filter_with_unicorn(api, uc, fault)
        } else {
            Ok(false)
        }?;
        if handled {
            return Ok(true);
        }
        self.restore_unicorn_thread_registers(api, uc, &original_registers)?;
        Ok(false)
    }

    fn dispatch_x86_top_level_exception_filter_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let filter = self.top_level_exception_filter;
        if filter == 0 {
            return Ok(false);
        }

        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_esp = registers.get("esp").copied().unwrap_or(0);
        let fault_eflags = registers.get("eflags").copied().unwrap_or(0x202) as u32;
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let dispatcher_esp = match fault_esp.checked_sub(X86_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x20) => value,
            _ => return Ok(false),
        };
        let exception_record = dispatcher_esp + 0x40;
        let context_record =
            (exception_record + X86_EXCEPTION_RECORD_SIZE as u64 + 0x0F) & !0x0Fu64;
        let exception_pointers =
            align_up_u64(context_record + X86_CONTEXT_SIZE as u64 + 0x10, 0x10);
        let scratch_start = dispatcher_esp.saturating_sub(0x20);
        let scratch_end = exception_pointers + self.arch.pointer_size as u64 * 2;
        let scratch_size =
            usize::try_from(scratch_end.saturating_sub(scratch_start)).map_err(|_| {
                VmError::RuntimeInvariant("x86 top-level filter scratch frame too large")
            })?;
        self.modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x86_exception_record(exception_record, fault)?;
        self.write_x86_context_record(api, uc, context_record, &registers)?;
        self.write_pointer_value(exception_pointers, exception_record)?;
        self.write_pointer_value(
            exception_pointers + self.arch.pointer_size as u64,
            context_record,
        )?;

        let filter_result = self.call_x86_native_with_unicorn_context(
            filter,
            &[exception_pointers],
            fault_esp,
            fault_eflags,
            NativeCallRunMode::Standalone,
        )? as i32;
        if filter_result != EXCEPTION_CONTINUE_EXECUTION_FILTER {
            return Ok(false);
        }

        let restored =
            deserialize_register_context(self.modules.memory(), self.arch, context_record)?;
        self.log_seh_resume(context_record, &restored)?;
        self.restore_unicorn_thread_registers(api, uc, &restored)?;
        self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
        Ok(true)
    }

    fn dispatch_x64_top_level_exception_filter_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let filter = self.top_level_exception_filter;
        if filter == 0 {
            return Ok(false);
        }

        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_rsp = registers.get("rsp").copied().unwrap_or(0);
        let fault_rflags = registers.get("rflags").copied().unwrap_or(0x202);
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let scratch_end = fault_rsp & !0x0Fu64;
        let scratch_start = match scratch_end.checked_sub(X64_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x40) => value,
            _ => return Ok(false),
        };
        let exception_record = align_up_u64(scratch_start + 0x40, 0x10);
        let context_record = align_up_u64(
            exception_record + X64_EXCEPTION_RECORD_SIZE as u64 + 0x20,
            0x10,
        );
        let exception_pointers =
            align_up_u64(context_record + X64_CONTEXT_SIZE as u64 + 0x20, 0x10);
        let scratch_size = usize::try_from(
            exception_pointers
                .saturating_add(X64_EXCEPTION_POINTERS_SIZE as u64)
                .saturating_sub(scratch_start),
        )
        .map_err(|_| VmError::RuntimeInvariant("x64 top-level filter scratch frame too large"))?;
        self.modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x64_exception_record(exception_record, fault)?;
        self.write_x64_context_record(context_record, &registers)?;
        self.write_pointer_value(exception_pointers + 0x00, exception_record)?;
        self.write_pointer_value(exception_pointers + 0x08, context_record)?;

        let filter_result = self.call_x64_native_with_unicorn_context(
            filter,
            &[exception_pointers],
            scratch_end,
            fault_rflags,
            NativeCallRunMode::Standalone,
        )? as i32;
        if filter_result != EXCEPTION_CONTINUE_EXECUTION_FILTER {
            return Ok(false);
        }

        let restored =
            deserialize_register_context(self.modules.memory(), self.arch, context_record)?;
        self.log_seh_resume(context_record, &restored)?;
        self.restore_unicorn_thread_registers(api, uc, &restored)?;
        Ok(true)
    }

    fn dispatch_x86_seh_fault_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let exception_list_ptr =
            self.process_env.current_teb() + self.process_env.offsets().teb_exception_list as u64;
        let mut registration = self.read_pointer_value(exception_list_ptr)?;
        self.log_seh_dispatch(fault, registration)?;
        if registration == 0 || registration == X86_EXCEPTION_CHAIN_END {
            return Ok(false);
        }

        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_esp = registers.get("esp").copied().unwrap_or(0);
        let fault_eflags = registers.get("eflags").copied().unwrap_or(0x202) as u32;
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let dispatcher_esp = match fault_esp.checked_sub(X86_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x20) => value,
            _ => return Ok(false),
        };
        let exception_record = dispatcher_esp + 0x40;
        let context_record =
            (exception_record + X86_EXCEPTION_RECORD_SIZE as u64 + 0x0F) & !0x0Fu64;
        let scratch_start = dispatcher_esp.saturating_sub(0x20);
        let scratch_end = context_record + X86_CONTEXT_SIZE as u64;
        let scratch_size = usize::try_from(scratch_end.saturating_sub(scratch_start))
            .map_err(|_| VmError::RuntimeInvariant("x86 SEH scratch frame too large"))?;
        self.modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x86_exception_record(exception_record, fault)?;
        self.write_x86_context_record(api, uc, context_record, &registers)?;
        let fault_context = self
            .modules
            .memory()
            .read(context_record, X86_CONTEXT_SIZE)?;

        let mut visited = BTreeSet::new();
        loop {
            if registration == 0 || registration == X86_EXCEPTION_CHAIN_END {
                return Ok(false);
            }
            if !visited.insert(registration) {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: format!("x86 SEH registration cycle at 0x{registration:X}"),
                });
            }
            if !self.modules.memory().is_range_mapped(registration, 8) {
                return Ok(false);
            }

            let next = self.read_pointer_value(registration)?;
            let handler = self.read_pointer_value(registration + 4)?;
            if handler == 0 {
                registration = next;
                continue;
            }

            let disposition = self.call_x86_native_with_unicorn_context(
                handler,
                &[exception_record, registration, context_record, 0],
                fault_esp,
                fault_eflags,
                NativeCallRunMode::Standalone,
            )? as u32;
            self.log_seh_handler(registration, handler, disposition)?;
            if let Some(unwind) = self.pending_x86_seh_unwind.take() {
                let Some(tid) = self.scheduler.current_tid().or(self.main_thread_tid) else {
                    return Err(VmError::RuntimeInvariant(
                        "x86 SEH unwind restore missing current thread",
                    ));
                };
                self.scheduler
                    .set_thread_registers(tid, unwind.registers.clone())
                    .ok_or(VmError::RuntimeInvariant(
                        "failed to stage x86 SEH unwind registers",
                    ))?;
                self.log_seh_resume(unwind.context_address, &unwind.registers)?;
                self.restore_unicorn_thread_registers(api, uc, &unwind.registers)?;
                self.restore_unicorn_x86_segments_from_context(api, uc, unwind.context_address)?;
                return Ok(true);
            }
            match disposition {
                EXCEPTION_CONTINUE_EXECUTION => {
                    let restored = deserialize_register_context(
                        self.modules.memory(),
                        self.arch,
                        context_record,
                    )?;
                    self.log_seh_resume(context_record, &restored)?;
                    self.restore_unicorn_thread_registers(api, uc, &restored)?;
                    self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
                    return Ok(true);
                }
                EXCEPTION_CONTINUE_SEARCH => {
                    self.modules
                        .memory_mut()
                        .write(context_record, &fault_context)?;
                    self.restore_unicorn_thread_registers(api, uc, &registers)?;
                    self.restore_unicorn_x86_segments_from_context(api, uc, context_record)?;
                    registration = next;
                }
                _ => {
                    return Err(VmError::NativeExecution {
                        op: "seh",
                        detail: format!(
                            "unsupported x86 SEH disposition {disposition} from handler 0x{handler:X}"
                        ),
                    });
                }
            }
        }
    }

    fn dispatch_x64_seh_fault_with_unicorn(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        fault: UnicornFault,
    ) -> Result<bool, VmError> {
        let registers = self.capture_unicorn_thread_registers(api, uc)?;
        let fault_rsp = registers.get("rsp").copied().unwrap_or(0);
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        let scratch_end = fault_rsp & !0x0Fu64;
        let scratch_start = match scratch_end.checked_sub(X64_EXCEPTION_DISPATCH_STACK) {
            Some(value) if value >= thread.stack_limit.saturating_add(0x40) => value,
            _ => return Ok(false),
        };
        let exception_record = align_up_u64(scratch_start + 0x40, 0x10);
        let context_record = align_up_u64(
            exception_record + X64_EXCEPTION_RECORD_SIZE as u64 + 0x20,
            0x10,
        );
        let dispatcher_context =
            align_up_u64(context_record + X64_CONTEXT_SIZE as u64 + 0x20, 0x10);
        let scratch_size = usize::try_from(
            dispatcher_context
                .saturating_add(X64_DISPATCHER_CONTEXT_SIZE as u64)
                .saturating_sub(scratch_start),
        )
        .map_err(|_| VmError::RuntimeInvariant("x64 SEH scratch frame too large"))?;
        self.modules
            .memory_mut()
            .write(scratch_start, &vec![0u8; scratch_size])?;

        self.write_x64_exception_record(exception_record, fault)?;
        self.write_x64_context_record(context_record, &registers)?;
        self.log_x64_seh_dispatch(fault, exception_record, context_record)?;
        let exception_code = self.read_u32(exception_record)?;

        let mut working = registers;
        let mut visited = BTreeSet::new();
        for _ in 0..64usize {
            let control_pc = working.get("rip").copied().unwrap_or(0);
            let current_rsp = working.get("rsp").copied().unwrap_or(0);
            if control_pc == 0 || current_rsp == 0 {
                return Ok(false);
            }
            if control_pc == self.native_return_sentinel {
                let mut terminated = working.clone();
                terminated.insert("rip".to_string(), self.native_return_sentinel);
                terminated.insert("rax".to_string(), u64::from(exception_code));
                self.log_x64_seh_unhandled(exception_code, control_pc, current_rsp)?;
                self.restore_unicorn_thread_registers(api, uc, &terminated)?;
                return Ok(true);
            }
            if !visited.insert((control_pc, current_rsp)) {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: format!(
                        "x64 SEH unwind cycle at pc=0x{control_pc:X} rsp=0x{current_rsp:X}"
                    ),
                });
            }

            let Some(unwind) =
                self.x64_virtual_unwind_context(control_pc, &working, X64_UNW_FLAG_EHANDLER)?
            else {
                return Ok(false);
            };
            self.write_x64_dispatcher_context(
                dispatcher_context,
                control_pc,
                unwind.image_base,
                unwind.function_entry_address,
                unwind.establisher_frame,
                context_record,
                unwind.handler_address.unwrap_or(0),
                unwind.handler_data_address.unwrap_or(0),
            )?;
            self.log_x64_seh_frame(
                control_pc,
                unwind.function_entry_address,
                unwind.unwind_info_address,
                unwind.establisher_frame,
                unwind.handler_address,
                unwind.handler_data_address,
                unwind.flags,
                unwind.leaf,
                unwind.caller_context.get("rip").copied().unwrap_or(0),
                unwind.caller_context.get("rsp").copied().unwrap_or(0),
            )?;

            if let Some(handler) = unwind.handler_address {
                let handler_rflags = working.get("rflags").copied().unwrap_or(0x202);
                let disposition = if let Some(disposition) = self.dispatch_x64_bound_handler(
                    handler,
                    exception_record,
                    unwind.establisher_frame,
                    context_record,
                    dispatcher_context,
                    &working,
                    scratch_end,
                    handler_rflags,
                )? {
                    disposition
                } else {
                    self.restore_unicorn_thread_registers(api, uc, &working)?;
                    self.call_x64_native_with_unicorn_context(
                        handler,
                        &[
                            exception_record,
                            unwind.establisher_frame,
                            context_record,
                            dispatcher_context,
                        ],
                        scratch_end,
                        handler_rflags,
                        NativeCallRunMode::Standalone,
                    )? as u32
                };
                self.log_seh_handler(unwind.function_entry_address, handler, disposition)?;
                match disposition {
                    EXCEPTION_CONTINUE_EXECUTION => {
                        let restored = deserialize_register_context(
                            self.modules.memory(),
                            self.arch,
                            context_record,
                        )?;
                        self.log_seh_resume(context_record, &restored)?;
                        self.restore_unicorn_thread_registers(api, uc, &restored)?;
                        return Ok(true);
                    }
                    EXCEPTION_CONTINUE_SEARCH => {
                        working = unwind.caller_context;
                        continue;
                    }
                    _ => {
                        return Err(VmError::NativeExecution {
                            op: "seh",
                            detail: format!(
                                "unsupported x64 SEH disposition {disposition} from handler 0x{handler:X}"
                            ),
                        });
                    }
                }
            }

            working = unwind.caller_context;
        }

        Err(VmError::NativeExecution {
            op: "seh",
            detail: "x64 SEH unwind exceeded 64 frames".to_string(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_x64_bound_handler(
        &mut self,
        handler: u64,
        exception_record: u64,
        establisher_frame: u64,
        context_record: u64,
        dispatcher_context: u64,
        frame_context: &BTreeMap<String, u64>,
        handler_stack_top: u64,
        handler_rflags: u64,
    ) -> Result<Option<u32>, VmError> {
        let Some(bound) = self.resolve_bound_exception_handler(handler)? else {
            return Ok(None);
        };
        if bound.0 == "msvcrt.dll" && bound.1 == "__c_specific_handler" {
            return self
                .dispatch_x64_c_specific_handler(
                    exception_record,
                    establisher_frame,
                    context_record,
                    dispatcher_context,
                    frame_context,
                    handler_stack_top,
                    handler_rflags,
                )
                .map(Some);
        }
        if bound.0 == "msvcrt.dll" && bound.1 == "__cxxframehandler3" {
            return Ok(Some(EXCEPTION_CONTINUE_SEARCH));
        }
        Ok(None)
    }

    fn resolve_bound_exception_handler(
        &self,
        address: u64,
    ) -> Result<Option<(String, String)>, VmError> {
        if let Some(bound) = self.hooks.bound_lookup(address) {
            return Ok(Some((bound.module.to_string(), bound.function.to_string())));
        }
        let Ok(bytes) = self.read_bytes_from_memory(address, 6) else {
            return Ok(None);
        };
        if bytes.len() != 6 || bytes[0] != 0xFF || bytes[1] != 0x25 {
            return Ok(None);
        }
        let displacement = i32::from_le_bytes(bytes[2..6].try_into().unwrap()) as i64;
        let slot = address
            .checked_add(6)
            .and_then(|next| next.checked_add_signed(displacement))
            .ok_or(VmError::NativeExecution {
                op: "seh",
                detail: format!("x64 import thunk overflow while resolving 0x{address:X}"),
            })?;
        let target = self.read_pointer_value(slot)?;
        Ok(self
            .hooks
            .bound_lookup(target)
            .map(|bound| (bound.module.to_string(), bound.function.to_string())))
    }

    fn dispatch_x64_c_specific_handler(
        &mut self,
        exception_record: u64,
        establisher_frame: u64,
        context_record: u64,
        dispatcher_context: u64,
        frame_context: &BTreeMap<String, u64>,
        handler_stack_top: u64,
        handler_rflags: u64,
    ) -> Result<u32, VmError> {
        let exception_flags = self.read_u32(exception_record + 0x04)?;
        // Unwind / termination handling is still conservative. Search-phase filters are what the
        // current samples rely on.
        if exception_flags != 0 {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }
        let image_base = self.read_pointer_value(dispatcher_context + 0x08)?;
        let control_pc = self.read_pointer_value(dispatcher_context + 0x00)?;
        let handler_data = self.read_pointer_value(dispatcher_context + 0x38)?;
        if image_base == 0 || handler_data == 0 || control_pc < image_base {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }
        let control_rva = u32::try_from(control_pc.saturating_sub(image_base)).map_err(|_| {
            VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "x64 __C_specific_handler control pc 0x{control_pc:X} out of range"
                ),
            }
        })?;
        let scope_records = self.read_x64_scope_records(handler_data)?;
        if scope_records.is_empty() {
            return Ok(EXCEPTION_CONTINUE_SEARCH);
        }

        let exception_pointers = align_up_u64(
            dispatcher_context + X64_DISPATCHER_CONTEXT_SIZE as u64 + 0x10,
            0x10,
        );
        self.modules
            .memory_mut()
            .write(exception_pointers, &vec![0u8; X64_EXCEPTION_POINTERS_SIZE])?;
        self.write_pointer_value(exception_pointers + 0x00, exception_record)?;
        self.write_pointer_value(exception_pointers + 0x08, context_record)?;

        for record in scope_records {
            if control_rva < record.begin_rva || control_rva >= record.end_rva {
                continue;
            }
            if record.jump_target == 0 {
                continue;
            }
            let filter = image_base + record.handler_rva as u64;
            let filter_result = self.call_x64_native_with_unicorn_context(
                filter,
                &[exception_pointers, establisher_frame],
                handler_stack_top,
                handler_rflags,
                NativeCallRunMode::Standalone,
            )? as u32;
            let filter_result_signed = filter_result as i32;
            if filter_result_signed < 0 {
                return Ok(EXCEPTION_CONTINUE_EXECUTION);
            }
            if filter_result_signed == 0 {
                continue;
            }

            let mut resume_context = frame_context.clone();
            resume_context.insert("rip".to_string(), image_base + record.jump_target as u64);
            resume_context.insert("rsp".to_string(), establisher_frame);
            self.write_x64_context_record(context_record, &resume_context)?;
            return Ok(EXCEPTION_CONTINUE_EXECUTION);
        }

        Ok(EXCEPTION_CONTINUE_SEARCH)
    }

    fn read_x64_scope_records(&self, handler_data: u64) -> Result<Vec<X64ScopeRecord>, VmError> {
        let count = self.read_u32(handler_data)? as usize;
        if count == 0 || count > 64 {
            return Ok(Vec::new());
        }
        let mut records = Vec::with_capacity(count);
        let mut cursor = handler_data + 4;
        for _ in 0..count {
            records.push(X64ScopeRecord {
                begin_rva: self.read_u32(cursor)?,
                end_rva: self.read_u32(cursor + 4)?,
                handler_rva: self.read_u32(cursor + 8)?,
                jump_target: self.read_u32(cursor + 12)?,
            });
            cursor += 16;
        }
        Ok(records)
    }

    pub(in crate::runtime::engine) fn lookup_x64_runtime_function_entry(
        &self,
        control_pc: u64,
    ) -> Result<Option<X64RuntimeFunctionLookup>, VmError> {
        let Some(module) = self.modules.get_by_address(control_pc) else {
            return Ok(None);
        };
        let Some(function) = self.lookup_x64_runtime_function_in_module(module, control_pc)? else {
            return Ok(None);
        };
        Ok(Some(X64RuntimeFunctionLookup {
            image_base: module.base,
            function_entry_address: function.entry_address,
        }))
    }

    pub(in crate::runtime::engine) fn rtl_virtual_unwind(
        &mut self,
        handler_type: u64,
        image_base: u64,
        control_pc: u64,
        function_entry: u64,
        context_record: u64,
        handler_data_out: u64,
        establisher_frame_out: u64,
    ) -> Result<u64, VmError> {
        if !self.arch.is_x64() || context_record == 0 {
            if handler_data_out != 0 {
                self.write_pointer_value(handler_data_out, 0)?;
            }
            if establisher_frame_out != 0 {
                self.write_pointer_value(establisher_frame_out, 0)?;
            }
            return Ok(0);
        }

        let registers =
            deserialize_register_context(self.modules.memory(), self.arch, context_record)?;
        let control_pc = if control_pc != 0 {
            control_pc
        } else {
            registers.get("rip").copied().unwrap_or(0)
        };
        let unwind = self.x64_virtual_unwind_context_with_module_hint(
            control_pc,
            image_base,
            function_entry,
            &registers,
            handler_type as u8,
        )?;
        let Some(unwind) = unwind else {
            if handler_data_out != 0 {
                self.write_pointer_value(handler_data_out, 0)?;
            }
            if establisher_frame_out != 0 {
                self.write_pointer_value(establisher_frame_out, 0)?;
            }
            return Ok(0);
        };

        self.write_x64_context_record(context_record, &unwind.caller_context)?;
        if handler_data_out != 0 {
            self.write_pointer_value(handler_data_out, unwind.handler_data_address.unwrap_or(0))?;
        }
        if establisher_frame_out != 0 {
            self.write_pointer_value(establisher_frame_out, unwind.establisher_frame)?;
        }
        Ok(unwind.handler_address.unwrap_or(0))
    }

    fn lookup_x64_runtime_function_in_module(
        &self,
        module: &ModuleRecord,
        control_pc: u64,
    ) -> Result<Option<X64RuntimeFunction>, VmError> {
        let Some((table_base, table_size)) = self.x64_exception_directory(module)? else {
            return Ok(None);
        };
        if control_pc < module.base || control_pc >= module.base.saturating_add(module.size) {
            return Ok(None);
        }
        let control_rva = u32::try_from(control_pc.saturating_sub(module.base)).map_err(|_| {
            VmError::NativeExecution {
                op: "seh",
                detail: format!("control pc 0x{control_pc:X} is outside x64 RVA space"),
            }
        })?;
        let entry_count = usize::try_from(table_size / 12).unwrap_or(0);
        let mut low = 0usize;
        let mut high = entry_count;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry_address = table_base + mid as u64 * 12;
            let begin_rva = self.read_u32(entry_address)?;
            let end_rva = self.read_u32(entry_address + 4)?;
            if control_rva < begin_rva {
                high = mid;
            } else if control_rva >= end_rva {
                low = mid + 1;
            } else {
                let unwind_rva = self.read_u32(entry_address + 8)?;
                return Ok(Some(X64RuntimeFunction {
                    entry_address,
                    begin_rva,
                    end_rva,
                    unwind_rva,
                }));
            }
        }
        Ok(None)
    }

    fn x64_exception_directory(
        &self,
        module: &ModuleRecord,
    ) -> Result<Option<(u64, u32)>, VmError> {
        if module.synthetic || module.base == 0 {
            return Ok(None);
        }
        let e_lfanew = self.read_u32(module.base + 0x3C)? as u64;
        let optional_header = module.base + e_lfanew + 4 + 20;
        let magic = self.read_u16(optional_header)?;
        if magic != 0x20B {
            return Ok(None);
        }
        let number_of_rva_and_sizes = self.read_u32(optional_header + 0x6C)?;
        if number_of_rva_and_sizes <= 3 {
            return Ok(None);
        }
        let directory = optional_header + 0x70 + 3 * 8;
        let rva = self.read_u32(directory)?;
        let size = self.read_u32(directory + 4)?;
        if rva == 0 || size < 12 {
            return Ok(None);
        }
        Ok(Some((module.base + rva as u64, size)))
    }

    fn x64_virtual_unwind_context(
        &self,
        control_pc: u64,
        registers: &BTreeMap<String, u64>,
        handler_mask: u8,
    ) -> Result<Option<X64VirtualUnwindResult>, VmError> {
        self.x64_virtual_unwind_context_with_module_hint(control_pc, 0, 0, registers, handler_mask)
    }

    fn x64_virtual_unwind_context_with_module_hint(
        &self,
        control_pc: u64,
        image_base_hint: u64,
        function_entry_hint: u64,
        registers: &BTreeMap<String, u64>,
        handler_mask: u8,
    ) -> Result<Option<X64VirtualUnwindResult>, VmError> {
        let hinted_module = if image_base_hint != 0 {
            self.modules.get_by_base(image_base_hint)
        } else {
            None
        };
        let module = hinted_module.or_else(|| self.modules.get_by_address(control_pc));
        if let Some(module) = module {
            let function = if function_entry_hint != 0 {
                Some(self.read_x64_runtime_function(function_entry_hint)?)
            } else {
                self.lookup_x64_runtime_function_in_module(module, control_pc)?
            };
            if let Some(function) = function {
                let unwind = self.parse_x64_unwind_info(module, &function, 0)?;
                let control_offset =
                    control_pc.saturating_sub(module.base + function.begin_rva as u64) as u32;
                let in_prolog = u64::from(control_offset) < u64::from(unwind.prolog_size);
                let establisher_frame =
                    self.x64_establisher_frame(registers, &unwind, in_prolog, control_offset);
                let mut caller_context = registers.clone();
                let mut rsp = registers.get("rsp").copied().unwrap_or(0);
                for code in &unwind.operations {
                    if in_prolog && u64::from(code.code_offset) > u64::from(control_offset) {
                        continue;
                    }
                    self.apply_x64_unwind_code(
                        &mut caller_context,
                        &mut rsp,
                        establisher_frame,
                        code,
                    )?;
                }
                let return_address = self.read_pointer_value(rsp)?;
                caller_context.insert("rsp".to_string(), rsp.saturating_add(8));
                caller_context.insert("rip".to_string(), return_address);
                return Ok(Some(X64VirtualUnwindResult {
                    image_base: module.base,
                    function_entry_address: function.entry_address,
                    unwind_info_address: unwind.unwind_info_address,
                    establisher_frame,
                    handler_address: if unwind.flags & handler_mask != 0 {
                        unwind.handler_address
                    } else {
                        None
                    },
                    handler_data_address: if unwind.flags & handler_mask != 0 {
                        unwind.handler_data_address
                    } else {
                        None
                    },
                    flags: unwind.flags,
                    leaf: false,
                    caller_context,
                }));
            }
        }

        let rsp = registers.get("rsp").copied().unwrap_or(0);
        if rsp == 0 || !self.modules.memory().is_range_mapped(rsp, 8) {
            return Ok(None);
        }
        let mut caller_context = registers.clone();
        let return_address = self.read_pointer_value(rsp)?;
        caller_context.insert("rsp".to_string(), rsp.saturating_add(8));
        caller_context.insert("rip".to_string(), return_address);
        Ok(Some(X64VirtualUnwindResult {
            image_base: module.map(|record| record.base).unwrap_or(0),
            function_entry_address: 0,
            unwind_info_address: 0,
            establisher_frame: rsp,
            handler_address: None,
            handler_data_address: None,
            flags: 0,
            leaf: true,
            caller_context,
        }))
    }

    fn read_x64_runtime_function(&self, address: u64) -> Result<X64RuntimeFunction, VmError> {
        Ok(X64RuntimeFunction {
            entry_address: address,
            begin_rva: self.read_u32(address)?,
            end_rva: self.read_u32(address + 4)?,
            unwind_rva: self.read_u32(address + 8)?,
        })
    }

    fn parse_x64_unwind_info(
        &self,
        module: &ModuleRecord,
        function: &X64RuntimeFunction,
        depth: usize,
    ) -> Result<X64UnwindInfo, VmError> {
        if depth > 4 {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "x64 chained UNWIND_INFO recursion exceeded limit for 0x{:X}",
                    function.entry_address
                ),
            });
        }

        let unwind_info_address = module.base + function.unwind_rva as u64;
        let version_and_flags = self.read_u8(unwind_info_address)?;
        let version = version_and_flags & 0x07;
        let flags = version_and_flags >> 3;
        if version != 1 {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!(
                    "unsupported x64 UNWIND_INFO version {version} at 0x{unwind_info_address:X}"
                ),
            });
        }
        let prolog_size = self.read_u8(unwind_info_address + 1)?;
        let count_of_codes = self.read_u8(unwind_info_address + 2)? as usize;
        let frame = self.read_u8(unwind_info_address + 3)?;
        let frame_register = frame & 0x0F;
        let frame_offset = frame >> 4;
        let mut cursor = unwind_info_address + 4;
        let mut slot = 0usize;
        let mut operations = Vec::new();
        while slot < count_of_codes {
            let code_offset = self.read_u8(cursor)?;
            let unwind = self.read_u8(cursor + 1)?;
            let op = unwind & 0x0F;
            let op_info = unwind >> 4;
            cursor += 2;
            slot += 1;
            let operation = match op {
                X64_UWOP_PUSH_NONVOL => X64UnwindOperation::PushNonVol { register: op_info },
                X64_UWOP_ALLOC_LARGE => {
                    let size = if op_info == 0 {
                        let scaled = self.read_u16(cursor)? as u32;
                        cursor += 2;
                        slot += 1;
                        scaled.saturating_mul(8)
                    } else if op_info == 1 {
                        let low = self.read_u16(cursor)? as u32;
                        let high = self.read_u16(cursor + 2)? as u32;
                        cursor += 4;
                        slot += 2;
                        low | (high << 16)
                    } else {
                        return Err(VmError::NativeExecution {
                            op: "seh",
                            detail: format!(
                                "unsupported x64 UWOP_ALLOC_LARGE info {op_info} at 0x{unwind_info_address:X}"
                            ),
                        });
                    };
                    X64UnwindOperation::AllocLarge { size }
                }
                X64_UWOP_ALLOC_SMALL => X64UnwindOperation::AllocSmall {
                    size: u32::from(op_info).saturating_mul(8).saturating_add(8),
                },
                X64_UWOP_SET_FPREG => X64UnwindOperation::SetFpReg,
                X64_UWOP_SAVE_NONVOL => {
                    let scaled = self.read_u16(cursor)? as u32;
                    cursor += 2;
                    slot += 1;
                    X64UnwindOperation::SaveNonVol {
                        register: op_info,
                        offset: scaled.saturating_mul(8),
                    }
                }
                X64_UWOP_SAVE_NONVOL_FAR => {
                    let low = self.read_u16(cursor)? as u32;
                    let high = self.read_u16(cursor + 2)? as u32;
                    cursor += 4;
                    slot += 2;
                    X64UnwindOperation::SaveNonVolFar {
                        register: op_info,
                        offset: low | (high << 16),
                    }
                }
                X64_UWOP_SAVE_XMM128 => {
                    let scaled = self.read_u16(cursor)? as u32;
                    cursor += 2;
                    slot += 1;
                    X64UnwindOperation::SaveXmm128 {
                        register: op_info,
                        offset: scaled.saturating_mul(16),
                    }
                }
                X64_UWOP_SAVE_XMM128_FAR => {
                    let low = self.read_u16(cursor)? as u32;
                    let high = self.read_u16(cursor + 2)? as u32;
                    cursor += 4;
                    slot += 2;
                    X64UnwindOperation::SaveXmm128Far {
                        register: op_info,
                        offset: low | (high << 16),
                    }
                }
                X64_UWOP_PUSH_MACHFRAME => X64UnwindOperation::PushMachFrame {
                    with_error_code: op_info != 0,
                },
                _ => {
                    return Err(VmError::NativeExecution {
                        op: "seh",
                        detail: format!(
                            "unsupported x64 unwind op {op} at 0x{unwind_info_address:X}"
                        ),
                    });
                }
            };
            operations.push(X64UnwindCode {
                code_offset,
                operation,
            });
        }

        let trailer = unwind_info_address + 4 + (count_of_codes.next_multiple_of(2) as u64 * 2);
        let mut handler_address = None;
        let mut handler_data_address = None;
        if flags & X64_UNW_FLAG_CHAININFO != 0 {
            let chained = self.read_x64_runtime_function(trailer)?;
            let chained_info = self.parse_x64_unwind_info(module, &chained, depth + 1)?;
            operations.extend(chained_info.operations);
            handler_address = chained_info.handler_address;
            handler_data_address = chained_info.handler_data_address;
        } else if flags & (X64_UNW_FLAG_EHANDLER | X64_UNW_FLAG_UHANDLER) != 0 {
            let handler_rva = self.read_u32(trailer)?;
            handler_address = Some(module.base + handler_rva as u64);
            handler_data_address = Some(trailer + 4);
        }

        Ok(X64UnwindInfo {
            flags,
            prolog_size,
            frame_register,
            frame_offset,
            unwind_info_address,
            handler_address,
            handler_data_address,
            operations,
        })
    }

    fn x64_establisher_frame(
        &self,
        registers: &BTreeMap<String, u64>,
        unwind: &X64UnwindInfo,
        in_prolog: bool,
        control_offset: u32,
    ) -> u64 {
        let current_rsp = registers.get("rsp").copied().unwrap_or(0);
        if unwind.frame_register == 0 {
            return current_rsp;
        }
        let frame_reg_active = !in_prolog
            || unwind.operations.iter().any(|code| {
                matches!(code.operation, X64UnwindOperation::SetFpReg)
                    && u64::from(code.code_offset) <= u64::from(control_offset)
            });
        if !frame_reg_active {
            return current_rsp;
        }
        let Some(name) = x64_register_name(unwind.frame_register) else {
            return current_rsp;
        };
        registers
            .get(name)
            .copied()
            .unwrap_or(current_rsp)
            .saturating_sub(u64::from(unwind.frame_offset) * 16)
    }

    fn apply_x64_unwind_code(
        &self,
        registers: &mut BTreeMap<String, u64>,
        rsp: &mut u64,
        establisher_frame: u64,
        code: &X64UnwindCode,
    ) -> Result<(), VmError> {
        match &code.operation {
            X64UnwindOperation::PushNonVol { register } => {
                let value = self.read_pointer_value(*rsp)?;
                self.write_x64_unwind_register(registers, *register, value)?;
                *rsp = rsp.saturating_add(8);
            }
            X64UnwindOperation::AllocLarge { size } | X64UnwindOperation::AllocSmall { size } => {
                *rsp = rsp.saturating_add(u64::from(*size));
            }
            X64UnwindOperation::SetFpReg => {
                *rsp = establisher_frame;
            }
            X64UnwindOperation::SaveNonVol { register, offset }
            | X64UnwindOperation::SaveNonVolFar { register, offset } => {
                let value = self.read_pointer_value(establisher_frame + u64::from(*offset))?;
                self.write_x64_unwind_register(registers, *register, value)?;
            }
            X64UnwindOperation::SaveXmm128 { .. } | X64UnwindOperation::SaveXmm128Far { .. } => {
                // Current fidelity work only needs caller RIP/RSP and preserved integer registers.
            }
            X64UnwindOperation::PushMachFrame { .. } => {
                return Err(VmError::NativeExecution {
                    op: "seh",
                    detail: "x64 UWOP_PUSH_MACHFRAME is not implemented".to_string(),
                });
            }
        }
        Ok(())
    }

    fn write_x64_unwind_register(
        &self,
        registers: &mut BTreeMap<String, u64>,
        register: u8,
        value: u64,
    ) -> Result<(), VmError> {
        let Some(name) = x64_register_name(register) else {
            return Err(VmError::NativeExecution {
                op: "seh",
                detail: format!("unsupported x64 register index {register} in unwind info"),
            });
        };
        registers.insert(name.to_string(), value);
        Ok(())
    }

    fn write_x86_exception_record(
        &mut self,
        address: u64,
        fault: UnicornFault,
    ) -> Result<(), VmError> {
        self.write_u32(address, STATUS_ACCESS_VIOLATION)?;
        self.write_u32(address + 0x04, 0)?;
        self.write_u32(address + 0x08, 0)?;
        self.write_u32(address + 0x0C, fault.pc as u32)?;
        self.write_u32(address + 0x10, 2)?;
        self.write_u32(
            address + 0x14,
            self.exception_access_code(fault.access) as u32,
        )?;
        self.write_u32(address + 0x18, fault.address as u32)?;
        Ok(())
    }

    fn write_x64_exception_record(
        &mut self,
        address: u64,
        fault: UnicornFault,
    ) -> Result<(), VmError> {
        self.write_u32(address, STATUS_ACCESS_VIOLATION)?;
        self.write_u32(address + 0x04, 0)?;
        self.write_pointer_value(address + 0x08, 0)?;
        self.write_pointer_value(address + 0x10, fault.pc)?;
        self.write_u32(address + 0x18, 2)?;
        self.write_u32(address + 0x1C, 0)?;
        self.write_pointer_value(address + 0x20, self.exception_access_code(fault.access))?;
        self.write_pointer_value(address + 0x28, fault.address)?;
        Ok(())
    }

    fn write_x86_context_record(
        &mut self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
        registers: &BTreeMap<String, u64>,
    ) -> Result<(), VmError> {
        self.write_u32(address, X86_CONTEXT_FULL)?;
        serialize_register_context(self.modules.memory_mut(), self.arch, address, registers)?;
        for (offset, regid, op) in [
            (X86_CONTEXT_SEG_GS_OFFSET, UC_X86_REG_GS, "uc_reg_read(gs)"),
            (X86_CONTEXT_SEG_FS_OFFSET, UC_X86_REG_FS, "uc_reg_read(fs)"),
            (X86_CONTEXT_SEG_ES_OFFSET, UC_X86_REG_ES, "uc_reg_read(es)"),
            (X86_CONTEXT_SEG_DS_OFFSET, UC_X86_REG_DS, "uc_reg_read(ds)"),
            (X86_CONTEXT_SEG_CS_OFFSET, UC_X86_REG_CS, "uc_reg_read(cs)"),
            (X86_CONTEXT_SEG_SS_OFFSET, UC_X86_REG_SS, "uc_reg_read(ss)"),
        ] {
            let value = unsafe { api.reg_read_raw(uc, regid) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
            self.write_u32(address + offset, value as u32)?;
        }
        Ok(())
    }

    fn write_x64_context_record(
        &mut self,
        address: u64,
        registers: &BTreeMap<String, u64>,
    ) -> Result<(), VmError> {
        self.modules
            .memory_mut()
            .write(address, &vec![0u8; X64_CONTEXT_SIZE])?;
        self.write_u32(address + X64_CONTEXT_FLAGS_OFFSET, X64_CONTEXT_FULL)?;
        serialize_register_context(self.modules.memory_mut(), self.arch, address, registers)?;
        Ok(())
    }

    fn write_x64_dispatcher_context(
        &mut self,
        address: u64,
        control_pc: u64,
        image_base: u64,
        function_entry: u64,
        establisher_frame: u64,
        context_record: u64,
        language_handler: u64,
        handler_data: u64,
    ) -> Result<(), VmError> {
        self.modules
            .memory_mut()
            .write(address, &vec![0u8; X64_DISPATCHER_CONTEXT_SIZE])?;
        self.write_pointer_value(address + 0x00, control_pc)?;
        self.write_pointer_value(address + 0x08, image_base)?;
        self.write_pointer_value(address + 0x10, function_entry)?;
        self.write_pointer_value(address + 0x18, establisher_frame)?;
        self.write_pointer_value(address + 0x20, 0)?;
        self.write_pointer_value(address + 0x28, context_record)?;
        self.write_pointer_value(address + 0x30, language_handler)?;
        self.write_pointer_value(address + 0x38, handler_data)?;
        self.write_pointer_value(address + 0x40, 0)?;
        self.write_u32(address + 0x48, 0)?;
        self.write_u32(address + 0x4C, 0)?;
        Ok(())
    }

    fn exception_access_code(&self, access: UnicornFaultAccess) -> u64 {
        match access {
            UnicornFaultAccess::Read => 0,
            UnicornFaultAccess::Write => 1,
            UnicornFaultAccess::Execute => 8,
        }
    }

    pub(in crate::runtime::engine) fn restore_unicorn_x86_segments_from_context(
        &self,
        api: &UnicornApi,
        uc: *mut UcEngine,
        address: u64,
    ) -> Result<(), VmError> {
        for (offset, regid, op) in [
            (X86_CONTEXT_SEG_GS_OFFSET, UC_X86_REG_GS, "uc_reg_write(gs)"),
            (X86_CONTEXT_SEG_FS_OFFSET, UC_X86_REG_FS, "uc_reg_write(fs)"),
            (X86_CONTEXT_SEG_ES_OFFSET, UC_X86_REG_ES, "uc_reg_write(es)"),
            (X86_CONTEXT_SEG_DS_OFFSET, UC_X86_REG_DS, "uc_reg_write(ds)"),
            (X86_CONTEXT_SEG_CS_OFFSET, UC_X86_REG_CS, "uc_reg_write(cs)"),
            (X86_CONTEXT_SEG_SS_OFFSET, UC_X86_REG_SS, "uc_reg_write(ss)"),
        ] {
            let value = self.read_u32(address + offset)? as u64;
            if value == 0 {
                continue;
            }
            unsafe { api.reg_write_raw(uc, regid, value) }
                .map_err(|detail| VmError::NativeExecution { op, detail })?;
        }
        Ok(())
    }
}

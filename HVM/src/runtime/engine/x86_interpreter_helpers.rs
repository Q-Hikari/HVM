use super::*;
use crate::hooks::types::LogicalAbi;

#[derive(Debug, Clone, Copy)]
pub(super) struct X86State {
    pub(super) eax: u32,
    pub(super) ecx: u32,
    pub(super) edx: u32,
    pub(super) ebx: u32,
    pub(super) esp: u32,
    pub(super) ebp: u32,
    pub(super) esi: u32,
    pub(super) edi: u32,
    pub(super) eip: u32,
    pub(super) _eflags: u32,
}

impl X86State {
    pub(super) fn new(eip: u32, esp: u32, eflags: u32) -> Self {
        Self {
            eax: 0,
            ecx: 0,
            edx: 0,
            ebx: 0,
            esp,
            ebp: 0,
            esi: 0,
            edi: 0,
            eip,
            _eflags: eflags,
        }
    }

    pub(super) fn gpr(&self, register: u8) -> u32 {
        match register {
            0 => self.eax,
            1 => self.ecx,
            2 => self.edx,
            3 => self.ebx,
            4 => self.esp,
            5 => self.ebp,
            6 => self.esi,
            7 => self.edi,
            _ => 0,
        }
    }

    pub(super) fn set_gpr(&mut self, register: u8, value: u32) {
        match register {
            0 => self.eax = value,
            1 => self.ecx = value,
            2 => self.edx = value,
            3 => self.ebx = value,
            4 => self.esp = value,
            5 => self.ebp = value,
            6 => self.esi = value,
            7 => self.edi = value,
            _ => {}
        }
    }
}

impl VirtualExecutionEngine {
    pub(super) fn resolve_x86_rm_memory_address(
        &self,
        state: &X86State,
        modrm: u8,
        operand_pc: u64,
    ) -> Result<(u64, usize), VmError> {
        let addressing_mode = modrm >> 6;
        let rm = modrm & 0x7;
        let mut consumed = 0usize;

        let (base, displacement) = match addressing_mode {
            0 => match rm {
                4 => {
                    let sib = self.read_u8(operand_pc)?;
                    consumed += 1;
                    let scale = 1u32 << ((sib >> 6) & 0x3);
                    let index = (sib >> 3) & 0x7;
                    let base = sib & 0x7;
                    let index_value = if index == 4 {
                        0
                    } else {
                        state.gpr(index).wrapping_mul(scale)
                    };
                    if base == 5 {
                        let displacement = self.read_i32(operand_pc + 1)?;
                        consumed += 4;
                        (index_value, displacement)
                    } else {
                        (state.gpr(base).wrapping_add(index_value), 0)
                    }
                }
                5 => {
                    let displacement = self.read_i32(operand_pc)?;
                    consumed += 4;
                    (0, displacement)
                }
                _ => (state.gpr(rm), 0),
            },
            1 => {
                if rm == 4 {
                    let sib = self.read_u8(operand_pc)?;
                    let scale = 1u32 << ((sib >> 6) & 0x3);
                    let index = (sib >> 3) & 0x7;
                    let base = sib & 0x7;
                    let index_value = if index == 4 {
                        0
                    } else {
                        state.gpr(index).wrapping_mul(scale)
                    };
                    let displacement = self.read_u8(operand_pc + 1)? as i8 as i32;
                    consumed += 2;
                    (state.gpr(base).wrapping_add(index_value), displacement)
                } else {
                    let displacement = self.read_u8(operand_pc)? as i8 as i32;
                    consumed += 1;
                    (state.gpr(rm), displacement)
                }
            }
            2 => {
                if rm == 4 {
                    let sib = self.read_u8(operand_pc)?;
                    let scale = 1u32 << ((sib >> 6) & 0x3);
                    let index = (sib >> 3) & 0x7;
                    let base = sib & 0x7;
                    let index_value = if index == 4 {
                        0
                    } else {
                        state.gpr(index).wrapping_mul(scale)
                    };
                    let displacement = self.read_i32(operand_pc + 1)?;
                    consumed += 5;
                    (state.gpr(base).wrapping_add(index_value), displacement)
                } else {
                    let displacement = self.read_i32(operand_pc)?;
                    consumed += 4;
                    (state.gpr(rm), displacement)
                }
            }
            _ => {
                return Err(VmError::NativeExecution {
                    op: "decode",
                    detail: "register mode does not resolve to memory".to_string(),
                });
            }
        };

        Ok((base.wrapping_add_signed(displacement) as u64, consumed))
    }

    pub(super) fn read_x86_rm32(
        &self,
        state: &X86State,
        modrm: u8,
        operand_pc: u64,
    ) -> Result<(u32, usize), VmError> {
        if (modrm >> 6) == 0x3 {
            return Ok((state.gpr(modrm & 0x7), 2));
        }
        let (address, consumed) = self.resolve_x86_rm_memory_address(state, modrm, operand_pc)?;
        Ok((self.read_u32(address)?, 2 + consumed))
    }

    pub(super) fn handle_x86_push_register_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let register = opcode - 0x50;
        let value = state.gpr(register);
        state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
            op: "push",
            detail: "stack underflow".to_string(),
        })?;
        self.write_u32(state.esp as u64, value)?;
        state.eip = state.eip.wrapping_add(1);
        Ok(())
    }

    pub(super) fn handle_x86_pop_register_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let register = opcode - 0x58;
        let value = self.read_u32(state.esp as u64)?;
        state.esp = state.esp.wrapping_add(4);
        state.set_gpr(register, value);
        state.eip = state.eip.wrapping_add(1);
        Ok(())
    }

    pub(super) fn handle_x86_push_imm32_opcode(
        &mut self,
        state: &mut X86State,
    ) -> Result<(), VmError> {
        let value = self.read_u32(state.eip as u64 + 1)?;
        state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
            op: "push",
            detail: "stack underflow".to_string(),
        })?;
        self.write_u32(state.esp as u64, value)?;
        state.eip = state.eip.wrapping_add(5);
        Ok(())
    }

    pub(super) fn handle_x86_push_imm8_opcode(
        &mut self,
        state: &mut X86State,
    ) -> Result<(), VmError> {
        let value = self.read_u8(state.eip as u64 + 1)? as i8 as i32 as u32;
        state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
            op: "push",
            detail: "stack underflow".to_string(),
        })?;
        self.write_u32(state.esp as u64, value)?;
        state.eip = state.eip.wrapping_add(2);
        Ok(())
    }

    pub(super) fn handle_x86_lea_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let modrm = self.read_u8(state.eip as u64 + 1)?;
        let destination = (modrm >> 3) & 0x7;
        let addressing_mode = modrm >> 6;
        let rm = modrm & 0x7;
        let (effective, length) = match (addressing_mode, rm) {
            (0, 4) => {
                let sib = self.read_u8(state.eip as u64 + 2)?;
                if sib != 0x24 {
                    return Err(self.unsupported_x86(opcode, state.eip as u64));
                }
                (state.esp, 3)
            }
            (1, 4) => {
                let sib = self.read_u8(state.eip as u64 + 2)?;
                if sib != 0x24 {
                    return Err(self.unsupported_x86(opcode, state.eip as u64));
                }
                let displacement = self.read_u8(state.eip as u64 + 3)? as i8 as i32;
                (state.esp.wrapping_add_signed(displacement), 4)
            }
            (2, 4) => {
                let sib = self.read_u8(state.eip as u64 + 2)?;
                if sib != 0x24 {
                    return Err(self.unsupported_x86(opcode, state.eip as u64));
                }
                let displacement = self.read_i32(state.eip as u64 + 3)?;
                (state.esp.wrapping_add_signed(displacement), 7)
            }
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        };
        state.set_gpr(destination, effective);
        state.eip = state.eip.wrapping_add(length);
        Ok(())
    }

    pub(super) fn handle_x86_group_83_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let modrm = self.read_u8(state.eip as u64 + 1)?;
        let value = self.read_u8(state.eip as u64 + 2)? as i8 as i32;
        match modrm {
            0xC4 => {
                state.esp = state.esp.wrapping_add(value as u32);
                state.eip = state.eip.wrapping_add(3);
            }
            0xEC => {
                state.esp =
                    state
                        .esp
                        .checked_sub(value as u32)
                        .ok_or(VmError::NativeExecution {
                            op: "sub",
                            detail: "stack underflow".to_string(),
                        })?;
                state.eip = state.eip.wrapping_add(3);
            }
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        }
        Ok(())
    }

    pub(super) fn handle_x86_ret_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let return_address = self.read_u32(state.esp as u64)?;
        match opcode {
            0xC2 => {
                let stack_adjust = self.read_u16(state.eip as u64 + 1)? as u32;
                state.esp = state.esp.wrapping_add(4 + stack_adjust);
            }
            0xC3 => {
                state.esp = state.esp.wrapping_add(4);
            }
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        }
        state.eip = return_address;
        Ok(())
    }

    pub(super) fn handle_x86_branch_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        match opcode {
            0xE8 => {
                let displacement = self.read_i32(state.eip as u64 + 1)?;
                let return_address = state.eip.wrapping_add(5);
                state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
                    op: "call",
                    detail: "stack underflow".to_string(),
                })?;
                self.write_u32(state.esp as u64, return_address)?;
                let target = return_address.wrapping_add_signed(displacement);
                state.eip = target;
            }
            0xE9 => {
                let displacement = self.read_i32(state.eip as u64 + 1)?;
                state.eip = state.eip.wrapping_add(5).wrapping_add_signed(displacement);
            }
            0xEB => {
                let displacement = self.read_u8(state.eip as u64 + 1)? as i8 as i32;
                state.eip = state.eip.wrapping_add(2).wrapping_add_signed(displacement);
            }
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        }
        Ok(())
    }

    pub(super) fn handle_x86_group_ff_opcode(
        &mut self,
        state: &mut X86State,
        opcode: u8,
    ) -> Result<(), VmError> {
        let modrm = self.read_u8(state.eip as u64 + 1)?;
        let group = (modrm >> 3) & 0x7;
        let (value, length) = self.read_x86_rm32(state, modrm, state.eip as u64 + 2)?;
        match group {
            2 => {
                let return_address = state.eip.wrapping_add(length as u32);
                state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
                    op: "call",
                    detail: "stack underflow".to_string(),
                })?;
                self.write_u32(state.esp as u64, return_address)?;
                state.eip = value;
            }
            4 => {
                state.eip = value;
            }
            6 => {
                state.esp = state.esp.checked_sub(4).ok_or(VmError::NativeExecution {
                    op: "push",
                    detail: "stack underflow".to_string(),
                })?;
                self.write_u32(state.esp as u64, value)?;
                state.eip = state.eip.wrapping_add(length as u32);
            }
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        }
        Ok(())
    }

    fn apply_pending_x86_context_restore(&mut self, state: &mut X86State) -> bool {
        let Some(restore) = self.exception.pending_context_restore.take() else {
            return false;
        };
        let registers = &restore.registers;
        state.eax = registers.eax as u32;
        state.ebx = registers.ebx as u32;
        state.ecx = registers.ecx as u32;
        state.edx = registers.edx as u32;
        state.esi = registers.esi as u32;
        state.edi = registers.edi as u32;
        state.ebp = registers.ebp as u32;
        state.esp = registers.esp as u32;
        state.eip = registers.eip as u32;
        state._eflags = registers.eflags as u32;
        self.dispatch.reset_api_flow_control();
        true
    }

    pub(super) fn step_x86_interpreter(&mut self, state: &mut X86State) -> Result<(), VmError> {
        if let Some(bound) = self.core.hooks.bound_lookup(state.eip as u64) {
            let bound_module = bound.module.to_string();
            let bound_function = bound.function.to_string();
            if let Some(signature) = bound.signature.cloned() {
                let argc = signature.params.len();
                let return_address = self.read_u32(state.esp as u64)? as u64;
                let args = self.capture_stack_args(state.esp as u64 + 4, argc)?;
                self.dispatch.api_log_context_override = if self.core.config.api_log_include_context
                {
                    let stack_words = (0..self.core.config.api_log_stack_words)
                        .map(|index| {
                            let address = state.esp as u64 + (index as u64 * 4);
                            let value = self.read_u32(address).ok().map(|value| value as u64);
                            ApiStackWord {
                                address,
                                value,
                                value_ref: value
                                    .filter(|value| *value != 0)
                                    .map(|value| self.address_ref(value)),
                                read_error: value.is_none().then(|| "read_u32(stack)".to_string()),
                            }
                        })
                        .collect::<Vec<_>>();
                    Some(ApiExecutionContext {
                        ip: state.eip as u64,
                        sp: state.esp as u64,
                        bp: state.ebp as u64,
                        ax: state.eax as u64,
                        bx: state.ebx as u64,
                        cx: state.ecx as u64,
                        dx: state.edx as u64,
                        si: state.esi as u64,
                        di: state.edi as u64,
                        flags: state._eflags as u64,
                        direction_flag: (((state._eflags as u64) >> 10) & 1) != 0,
                        stack_words,
                    })
                } else {
                    None
                };
                let retval = self.dispatch_bound_stub_with_signature(
                    &signature,
                    state.eip as u64,
                    Some(return_address),
                    &args,
                )?;
                self.dispatch.api_log_context_override = None;
                if self.apply_pending_x86_context_restore(state) {
                    let _ = self.dispatch.take_hook_return_override();
                    return Ok(());
                }
                if self.dispatch.api_return_deferred() {
                    let _ = self.dispatch.take_hook_return_override();
                    return Ok(());
                }
                let current_thread_state = self
                    .core
                    .scheduler
                    .current_tid()
                    .and_then(|tid| self.core.scheduler.thread_state(tid));
                let yielded_blocking_thread = current_thread_state != Some("running");
                if self.dispatch.preserve_blocked_api_frame
                    && self.dispatch.thread_yield_requested()
                    && yielded_blocking_thread
                {
                    let _ = self.dispatch.take_hook_return_override();
                    return Ok(());
                }
                let hook_return_override = self.dispatch.take_hook_return_override();
                state.eax = hook_return_override
                    .map(|override_value| override_value.raw_retval as u32)
                    .unwrap_or_else(|| retval.into_raw(&self.core.arch) as u32);
                if let Some(override_value) = hook_return_override {
                    state._eflags = ((state._eflags as u64 & !override_value.flags_mask)
                        | override_value.flags_value) as u32;
                }
                match signature.abi {
                    LogicalAbi::WinApi | LogicalAbi::ComMethod => {
                        // stdcall callee-cleanup: pop return address + args
                        state.esp = state.esp.wrapping_add(4 + (argc as u32).saturating_mul(4));
                    }
                    LogicalAbi::Cdecl
                    | LogicalAbi::VariadicCdecl
                    | LogicalAbi::Win64Only
                    | LogicalAbi::Callback
                    | LogicalAbi::Custom(_) => {
                        // caller-cleanup: pop only return address
                        state.esp = state.esp.wrapping_add(4);
                    }
                }
                if self.dispatch.force_native_return {
                    self.dispatch.force_native_return = false;
                    state.eip = self.core.native_return_sentinel as u32;
                } else {
                    state.eip = return_address as u32;
                }
                return Ok(());
            }

            let _ = self.log_unsupported_bound_stub(
                state.eip as u64,
                &bound_module,
                &bound_function,
                "missing hook definition",
            );
            state.eax = 0;
            state.eip = self.read_u32(state.esp as u64)?;
            state.esp = state.esp.wrapping_add(4);
            return Ok(());
        }

        let opcode = self.read_u8(state.eip as u64)?;
        match opcode {
            0x90 => {
                state.eip = state.eip.wrapping_add(1);
            }
            0xA1 => {
                let address = self.read_u32(state.eip as u64 + 1)? as u64;
                state.eax = self.read_u32(address)?;
                state.eip = state.eip.wrapping_add(5);
            }
            0xA3 => {
                let address = self.read_u32(state.eip as u64 + 1)? as u64;
                self.write_u32(address, state.eax)?;
                state.eip = state.eip.wrapping_add(5);
            }
            0xB8..=0xBF => {
                let register = opcode - 0xB8;
                let value = self.read_u32(state.eip as u64 + 1)?;
                state.set_gpr(register, value);
                state.eip = state.eip.wrapping_add(5);
            }
            0x50..=0x57 => self.handle_x86_push_register_opcode(state, opcode)?,
            0x58..=0x5F => self.handle_x86_pop_register_opcode(state, opcode)?,
            0x68 => self.handle_x86_push_imm32_opcode(state)?,
            0x6A => self.handle_x86_push_imm8_opcode(state)?,
            0x8D => self.handle_x86_lea_opcode(state, opcode)?,
            0x31 => {
                let modrm = self.read_u8(state.eip as u64 + 1)?;
                if modrm == 0xC0 {
                    state.eax = 0;
                    state.eip = state.eip.wrapping_add(2);
                } else {
                    return Err(self.unsupported_x86(opcode, state.eip as u64));
                }
            }
            0x83 => self.handle_x86_group_83_opcode(state, opcode)?,
            0xC2 | 0xC3 => self.handle_x86_ret_opcode(state, opcode)?,
            0xE8 | 0xE9 | 0xEB => self.handle_x86_branch_opcode(state, opcode)?,
            0xFF => self.handle_x86_group_ff_opcode(state, opcode)?,
            _ => {
                return Err(self.unsupported_x86(opcode, state.eip as u64));
            }
        }

        Ok(())
    }

    pub(super) fn run_interpreter_thread_slice(
        &mut self,
        tid: u32,
        instruction_budget: u64,
    ) -> Result<(), VmError> {
        let registers = self
            .core
            .scheduler
            .thread_registers(tid)
            .ok_or(VmError::RuntimeInvariant("thread snapshot missing"))?;
        let stack_top = self
            .core
            .scheduler
            .thread_ref(tid)
            .map(|t| t.stack_top)
            .unwrap_or(0);
        let start_address = self.core.scheduler.thread_start_address(tid).unwrap_or(0);
        let mut state = X86State {
            eax: registers.eax as u32,
            ecx: registers.ecx as u32,
            edx: registers.edx as u32,
            ebx: registers.ebx as u32,
            esp: if registers.esp != 0 {
                registers.esp
            } else {
                stack_top
            } as u32,
            ebp: registers.ebp as u32,
            esi: registers.esi as u32,
            edi: registers.edi as u32,
            eip: if registers.eip != 0 {
                registers.eip
            } else {
                start_address
            } as u32,
            _eflags: if registers.eflags != 0 {
                registers.eflags
            } else {
                0x202
            } as u32,
        };
        let mut failure = None;

        for _ in 0..instruction_budget.max(1) {
            if state.eip as u64 == self.core.native_return_sentinel {
                break;
            }
            self.record_instruction_retired();
            if let Err(error) = self.step_x86_interpreter(&mut state) {
                failure = Some(error);
                break;
            }
            if self.dispatch.thread_yield_requested() {
                break;
            }
        }

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
                "failed to capture thread registers",
            ))?;

        let exit_pc = state.eip as u64;
        let return_value = state.eax;
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

        if let Some(error) = failure {
            let message = format!(
                "{}; pc=0x{exit_pc:X}; sp=0x{:X}; eax=0x{:X}; ebx=0x{:X}; ecx=0x{:X}; edx=0x{:X}; ebp=0x{:X}; esi=0x{:X}; edi=0x{:X}",
                error,
                state.esp,
                state.eax,
                state.ebx,
                state.ecx,
                state.edx,
                state.ebp,
                state.esi,
                state.edi,
            );
            self.log_emu_stop("interpreter", exit_pc, &message)?;
            return Err(match error {
                VmError::NativeExecution { op, .. } => VmError::NativeExecution {
                    op,
                    detail: message,
                },
                other => other,
            });
        }

        Ok(())
    }
}

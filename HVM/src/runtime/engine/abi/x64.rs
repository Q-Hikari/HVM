use crate::arch::ArchSpec;
use crate::error::VmError;
use crate::hooks::signature::HookSignature;
use crate::hooks::types::HookFlags;

use super::adapter::AbiAdapter;
use super::frame::{PreparedCallbackFrame, RawCallFrame};

/// x64 (Win64) ABI adapter.
///
/// First 4 params in RCX/RDX/R8/R9, remaining on stack at RSP+0x28.
/// Shadow space: 32 bytes at RSP+0x08.
pub struct X64Adapter;

/// Maximum extra arguments to capture beyond the fixed parameter count for
/// variadic functions on x64.  Matches the x86 constant.
const MAX_VARIADIC_EXTRA: usize = 16;

impl AbiAdapter for X64Adapter {
    fn capture_call_frame(
        &self,
        _arch: &ArchSpec,
        signature: &HookSignature,
        reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<RawCallFrame, VmError> {
        use crate::runtime::unicorn::{
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP,
            UC_X86_REG_RSP,
        };

        let rsp = reg_read(UC_X86_REG_RSP).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_read(rsp)",
            detail,
        })?;
        let rip = reg_read(UC_X86_REG_RIP).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_read(rip)",
            detail,
        })?;

        let return_address_bytes = mem_read(rsp, 8).map_err(|detail| VmError::NativeExecution {
            op: "uc_mem_read(stack)",
            detail,
        })?;
        let return_address = u64::from_le_bytes(return_address_bytes.try_into().unwrap_or([0; 8]));

        let argc = signature.argc();
        let extra = if signature.flags.contains(HookFlags::VARIADIC) {
            MAX_VARIADIC_EXTRA
        } else {
            0
        };
        let total_args = argc + extra;

        let mut args = smallvec::SmallVec::with_capacity(total_args);

        // First 4 parameters in registers (or up to total_args if fewer).
        let reg_params: [(i32, &str); 4] = [
            (UC_X86_REG_RCX, "uc_reg_read(rcx)"),
            (UC_X86_REG_RDX, "uc_reg_read(rdx)"),
            (UC_X86_REG_R8, "uc_reg_read(r8)"),
            (UC_X86_REG_R9, "uc_reg_read(r9)"),
        ];
        let reg_count = total_args.min(4);
        for (regid, op) in reg_params.into_iter().take(reg_count) {
            args.push(reg_read(regid).map_err(|detail| VmError::NativeExecution { op, detail })?);
        }

        // Remaining parameters on the stack at RSP + 0x28.
        if total_args > 4 {
            let stack_arg_count = total_args - 4;
            let stack_args = mem_read(rsp + 0x28, stack_arg_count * 8).map_err(|detail| {
                VmError::NativeExecution {
                    op: "uc_mem_read(stack_args)",
                    detail,
                }
            })?;
            for chunk in stack_args.chunks_exact(8) {
                args.push(u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])));
            }
        }

        Ok(RawCallFrame {
            args,
            return_address: Some(return_address),
            stack_pointer: rsp,
            instruction_pointer: rip,
            abi_snapshot: super::frame::AbiSnapshot {
                callee_cleanup: false,
                callee_stack_pop: 0,
            },
        })
    }

    fn write_return_value(
        &self,
        _arch: &ArchSpec,
        value: u64,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
    ) -> Result<(), VmError> {
        use crate::runtime::unicorn::UC_X86_REG_RAX;
        reg_write(UC_X86_REG_RAX, value).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(rax)",
            detail,
        })
    }

    fn adjust_stack_after_call(
        &self,
        _arch: &ArchSpec,
        _signature: &HookSignature,
        stack_pointer: u64,
    ) -> u64 {
        stack_pointer + 8
    }

    fn prepare_callback_frame(
        &self,
        _arch: &ArchSpec,
        callback_address: u64,
        return_address: u64,
        args: &[u64],
        current_sp: u64,
        _reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
        mem_write: &mut dyn FnMut(u64, &[u8]) -> Result<(), String>,
    ) -> Result<PreparedCallbackFrame, VmError> {
        use crate::runtime::unicorn::{
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP,
            UC_X86_REG_RSP,
        };

        // Win64 ABI: 0x20 shadow space + 8 bytes return address = 0x28 minimum.
        let stack_arg_count = args.len().saturating_sub(4);
        let frame_size = 0x28u64 + stack_arg_count as u64 * 8;
        let new_sp = current_sp - frame_size;

        // Build frame: [return_address(8B)] [shadow space 0x20 bytes] [stack args...]
        let mut frame_bytes = Vec::with_capacity(frame_size as usize);
        frame_bytes.extend_from_slice(&return_address.to_le_bytes()); // [0..8]
        frame_bytes.extend_from_slice(&[0u8; 0x20]); // [0x08..0x28] shadow space
        for i in 4..args.len() {
            frame_bytes.extend_from_slice(&args[i].to_le_bytes()); // stack args
        }

        mem_write(new_sp, &frame_bytes).map_err(|detail| VmError::NativeExecution {
            op: "uc_mem_write(callback_frame)",
            detail,
        })?;

        // Set instruction pointer.
        reg_write(UC_X86_REG_RIP, callback_address).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(rip)",
            detail,
        })?;

        // Set stack pointer.
        reg_write(UC_X86_REG_RSP, new_sp).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(rsp)",
            detail,
        })?;

        // Set register parameters (first 4 args in RCX, RDX, R8, R9).
        let reg_params: [(i32, &str); 4] = [
            (UC_X86_REG_RCX, "uc_reg_write(rcx)"),
            (UC_X86_REG_RDX, "uc_reg_write(rdx)"),
            (UC_X86_REG_R8, "uc_reg_write(r8)"),
            (UC_X86_REG_R9, "uc_reg_write(r9)"),
        ];
        for (i, (regid, op)) in reg_params.into_iter().enumerate() {
            let val = args.get(i).copied().unwrap_or(0);
            reg_write(regid, val).map_err(|detail| VmError::NativeExecution { op, detail })?;
        }

        Ok(PreparedCallbackFrame {
            new_sp,
            new_pc: callback_address,
            save_callee_saved: false,
            callee_cleanup_bytes: 0,
        })
    }
}

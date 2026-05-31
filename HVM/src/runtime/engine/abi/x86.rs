use crate::arch::ArchSpec;
use crate::error::VmError;
use crate::hooks::signature::{HookSignature, ParamSpec};
use crate::hooks::types::{HookFlags, ParamType};

use super::adapter::AbiAdapter;
use super::frame::{PreparedCallbackFrame, RawCallFrame};

/// x86 stdcall ABI adapter.
///
/// All parameters on the stack, callee cleans up.
pub struct X86StdcallAdapter;

/// x86 cdecl ABI adapter.
///
/// All parameters on the stack, caller cleans up.
pub struct X86CdeclAdapter;

/// Maximum extra arguments to capture beyond the fixed parameter count for
/// variadic functions.  This is a pragmatic upper bound; real-world printf-style
/// calls rarely exceed a dozen variadic arguments.
const MAX_VARIADIC_EXTRA: usize = 16;

/// Returns the total byte count of the x86 stack argument area for `params`.
///
/// Parameters wider than 4 bytes (U64 / I64 / Hex64) occupy two 4-byte stack
/// slots; all other types occupy a single slot.  This is the value that must be
/// used for both frame capture and callee stack cleanup so the two stay in
/// sync.
fn x86_param_stack_bytes(params: &[ParamSpec]) -> usize {
    params
        .iter()
        .map(|p| match p.ty {
            ParamType::U64 | ParamType::I64 | ParamType::Hex64 => 8,
            _ => 4,
        })
        .sum()
}

fn capture_x86_frame(
    signature: &HookSignature,
    reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
    mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>,
) -> Result<RawCallFrame, VmError> {
    use crate::runtime::unicorn::UC_X86_REG_ESP;

    let esp = reg_read(UC_X86_REG_ESP).map_err(|detail| VmError::NativeExecution {
        op: "uc_reg_read(esp)",
        detail,
    })?;

    let param_stack_bytes = x86_param_stack_bytes(signature.params);
    let extra = if signature.flags.contains(HookFlags::VARIADIC) {
        MAX_VARIADIC_EXTRA
    } else {
        0
    };
    let extra_bytes = extra * 4;
    let frame_size = 4 + param_stack_bytes + extra_bytes;
    let stack = mem_read(esp, frame_size).map_err(|detail| VmError::NativeExecution {
        op: "uc_mem_read(stack)",
        detail,
    })?;

    let return_address = u32::from_le_bytes(stack[0..4].try_into().unwrap_or([0; 4])) as u64;
    let total_slots = (param_stack_bytes / 4).saturating_add(extra);
    let mut args = smallvec::SmallVec::with_capacity(total_slots);
    let mut offset = 4usize;
    for param in signature.params {
        match param.ty {
            ParamType::U64 | ParamType::I64 | ParamType::Hex64 => {
                let lo = u32::from_le_bytes(stack[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    as u64;
                let hi =
                    u32::from_le_bytes(stack[offset + 4..offset + 8].try_into().unwrap_or([0; 4]))
                        as u64;
                args.push(lo);
                args.push(hi);
                offset += 8;
            }
            _ => {
                let val = u32::from_le_bytes(stack[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    as u64;
                args.push(val);
                offset += 4;
            }
        }
    }
    // Append any variadic extra slots (each 4 bytes).
    for chunk in stack[offset..].chunks_exact(4) {
        args.push(u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64);
    }

    // For stdcall, callee cleanup is based on the declared param byte count.
    Ok(RawCallFrame {
        args,
        return_address: Some(return_address),
        stack_pointer: esp,
        instruction_pointer: 0,
        abi_snapshot: super::frame::AbiSnapshot {
            callee_cleanup: true,
            callee_stack_pop: param_stack_bytes as u32,
        },
    })
}

impl AbiAdapter for X86StdcallAdapter {
    fn capture_call_frame(
        &self,
        _arch: &ArchSpec,
        signature: &HookSignature,
        reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<RawCallFrame, VmError> {
        capture_x86_frame(signature, reg_read, mem_read)
    }

    fn write_return_value(
        &self,
        _arch: &ArchSpec,
        value: u64,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
    ) -> Result<(), VmError> {
        use crate::runtime::unicorn::UC_X86_REG_EAX;
        reg_write(UC_X86_REG_EAX, value).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(eax)",
            detail,
        })
    }

    fn adjust_stack_after_call(
        &self,
        _arch: &ArchSpec,
        signature: &HookSignature,
        stack_pointer: u64,
    ) -> u64 {
        // stdcall: callee pops args + return address.
        // Use the byte-level parameter size so 64-bit params (2 slots each)
        // are cleaned up correctly.
        stack_pointer + 4 + x86_param_stack_bytes(signature.params) as u64
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
        use crate::runtime::unicorn::{UC_X86_REG_EIP, UC_X86_REG_ESP};

        let frame_size = 4 + args.len() * 4; // return address + args
        let new_sp = current_sp - frame_size as u64;

        // Build frame: [return_address(4 bytes LE)] [arg0(4 bytes LE)] [arg1(4 bytes LE)] ...
        let mut frame_bytes = Vec::with_capacity(frame_size);
        frame_bytes.extend_from_slice(&(return_address as u32).to_le_bytes());
        for &arg in args {
            frame_bytes.extend_from_slice(&(arg as u32).to_le_bytes());
        }

        mem_write(new_sp, &frame_bytes).map_err(|detail| VmError::NativeExecution {
            op: "uc_mem_write(callback_frame)",
            detail,
        })?;

        reg_write(UC_X86_REG_EIP, callback_address).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(eip)",
            detail,
        })?;

        reg_write(UC_X86_REG_ESP, new_sp).map_err(|detail| VmError::NativeExecution {
            op: "uc_reg_write(esp)",
            detail,
        })?;

        Ok(PreparedCallbackFrame {
            new_sp,
            new_pc: callback_address,
            save_callee_saved: false,
            callee_cleanup_bytes: args.len() as u32 * 4,
        })
    }
}

impl AbiAdapter for X86CdeclAdapter {
    fn capture_call_frame(
        &self,
        _arch: &ArchSpec,
        signature: &HookSignature,
        reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<RawCallFrame, VmError> {
        let mut frame = capture_x86_frame(signature, reg_read, mem_read)?;
        frame.abi_snapshot.callee_cleanup = false;
        frame.abi_snapshot.callee_stack_pop = 0;
        Ok(frame)
    }

    fn write_return_value(
        &self,
        arch: &ArchSpec,
        value: u64,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
    ) -> Result<(), VmError> {
        X86StdcallAdapter.write_return_value(arch, value, reg_write)
    }

    fn adjust_stack_after_call(
        &self,
        _arch: &ArchSpec,
        _signature: &HookSignature,
        stack_pointer: u64,
    ) -> u64 {
        // cdecl: caller pops, so we only skip the return address.
        stack_pointer + 4
    }

    fn prepare_callback_frame(
        &self,
        arch: &ArchSpec,
        callback_address: u64,
        return_address: u64,
        args: &[u64],
        current_sp: u64,
        reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
        mem_write: &mut dyn FnMut(u64, &[u8]) -> Result<(), String>,
    ) -> Result<PreparedCallbackFrame, VmError> {
        // Delegate frame construction to stdcall adapter, then override cleanup.
        let mut frame = X86StdcallAdapter.prepare_callback_frame(
            arch,
            callback_address,
            return_address,
            args,
            current_sp,
            reg_read,
            reg_write,
            mem_write,
        )?;
        // cdecl: caller cleans up, so callee_cleanup_bytes = 0.
        frame.callee_cleanup_bytes = 0;
        Ok(frame)
    }
}

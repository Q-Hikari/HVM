use crate::arch::ArchSpec;
use crate::error::VmError;
use crate::hooks::signature::HookSignature;
use crate::hooks::types::LogicalAbi;

use super::frame::{PreparedCallbackFrame, RawCallFrame};

/// Trait for architecture-specific ABI adapters.
///
/// Each adapter knows how to:
/// - Capture the raw call frame from the guest CPU state
/// - Write a return value back to the appropriate register(s)
/// - Prepare a callback invocation frame
///
/// Concrete implementations: `x86.rs`, `x64.rs` (and future `arm64.rs`).
///
/// Register IDs use `i32` to match the Unicorn engine constants (`c_int`).
pub trait AbiAdapter {
    /// Captures the raw argument frame from the current guest CPU state.
    ///
    /// The implementation reads registers and/or stack memory depending on
    /// the calling convention, populates `RawCallFrame.args`, and records
    /// the return address and stack pointer.
    fn capture_call_frame(
        &self,
        arch: &ArchSpec,
        signature: &HookSignature,
        reg_read: &mut dyn FnMut(i32) -> Result<u64, String>,
        mem_read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<RawCallFrame, VmError>;

    /// Writes the return value to the appropriate guest register(s).
    ///
    /// On x86 this writes EAX; on x64 this writes RAX (and EDX/RDX for
    /// 64-bit returns that use EDX:EAX, e.g. VerSetConditionMask).
    fn write_return_value(
        &self,
        arch: &ArchSpec,
        value: u64,
        reg_write: &mut dyn FnMut(i32, u64) -> Result<(), String>,
    ) -> Result<(), VmError>;

    /// Adjusts the stack pointer after the hook returns.
    ///
    /// For stdcall on x86, the callee pops the arguments.
    /// For cdecl/x64, the caller pops (no adjustment here).
    fn adjust_stack_after_call(
        &self,
        arch: &ArchSpec,
        signature: &HookSignature,
        stack_pointer: u64,
    ) -> u64;

    /// Prepares a callback invocation frame.
    ///
    /// Given a callback address, return address (continuation stub), and arguments,
    /// this method constructs the appropriate stack/register state so that the guest
    /// will execute the callback function with the correct calling convention.
    ///
    /// Returns a `PreparedCallbackFrame` containing the new SP, new PC (callback address),
    /// whether callee-saved registers should be preserved, and cleanup information.
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
    ) -> Result<PreparedCallbackFrame, VmError>;
}

/// Computes the stack pointer that should be visible after a deferred API
/// returns to its caller.
///
/// This differs from `prepare_callback_frame()`: it models cleanup for the
/// original API frame that was interrupted while a guest callback was run.
pub fn post_return_stack_pointer(
    arch: &ArchSpec,
    abi: LogicalAbi,
    arg_count: usize,
    stack_pointer: u64,
) -> u64 {
    if arch.is_x64() {
        stack_pointer + 8
    } else {
        match abi {
            LogicalAbi::WinApi | LogicalAbi::ComMethod => stack_pointer + 4 + arg_count as u64 * 4,
            LogicalAbi::Cdecl
            | LogicalAbi::VariadicCdecl
            | LogicalAbi::Win64Only
            | LogicalAbi::Callback
            | LogicalAbi::Custom(_) => stack_pointer + 4,
        }
    }
}

/// Selects the appropriate `AbiAdapter` for the given architecture and logical ABI.
///
/// # Panics
///
/// Panics if `arch` is neither x86 nor x64. Future ARM64 support will add
/// an explicit arm64 branch; until then, unsupported architectures fail loudly
/// instead of silently falling back to the x64 adapter.
pub fn select_adapter(arch: &ArchSpec, abi: &LogicalAbi) -> &'static dyn AbiAdapter {
    if arch.is_x86() {
        match abi {
            LogicalAbi::Cdecl | LogicalAbi::VariadicCdecl => &super::x86::X86CdeclAdapter,
            _ => &super::x86::X86StdcallAdapter,
        }
    } else if arch.is_x64() {
        &super::x64::X64Adapter
    } else {
        panic!(
            "select_adapter: unsupported architecture '{}' (expected x86 or x64)",
            arch.name
        )
    }
}

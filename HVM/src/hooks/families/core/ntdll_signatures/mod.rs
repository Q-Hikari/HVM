//! Full `HookSignature` table for high-frequency `ntdll.dll` functions.
//!
//! Covers ~50 functions that account for ~80 % of `arg(args, N)` calls in
//! `runtime/engine/hooks/core/ntdll.rs`.
//!
//! Split into sub-modules by functional category for maintainability.

mod crt_ldr;
mod crt_zw;
mod memory_process;
mod nt_syscalls_1;
mod nt_syscalls_2;
mod rtl_1;
mod rtl_2;
mod version;

use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;

/// Register all ntdll signatures into the hook registry.
pub(super) fn register_all(registry: &mut HookRegistry) {
    registry.register_signatures(memory_process::MEMORY_PROCESS_SIGS);
    registry.register_signatures(crt_ldr::CRT_LDR_SIGS);
    registry.register_signatures(nt_syscalls_1::NT_SYSCALLS_1_SIGS);
    registry.register_signatures(nt_syscalls_2::NT_SYSCALLS_2_SIGS);
    registry.register_signatures(rtl_1::RTL_1_SIGS);
    registry.register_signatures(rtl_2::RTL_2_SIGS);
    registry.register_signatures(crt_zw::CRT_ZW_SIGS);
    registry.register_signatures(version::VERSION_SIGS);
}

/// All ntdll signature slices combined, for use in api-set contract aliasing.
pub(super) static ALL_SLICES: &[&[HookSignature]] = &[
    memory_process::MEMORY_PROCESS_SIGS,
    crt_ldr::CRT_LDR_SIGS,
    nt_syscalls_1::NT_SYSCALLS_1_SIGS,
    nt_syscalls_2::NT_SYSCALLS_2_SIGS,
    rtl_1::RTL_1_SIGS,
    rtl_2::RTL_2_SIGS,
    crt_zw::CRT_ZW_SIGS,
    version::VERSION_SIGS,
];

//! Full `HookSignature` table for `kernel32.dll` functions.

mod sigs_1;
mod sigs_2;
mod sigs_3;
mod sigs_4;

use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;

/// All kernel32 signature slices combined, for use in api-set contract aliasing.
pub(super) static ALL_SLICES: &[&[HookSignature]] = &[
    sigs_1::KERNEL32_SIGS_1,
    sigs_2::KERNEL32_SIGS_2,
    sigs_3::KERNEL32_SIGS_3,
    sigs_4::KERNEL32_SIGS_4,
];

/// Register all kernel32 signatures into the hook registry.
pub(super) fn register_all(registry: &mut HookRegistry) {
    registry.register_signatures(sigs_1::KERNEL32_SIGS_1);
    registry.register_signatures(sigs_2::KERNEL32_SIGS_2);
    registry.register_signatures(sigs_3::KERNEL32_SIGS_3);
    registry.register_signatures(sigs_4::KERNEL32_SIGS_4);
}

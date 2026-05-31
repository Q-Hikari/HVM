//! Full `HookSignature` table for `user32.dll` functions.

mod sigs_1;
mod sigs_2;
mod sigs_3;

use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;

/// All user32 signature slices combined.
#[allow(dead_code)]
pub(super) static ALL_SLICES: &[&[HookSignature]] = &[
    sigs_1::USER32_SIGS_1,
    sigs_2::USER32_SIGS_2,
    sigs_3::USER32_SIGS_3,
];

/// Register all user32 signatures into the hook registry.
pub(super) fn register_all(registry: &mut HookRegistry) {
    registry.register_signatures(sigs_1::USER32_SIGS_1);
    registry.register_signatures(sigs_2::USER32_SIGS_2);
    registry.register_signatures(sigs_3::USER32_SIGS_3);
}

//! Full `HookSignature` table for `advapi32.dll` functions.

mod sigs_1;
mod sigs_2;

use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;

/// All advapi32 signature slices combined.
pub(crate) static ALL_SLICES: &[&[HookSignature]] =
    &[sigs_1::ADVAPI32_SIGS_1, sigs_2::ADVAPI32_SIGS_2];

/// Register all advapi32 signatures into the hook registry.
pub(crate) fn register_all(registry: &mut HookRegistry) {
    registry.register_signatures(sigs_1::ADVAPI32_SIGS_1);
    registry.register_signatures(sigs_2::ADVAPI32_SIGS_2);
}

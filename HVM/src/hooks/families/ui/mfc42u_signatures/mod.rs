//! Full `HookSignature` table for `mfc42u.dll` ordinal exports.
//!
//! Split into sub-modules by ordinal range for maintainability.

mod ordinals_1;
mod ordinals_2;
mod ordinals_3;
mod ordinals_4;
mod ordinals_5;
mod ordinals_6;

use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::HookSignature;

/// All mfc42u signature slices combined.
#[allow(dead_code)]
pub(super) static ALL_SLICES: &[&[HookSignature]] = &[
    ordinals_1::ORDINALS_1_SIGS,
    ordinals_2::ORDINALS_2_SIGS,
    ordinals_3::ORDINALS_3_SIGS,
    ordinals_4::ORDINALS_4_SIGS,
    ordinals_5::ORDINALS_5_SIGS,
    ordinals_6::ORDINALS_6_SIGS,
];

/// Register all mfc42u signatures into the hook registry.
pub(super) fn register_all(registry: &mut HookRegistry) {
    registry.register_signatures(ordinals_1::ORDINALS_1_SIGS);
    registry.register_signatures(ordinals_2::ORDINALS_2_SIGS);
    registry.register_signatures(ordinals_3::ORDINALS_3_SIGS);
    registry.register_signatures(ordinals_4::ORDINALS_4_SIGS);
    registry.register_signatures(ordinals_5::ORDINALS_5_SIGS);
    registry.register_signatures(ordinals_6::ORDINALS_6_SIGS);
}

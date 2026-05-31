use crate::hooks::registry::HookRegistry;

pub mod comctl32;
pub mod comctl32_signatures;
pub mod comdlg32;
pub mod comdlg32_signatures;
pub mod imm32;
pub mod imm32_signatures;
pub mod mfc100;
pub mod mfc100_signatures;
pub mod mfc42u;
pub mod mfc42u_signatures;
pub mod user32;
pub mod uxtheme;
pub mod uxtheme_signatures;

/// Registers windowing and shell UI DLL families.
pub fn register(registry: &mut HookRegistry) {
    comctl32::register_comctl32_hooks(registry);
    comdlg32::register_comdlg32_hooks(registry);
    imm32::register_imm32_hooks(registry);
    mfc100::register_mfc100_hooks(registry);
    mfc42u::register_mfc42u_hooks(registry);
    user32::register_user32_hooks(registry);
    uxtheme::register_uxtheme_hooks(registry);
    registry.register_signatures(comctl32_signatures::COMCTL32_SIGNATURES);
    registry.register_signatures(comdlg32_signatures::COMDLG32_SIGNATURES);
    registry.register_signatures(imm32_signatures::IMM32_SIGNATURES);
    mfc42u_signatures::register_all(registry);
    registry.register_signatures(uxtheme_signatures::UXHEME_SIGNATURES);
}

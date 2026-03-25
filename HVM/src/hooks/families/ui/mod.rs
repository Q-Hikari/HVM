use crate::hooks::registry::HookRegistry;

pub mod comctl32;
pub mod comdlg32;
pub mod imm32;
pub mod user32;
pub mod uxtheme;

/// Registers windowing and shell UI DLL families.
pub fn register(registry: &mut HookRegistry) {
    comctl32::register_comctl32_hooks(registry);
    comdlg32::register_comdlg32_hooks(registry);
    imm32::register_imm32_hooks(registry);
    user32::register_user32_hooks(registry);
    uxtheme::register_uxtheme_hooks(registry);
}

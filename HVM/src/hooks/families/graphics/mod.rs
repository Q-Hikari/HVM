use crate::hooks::registry::HookRegistry;

pub mod gdi32;
pub mod gdiplus;
pub mod msimg32;
pub mod winmm;

/// Registers graphics and media DLL families.
pub fn register(registry: &mut HookRegistry) {
    gdi32::register_gdi32_hooks(registry);
    gdiplus::register_gdiplus_hooks(registry);
    msimg32::register_msimg32_hooks(registry);
    winmm::register_winmm_hooks(registry);
}

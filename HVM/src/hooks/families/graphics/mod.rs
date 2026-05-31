use crate::hooks::registry::HookRegistry;

pub mod dxgi;
pub mod dxgi_signatures;
pub mod gdi32;
pub mod gdi32_signatures;
pub mod gdiplus;
pub mod gdiplus_signatures;
pub mod msimg32;
pub mod msimg32_signatures;
pub mod winmm;
pub mod winmm_signatures;

/// Registers graphics and media DLL families.
pub fn register(registry: &mut HookRegistry) {
    dxgi::register_dxgi_hooks(registry);
    gdi32::register_gdi32_hooks(registry);
    gdiplus::register_gdiplus_hooks(registry);
    msimg32::register_msimg32_hooks(registry);
    winmm::register_winmm_hooks(registry);
    registry.register_signatures(dxgi_signatures::DXGI_SIGNATURES);
    registry.register_signatures(gdi32_signatures::GDI32_SIGNATURES);
    registry.register_signatures(gdiplus_signatures::GDIPLUS_SIGNATURES);
    registry.register_signatures(msimg32_signatures::MSIMG32_SIGNATURES);
    registry.register_signatures(winmm_signatures::WINMM_SIGNATURES);
}

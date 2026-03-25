use crate::hooks::registry::HookRegistry;

pub mod msvcp140;
pub mod msvcrt;
pub mod ucrt;
pub mod vcruntime140;

/// Registers C/C++ runtime hook catalogs.
pub fn register(registry: &mut HookRegistry) {
    msvcrt::register_msvcrt_hooks(registry);
    msvcp140::register_msvcp140_hooks(registry);
    ucrt::register_ucrt_hooks(registry);
    vcruntime140::register_vcruntime140_hooks(registry);
}

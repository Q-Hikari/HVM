use crate::hooks::registry::HookRegistry;

pub mod msvcp140;
pub mod msvcp140_signatures;
pub mod msvcrt;
pub mod msvcrt_signatures;
pub mod ucrt;
pub mod ucrt_signatures;
pub mod variadic_signatures;
pub mod vcruntime140;
pub mod vcruntime140_signatures;

/// Registers C/C++ runtime hook catalogs.
pub fn register(registry: &mut HookRegistry) {
    msvcrt::register_msvcrt_hooks(registry);
    msvcp140::register_msvcp140_hooks(registry);
    ucrt::register_ucrt_hooks(registry);
    vcruntime140::register_vcruntime140_hooks(registry);
    registry.register_signatures(msvcp140_signatures::MSVCP140_SIGNATURES);
    registry.register_signatures(ucrt_signatures::UCRT_SIGNATURES);
    registry.register_signatures(vcruntime140_signatures::VCRUNTIME140_SIGNATURES);
}

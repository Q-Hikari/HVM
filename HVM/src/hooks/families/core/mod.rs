use crate::hooks::registry::HookRegistry;

pub mod appmodel_runtime;
pub mod kernel32;
pub mod ntdll;
pub mod psapi;
pub mod version;

/// Registers process/runtime core DLL families.
pub fn register(registry: &mut HookRegistry) {
    appmodel_runtime::register_appmodel_runtime_hooks(registry);
    kernel32::register_kernel32_hooks(registry);
    ntdll::register_ntdll_hooks(registry);
    psapi::register_psapi_hooks(registry);
    version::register_version_hooks(registry);
}

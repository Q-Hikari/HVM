use crate::hooks::registry::HookRegistry;

pub mod shell32;
pub mod shlwapi;
pub mod taskschd;
pub mod urlmon;
pub mod wtsapi32;

/// Registers shell, session, task, and URL moniker DLL families.
pub fn register(registry: &mut HookRegistry) {
    shell32::register_shell32_hooks(registry);
    shlwapi::register_shlwapi_hooks(registry);
    taskschd::register_taskschd_hooks(registry);
    urlmon::register_urlmon_hooks(registry);
    wtsapi32::register_wtsapi32_hooks(registry);
}

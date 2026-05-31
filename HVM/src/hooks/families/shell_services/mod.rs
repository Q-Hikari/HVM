use crate::hooks::registry::HookRegistry;

pub mod propsys;
pub mod propsys_signatures;
pub mod shell32;
pub mod shell32_signatures;
pub mod shlwapi;
pub mod shlwapi_signatures;
pub mod taskschd;
pub mod taskschd_signatures;
pub mod urlmon;
pub mod urlmon_signatures;
pub mod wtsapi32;
pub mod wtsapi32_signatures;
pub mod xmllite;
pub mod xmllite_signatures;

/// Registers shell, session, task, and URL moniker DLL families.
pub fn register(registry: &mut HookRegistry) {
    propsys::register_propsys_hooks(registry);
    shell32::register_shell32_hooks(registry);
    shlwapi::register_shlwapi_hooks(registry);
    taskschd::register_taskschd_hooks(registry);
    urlmon::register_urlmon_hooks(registry);
    wtsapi32::register_wtsapi32_hooks(registry);
    xmllite::register_xmllite_hooks(registry);
    registry.register_signatures(propsys_signatures::PROPSYS_SIGNATURES);
    registry.register_signatures(shell32_signatures::SHELL32_SIGNATURES);
    registry.register_signatures(shlwapi_signatures::SHLWAPI_SIGNATURES);
    registry.register_signatures(taskschd_signatures::TASKSCHD_SIGNATURES);
    registry.register_signatures(urlmon_signatures::URLMON_SIGNATURES);
    registry.register_signatures(wtsapi32_signatures::WTSAPI32_SIGNATURES);
    registry.register_signatures(xmllite_signatures::XMLLITE_SIGNATURES);
}

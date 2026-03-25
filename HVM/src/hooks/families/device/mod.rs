use crate::hooks::registry::HookRegistry;

pub mod cabinet;
pub mod cfgmgr32;
pub mod setupapi;

/// Registers device, installation, and compression DLL families.
pub fn register(registry: &mut HookRegistry) {
    cabinet::register_cabinet_hooks(registry);
    cfgmgr32::register_cfgmgr32_hooks(registry);
    setupapi::register_setupapi_hooks(registry);
}

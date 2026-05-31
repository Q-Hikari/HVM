use crate::hooks::registry::HookRegistry;

pub mod cabinet;
pub mod cabinet_signatures;
pub mod cfgmgr32;
pub mod cfgmgr32_signatures;
pub mod setupapi;
pub mod setupapi_signatures;

/// Registers device, installation, and compression DLL families.
pub fn register(registry: &mut HookRegistry) {
    cabinet::register_cabinet_hooks(registry);
    cfgmgr32::register_cfgmgr32_hooks(registry);
    setupapi::register_setupapi_hooks(registry);
    registry.register_signatures(cabinet_signatures::CABINET_SIGNATURES);
    registry.register_signatures(cfgmgr32_signatures::CFGMGR32_SIGNATURES);
    registry.register_signatures(setupapi_signatures::SETUPAPI_SIGNATURES);
}

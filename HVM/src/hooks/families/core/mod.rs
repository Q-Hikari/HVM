use crate::hooks::registry::HookRegistry;

pub mod api_set_contracts;
pub mod appmodel_runtime;
pub mod appmodel_runtime_signatures;
pub mod featurestaging;
pub mod featurestaging_signatures;
pub mod kernel32;
pub mod kernel32_signatures;
pub mod ntdll;
pub mod ntdll_signatures;
pub mod psapi;
pub mod psapi_signatures;
pub mod version;
pub mod version_signatures;

/// Registers process/runtime core DLL families.
pub fn register(registry: &mut HookRegistry) {
    api_set_contracts::register_api_set_contract_hooks(registry);
    appmodel_runtime::register_appmodel_runtime_hooks(registry);
    featurestaging::register_featurestaging_hooks(registry);
    kernel32::register_kernel32_hooks(registry);
    ntdll::register_ntdll_hooks(registry);
    psapi::register_psapi_hooks(registry);
    version::register_version_hooks(registry);
    registry.register_signatures(appmodel_runtime_signatures::APPMODEL_RUNTIME_SIGNATURES);
    registry.register_signatures(featurestaging_signatures::FEATURESTAGING_SIGNATURES);
    registry.register_signatures(psapi_signatures::PSAPI_SIGNATURES);
    registry.register_signatures(version_signatures::VERSION_SIGNATURES);
}

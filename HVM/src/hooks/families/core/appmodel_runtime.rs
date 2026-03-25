use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("AppPolicyGetProcessTerminationMethod", 2),
    ("AppPolicyGetThreadInitializationType", 2),
];

/// Collects the generated hook definitions for appmodel runtime API-set exports.
#[derive(Debug, Default, Clone, Copy)]
pub struct AppModelRuntimeHookLibrary;

impl HookLibrary for AppModelRuntimeHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("api-ms-win-appmodel-runtime-l1-1-2.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this API-set family.
pub fn register_appmodel_runtime_hooks(registry: &mut HookRegistry) {
    registry.register_library(&AppModelRuntimeHookLibrary);
}

use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("AppPolicyGetProcessTerminationMethod", LogicalAbi::WinApi),
    ("AppPolicyGetThreadInitializationType", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this API-set family.
pub fn register_appmodel_runtime_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("api-ms-win-appmodel-runtime-l1-1-2.dll", &EXPORTS);
}

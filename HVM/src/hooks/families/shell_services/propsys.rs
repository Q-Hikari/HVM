use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("PropVariantToString", LogicalAbi::WinApi),
    ("PropVariantToUInt32", LogicalAbi::WinApi),
    ("PropVariantToUInt32WithDefault", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_propsys_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("propsys.dll", &EXPORTS);
}

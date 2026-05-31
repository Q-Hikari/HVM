use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("AccessibleObjectFromWindow", LogicalAbi::WinApi),
    ("CreateStdAccessibleObject", LogicalAbi::WinApi),
    ("LresultFromObject", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_oleacc_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("oleacc.dll", &EXPORTS);
}

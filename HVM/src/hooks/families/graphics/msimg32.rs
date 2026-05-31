use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("AlphaBlend", LogicalAbi::WinApi),
    ("TransparentBlt", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_msimg32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("msimg32.dll", &EXPORTS);
}

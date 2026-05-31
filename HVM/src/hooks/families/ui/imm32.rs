use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("ImmGetContext", LogicalAbi::WinApi),
    ("ImmGetOpenStatus", LogicalAbi::WinApi),
    ("ImmReleaseContext", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_imm32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("imm32.dll", &EXPORTS);
}

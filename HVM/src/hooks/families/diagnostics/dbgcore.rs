use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("MiniDumpWriteDump", LogicalAbi::WinApi),
    ("MiniDumpReadDumpStream", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_dbgcore_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("dbgcore.dll", &FUNCTIONS);
}

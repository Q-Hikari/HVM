use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("ApphelpCheckShellObject", LogicalAbi::WinApi),
    ("SdbInitDatabase", LogicalAbi::WinApi),
    ("SdbOpenDatabase", LogicalAbi::WinApi),
    ("SdbOpenApphelpDetailsDatabase", LogicalAbi::WinApi),
    ("SdbCloseDatabase", LogicalAbi::WinApi),
    ("SdbReleaseDatabase", LogicalAbi::WinApi),
    ("SdbGetAppPatchDir", LogicalAbi::WinApi),
    ("SdbTagRefToTagID", LogicalAbi::WinApi),
    ("ShimFlushCache", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_apphelp_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("apphelp.dll", &FUNCTIONS);
}

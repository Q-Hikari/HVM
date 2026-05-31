use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("NetApiBufferFree", LogicalAbi::WinApi),
    ("NetpIsRemote", LogicalAbi::WinApi),
    ("NetpIsRemoteNameValid", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_netutils_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("netutils.dll", &FUNCTIONS);
}

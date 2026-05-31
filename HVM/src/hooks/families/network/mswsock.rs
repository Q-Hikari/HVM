use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[("TransmitFile", LogicalAbi::WinApi)];

/// Registers the generated hook definitions for this DLL family.
pub fn register_mswsock_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("mswsock.dll", &FUNCTIONS);
}

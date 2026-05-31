use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("RasDialA", LogicalAbi::WinApi),
    ("RasDialW", LogicalAbi::WinApi),
    ("RasEnumConnectionsA", LogicalAbi::WinApi),
    ("RasEnumConnectionsW", LogicalAbi::WinApi),
    ("RasEnumEntriesA", LogicalAbi::WinApi),
    ("RasEnumEntriesW", LogicalAbi::WinApi),
    ("RasGetConnectStatusA", LogicalAbi::WinApi),
    ("RasGetConnectStatusW", LogicalAbi::WinApi),
    ("RasGetErrorStringA", LogicalAbi::WinApi),
    ("RasGetErrorStringW", LogicalAbi::WinApi),
    ("RasHangUpA", LogicalAbi::WinApi),
    ("RasHangUpW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_rasapi32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("rasapi32.dll", &FUNCTIONS);
}

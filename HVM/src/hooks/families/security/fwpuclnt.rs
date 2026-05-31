use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("FwpmEngineOpen0", LogicalAbi::WinApi),
    ("FwpmEngineClose0", LogicalAbi::WinApi),
    ("FwpmTransactionBegin0", LogicalAbi::WinApi),
    ("FwpmTransactionCommit0", LogicalAbi::WinApi),
    ("FwpmSubLayerAdd0", LogicalAbi::WinApi),
    ("FwpmCalloutAdd0", LogicalAbi::WinApi),
    ("FwpmFilterAdd0", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_fwpuclnt_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("fwpuclnt.dll", &FUNCTIONS);
}

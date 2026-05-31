use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WlanOpenHandle", LogicalAbi::WinApi),
    ("WlanCloseHandle", LogicalAbi::WinApi),
    ("WlanEnumInterfaces", LogicalAbi::WinApi),
    ("WlanQueryInterface", LogicalAbi::WinApi),
    ("WlanScan", LogicalAbi::WinApi),
    ("WlanGetAvailableNetworkList", LogicalAbi::WinApi),
    ("WlanConnect", LogicalAbi::WinApi),
    ("WlanDisconnect", LogicalAbi::WinApi),
    ("WlanFreeMemory", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wlanapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wlanapi.dll", &FUNCTIONS);
}

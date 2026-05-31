use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("GetBestInterface", LogicalAbi::WinApi),
    ("GetNumberOfInterfaces", LogicalAbi::WinApi),
    ("GetFriendlyIfIndex", LogicalAbi::WinApi),
    ("GetAdaptersInfo", LogicalAbi::WinApi),
    ("GetNetworkParams", LogicalAbi::WinApi),
    ("GetAdaptersAddresses", LogicalAbi::WinApi),
    ("GetExtendedTcpTable", LogicalAbi::WinApi),
    ("GetTcpTable", LogicalAbi::WinApi),
    ("GetUdpTable", LogicalAbi::WinApi),
    ("GetIpNetTable", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_iphlpapi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("iphlpapi.dll", &FUNCTIONS);
}

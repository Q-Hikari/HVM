use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("MultinetGetConnectionPerformanceA", LogicalAbi::WinApi),
    ("MultinetGetConnectionPerformanceW", LogicalAbi::WinApi),
    ("WNetAddConnectionA", LogicalAbi::WinApi),
    ("WNetAddConnectionW", LogicalAbi::WinApi),
    ("WNetAddConnection2A", LogicalAbi::WinApi),
    ("WNetAddConnection2W", LogicalAbi::WinApi),
    ("WNetAddConnection3A", LogicalAbi::WinApi),
    ("WNetAddConnection3W", LogicalAbi::WinApi),
    ("WNetUseConnectionA", LogicalAbi::WinApi),
    ("WNetUseConnectionW", LogicalAbi::WinApi),
    ("WNetCancelConnectionA", LogicalAbi::WinApi),
    ("WNetCancelConnectionW", LogicalAbi::WinApi),
    ("WNetCancelConnection2A", LogicalAbi::WinApi),
    ("WNetCancelConnection2W", LogicalAbi::WinApi),
    ("WNetOpenEnumA", LogicalAbi::WinApi),
    ("WNetOpenEnumW", LogicalAbi::WinApi),
    ("WNetEnumResourceA", LogicalAbi::WinApi),
    ("WNetEnumResourceW", LogicalAbi::WinApi),
    ("WNetCloseEnum", LogicalAbi::WinApi),
    ("WNetGetConnectionA", LogicalAbi::WinApi),
    ("WNetGetConnectionW", LogicalAbi::WinApi),
    ("WNetGetLastErrorA", LogicalAbi::WinApi),
    ("WNetGetLastErrorW", LogicalAbi::WinApi),
    ("WNetGetNetworkInformationA", LogicalAbi::WinApi),
    ("WNetGetNetworkInformationW", LogicalAbi::WinApi),
    ("WNetGetProviderNameA", LogicalAbi::WinApi),
    ("WNetGetProviderNameW", LogicalAbi::WinApi),
    ("WNetGetResourceInformationA", LogicalAbi::WinApi),
    ("WNetGetResourceInformationW", LogicalAbi::WinApi),
    ("WNetGetResourceParentA", LogicalAbi::WinApi),
    ("WNetGetResourceParentW", LogicalAbi::WinApi),
    ("WNetGetUniversalNameA", LogicalAbi::WinApi),
    ("WNetGetUniversalNameW", LogicalAbi::WinApi),
    ("WNetGetUserA", LogicalAbi::WinApi),
    ("WNetGetUserW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_mpr_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("mpr.dll", &FUNCTIONS);
}

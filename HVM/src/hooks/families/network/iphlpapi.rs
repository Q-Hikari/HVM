use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "iphlpapi.dll",
        "GetBestInterface",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetNumberOfInterfaces",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetFriendlyIfIndex",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetAdaptersInfo",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetNetworkParams",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetAdaptersAddresses",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetExtendedTcpTable",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetTcpTable",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetUdpTable",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "iphlpapi.dll",
        "GetIpNetTable",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct IphlpapiHookLibrary;

impl HookLibrary for IphlpapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_iphlpapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&IphlpapiHookLibrary);
}

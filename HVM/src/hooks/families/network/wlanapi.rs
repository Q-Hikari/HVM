use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "wlanapi.dll",
        "WlanOpenHandle",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanCloseHandle",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanEnumInterfaces",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanQueryInterface",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanScan",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanGetAvailableNetworkList",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanConnect",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanDisconnect",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wlanapi.dll",
        "WlanFreeMemory",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WlanapiHookLibrary;

impl HookLibrary for WlanapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_wlanapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WlanapiHookLibrary);
}

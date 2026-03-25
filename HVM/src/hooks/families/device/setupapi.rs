use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "setupapi.dll",
        "SetupDiGetClassDevsA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetClassDevsW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiDestroyDeviceInfoList",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiEnumDeviceInfo",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceRegistryPropertyA",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceRegistryPropertyW",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceInstanceIdA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceInstanceIdW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiOpenDevRegKey",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiEnumDeviceInterfaces",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceInterfaceDetailA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetDeviceInterfaceDetailW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiClassGuidsFromNameA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiClassGuidsFromNameW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetINFClassA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "setupapi.dll",
        "SetupDiGetINFClassW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct SetupapiHookLibrary;

impl HookLibrary for SetupapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_setupapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&SetupapiHookLibrary);
}

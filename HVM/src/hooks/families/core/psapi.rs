use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "psapi.dll",
        "EnumProcesses",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "EnumProcessModules",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "EnumProcessModulesEx",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32EnumProcessModules",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32EnumProcessModulesEx",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetModuleBaseNameA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetModuleBaseNameW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetModuleBaseNameA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetModuleBaseNameW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetModuleFileNameExA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetModuleFileNameExW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetModuleFileNameExA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetModuleFileNameExW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetModuleInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetModuleInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetProcessImageFileNameA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetProcessImageFileNameW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetMappedFileNameA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetMappedFileNameW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "EmptyWorkingSet",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "psapi.dll",
        "GetProcessMemoryInfo",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "kernel32.dll",
        "K32GetProcessMemoryInfo",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct PsapiHookLibrary;

impl HookLibrary for PsapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_psapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&PsapiHookLibrary);
}

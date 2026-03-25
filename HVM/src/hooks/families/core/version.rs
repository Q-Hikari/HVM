use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "version.dll",
        "GetFileVersionInfoSizeA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoSizeW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoSizeExA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoSizeExW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoExA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "GetFileVersionInfoExW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "VerQueryValueA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "VerQueryValueW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "VerLanguageNameA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "version.dll",
        "VerLanguageNameW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct VersionHookLibrary;

impl HookLibrary for VersionHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_version_hooks(registry: &mut HookRegistry) {
    registry.register_library(&VersionHookLibrary);
}

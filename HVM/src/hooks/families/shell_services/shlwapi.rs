use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "shlwapi.dll",
        "PathFileExistsW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathAppendW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathAddBackslashW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathCombineW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathFindFileNameW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathFindExtensionW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathIsUNCW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathRemoveFileSpecW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathStripToRootW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "PathMatchSpecA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrCmpIW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrCmpNIW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrStrIW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrStrIA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrRChrW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrTrimA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "SHGetValueW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "SHGetValueA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "SHSetValueW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "SHSetValueA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "SHCreateStreamOnFileW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "shlwapi.dll",
        "StrFormatKBSizeW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShlwapiHookLibrary;

impl HookLibrary for ShlwapiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_shlwapi_hooks(registry: &mut HookRegistry) {
    registry.register_library(&ShlwapiHookLibrary);
}

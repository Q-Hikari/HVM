use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "apphelp.dll",
        "ApphelpCheckShellObject",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbInitDatabase",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbOpenDatabase",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbOpenApphelpDetailsDatabase",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbCloseDatabase",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbReleaseDatabase",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbGetAppPatchDir",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "SdbTagRefToTagID",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "apphelp.dll",
        "ShimFlushCache",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApphelpHookLibrary;

impl HookLibrary for ApphelpHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_apphelp_hooks(registry: &mut HookRegistry) {
    registry.register_library(&ApphelpHookLibrary);
}

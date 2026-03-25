use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "netutils.dll",
        "NetApiBufferFree",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "netutils.dll",
        "NetpIsRemote",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "netutils.dll",
        "NetpIsRemoteNameValid",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetutilsHookLibrary;

impl HookLibrary for NetutilsHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_netutils_hooks(registry: &mut HookRegistry) {
    registry.register_library(&NetutilsHookLibrary);
}

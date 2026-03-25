use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "cryptnet.dll",
        "CryptRetrieveObjectByUrlA",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptnet.dll",
        "CryptRetrieveObjectByUrlW",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptnet.dll",
        "CryptGetObjectUrl",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptnet.dll",
        "CryptGetTimeValidObject",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct CryptnetHookLibrary;

impl HookLibrary for CryptnetHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_cryptnet_hooks(registry: &mut HookRegistry) {
    registry.register_library(&CryptnetHookLibrary);
}

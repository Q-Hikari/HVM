use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "ncrypt.dll",
        "NCryptOpenStorageProvider",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptOpenKey",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptCreatePersistedKey",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptFinalizeKey",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptDeleteKey",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptFreeObject",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptGetProperty",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptSetProperty",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptSignHash",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptVerifySignature",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptEncrypt",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptDecrypt",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptImportKey",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "ncrypt.dll",
        "NCryptExportKey",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct NcryptHookLibrary;

impl HookLibrary for NcryptHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_ncrypt_hooks(registry: &mut HookRegistry) {
    registry.register_library(&NcryptHookLibrary);
}

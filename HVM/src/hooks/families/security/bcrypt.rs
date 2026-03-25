use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "bcrypt.dll",
        "BCryptOpenAlgorithmProvider",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptCloseAlgorithmProvider",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptGetProperty",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptSetProperty",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptCreateHash",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptHashData",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptFinishHash",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptDestroyHash",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptDuplicateHash",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptGenRandom",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptGenerateSymmetricKey",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptImportKey",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptImportKeyPair",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptExportKey",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptEncrypt",
        10,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptDecrypt",
        10,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "bcrypt.dll",
        "BCryptDestroyKey",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct BcryptHookLibrary;

impl HookLibrary for BcryptHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_bcrypt_hooks(registry: &mut HookRegistry) {
    registry.register_library(&BcryptHookLibrary);
}

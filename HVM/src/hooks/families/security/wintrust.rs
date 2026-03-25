use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "wintrust.dll",
        "WinVerifyTrust",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "WinVerifyTrustEx",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminAcquireContext",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminAcquireContext2",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminReleaseContext",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminCalcHashFromFileHandle",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminCalcHashFromFileHandle2",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminEnumCatalogFromHash",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATCatalogInfoFromContext",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATAdminReleaseCatalogContext",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "WTHelperProvDataFromStateData",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "WTHelperGetProvSignerFromChain",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "WTHelperGetProvCertFromChain",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATOpen",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATClose",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATEnumerateMember",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "wintrust.dll",
        "CryptCATStoreFromHandle",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WintrustHookLibrary;

impl HookLibrary for WintrustHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_wintrust_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WintrustHookLibrary);
}

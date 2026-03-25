use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "cryptui.dll",
        "CryptUIDlgViewContext",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgSelectCertificateFromStore",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgSelectCertificateA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgSelectCertificateW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgSelectStoreA",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgSelectStoreW",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgCertMgr",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgViewCertificateA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgViewCertificateW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgViewCertificatePropertiesA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIDlgViewCertificatePropertiesW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIGetCertificatePropertiesPagesA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIGetCertificatePropertiesPagesW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIGetViewSignaturesPagesA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIGetViewSignaturesPagesW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIWizDigitalSign",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIWizFreeDigitalSignContext",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIWizExport",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIWizImport",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cryptui.dll",
        "CryptUIStartCertMgr",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct CryptuiHookLibrary;

impl HookLibrary for CryptuiHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_cryptui_hooks(registry: &mut HookRegistry) {
    registry.register_library(&CryptuiHookLibrary);
}

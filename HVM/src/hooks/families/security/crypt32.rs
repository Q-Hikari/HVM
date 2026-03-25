use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "crypt32.dll",
        "CertOpenStore",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertOpenSystemStoreW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertCloseStore",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertAddStoreToCollection",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertFindCertificateInStore",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertEnumCertificatesInStore",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertFreeCertificateContext",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertGetCertificateContextProperty",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertGetNameStringW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptDecodeObjectEx",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptDecodeObject",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptQueryObject",
        11,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptMsgOpenToDecode",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptMsgUpdate",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptMsgGetParam",
        5,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptMsgControl",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertGetCertificateChain",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CertFreeCertificateChain",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "crypt32.dll",
        "CryptMsgClose",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Crypt32HookLibrary;

impl HookLibrary for Crypt32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_crypt32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Crypt32HookLibrary);
}

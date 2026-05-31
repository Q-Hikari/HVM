use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CertOpenStore", LogicalAbi::WinApi),
    ("CertOpenSystemStoreW", LogicalAbi::WinApi),
    ("CertCloseStore", LogicalAbi::WinApi),
    ("CertAddStoreToCollection", LogicalAbi::WinApi),
    ("CertFindCertificateInStore", LogicalAbi::WinApi),
    ("CertEnumCertificatesInStore", LogicalAbi::WinApi),
    ("CertFreeCertificateContext", LogicalAbi::WinApi),
    ("CertGetCertificateContextProperty", LogicalAbi::WinApi),
    ("CertGetNameStringW", LogicalAbi::WinApi),
    ("CryptDecodeObjectEx", LogicalAbi::WinApi),
    ("CryptDecodeObject", LogicalAbi::WinApi),
    ("CryptQueryObject", LogicalAbi::WinApi),
    ("CryptMsgOpenToDecode", LogicalAbi::WinApi),
    ("CryptMsgUpdate", LogicalAbi::WinApi),
    ("CryptMsgGetParam", LogicalAbi::WinApi),
    ("CryptMsgControl", LogicalAbi::WinApi),
    ("CertGetCertificateChain", LogicalAbi::WinApi),
    ("CertFreeCertificateChain", LogicalAbi::WinApi),
    ("CryptMsgClose", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_crypt32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("crypt32.dll", &FUNCTIONS);
}

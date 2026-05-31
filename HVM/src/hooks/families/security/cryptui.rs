use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CryptUIDlgViewContext", LogicalAbi::WinApi),
    ("CryptUIDlgSelectCertificateFromStore", LogicalAbi::WinApi),
    ("CryptUIDlgSelectCertificateA", LogicalAbi::WinApi),
    ("CryptUIDlgSelectCertificateW", LogicalAbi::WinApi),
    ("CryptUIDlgSelectStoreA", LogicalAbi::WinApi),
    ("CryptUIDlgSelectStoreW", LogicalAbi::WinApi),
    ("CryptUIDlgCertMgr", LogicalAbi::WinApi),
    ("CryptUIDlgViewCertificateA", LogicalAbi::WinApi),
    ("CryptUIDlgViewCertificateW", LogicalAbi::WinApi),
    ("CryptUIDlgViewCertificatePropertiesA", LogicalAbi::WinApi),
    ("CryptUIDlgViewCertificatePropertiesW", LogicalAbi::WinApi),
    ("CryptUIGetCertificatePropertiesPagesA", LogicalAbi::WinApi),
    ("CryptUIGetCertificatePropertiesPagesW", LogicalAbi::WinApi),
    ("CryptUIGetViewSignaturesPagesA", LogicalAbi::WinApi),
    ("CryptUIGetViewSignaturesPagesW", LogicalAbi::WinApi),
    ("CryptUIWizDigitalSign", LogicalAbi::WinApi),
    ("CryptUIWizFreeDigitalSignContext", LogicalAbi::WinApi),
    ("CryptUIWizExport", LogicalAbi::WinApi),
    ("CryptUIWizImport", LogicalAbi::WinApi),
    ("CryptUIStartCertMgr", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_cryptui_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("cryptui.dll", &FUNCTIONS);
}

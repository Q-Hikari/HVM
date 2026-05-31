use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("NCryptOpenStorageProvider", LogicalAbi::WinApi),
    ("NCryptOpenKey", LogicalAbi::WinApi),
    ("NCryptCreatePersistedKey", LogicalAbi::WinApi),
    ("NCryptFinalizeKey", LogicalAbi::WinApi),
    ("NCryptDeleteKey", LogicalAbi::WinApi),
    ("NCryptFreeObject", LogicalAbi::WinApi),
    ("NCryptGetProperty", LogicalAbi::WinApi),
    ("NCryptSetProperty", LogicalAbi::WinApi),
    ("NCryptSignHash", LogicalAbi::WinApi),
    ("NCryptVerifySignature", LogicalAbi::WinApi),
    ("NCryptEncrypt", LogicalAbi::WinApi),
    ("NCryptDecrypt", LogicalAbi::WinApi),
    ("NCryptImportKey", LogicalAbi::WinApi),
    ("NCryptExportKey", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_ncrypt_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("ncrypt.dll", &FUNCTIONS);
}

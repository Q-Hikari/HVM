use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("BCryptOpenAlgorithmProvider", LogicalAbi::WinApi),
    ("BCryptCloseAlgorithmProvider", LogicalAbi::WinApi),
    ("BCryptGetProperty", LogicalAbi::WinApi),
    ("BCryptSetProperty", LogicalAbi::WinApi),
    ("BCryptCreateHash", LogicalAbi::WinApi),
    ("BCryptHashData", LogicalAbi::WinApi),
    ("BCryptFinishHash", LogicalAbi::WinApi),
    ("BCryptDestroyHash", LogicalAbi::WinApi),
    ("BCryptDuplicateHash", LogicalAbi::WinApi),
    ("BCryptGenRandom", LogicalAbi::WinApi),
    ("BCryptGenerateSymmetricKey", LogicalAbi::WinApi),
    ("BCryptImportKey", LogicalAbi::WinApi),
    ("BCryptImportKeyPair", LogicalAbi::WinApi),
    ("BCryptExportKey", LogicalAbi::WinApi),
    ("BCryptEncrypt", LogicalAbi::WinApi),
    ("BCryptDecrypt", LogicalAbi::WinApi),
    ("BCryptDestroyKey", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_bcrypt_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("bcrypt.dll", &FUNCTIONS);
}

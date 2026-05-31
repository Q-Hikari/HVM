use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("WinVerifyTrust", LogicalAbi::WinApi),
    ("WinVerifyTrustEx", LogicalAbi::WinApi),
    ("CryptCATAdminAcquireContext", LogicalAbi::WinApi),
    ("CryptCATAdminAcquireContext2", LogicalAbi::WinApi),
    ("CryptCATAdminReleaseContext", LogicalAbi::WinApi),
    ("CryptCATAdminCalcHashFromFileHandle", LogicalAbi::WinApi),
    ("CryptCATAdminCalcHashFromFileHandle2", LogicalAbi::WinApi),
    ("CryptCATAdminEnumCatalogFromHash", LogicalAbi::WinApi),
    ("CryptCATCatalogInfoFromContext", LogicalAbi::WinApi),
    ("CryptCATAdminReleaseCatalogContext", LogicalAbi::WinApi),
    ("WTHelperProvDataFromStateData", LogicalAbi::WinApi),
    ("WTHelperGetProvSignerFromChain", LogicalAbi::WinApi),
    ("WTHelperGetProvCertFromChain", LogicalAbi::WinApi),
    ("CryptCATOpen", LogicalAbi::WinApi),
    ("CryptCATClose", LogicalAbi::WinApi),
    ("CryptCATEnumerateMember", LogicalAbi::WinApi),
    ("CryptCATStoreFromHandle", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wintrust_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wintrust.dll", &FUNCTIONS);
}

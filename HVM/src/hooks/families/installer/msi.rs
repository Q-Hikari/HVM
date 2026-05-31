use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("DllCanUnloadNow", LogicalAbi::WinApi),
    ("DllGetClassObject", LogicalAbi::WinApi),
    ("MsiCloseHandle", LogicalAbi::WinApi),
    ("MsiCloseAllHandles", LogicalAbi::WinApi),
    ("MsiOpenPackageA", LogicalAbi::WinApi),
    ("MsiOpenPackageW", LogicalAbi::WinApi),
    ("MsiOpenPackageExA", LogicalAbi::WinApi),
    ("MsiOpenPackageExW", LogicalAbi::WinApi),
    ("MsiOpenDatabaseA", LogicalAbi::WinApi),
    ("MsiOpenDatabaseW", LogicalAbi::WinApi),
    ("MsiGetPropertyA", LogicalAbi::WinApi),
    ("MsiGetPropertyW", LogicalAbi::WinApi),
    ("MsiSetPropertyA", LogicalAbi::WinApi),
    ("MsiSetPropertyW", LogicalAbi::WinApi),
    ("MsiGetMode", LogicalAbi::WinApi),
    ("MsiDoActionA", LogicalAbi::WinApi),
    ("MsiDoActionW", LogicalAbi::WinApi),
    ("MsiProcessMessage", LogicalAbi::WinApi),
    ("MsiQueryProductStateA", LogicalAbi::WinApi),
    ("MsiQueryProductStateW", LogicalAbi::WinApi),
    ("MsiEnumProductsA", LogicalAbi::WinApi),
    ("MsiEnumProductsW", LogicalAbi::WinApi),
    ("MsiEnumProductsExA", LogicalAbi::WinApi),
    ("MsiEnumProductsExW", LogicalAbi::WinApi),
    ("MsiGetProductInfoA", LogicalAbi::WinApi),
    ("MsiGetProductInfoW", LogicalAbi::WinApi),
    ("MsiGetProductInfoExA", LogicalAbi::WinApi),
    ("MsiGetProductInfoExW", LogicalAbi::WinApi),
    ("MsiGetFileVersionA", LogicalAbi::WinApi),
    ("MsiGetFileVersionW", LogicalAbi::WinApi),
    ("MsiGetComponentPathA", LogicalAbi::WinApi),
    ("MsiGetComponentPathW", LogicalAbi::WinApi),
    ("MsiLocateComponentA", LogicalAbi::WinApi),
    ("MsiLocateComponentW", LogicalAbi::WinApi),
    ("MsiGetProductCodeA", LogicalAbi::WinApi),
    ("MsiGetProductCodeW", LogicalAbi::WinApi),
    ("MsiGetSummaryInformationA", LogicalAbi::WinApi),
    ("MsiGetSummaryInformationW", LogicalAbi::WinApi),
    ("MsiSummaryInfoGetPropertyA", LogicalAbi::WinApi),
    ("MsiSummaryInfoGetPropertyW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_msi_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("msi.dll", &FUNCTIONS);
}

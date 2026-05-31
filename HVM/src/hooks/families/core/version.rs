use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("GetFileVersionInfoSizeA", LogicalAbi::WinApi),
    ("GetFileVersionInfoSizeW", LogicalAbi::WinApi),
    ("GetFileVersionInfoSizeExA", LogicalAbi::WinApi),
    ("GetFileVersionInfoSizeExW", LogicalAbi::WinApi),
    ("GetFileVersionInfoA", LogicalAbi::WinApi),
    ("GetFileVersionInfoW", LogicalAbi::WinApi),
    ("GetFileVersionInfoExA", LogicalAbi::WinApi),
    ("GetFileVersionInfoExW", LogicalAbi::WinApi),
    ("VerQueryValueA", LogicalAbi::WinApi),
    ("VerQueryValueW", LogicalAbi::WinApi),
    ("VerLanguageNameA", LogicalAbi::WinApi),
    ("VerLanguageNameW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_version_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("version.dll", &FUNCTIONS);
}

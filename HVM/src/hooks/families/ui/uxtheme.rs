use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("CloseThemeData", LogicalAbi::WinApi),
    ("DrawThemeBackground", LogicalAbi::WinApi),
    ("DrawThemeParentBackground", LogicalAbi::WinApi),
    ("DrawThemeText", LogicalAbi::WinApi),
    ("GetCurrentThemeName", LogicalAbi::WinApi),
    ("GetThemeColor", LogicalAbi::WinApi),
    ("GetThemePartSize", LogicalAbi::WinApi),
    ("GetThemeSysColor", LogicalAbi::WinApi),
    ("GetWindowTheme", LogicalAbi::WinApi),
    ("IsAppThemed", LogicalAbi::WinApi),
    ("IsThemeBackgroundPartiallyTransparent", LogicalAbi::WinApi),
    ("OpenThemeData", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_uxtheme_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("uxtheme.dll", &EXPORTS);
}

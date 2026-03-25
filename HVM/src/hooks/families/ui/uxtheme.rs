use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;

const EXPORTS: &[(&str, usize)] = &[
    ("CloseThemeData", 1),
    ("DrawThemeBackground", 6),
    ("DrawThemeParentBackground", 3),
    ("DrawThemeText", 9),
    ("GetCurrentThemeName", 6),
    ("GetThemeColor", 5),
    ("GetThemePartSize", 7),
    ("GetThemeSysColor", 2),
    ("GetWindowTheme", 1),
    ("IsAppThemed", 0),
    ("IsThemeBackgroundPartiallyTransparent", 3),
    ("OpenThemeData", 2),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct UxthemeHookLibrary;

impl HookLibrary for UxthemeHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stdcall_definitions("uxtheme.dll", EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_uxtheme_hooks(registry: &mut HookRegistry) {
    registry.register_library(&UxthemeHookLibrary);
}

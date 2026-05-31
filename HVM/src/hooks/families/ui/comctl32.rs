use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("InitCommonControlsEx", LogicalAbi::WinApi),
    ("ImageList_Draw", LogicalAbi::WinApi),
    ("ImageList_GetImageCount", LogicalAbi::WinApi),
    ("ImageList_Remove", LogicalAbi::WinApi),
    ("ImageList_ReplaceIcon", LogicalAbi::WinApi),
    ("ordinal_345", LogicalAbi::WinApi),
    ("ordinal_381", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_comctl32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("comctl32.dll", &EXPORTS);
}

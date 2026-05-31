use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CommDlgExtendedError", LogicalAbi::WinApi),
    ("GetOpenFileNameA", LogicalAbi::WinApi),
    ("GetOpenFileNameW", LogicalAbi::WinApi),
    ("GetSaveFileNameA", LogicalAbi::WinApi),
    ("GetSaveFileNameW", LogicalAbi::WinApi),
    ("GetFileTitleA", LogicalAbi::WinApi),
    ("GetFileTitleW", LogicalAbi::WinApi),
    ("ChooseColorA", LogicalAbi::WinApi),
    ("ChooseColorW", LogicalAbi::WinApi),
    ("ChooseFontA", LogicalAbi::WinApi),
    ("ChooseFontW", LogicalAbi::WinApi),
    ("PrintDlgA", LogicalAbi::WinApi),
    ("PrintDlgW", LogicalAbi::WinApi),
    ("PageSetupDlgA", LogicalAbi::WinApi),
    ("PageSetupDlgW", LogicalAbi::WinApi),
    ("FindTextA", LogicalAbi::WinApi),
    ("FindTextW", LogicalAbi::WinApi),
    ("ReplaceTextA", LogicalAbi::WinApi),
    ("ReplaceTextW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_comdlg32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("comdlg32.dll", &FUNCTIONS);
}
